import hmac
import hashlib
import json
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.models import Repo, Scan, Finding, RepoMemory
from app.tasks import run_scan
from app.main import app
from app.config import settings

# Setup isolated test database using StaticPool to retain tables across connections
engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(name="db_session", autouse=True)
def db_session_fixture():
    """Initializes in-memory database schema before each test."""
    Base.metadata.create_all(engine)
    session = TestingSessionLocal()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


@pytest.fixture(name="client")
def client_fixture(db_session):
    """Test client with overridden database dependency."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_webhook_creates_records_and_dispatches_task(client, db_session):
    """Test webhook endpoint verifies signatures, writes Repo/Scan records, and triggers Celery."""
    secret = "test_secret_123"
    payload = {
        "action": "opened",
        "number": 12,
        "repository": {
            "id": 999111,
            "owner": {"login": "test-owner"},
            "name": "test-repo",
        },
        "pull_request": {
            "head": {"sha": "headsha12345"},
        },
        "installation": {
            "id": 888222,
        },
    }
    body_bytes = json.dumps(payload).encode("utf-8")
    
    # Compute signature
    sig = "sha256=" + hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()

    with patch.object(settings, "VERIFY_GITHUB_WEBHOOKS", True), \
         patch.object(settings, "GITHUB_WEBHOOK_SECRET", secret), \
         patch("app.main.run_scan.delay") as mock_run_scan:
        
        response = client.post(
            "/webhook",
            content=body_bytes,
            headers={
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": sig,
                "Content-Type": "application/json",
            }
        )
        
        assert response.status_code == 200
        assert response.json()["status"] == "queued"
        
        # Verify Repo record created
        repo = db_session.query(Repo).filter(Repo.repo_id == 999111).first()
        assert repo is not None
        assert repo.owner == "test-owner"
        assert repo.name == "test-repo"
        assert repo.install_id == "888222"

        # Verify Scan record created
        scan = db_session.query(Scan).filter(Scan.repo_id == 999111).first()
        assert scan is not None
        assert scan.pr_number == 12
        assert scan.pr_sha == "headsha12345"
        assert scan.status == "pending"
        
        # Verify celery task was dispatched
        mock_run_scan.assert_called_once_with(
            scan_id=scan.id,
            install_id="888222",
            owner="test-owner",
            repo="test-repo",
            pr_number=12,
            head_sha="headsha12345"
        )


def test_run_scan_celery_task_execution_with_suppression(db_session):
    """
    Test Celery task run_scan end-to-end:
    - Fetches and parses diff & files.
    - Suppresses matching findings in RepoMemory.
    - Saves remaining findings and updates risk score/status.
    """
    # 1. Setup mock database records
    repo = Repo(repo_id=555666, owner="acme", name="app", install_id="install_99")
    db_session.add(repo)
    db_session.commit()

    scan = Scan(repo_id=repo.repo_id, pr_number=1, pr_sha="sha99", status="pending")
    db_session.add(scan)
    db_session.commit()

    # 2. Add suppression memory rule: suppress 'hardcoded-secret' in 'suppressed.py'
    suppression = RepoMemory(
        repo_id=repo.repo_id,
        rule_id="hardcoded-secret",
        file_pattern="suppressed.py",
        outcome="false_positive",
    )
    db_session.add(suppression)
    db_session.commit()

    # 3. Define mock diff and file contents
    mock_diff = """diff --git a/vuln.py b/vuln.py
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/vuln.py
@@ -0,0 +1,4 @@
+my_secret_key = "supersecret123"
+def run(cmd):
+    execute("SELECT * FROM users WHERE name = " + cmd)
diff --git a/suppressed.py b/suppressed.py
new file mode 100644
index 0000000..7891011
--- /dev/null
+++ b/suppressed.py
@@ -0,0 +1,3 @@
+admin_token = "admin-secret-token"
+def test():
+    pass
"""

    file_contents = {
        "vuln.py": 'my_secret_key = "supersecret123"\ndef run(cmd):\n    execute("SELECT * FROM users WHERE name = " + cmd)\n',
        "suppressed.py": 'admin_token = "admin-secret-token"\ndef test():\n    pass\n',
    }

    # Helper function to mock get_file_content calls
    def mock_get_file_content(owner, repo, path, ref, token):
        return file_contents[path]

    # Patch GitHub API client methods in the origin app.github_client module
    with patch("app.github_client.get_installation_token", return_value="fake_token"), \
         patch("app.github_client.get_pr_diff", return_value=mock_diff), \
         patch("app.github_client.get_file_content", side_effect=mock_get_file_content), \
         patch("app.github_client.post_review") as mock_post_review, \
         patch("app.database.SessionLocal", return_value=db_session):
        
        # Execute Celery task synchronously
        run_scan(
            scan_id=scan.id,
            install_id="install_99",
            owner="acme",
            repo="app",
            pr_number=1,
            head_sha="sha99"
        )

    # 4. Verify Scan and Findings records in DB
    scan_updated = db_session.query(Scan).filter(Scan.id == scan.id).first()
    assert scan_updated.status == "completed"
    
    # Expected: vuln.py line 1 (secret) + vuln.py line 3 (sql) = 20 risk score
    # suppressed.py line 1 (secret) is suppressed, so total risk = 20
    assert scan_updated.risk_score == 20

    findings = db_session.query(Finding).filter(Finding.scan_id == scan.id).all()
    # Check details of saved findings (should only be 2 findings from vuln.py)
    assert len(findings) == 2
    
    paths = [f.file_path for f in findings]
    assert "vuln.py" in paths
    assert "suppressed.py" not in paths
    
    rules = [f.rule_id for f in findings]
    assert "hardcoded-secret" in rules
    assert "sql-injection" in rules

    mock_post_review.assert_called_once()
    args, _ = mock_post_review.call_args
    owner, repo, pr_number, head_sha, token, findings, risk_score = args
    assert owner == "acme"
    assert repo == "app"
    assert pr_number == 1
    assert head_sha == "sha99"
    assert token == "mock_token"
    assert risk_score == 20
    assert len(findings) == 2
