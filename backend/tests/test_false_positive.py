import hmac
import hashlib
import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.database import Base, get_db
from app.main import app, FP_ACK_MESSAGE
from app.models import Repo, Scan, Finding, RepoMemory

engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(name="db_session", autouse=True)
def db_session_fixture():
    Base.metadata.create_all(engine)
    session = TestingSessionLocal()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


@pytest.fixture(name="client")
def client_fixture(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture(name="scan_with_finding")
def scan_with_finding_fixture(db_session):
    repo = Repo(repo_id=12345, owner="acme", name="app", install_id="install_1")
    db_session.add(repo)
    db_session.commit()

    scan = Scan(
        repo_id=repo.repo_id,
        pr_number=7,
        pr_sha="abc123",
        status="completed",
        risk_score=10,
    )
    db_session.add(scan)
    db_session.commit()

    finding = Finding(
        scan_id=scan.id,
        file_path="vuln.py",
        line_number=3,
        rule_id="sql-injection",
        severity="high",
        description="SQL injection risk.",
        confidence="high",
    )
    db_session.add(finding)
    db_session.commit()
    return repo, scan, finding


def _signed_request(client, event, payload, secret="test_secret"):
    body_bytes = json.dumps(payload).encode("utf-8")
    signature = "sha256=" + hmac.new(
        secret.encode("utf-8"), body_bytes, hashlib.sha256
    ).hexdigest()

    with patch.object(settings, "VERIFY_GITHUB_WEBHOOKS", True), patch.object(
        settings, "GITHUB_WEBHOOK_SECRET", secret
    ):
        return client.post(
            "/webhook",
            content=body_bytes,
            headers={
                "X-GitHub-Event": event,
                "X-Hub-Signature-256": signature,
                "Content-Type": "application/json",
            },
        )


def _review_comment_payload(body, path, line, pr_number=7, comment_id=9001):
    return {
        "action": "created",
        "comment": {
            "id": comment_id,
            "body": body,
            "path": path,
            "line": line,
        },
        "pull_request": {"number": pr_number},
        "repository": {
            "id": 12345,
            "owner": {"login": "acme"},
            "name": "app",
        },
        "installation": {"id": 1},
    }


def test_fp_on_valid_finding_writes_repo_memory(client, db_session, scan_with_finding):
    repo, scan, finding = scan_with_finding
    payload = _review_comment_payload("/fp", "vuln.py", 3)

    with patch("app.main.post_comment") as mock_post_comment:
        response = _signed_request(client, "pull_request_review_comment", payload)

    assert response.status_code == 200
    assert response.json()["status"] == "recorded"
    assert response.json()["rule_id"] == "sql-injection"
    assert response.json()["file_pattern"] == "vuln.py"

    memory = db_session.query(RepoMemory).filter(RepoMemory.repo_id == repo.repo_id).all()
    assert len(memory) == 1
    assert memory[0].rule_id == finding.rule_id
    assert memory[0].file_pattern == "vuln.py"
    assert memory[0].outcome == "false_positive"

    mock_post_comment.assert_called_once_with(
        "acme",
        "app",
        7,
        9001,
        "mock_token",
        FP_ACK_MESSAGE,
    )


def test_fp_on_unrecognized_position_does_nothing(client, db_session, scan_with_finding):
    repo, _, _ = scan_with_finding
    payload = _review_comment_payload("/fp", "vuln.py", 99)

    with patch("app.main.post_comment") as mock_post_comment:
        response = _signed_request(client, "pull_request_review_comment", payload)

    assert response.status_code == 200
    assert response.json()["status"] == "ignored"

    memory = db_session.query(RepoMemory).filter(RepoMemory.repo_id == repo.repo_id).all()
    assert len(memory) == 0
    mock_post_comment.assert_not_called()


def test_non_fp_comments_are_ignored(client, db_session, scan_with_finding):
    repo, _, _ = scan_with_finding
    payload = _review_comment_payload("please ignore this", "vuln.py", 3)

    with patch("app.main.post_comment") as mock_post_comment:
        response = _signed_request(client, "pull_request_review_comment", payload)

    assert response.status_code == 200
    assert response.json()["status"] == "ignored"

    memory = db_session.query(RepoMemory).filter(RepoMemory.repo_id == repo.repo_id).all()
    assert len(memory) == 0
    mock_post_comment.assert_not_called()