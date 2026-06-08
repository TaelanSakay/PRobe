import hmac
import hashlib
import json
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.config import settings
from app.database import Base, get_db

# Setup in-memory SQLite database using StaticPool to preserve tables across connections
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


def test_health_check(client):
    """Test the health check endpoint returns 200 and correct status."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["app"] == "PRobe"


def test_webhook_missing_signature(client):
    """Test webhook fails with 401 when signature header is missing and validation is enabled."""
    with patch.object(settings, "VERIFY_GITHUB_WEBHOOKS", True), \
         patch.object(settings, "GITHUB_WEBHOOK_SECRET", "test_secret"):
        response = client.post(
            "/webhook",
            json={"action": "opened"},
            headers={"X-GitHub-Event": "pull_request"}
        )
        assert response.status_code == 401
        assert "Missing webhook signature" in response.json()["detail"]


def test_webhook_invalid_signature(client):
    """Test webhook fails with 401 when signature header is invalid."""
    with patch.object(settings, "VERIFY_GITHUB_WEBHOOKS", True), \
         patch.object(settings, "GITHUB_WEBHOOK_SECRET", "test_secret"):
        response = client.post(
            "/webhook",
            json={"action": "opened"},
            headers={
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": "sha256=invalid_signature_here"
            }
        )
        assert response.status_code == 401
        assert "Invalid webhook signature" in response.json()["detail"]


def test_webhook_valid_signature_queued(client):
    """Test webhook succeeds and queues celery task with valid signature and payload."""
    secret = "test_secret"
    payload = {
        "action": "opened",
        "number": 42,
        "repository": {
            "id": 12345,
            "owner": {"login": "owner"},
            "name": "repo"
        },
        "pull_request": {
            "head": {"sha": "sha_abc_123"}
        },
        "installation": {
            "id": 999
        }
    }
    body_bytes = json.dumps(payload).encode("utf-8")
    
    # Compute valid signature
    signature = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        body_bytes,
        hashlib.sha256
    ).hexdigest()

    with patch.object(settings, "VERIFY_GITHUB_WEBHOOKS", True), \
         patch.object(settings, "GITHUB_WEBHOOK_SECRET", secret), \
         patch("app.main.run_scan.delay") as mock_run_scan:
        
        response = client.post(
            "/webhook",
            content=body_bytes,
            headers={
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": signature,
                "Content-Type": "application/json"
            }
        )
        
        assert response.status_code == 200
        assert response.json()["status"] == "queued"
        mock_run_scan.assert_called_once_with(
            scan_id=response.json()["scan_id"],
            install_id="999",
            owner="owner",
            repo="repo",
            pr_number=42,
            head_sha="sha_abc_123"
        )


def test_webhook_ignored_event(client):
    """Test webhook ignores non-pull_request events with valid signature."""
    secret = "test_secret"
    payload = {"zen": "Keep it simple, stupid."}
    body_bytes = json.dumps(payload).encode("utf-8")
    
    # Compute valid signature
    signature = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        body_bytes,
        hashlib.sha256
    ).hexdigest()

    with patch.object(settings, "VERIFY_GITHUB_WEBHOOKS", True), \
         patch.object(settings, "GITHUB_WEBHOOK_SECRET", secret), \
         patch("app.main.run_scan.delay") as mock_run_scan:
        
        response = client.post(
            "/webhook",
            content=body_bytes,
            headers={
                "X-GitHub-Event": "ping",
                "X-Hub-Signature-256": signature,
                "Content-Type": "application/json"
            }
        )
        
        assert response.status_code == 200
        assert response.json()["status"] == "ignored"
        mock_run_scan.assert_not_called()
