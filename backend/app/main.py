import hmac
import hashlib
import json
import logging
from fastapi import FastAPI, Request, HTTPException, Header, status, Depends
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.models import Repo, Scan, Finding, RepoMemory
from app.tasks import run_scan
from app.github_client import get_installation_token, post_comment

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("probe")

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="GitHub App for AST-based security vulnerability scanning on Pull Requests",
    version="0.1.0",
)


def verify_signature(payload_bytes: bytes, signature_header: str, secret: str) -> bool:
    """
    Verify that the payload matches the signature sent by GitHub.
    GitHub uses HMAC-SHA256.
    """
    if not signature_header.startswith("sha256="):
        return False
    
    expected_signature = signature_header[7:]
    computed_signature = hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(expected_signature, computed_signature)


FP_ACK_MESSAGE = (
    "Got it — I'll stop flagging this pattern in future PRs for this repo. 🧠"
)


def _get_github_token(install_id: str) -> str:
    try:
        if (
            not settings.GITHUB_APP_ID
            or not settings.GITHUB_PRIVATE_KEY
            or settings.GITHUB_PRIVATE_KEY == "mock_key_contents"
        ):
            raise ValueError("Missing/placeholder GitHub App configuration")
        return get_installation_token(
            install_id,
            settings.GITHUB_APP_ID,
            settings.GITHUB_PRIVATE_KEY,
        )
    except Exception as auth_err:
        logger.warning(
            f"Authentication warning: {auth_err}. Proceeding with mock token."
        )
        return "mock_token"


def _find_finding_for_comment(
    db: Session,
    repo_id: int,
    pr_number: int,
    file_path: str,
    line_number: int,
) -> Finding | None:
    scan = (
        db.query(Scan)
        .filter(
            Scan.repo_id == repo_id,
            Scan.pr_number == pr_number,
            Scan.status == "completed",
        )
        .order_by(Scan.created_at.desc())
        .first()
    )
    if not scan:
        return None

    return (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan.id,
            Finding.file_path == file_path,
            Finding.line_number == line_number,
        )
        .first()
    )


def _handle_fp_comment(
    db: Session,
    payload: dict,
    *,
    pr_number: int,
    file_path: str | None,
    line_number: int | None,
    comment_id: int,
) -> dict:
    if not file_path or line_number is None:
        logger.info("Ignored /fp comment with unrecognized position.")
        return {"status": "ignored", "message": "Unrecognized comment position."}

    repo_id = payload["repository"]["id"]
    owner = payload["repository"]["owner"]["login"]
    repo_name = payload["repository"]["name"]

    repo = db.query(Repo).filter(Repo.repo_id == repo_id).first()
    if not repo:
        logger.info(f"Ignored /fp comment for unknown repo {repo_id}.")
        return {"status": "ignored", "message": "Repository not found."}

    finding = _find_finding_for_comment(
        db, repo_id, pr_number, file_path, line_number
    )
    if not finding:
        logger.info(
            f"Ignored /fp comment with no matching finding at {file_path}:{line_number}."
        )
        return {"status": "ignored", "message": "No matching finding."}

    memory = RepoMemory(
        repo_id=repo_id,
        rule_id=finding.rule_id,
        file_pattern=finding.file_path,
        outcome="false_positive",
    )
    db.add(memory)
    db.commit()

    token = _get_github_token(repo.install_id)
    try:
        post_comment(
            owner,
            repo_name,
            pr_number,
            comment_id,
            token,
            FP_ACK_MESSAGE,
        )
    except Exception as reply_err:
        logger.warning(f"Failed to post false-positive acknowledgement: {reply_err}")

    logger.info(
        f"Recorded false positive for {finding.rule_id} in {finding.file_path} "
        f"on PR #{pr_number} ({owner}/{repo_name})."
    )
    return {
        "status": "recorded",
        "message": "False positive recorded.",
        "rule_id": finding.rule_id,
        "file_pattern": finding.file_path,
    }


@app.get("/health")
def health_check():
    """
    Health check endpoint.
    """
    return {
        "status": "healthy",
        "app": settings.PROJECT_NAME,
        "debug_mode": settings.DEBUG,
    }


@app.post("/webhook")
async def github_webhook(
    request: Request,
    x_github_event: str = Header(None),
    x_hub_signature_256: str = Header(None),
    db: Session = Depends(get_db),
):
    """
    Webhook receiver for GitHub events.
    Verifies payload signatures, upserts repos/scans in the database,
    and queues scan tasks.
    """
    body = await request.body()
    
    # Verify GitHub signature if enabled
    if settings.VERIFY_GITHUB_WEBHOOKS:
        if not settings.GITHUB_WEBHOOK_SECRET:
            logger.error("VERIFY_GITHUB_WEBHOOKS is enabled but GITHUB_WEBHOOK_SECRET is not set")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Webhook secret configuration error."
            )
        
        if not x_hub_signature_256:
            logger.warning("Missing signature header X-Hub-Signature-256")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing webhook signature."
            )
            
        if not verify_signature(body, x_hub_signature_256, settings.GITHUB_WEBHOOK_SECRET):
            logger.warning("Invalid signature verification failed")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid webhook signature."
            )

    # Parse JSON body
    try:
        payload = json.loads(body.decode("utf-8")) if body else {}
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse JSON body: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload."
        )

    logger.info(f"Received GitHub Event: '{x_github_event}'")

    # We are specifically interested in pull_request events
    if x_github_event == "pull_request":
        action = payload.get("action")
        # Only queue scan if PR is opened or synchronized
        if action in ("opened", "synchronize"):
            try:
                repo_id = payload["repository"]["id"]
                owner = payload["repository"]["owner"]["login"]
                name = payload["repository"]["name"]
                pr_number = payload["number"]
                head_sha = payload["pull_request"]["head"]["sha"]
                install_id = payload.get("installation", {}).get("id")
                
                if not install_id:
                    raise KeyError("installation.id is missing in payload")
            except KeyError as e:
                logger.warning(f"Missing required fields in pull_request payload: {e}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid webhook payload layout: missing {e}"
                )

            # 1. Upsert Repository record
            repo = db.query(Repo).filter(Repo.repo_id == repo_id).first()
            if not repo:
                repo = Repo(
                    repo_id=repo_id,
                    owner=owner,
                    name=name,
                    install_id=str(install_id)
                )
                db.add(repo)
            else:
                repo.owner = owner
                repo.name = name
                repo.install_id = str(install_id)
            
            # 2. Create Scan record with status pending
            scan = Scan(
                repo_id=repo_id,
                pr_number=pr_number,
                pr_sha=head_sha,
                status="pending"
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
            
            logger.info(f"Created pending scan {scan.id} for PR #{pr_number} on {owner}/{name}")

            # 3. Queue the Celery task
            run_scan.delay(
                scan_id=scan.id,
                install_id=str(install_id),
                owner=owner,
                repo=name,
                pr_number=pr_number,
                head_sha=head_sha
            )
            
            return {
                "status": "queued",
                "message": "PR scan task has been queued.",
                "scan_id": scan.id
            }
        else:
            logger.info(f"Ignored pull_request action: {action}")
            return {"status": "ignored", "message": f"Ignored pull_request action '{action}'"}

    if x_github_event == "issue_comment":
        action = payload.get("action")
        if action != "created":
            logger.info(f"Ignored issue_comment action: {action}")
            return {"status": "ignored", "message": f"Ignored issue_comment action '{action}'"}

        comment = payload.get("comment", {})
        if comment.get("body") != "/fp":
            return {"status": "ignored", "message": "Not a false-positive command."}

        issue = payload.get("issue", {})
        if "pull_request" not in issue:
            return {"status": "ignored", "message": "Comment is not on a pull request."}

        pr_number = issue["number"]
        return _handle_fp_comment(
            db,
            payload,
            pr_number=pr_number,
            file_path=comment.get("path"),
            line_number=comment.get("line"),
            comment_id=comment["id"],
        )

    if x_github_event == "pull_request_review_comment":
        action = payload.get("action")
        if action != "created":
            logger.info(f"Ignored pull_request_review_comment action: {action}")
            return {
                "status": "ignored",
                "message": f"Ignored pull_request_review_comment action '{action}'",
            }

        comment = payload.get("comment", {})
        if comment.get("body") != "/fp":
            return {"status": "ignored", "message": "Not a false-positive command."}

        pr_number = payload["pull_request"]["number"]
        line_number = comment.get("line")
        if line_number is None:
            line_number = comment.get("original_line")

        return _handle_fp_comment(
            db,
            payload,
            pr_number=pr_number,
            file_path=comment.get("path"),
            line_number=line_number,
            comment_id=comment["id"],
        )

    return {"status": "ignored", "message": f"Event '{x_github_event}' not processed."}
