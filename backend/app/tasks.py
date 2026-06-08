import time
import fnmatch
import logging
from celery import Celery
from app.config import settings

logger = logging.getLogger("probe.tasks")

# Initialize Celery app
celery_app = Celery(
    "probe_tasks",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)


@celery_app.task(name="app.tasks.run_scan")
def run_scan(
    scan_id: int,
    install_id: str,
    owner: str,
    repo: str,
    pr_number: int,
    head_sha: str,
):
    """
    Background Celery task that performs end-to-end scanning of a Pull Request:
    1. Update scan status to 'running'
    2. Retrieve installation access token and PR diff from GitHub
    3. Parse the diff to find modified Python files and line numbers
    4. Fetch full content of modified files from GitHub at head SHA
    5. Run the AST vulnerability scanner
    6. Filter out suppressed rules via RepoMemory
    7. Save the remaining findings to database
    8. Compute risk score and set scan status to 'completed'
    """
    from app.database import SessionLocal
    from app.models import Scan, Finding, RepoMemory
    from app.github_client import (
        get_installation_token,
        get_pr_diff,
        get_file_content,
        parse_diff,
    )
    from app.scanner import scan_code

    logger.info(f"[*] Starting run_scan task for scan {scan_id}")
    db = SessionLocal()

    try:
        # 1. Update scan status to running
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan ID {scan_id} not found in database.")
            return

        scan.status = "running"
        db.commit()

        # 2. Authenticate and get installation token
        try:
            if (
                not settings.GITHUB_APP_ID
                or not settings.GITHUB_PRIVATE_KEY
                or settings.GITHUB_PRIVATE_KEY == "mock_key_contents"
            ):
                raise ValueError("Missing/placeholder GitHub App configuration")
            token = get_installation_token(
                install_id,
                settings.GITHUB_APP_ID,
                settings.GITHUB_PRIVATE_KEY,
            )
        except Exception as auth_err:
            logger.warning(
                f"Authentication warning: {auth_err}. Proceeding with mock token."
            )
            token = "mock_token"

        # 3. Fetch PR diff
        try:
            diff_text = get_pr_diff(owner, repo, pr_number, token)
        except Exception as diff_err:
            logger.error(f"Failed to fetch PR diff from GitHub: {diff_err}")
            scan.status = "failed"
            db.commit()
            return

        # 4. Parse diff
        changed_lines = parse_diff(diff_text)
        if not changed_lines:
            logger.info(f"No Python files modified in PR #{pr_number}. Completing scan.")
            scan.status = "completed"
            scan.risk_score = 0
            db.commit()
            return

        # 5. Fetch full content for changed files
        files_content = {}
        for file_path in changed_lines.keys():
            try:
                content = get_file_content(
                    owner, repo, file_path, head_sha, token
                )
                files_content[file_path] = content
            except Exception as file_err:
                logger.warning(
                    f"Failed to fetch content for {file_path}: {file_err}. Skipping file."
                )

        # 6. Run AST Scanner
        raw_findings = scan_code(files_content, changed_lines)

        # 7. Check suppression rule matches from RepoMemory
        suppression_rules = (
            db.query(RepoMemory).filter(RepoMemory.repo_id == scan.repo_id).all()
        )

        filtered_findings = []
        for finding in raw_findings:
            is_suppressed = False
            for rule in suppression_rules:
                if rule.rule_id == finding["rule_id"]:
                    # Check if file matches suppression pattern (glob matching)
                    if fnmatch.fnmatch(finding["file_path"], rule.file_pattern):
                        logger.info(
                            f"Suppressing finding {finding['rule_id']} in {finding['file_path']} due to rule {rule.id}"
                        )
                        is_suppressed = True
                        break
            if not is_suppressed:
                filtered_findings.append(finding)

        # 8. Persist findings and calculate risk score
        risk_score = 0
        for f_dict in filtered_findings:
            severity = f_dict["severity"].lower()
            if severity == "high":
                risk_score += 10
            elif severity == "medium":
                risk_score += 5
            elif severity == "low":
                risk_score += 2

            db_finding = Finding(
                scan_id=scan.id,
                file_path=f_dict["file_path"],
                line_number=f_dict["line_number"],
                rule_id=f_dict["rule_id"],
                severity=f_dict["severity"],
                description=f_dict["description"],
                fix_suggestion=f_dict.get("fix_suggestion"),
                confidence=f_dict["confidence"],
            )
            db.add(db_finding)

        # Cap the risk score at 100
        scan.risk_score = min(risk_score, 100)
        scan.status = "completed"
        db.commit()

        logger.info(
            f"[+] Finished scan {scan.id}. Score: {scan.risk_score}. Persisted {len(filtered_findings)} findings."
        )

    except Exception as e:
        logger.error(f"Unexpected error running scan {scan_id}: {e}")
        db.rollback()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "failed"
                db.commit()
        except Exception as inner_err:
            logger.error(f"Failed to update scan status to failed: {inner_err}")
    finally:
        db.close()
