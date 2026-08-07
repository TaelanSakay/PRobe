import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import Repo, Scan, Finding, RepoMemory
from app.scanner import scan_code
from app.scanner.scope import build_scan_scopes


def _scan(files, changed):
    scope = build_scan_scopes(files, changed)
    return scan_code(files, scope)


@pytest.fixture(name="db_session")
def db_session_fixture():
    """Fixture creating an in-memory SQLite database session for model verification."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


def test_models_relationships(db_session):
    """Test model constraints, foreign keys, and relationships in SQLAlchemy."""
    # Create Repo
    repo = Repo(
        repo_id=987654321, owner="owner", name="repo", install_id="inst_123"
    )
    db_session.add(repo)
    db_session.commit()

    # Create Scan
    scan = Scan(
        repo_id=repo.repo_id,
        pr_number=10,
        pr_sha="abc123sha",
        status="success",
        risk_score=45,
    )
    db_session.add(scan)
    db_session.commit()

    # Create Finding
    finding = Finding(
        scan_id=scan.id,
        file_path="app.py",
        line_number=15,
        rule_id="sql-injection",
        severity="high",
        description="SQL Injection vulnerability",
        confidence="high",
    )
    db_session.add(finding)

    # Create RepoMemory
    mem = RepoMemory(
        repo_id=repo.repo_id,
        rule_id="hardcoded-secret",
        file_pattern="tests/*",
        outcome="false_positive",
    )
    db_session.add(mem)
    db_session.commit()

    # Assertions
    assert len(repo.scans) == 1
    assert repo.scans[0].pr_number == 10
    assert len(scan.findings) == 1
    assert scan.findings[0].rule_id == "sql-injection"
    assert len(repo.memory) == 1
    assert repo.memory[0].file_pattern == "tests/*"


def test_hardcoded_secret_detection():
    """Verify that hardcoded secrets are caught while normal assignments are skipped."""
    code = """
api_key = "abc123XYZkey"
safe_var = "test_value"
empty_var = ""
    """
    files = {"app.py": code}
    # Test assignment on changed line
    changed = {"app.py": {2}}
    findings = _scan(files, changed)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "hardcoded-secret"
    assert findings[0]["line_number"] == 2

    # Test safe variable on changed line should not trigger
    changed_safe = {"app.py": {3, 4}}
    findings_safe = _scan(files, changed_safe)
    assert len(findings_safe) == 0


def test_sql_injection_detection():
    """Verify execute calls with dynamic variables trigger SQL injection findings."""
    code = """
def search_users(user_input):
    query = "SELECT * FROM users WHERE name = " + user_input
    execute(query)
    
    # Safe query
    safe_query = "SELECT * FROM users"
    execute(safe_query)
    """
    files = {"app.py": code}

    # Unsafe query executed on line 4
    changed = {"app.py": {4}}
    findings = _scan(files, changed)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "sql-injection"

    # Safe execute on line 8 — use a separate function so scope expansion
    # does not pull in the unsafe execute() above in search_users().
    code_with_safe_only = """
def search_users_safe():
    safe_query = "SELECT * FROM users"
    execute(safe_query)
"""
    files_safe = {"app.py": code_with_safe_only}
    changed_safe = {"app.py": {4}}
    findings_safe = _scan(files_safe, changed_safe)
    assert len(findings_safe) == 0


def test_command_injection_detection():
    """Verify dynamic OS/subprocess shell calls flag command injection, while static lists are safe."""
    code = """
import os
import subprocess

def run_command(user_cmd):
    os.system(user_cmd)
    
    # subprocess with shell=True
    subprocess.run("ping " + user_cmd, shell=True)
    
    # safe subprocess (no shell=True or static)
    subprocess.run(["ping", "localhost"])
    """
    files = {"app.py": code}

    # Unsafe os.system on line 6 — scope covers the whole function, so both
    # command-injection patterns in run_command() are reported.
    changed = {"app.py": {6}}
    findings = _scan(files, changed)
    assert len(findings) == 2
    assert all(f["rule_id"] == "command-injection" for f in findings)

    # Unsafe subprocess run on line 9 — same function, same expectation.
    changed_sub = {"app.py": {9}}
    findings_sub = _scan(files, changed_sub)
    assert len(findings_sub) == 2
    assert all(f["rule_id"] == "command-injection" for f in findings_sub)

    # Safe subprocess run on line 12 — isolated function, no expansion to run_command().
    code_with_safe_only = """
import subprocess

def run_safe_command():
    subprocess.run(["ping", "localhost"])
"""
    files_safe = {"app.py": code_with_safe_only}
    changed_safe = {"app.py": {4}}
    findings_safe = _scan(files_safe, changed_safe)
    assert len(findings_safe) == 0


def test_path_traversal_detection():
    """Verify dynamic opens flag path traversal, while basename-sanitized or static paths do not."""
    code = """
import os

def read_file(user_file):
    # Unsafe open
    open(user_file, "r")
    
    # Safe sanitized open
    safe_path = os.path.basename(user_file)
    open(safe_path, "r")
    
    # Safe static open
    open("static_config.json", "r")
    """
    files = {"app.py": code}

    # Unsafe open on line 6
    changed = {"app.py": {6}}
    findings = _scan(files, changed)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "path-traversal"

    # Safe basename open on line 10 — isolated function avoids expanding into read_file().
    code_with_basename_only = """
import os

def read_file_safe(user_file):
    safe_path = os.path.basename(user_file)
    open(safe_path, "r")
"""
    files_basename = {"app.py": code_with_basename_only}
    changed_safe_basename = {"app.py": {6}}
    findings_safe_basename = _scan(files_basename, changed_safe_basename)
    assert len(findings_safe_basename) == 0

    # Safe static open on line 13 — isolated function.
    code_with_static_only = """
def read_static_file():
    open("static_config.json", "r")
"""
    files_static = {"app.py": code_with_static_only}
    changed_safe_static = {"app.py": {3}}
    findings_safe_static = _scan(files_static, changed_safe_static)
    assert len(findings_safe_static) == 0


def test_changed_lines_filtering():
    """Verify that vulnerabilities residing on unchanged lines are explicitly omitted."""
    code = """
# Unsafe hardcoded key
super_secret_token = "critical-api-token"  # Line 3

# Unsafe SQL injection
def delete_item(item_id):
    execute("DELETE FROM items WHERE id = " + item_id)  # Line 7
    """
    files = {"app.py": code}

    # Scenario 1: Only Line 7 is changed, Line 3 is unchanged
    changed_only_sql = {"app.py": {7}}
    findings = _scan(files, changed_only_sql)
    # Only the SQL injection finding should be returned
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "sql-injection"
    assert findings[0]["line_number"] == 7

    # Scenario 2: Only Line 3 is changed, Line 7 is unchanged
    changed_only_secret = {"app.py": {3}}
    findings_sec = _scan(files, changed_only_secret)
    # Only the secret finding should be returned
    assert len(findings_sec) == 1
    assert findings_sec[0]["rule_id"] == "hardcoded-secret"
    assert findings_sec[0]["line_number"] == 3

    # Scenario 3: Changed lines that do not expand into either vulnerability
    changed_none = {"app.py": {1, 2, 4, 5}}
    findings_none = _scan(files, changed_none)
    assert len(findings_none) == 0
