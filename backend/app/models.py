from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, BigInteger, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.database import Base


class Repo(Base):
    __tablename__ = "repos"

    repo_id = Column(BigInteger, primary_key=True)  # GitHub's native ID (can be 64-bit)
    owner = Column(String(255), nullable=False)
    name = Column(String(255), nullable=False)
    install_id = Column(String(255), nullable=False)
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    scans = relationship("Scan", back_populates="repo", cascade="all, delete-orphan")
    memory = relationship(
        "RepoMemory", back_populates="repo", cascade="all, delete-orphan"
    )


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    repo_id = Column(
        BigInteger, ForeignKey("repos.repo_id", ondelete="CASCADE"), nullable=False
    )
    pr_number = Column(Integer, nullable=False)
    pr_sha = Column(String(40), nullable=False)
    risk_score = Column(Integer, nullable=True)  # 0 to 100
    status = Column(
        String(50), nullable=False, default="pending"
    )  # pending, running, success, failed
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    repo = relationship("Repo", back_populates="scans")
    findings = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(
        Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    file_path = Column(Text, nullable=False)
    line_number = Column(Integer, nullable=False)
    rule_id = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)  # high, medium, low
    description = Column(Text, nullable=False)
    fix_suggestion = Column(Text, nullable=True)
    confidence = Column(String(20), nullable=False)  # high, medium, low
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    scan = relationship("Scan", back_populates="findings")


class RepoMemory(Base):
    __tablename__ = "repo_memory"

    id = Column(Integer, primary_key=True, autoincrement=True)
    repo_id = Column(
        BigInteger, ForeignKey("repos.repo_id", ondelete="CASCADE"), nullable=False
    )
    rule_id = Column(String(100), nullable=False)
    file_pattern = Column(Text, nullable=False)
    outcome = Column(String(50), nullable=False, default="false_positive")
    created_at = Column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    repo = relationship("Repo", back_populates="memory")
