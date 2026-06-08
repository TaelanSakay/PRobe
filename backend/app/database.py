from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

# Engine configuration
engine = create_engine(
    settings.DATABASE_URL,
    # For SQLite compatibility during testing (e.g., sqlite:///:memory:)
    connect_args={"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """
    Database session dependency injection helper.
    Ensures session closure after request handling.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
