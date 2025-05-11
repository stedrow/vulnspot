import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session # Added Session for type hinting
from sqlalchemy.ext.declarative import declarative_base
from models.database import Base # Corrected import: removed grypeui.

# Path to the project root (grypeui directory)
# __file__ is app/database.py
# Path(__file__).resolve().parent is app/
# Path(__file__).resolve().parent.parent is project root.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_DIR = PROJECT_ROOT / "data" # This will be /app/data in the container

# DATABASE_URL is expected to be set in the Docker environment (e.g., docker-compose.yml)
# Fallback to a default path inside the container if it's not set for some reason.
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DB_DIR}/vuln_scanner.db")
print(f"GrypeUI DB: Using database URL: {SQLALCHEMY_DATABASE_URL}")

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False} # check_same_thread for SQLite
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    # Create all tables in the database.
    # This should ideally be handled by Alembic migrations in a production app.
    
    # The data directory (/app/data) inside the container is managed by Docker volume mounts.
    # No need to create it here.
        
    Base.metadata.create_all(bind=engine)
    print(f"Database initialized with tables at {SQLALCHEMY_DATABASE_URL}")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close() 