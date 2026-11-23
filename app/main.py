from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.encryption import validate_key
from app.database.connection import Base, engine, get_db
from app.database import models  # noqa: F401
from app.routes import audit, auth, documents, search, sharing, versions

@asynccontextmanager
async def lifespan(_app: FastAPI):
    validate_key()
    if engine.dialect.name == "sqlite":
        Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="DocuVault API",
    description="Encrypted document storage with versioning, sharing, and access controls.",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(auth.router)
app.include_router(documents.router)
app.include_router(versions.router)
app.include_router(sharing.router)
app.include_router(search.router)
app.include_router(audit.router)
@app.get("/", tags=["health"])
def root() -> dict[str, str]:
    return {
        "message": "Welcome to DocuVault API",
        "status": "success",
        "documentation": "/docs",
        "health": "/health"
    }


@app.get("/health", tags=["health"])
def health(db: Session = Depends(get_db)) -> dict[str, str]:
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        ) from exc
    return {"status": "ok"}


