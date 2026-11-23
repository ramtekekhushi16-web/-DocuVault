from datetime import datetime, timedelta, timezone
import secrets

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import create_token, hash_password, token_digest, verify_password
from app.database.models import RefreshToken, User


def register(db: Session, email: str, password: str) -> User:
    normalized_email = email.strip().lower()
    if db.query(User).filter(User.email == normalized_email).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered")
    user = User(email=normalized_email, password_hash=hash_password(password))
    db.add(user)
    db.flush()
    return user


def issue_pair(db: Session, user: User) -> dict[str, str]:
    access = create_token(str(user.id), "access", timedelta(minutes=settings.access_token_minutes))
    jti = secrets.token_urlsafe(24)
    lifetime = timedelta(days=settings.refresh_token_days)
    refresh = create_token(str(user.id), "refresh", lifetime, jti=jti)
    db.add(RefreshToken(
        jti=jti,
        token_hash=token_digest(refresh),
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + lifetime,
    ))
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}


def authenticate(db: Session, email: str, password: str) -> User:
    user = db.query(User).filter(User.email == email.strip().lower()).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    return user