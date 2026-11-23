from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import decode_token, token_digest
from app.database.connection import get_db
from app.database.models import RefreshToken, User
from app.schemas.user import RefreshRequest, TokenPair, UserCreate, UserOut
from app.services.audit_service import record, request_ip
from app.services.auth_service import authenticate, issue_pair, register

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_account(payload: UserCreate, request: Request, db: Session = Depends(get_db)):
    user = register(db, payload.email, payload.password)
    record(db, user.id, "auth.registered", "user", user.id, ip_address=request_ip(request))
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenPair)
def login(
    request: Request,
    username: str | None = Form(default=None, description="OAuth2 username; use the account email."),
    password: str = Form(...),
    email: str | None = Form(default=None, description="Email alias accepted for compatibility."),
    db: Session = Depends(get_db),
):
    if username and email and username.strip().casefold() != email.strip().casefold():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    user = authenticate(db, username or email or "", password)
    tokens = issue_pair(db, user)
    record(db, user.id, "auth.login", "user", user.id, ip_address=request_ip(request))
    db.commit()
    return tokens


@router.post("/token", response_model=TokenPair, include_in_schema=False)
def login_json(payload: UserCreate, db: Session = Depends(get_db)):
    user = authenticate(db, payload.email, payload.password)
    tokens = issue_pair(db, user)
    db.commit()
    return tokens


@router.post("/refresh", response_model=TokenPair)
def refresh(payload: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    try:
        claims = decode_token(payload.refresh_token, "refresh")
        jti = claims["jti"]
        user_id = int(claims["sub"])
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token") from exc

    token_record = db.query(RefreshToken).filter_by(jti=jti).with_for_update().first()
    now = datetime.now(timezone.utc)
    expiry = token_record.expires_at if token_record else now
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if (not token_record or token_record.user_id != user_id or token_record.revoked_at is not None
            or expiry <= now or token_record.token_hash != token_digest(payload.refresh_token)):
        raise HTTPException(status_code=401, detail="Refresh token has already been used or is invalid")

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User no longer exists")
    token_record.revoked_at = now
    tokens = issue_pair(db, user)
    try:
        new_claims = decode_token(tokens["refresh_token"], "refresh")
        token_record.replaced_by = new_claims["jti"]
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=500, detail="Unable to rotate refresh token") from exc
    record(db, user.id, "auth.refresh", "user", user.id, ip_address=request_ip(request))
    db.commit()
    return tokens


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(payload: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    try:
        claims = decode_token(payload.refresh_token, "refresh")
    except ValueError:
        return None
    token_record = db.query(RefreshToken).filter_by(
        jti=claims["jti"], token_hash=token_digest(payload.refresh_token)
    ).first()
    if token_record and token_record.revoked_at is None:
        token_record.revoked_at = datetime.now(timezone.utc)
        record(db, token_record.user_id, "auth.logout", "user", token_record.user_id,
               ip_address=request_ip(request))
        db.commit()
    return None