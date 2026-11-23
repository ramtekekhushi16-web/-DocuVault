from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.encryption import decrypt
from app.core.security import hash_password, new_share_token, token_digest, verify_password
from app.database.connection import get_db
from app.database.models import Document, ShareLink, User
from app.dependencies import get_current_user
from app.schemas.sharing import PublicDocumentOut, ShareCreate, ShareOut
from app.services.audit_service import record, request_ip
from app.services.document_service import get_document, require_role

router = APIRouter(prefix="/shares", tags=["sharing"])


@router.post("/{document_id}", response_model=ShareOut, status_code=201)
def create_share(document_id: int, request: Request, payload: ShareCreate | None = None,
                 db: Session = Depends(get_db),
                 user: User = Depends(get_current_user)):
    document, _ = get_document(db, document_id, user.id)
    require_role(db, document, user.id, {"owner", "editor"})
    token = new_share_token()
    expires_in_days = payload.expires_in_days if payload and payload.expires_in_days else settings.share_token_days
    expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)
    link = ShareLink(document_id=document.id, token_hash=token_digest(token), created_by=user.id,
                     expires_at=expires_at,
                     password_hash=hash_password(payload.password) if payload and payload.password else None,
                     one_time=payload.one_time if payload else False)
    db.add(link)
    record(db, user.id, "share.created", "document", document.id,
           {"one_time": link.one_time, "password_protected": link.password_hash is not None},
           ip_address=request_ip(request))
    db.commit()
    db.refresh(link)
    return {"id": link.id, "token": token, "expires_at": expires_at}


@router.get("/public/{token}", response_model=PublicDocumentOut)
def read_shared(token: str, request: Request, x_share_password: str | None = Header(default=None),
                db: Session = Depends(get_db)):
    link = db.query(ShareLink).filter_by(token_hash=token_digest(token)).with_for_update().first()
    now = datetime.now(timezone.utc)
    expiry = link.expires_at if link else now
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if not link or link.revoked or expiry <= now:
        raise HTTPException(status_code=404, detail="Share link not found or expired")
    if link.password_hash and (
        not x_share_password or not verify_password(x_share_password, link.password_hash)
    ):
        raise HTTPException(status_code=401, detail="Share password is required or incorrect",
                            headers={"WWW-Authenticate": "Share"})
    document = db.get(Document, link.document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Shared document no longer exists")
    content = decrypt(document.encrypted_content)
    if link.one_time:
        link.revoked = True
    record(db, None, "share.accessed", "document", document.id,
           {"one_time": link.one_time}, ip_address=request_ip(request))
    db.commit()
    return {"title": document.title, "content": content, "expires_at": link.expires_at}


@router.delete("/{document_id}/{share_id}", status_code=204)
def revoke_share(document_id: int, share_id: int, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(get_current_user)):
    document, _ = get_document(db, document_id, user.id)
    require_role(db, document, user.id, {"owner", "editor"})
    link = db.query(ShareLink).filter_by(id=share_id, document_id=document.id).first()
    if not link:
        raise HTTPException(status_code=404, detail="Share link not found")
    link.revoked = True
    record(db, user.id, "share.revoked", "document", document.id, {"share_id": share_id},
           ip_address=request_ip(request))
    db.commit()