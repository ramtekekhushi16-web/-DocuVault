from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.encryption import decrypt, encrypt
from app.database.models import Document, DocumentPermission, DocumentVersion, User
from app.services.audit_service import record


def role_for(db: Session, document: Document, user_id: int) -> str | None:
    if document.owner_id == user_id:
        return "owner"
    permission = db.query(DocumentPermission).filter_by(document_id=document.id, user_id=user_id).first()
    return permission.role if permission else None


def require_role(db: Session, document: Document, user_id: int, allowed: set[str]) -> str:
    role = role_for(db, document, user_id)
    if role not in allowed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND if role is None else status.HTTP_403_FORBIDDEN,
                            detail="Document not found" if role is None else "Insufficient document permissions")
    return role


def get_document(db: Session, document_id: int, user_id: int) -> tuple[Document, str]:
    document = db.get(Document, document_id)
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    role = require_role(db, document, user_id, {"owner", "editor", "viewer"})
    return document, role


def to_dict(document: Document, role: str) -> dict:
    return {
        "id": document.id,
        "title": document.title,
        "content": decrypt(document.encrypted_content),
        "role": role,
        "created_at": document.created_at,
        "updated_at": document.updated_at,
    }


def save_version(db: Session, document: Document, actor_id: int, ip_address: str | None = None) -> None:
    latest = db.query(DocumentVersion.version_number).filter_by(document_id=document.id).order_by(
        DocumentVersion.version_number.desc()
    ).first()
    db.add(DocumentVersion(
        document_id=document.id,
        version_number=(latest[0] if latest else 0) + 1,
        title=document.title,
        encrypted_content=document.encrypted_content,
        created_by=actor_id,
    ))
    record(db, actor_id, "document.version_created", "document", document.id, ip_address=ip_address)


def list_documents(db: Session, user: User) -> list[tuple[Document, str]]:
    documents = db.query(Document).outerjoin(
        DocumentPermission, DocumentPermission.document_id == Document.id
    ).filter(or_(Document.owner_id == user.id, DocumentPermission.user_id == user.id)).order_by(
        Document.updated_at.desc()
    ).all()
    return [(doc, role_for(db, doc, user.id) or "viewer") for doc in documents]


def create_document(db: Session, user: User, title: str, content: str,
                    ip_address: str | None = None) -> Document:
    if len(content.encode("utf-8")) > settings.max_document_bytes:
        raise HTTPException(status_code=413, detail="Document exceeds the configured size limit")
    document = Document(owner_id=user.id, title=title.strip(), encrypted_content=encrypt(content))
    db.add(document)
    db.flush()
    save_version(db, document, user.id, ip_address)
    record(db, user.id, "document.created", "document", document.id, ip_address=ip_address)
    db.commit()
    db.refresh(document)
    return document


def update_document(db: Session, document: Document, actor_id: int, title: str | None,
                    content: str | None, ip_address: str | None = None) -> Document:
    if content is not None and len(content.encode("utf-8")) > settings.max_document_bytes:
        raise HTTPException(status_code=413, detail="Document exceeds the configured size limit")
    if title is not None:
        document.title = title.strip()
    if content is not None:
        document.encrypted_content = encrypt(content)
    document.updated_at = datetime.now(timezone.utc)
    save_version(db, document, actor_id, ip_address)
    record(db, actor_id, "document.updated", "document", document.id, ip_address=ip_address)
    db.commit()
    db.refresh(document)
    return document