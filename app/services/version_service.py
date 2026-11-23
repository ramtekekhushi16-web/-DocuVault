from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.encryption import decrypt
from app.database.models import Document, DocumentVersion
from app.services.audit_service import record
from app.services.document_service import save_version


def list_versions(db: Session, document_id: int) -> list[DocumentVersion]:
    return db.query(DocumentVersion).filter_by(document_id=document_id).order_by(
        DocumentVersion.version_number.desc()
    ).all()


def restore_version(db: Session, document: Document, version_number: int, actor_id: int,
                    ip_address: str | None = None) -> Document:
    version = db.query(DocumentVersion).filter_by(
        document_id=document.id, version_number=version_number
    ).first()
    if not version:
        raise HTTPException(status_code=404, detail="Document version not found")
    document.title = version.title
    document.encrypted_content = version.encrypted_content
    save_version(db, document, actor_id, ip_address)
    record(db, actor_id, "document.version_restored", "document", document.id,
           {"restored_version": version_number}, ip_address=ip_address)
    db.commit()
    db.refresh(document)
    return document