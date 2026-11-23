from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import User
from app.dependencies import get_current_user
from app.schemas.document import DocumentOut, VersionOut
from app.services.audit_service import request_ip
from app.services.document_service import get_document, require_role, to_dict
from app.services.version_service import list_versions, restore_version

router = APIRouter(prefix="/documents/{document_id}/versions", tags=["versions"])


@router.get("", response_model=list[VersionOut])
def versions(document_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    get_document(db, document_id, user.id)
    return list_versions(db, document_id)


@router.post("/{version_number}/restore", response_model=DocumentOut)
def restore(document_id: int, version_number: int, request: Request,
            db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    document, role = get_document(db, document_id, user.id)
    if role not in {"owner", "editor"}:
        raise HTTPException(status_code=403, detail="Viewer access cannot restore versions")
    document = restore_version(db, document, version_number, user.id, request_ip(request))
    return to_dict(document, role)