from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import AuditLog, Document, User
from app.dependencies import get_current_user
from app.schemas.audit import AuditLogOut

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditLogOut],
            description="List your audit events and events for documents you own.")
def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    owned_document_ids = [
        str(document_id)
        for (document_id,) in db.query(Document.id).filter(Document.owner_id == user.id).all()
    ]
    visibility = [AuditLog.actor_id == user.id]
    if owned_document_ids:
        visibility.append(and_(
            AuditLog.resource_type == "document",
            AuditLog.resource_id.in_(owned_document_ids),
        ))
    return db.query(AuditLog).filter(or_(*visibility)).order_by(
        AuditLog.created_at.desc(), AuditLog.id.desc()
    ).limit(limit).all()
