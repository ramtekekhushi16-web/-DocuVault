import json

from fastapi import Request
from sqlalchemy.orm import Session

from app.database.models import AuditLog


def request_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def record(db: Session, actor_id: int | None, action: str, resource_type: str, resource_id: int | str,
           details: dict | None = None, ip_address: str | None = None) -> None:
    db.add(AuditLog(
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id),
        details=json.dumps(details or {}, sort_keys=True),
        ip_address=ip_address,
    ))