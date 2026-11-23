from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AuditLogOut(BaseModel):
    id: int
    actor_id: int | None
    action: str
    resource_type: str
    resource_id: str
    details: str
    ip_address: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
