from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class ShareCreate(BaseModel):
    expires_in_days: int | None = Field(default=None, ge=1, le=30)
    password: str | None = Field(default=None, min_length=12, max_length=72)
    one_time: bool = False

    @field_validator("password")
    @classmethod
    def password_utf8_limit(cls, value: str | None) -> str | None:
        if value is not None and len(value.encode("utf-8")) > 72:
            raise ValueError("Share password must be no more than 72 UTF-8 bytes")
        return value


class ShareOut(BaseModel):
    id: int
    token: str
    expires_at: datetime


class PublicDocumentOut(BaseModel):
    title: str
    content: str
    expires_at: datetime