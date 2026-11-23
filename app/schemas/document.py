from datetime import datetime

from pydantic import AliasChoices, BaseModel, ConfigDict, EmailStr, Field, field_validator


class DocumentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    content: str = Field(max_length=2_000_000)

    @field_validator("title")
    @classmethod
    def title_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Title cannot be blank")
        return value


class DocumentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=300)
    content: str | None = Field(default=None, max_length=2_000_000)

    @field_validator("title")
    @classmethod
    def updated_title_not_blank(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("Title cannot be blank")
        return value


class DocumentOut(BaseModel):
    id: int
    title: str
    content: str
    role: str
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class VersionOut(BaseModel):
    id: int
    version_number: int
    title: str
    created_by: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class PermissionCreate(BaseModel):
    user_email: EmailStr = Field(
        min_length=3,
        max_length=320,
        validation_alias=AliasChoices("user_email", "email"),
    )
    role: str = Field(pattern="^(editor|viewer)$")