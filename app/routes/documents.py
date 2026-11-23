from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.core.encryption import decrypt
from app.database.connection import get_db
from app.database.models import Document, DocumentPermission, User
from app.dependencies import get_current_user
from app.schemas.document import DocumentCreate, DocumentOut, DocumentUpdate, PermissionCreate
from app.services.audit_service import record, request_ip
from app.services.document_service import create_document, get_document, list_documents, require_role, to_dict, update_document

router = APIRouter(prefix="/documents", tags=["documents"])


@router.get("", response_model=list[DocumentOut])
def get_documents(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return [to_dict(doc, role) for doc, role in list_documents(db, user)]


@router.post("", response_model=DocumentOut, status_code=status.HTTP_201_CREATED)
def create(payload: DocumentCreate, request: Request, db: Session = Depends(get_db),
           user: User = Depends(get_current_user)):
    document = create_document(db, user, payload.title, payload.content, request_ip(request))
    return to_dict(document, "owner")


@router.get("/{document_id}", response_model=DocumentOut)
def read(document_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    document, role = get_document(db, document_id, user.id)
    return to_dict(document, role)


@router.patch("/{document_id}", response_model=DocumentOut)
def update(document_id: int, payload: DocumentUpdate, request: Request, db: Session = Depends(get_db),
           user: User = Depends(get_current_user)):
    document, role = get_document(db, document_id, user.id)
    if role not in {"owner", "editor"}:
        raise HTTPException(status_code=403, detail="Viewer access cannot modify documents")
    changes = payload.model_dump(exclude_unset=True)
    if not changes or all(value is None for value in changes.values()):
        raise HTTPException(status_code=422, detail="Provide at least one field to update")
    document = update_document(db, document, user.id, changes.get("title"), changes.get("content"),
                               request_ip(request))
    return to_dict(document, role)


@router.delete("/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete(document_id: int, request: Request, db: Session = Depends(get_db),
           user: User = Depends(get_current_user)):
    document, _ = get_document(db, document_id, user.id)
    require_role(db, document, user.id, {"owner"})
    record(db, user.id, "document.deleted", "document", document.id, ip_address=request_ip(request))
    db.delete(document)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.put("/{document_id}/permissions", status_code=status.HTTP_204_NO_CONTENT)
def grant_permission(document_id: int, payload: PermissionCreate, request: Request, db: Session = Depends(get_db),
                     user: User = Depends(get_current_user)):
    document, _ = get_document(db, document_id, user.id)
    require_role(db, document, user.id, {"owner"})
    target = db.query(User).filter(User.email == payload.user_email.strip().lower()).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == document.owner_id:
        raise HTTPException(status_code=422, detail="The owner already has full access")
    permission = db.query(DocumentPermission).filter_by(document_id=document.id, user_id=target.id).first()
    if permission:
        permission.role = payload.role
    else:
        db.add(DocumentPermission(document_id=document.id, user_id=target.id, role=payload.role))
    record(db, user.id, "permission.granted", "document", document.id,
           {"user_id": target.id, "role": payload.role}, ip_address=request_ip(request))
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/{document_id}/permissions/{target_user_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_permission(document_id: int, target_user_id: int, request: Request, db: Session = Depends(get_db),
                      user: User = Depends(get_current_user)):
    document, _ = get_document(db, document_id, user.id)
    require_role(db, document, user.id, {"owner"})
    permission = db.query(DocumentPermission).filter_by(
        document_id=document.id, user_id=target_user_id
    ).first()
    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")
    db.delete(permission)
    record(db, user.id, "permission.revoked", "document", document.id, {"user_id": target_user_id},
           ip_address=request_ip(request))
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{document_id}/download", response_class=Response,
            description="Decrypt and download a document after verifying its access permissions.")
def download(document_id: int, request: Request, db: Session = Depends(get_db),
             user: User = Depends(get_current_user)):
    document, _ = get_document(db, document_id, user.id)
    content = decrypt(document.encrypted_content)
    record(db, user.id, "document.downloaded", "document", document.id,
           ip_address=request_ip(request))
    db.commit()
    filename = quote(f"{document.title}.txt", safe="")
    return Response(
        content=content.encode("utf-8"),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{filename}",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )