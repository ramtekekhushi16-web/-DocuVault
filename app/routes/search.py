from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, literal_column, or_
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import Document, DocumentPermission, User
from app.dependencies import get_current_user
from app.services.document_service import role_for, to_dict

router = APIRouter(prefix="/search", tags=["search"])


@router.get("")
def search_documents(q: str = Query(min_length=1, max_length=200), db: Session = Depends(get_db),
                    user: User = Depends(get_current_user), limit: int = Query(default=20, ge=1, le=100)):
    query = db.query(Document).outerjoin(
        DocumentPermission, DocumentPermission.document_id == Document.id
    ).filter(or_(Document.owner_id == user.id, DocumentPermission.user_id == user.id))
    if db.bind.dialect.name == "postgresql":
        language = literal_column("'english'")
        search_vector = func.to_tsvector(language, Document.title)
        query = query.filter(search_vector.op("@@")(func.websearch_to_tsquery(language, q)))
    else:
        query = query.filter(Document.title.ilike(f"%{q}%"))
    rows = query.distinct().order_by(Document.updated_at.desc()).limit(limit).all()
    return [to_dict(document, role_for(db, document, user.id) or "viewer") for document in rows]