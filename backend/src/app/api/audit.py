from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import DB, AdminUser
from app.api.schemas import AuditOut, AuditPage
from app.storage.repositories import SqlAuditRepository

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=AuditPage)
def list_audit(
    _: AdminUser,
    db: DB,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    before_id: Annotated[int | None, Query(ge=1)] = None,
    action: Annotated[str | None, Query(max_length=64)] = None,
    target_type: Annotated[str | None, Query(max_length=32)] = None,
    target_id: Annotated[str | None, Query(max_length=64)] = None,
) -> AuditPage:
    rows = SqlAuditRepository(db).page(
        limit=limit,
        before_id=before_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
    )
    items = [AuditOut.model_validate(r) for r in rows]
    next_id = items[-1].id if len(items) == limit else None
    return AuditPage(items=items, next_before_id=next_id)
