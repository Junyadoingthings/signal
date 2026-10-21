from typing import Annotated, Literal

from fastapi import APIRouter, Query, Request, Response

from app.api.deps import DB, CurrentUser, client_ip
from app.core.errors import APIError
from app.reports import builder
from app.services import audit
from app.storage.models import Incident

router = APIRouter(prefix="/api/incidents", tags=["reports"])

# The printable report carries its own inline stylesheet, so it gets its own (still
# strict) policy: no scripts, no external loads of any kind.
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


@router.get("/{incident_id}/report")
def report(
    incident_id: int,
    request: Request,
    user: CurrentUser,
    db: DB,
    format: Annotated[Literal["md", "html"], Query()] = "md",
) -> Response:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise APIError(404, "not_found", "Incident not found")
    rep = builder.build(db, inc)
    audit.record(
        db,
        "incident.report",
        actor=user,
        target_type="incident",
        target_id=incident_id,
        after={"format": format},
        ip=client_ip(request),
    )
    if format == "html":
        return Response(
            builder.to_html(rep),
            media_type="text/html; charset=utf-8",
            headers={"Content-Security-Policy": REPORT_CSP},
        )
    return Response(
        builder.to_markdown(rep),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="incident-{incident_id}.md"'},
    )
