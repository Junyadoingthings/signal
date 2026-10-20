from fastapi import APIRouter, Request, Response

from app.api.deps import DB, AppSettings, CurrentPrincipal, client_ip
from app.api.schemas import LoginRequest, MeOut, UserOut
from app.core.config import Settings, get_settings
from app.core.errors import APIError
from app.core.ratelimit import limiter
from app.services import auth as auth_service

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _set_session_cookie(response: Response, settings: Settings, token: str) -> None:
    response.set_cookie(
        settings.cookie_name,
        token,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )


@router.post("/login", response_model=MeOut)
@limiter.limit(lambda: get_settings().login_rate_limit)
def login(
    request: Request, response: Response, body: LoginRequest, db: DB, settings: AppSettings
) -> MeOut:
    # Login has no session yet, so no CSRF token: requiring JSON means a cross-site form
    # can't submit it without a CORS preflight, which our CORS policy refuses.
    if not request.headers.get("content-type", "").startswith("application/json"):
        raise APIError(415, "unsupported_media_type", "Expected application/json")

    issued = auth_service.authenticate(
        db,
        settings,
        body.email,
        body.password,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    if issued is None:
        raise APIError(401, "invalid_credentials", "Invalid email or password")

    _set_session_cookie(response, settings, issued.token)
    return MeOut(
        user=UserOut.model_validate(issued.user),
        csrf_token=issued.csrf_token,
        session_expires_at=issued.session.expires_at,
    )


@router.post("/logout", status_code=204)
def logout(request: Request, p: CurrentPrincipal, db: DB, settings: AppSettings) -> Response:
    auth_service.logout(db, p.session, p.user, client_ip(request))
    response = Response(status_code=204)
    response.delete_cookie(
        settings.cookie_name,
        path="/",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )
    return response


@router.get("/me", response_model=MeOut)
def me(p: CurrentPrincipal) -> MeOut:
    return MeOut(
        user=UserOut.model_validate(p.user),
        csrf_token=p.session.csrf_token,
        session_expires_at=p.session.expires_at,
    )


@router.get("/session", response_model=MeOut | None)
def session(request: Request, db: DB, settings: AppSettings) -> MeOut | None:
    """Like /me, but answers 200 with null when signed out, so the SPA's boot check
    doesn't log a 401 in the browser console."""
    token = request.cookies.get(settings.cookie_name)
    resolved = auth_service.resolve(db, token) if token else None
    if resolved is None:
        return None
    s, user = resolved
    return MeOut(
        user=UserOut.model_validate(user), csrf_token=s.csrf_token, session_expires_at=s.expires_at
    )
