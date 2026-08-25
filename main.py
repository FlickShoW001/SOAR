"""
FastAPI main application: SOAR platform detect → enrich → decide → approve → respond → log pipeline.
Exposes REST endpoints for detection intake, approvals, and dashboard.
"""

import base64
import binascii
import hashlib
import hmac
import inspect
import json
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import (
    Depends,
    FastAPI,
    Form,
    HTTPException,
    Request,
    Response,
)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import APIKeyCookie, HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator, model_validator
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.datastructures import MutableHeaders

from audit_log import (
    audit_approval,
    audit_decision,
    audit_enrichment,
    audit_event_detection,
    audit_response,
    create_audit_entry,
    get_audit_log_for_event,
    verify_audit_chain,
)
from decision_engine import load_config as load_decision_config
from decision_engine import persist_decision
from enrichment import clear_cache as clear_enrichment_cache
from enrichment import enrich_ip
from models import Approval, AuditLog, Decision, EnrichmentResult, Event, init_db
from responder import execute_response, init_lab_allowlist

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def _database_url() -> str:
    """Return a stable database URL independent of the launch directory."""
    configured = os.getenv("DATABASE_URL")
    if not configured:
        return f"sqlite:///{BASE_DIR / 'soar.db'}"
    prefix = "sqlite:///"
    if configured.startswith(prefix):
        database_path = configured[len(prefix) :]
        if database_path and not Path(database_path).is_absolute():
            return f"{prefix}{(BASE_DIR / database_path).resolve()}"
    return configured


def _positive_env_int(name: str, default: int) -> int:
    """Read a positive integer setting without making startup brittle."""
    try:
        value = int(os.getenv(name, str(default)))
        return value if value > 0 else default
    except ValueError:
        return default


ADMIN_USERNAME = os.getenv("SOAR_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("SOAR_ADMIN_PASSWORD", "admin")
VALID_ROLES = {"admin", "operator", "viewer"}
SESSION_COOKIE_NAME = "soar_session"
SESSION_TTL_SECONDS = _positive_env_int("SOAR_SESSION_TTL_SECONDS", 28_800)
ENRICHMENT_CACHE_TTL_MINUTES = _positive_env_int(
    "ABUSEIPDB_CACHE_TTL_MINUTES", 60
)
SESSION_SECRET_CONFIGURED = bool(os.getenv("SOAR_SESSION_SECRET"))
SESSION_SECRET = os.getenv("SOAR_SESSION_SECRET") or secrets.token_urlsafe(32)
SESSION_COOKIE_SECURE = (
    os.getenv("SOAR_SESSION_COOKIE_SECURE", "false").lower() == "true"
)
dashboard_basic_security = HTTPBasic(realm="SOAR Dashboard", auto_error=False)
dashboard_cookie_security = APIKeyCookie(name=SESSION_COOKIE_NAME, auto_error=False)


@dataclass(frozen=True)
class UserIdentity:
    username: str
    role: str


def _load_users() -> dict[str, dict[str, str]]:
    users = {ADMIN_USERNAME: {"password": ADMIN_PASSWORD, "role": "admin"}}
    raw_users = os.getenv("SOAR_USERS_JSON")
    if not raw_users:
        return users
    try:
        configured = json.loads(raw_users)
        if not isinstance(configured, dict):
            raise ValueError("SOAR_USERS_JSON must contain an object")
        for username, record in configured.items():
            if not isinstance(record, dict):
                logger.warning("Ignoring malformed SOAR user record for %s", username)
                continue
            role = record.get("role")
            password = record.get("password")
            if username and password and role in VALID_ROLES:
                users[str(username)] = {"password": str(password), "role": role}
    except (TypeError, ValueError, json.JSONDecodeError):
        logger.error("SOAR_USERS_JSON is invalid; only the admin account is available")
    return users


AUTH_USERS = _load_users()

# Initialize database
DATABASE_URL = _database_url()
engine, SessionLocal = init_db(DATABASE_URL)

# Load configuration files
PLATFORM_CONFIG = load_decision_config(str(BASE_DIR / "config.yaml"))
RESPONDER_CONFIG = PLATFORM_CONFIG.get("responder", {})
# Only explicit YAML booleans can disable either safety layer. Misspelled or
# string values therefore remain in simulation rather than enabling a device.
RESPONDER_DRY_RUN = RESPONDER_CONFIG.get("dry_run", True) is not False
RESPONDER_SIMULATION_MODE = (
    RESPONDER_CONFIG.get("simulation_mode", True) is not False
)
init_lab_allowlist()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Log application lifecycle events and release process-local state."""
    logger.info("SOAR Platform starting up...")
    logger.info(f"Database: {DATABASE_URL}")
    logger.info("Config loaded: config.yaml")
    logger.info("Lab allow-list initialized")
    if ADMIN_PASSWORD in {"admin", "change_this_password", "change_me"}:
        logger.warning(
            "Dashboard is using an example administrator password; "
            "set a unique SOAR_ADMIN_PASSWORD before deployment"
        )
    if not SESSION_SECRET_CONFIGURED:
        logger.warning(
            "SOAR_SESSION_SECRET is not configured; browser sessions will reset "
            "when the application restarts"
        )
    elif SESSION_SECRET in {
        "replace_with_a_long_random_secret",
        "change_me",
        "changeme",
    }:
        logger.warning(
            "SOAR_SESSION_SECRET is still an example value; replace it with a "
            "long random secret before deployment"
        )
    try:
        yield
    finally:
        logger.info("SOAR Platform shutting down...")
        clear_enrichment_cache()


# FastAPI app
app = FastAPI(
    title="SOAR Platform",
    description="Security Orchestration, Automation, and Response platform",
    version="1.0.0",
    lifespan=lifespan,
)
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


class SecurityHeadersMiddleware:
    """Add browser security headers without buffering response bodies."""

    def __init__(self, asgi_app):
        self.app = asgi_app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("X-Frame-Options", "DENY")
                headers.setdefault("Referrer-Policy", "no-referrer")
                headers.setdefault(
                    "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
                )
                headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
                if scope.get("path") in {"/", "/login"}:
                    headers.setdefault("Cache-Control", "no-store")
            await send(message)

        await self.app(scope, receive, send_with_headers)


app.add_middleware(SecurityHeadersMiddleware)
app.mount(
    "/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static"
)


def _template_response(
    request: Request,
    name: str,
    context: dict,
    status_code: int = 200,
):
    """Render templates across the old and new Starlette call signatures."""
    template_context = {"request": request, **context}
    parameters = inspect.signature(templates.TemplateResponse).parameters
    if "request" in parameters:
        return templates.TemplateResponse(
            request=request,
            name=name,
            context=template_context,
            status_code=status_code,
        )
    return templates.TemplateResponse(
        name,
        template_context,
        status_code=status_code,
    )


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    """Avoid a noisy browser 404 when no custom favicon is configured."""
    return Response(status_code=204)


# Dependency: database session
def get_db():
    """Provide SQLAlchemy session for each request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _credentials_are_valid(username: str, password: str) -> bool:
    """Compare credentials in constant time."""
    record = AUTH_USERS.get(username)
    expected_password = record["password"] if record else secrets.token_hex(16)
    username_matches = secrets.compare_digest(
        username.encode("utf-8"),
        (username if record else ADMIN_USERNAME).encode("utf-8"),
    )
    password_matches = secrets.compare_digest(
        password.encode("utf-8"),
        expected_password.encode("utf-8"),
    )
    return username_matches and password_matches


def _create_session_token(username: str) -> str:
    payload = json.dumps(
        {"username": username, "expires": int(time.time()) + SESSION_TTL_SECONDS},
        separators=(",", ":"),
    ).encode("utf-8")
    encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    signature = hmac.new(
        SESSION_SECRET.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256
    ).hexdigest()
    return f"{encoded}.{signature}"


def _read_session_token(token: str | None) -> UserIdentity | None:
    if not token or "." not in token:
        return None
    encoded, supplied_signature = token.rsplit(".", 1)
    expected_signature = hmac.new(
        SESSION_SECRET.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256
    ).hexdigest()
    if not secrets.compare_digest(supplied_signature, expected_signature):
        return None
    try:
        padding = "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded + padding))
        if int(payload["expires"]) < int(time.time()):
            return None
        username = str(payload["username"])
    except (
        ValueError,
        KeyError,
        TypeError,
        UnicodeDecodeError,
        binascii.Error,
        json.JSONDecodeError,
    ):
        return None
    record = AUTH_USERS.get(username)
    return UserIdentity(username, record["role"]) if record else None


def get_optional_dashboard_user(
    credentials: HTTPBasicCredentials | None = Depends(dashboard_basic_security),
    session_token: str | None = Depends(dashboard_cookie_security),
) -> UserIdentity | None:
    """Resolve an operator from a signed session cookie or HTTP Basic auth."""
    session_username = _read_session_token(session_token)
    if session_username:
        return session_username
    if credentials and _credentials_are_valid(
        credentials.username, credentials.password
    ):
        return UserIdentity(
            credentials.username, AUTH_USERS[credentials.username]["role"]
        )
    return None


def get_optional_session_user(
    session_token: str | None = Depends(dashboard_cookie_security),
) -> UserIdentity | None:
    """Resolve a browser user only from the signed session cookie."""
    return _read_session_token(session_token)


def authenticate_dashboard_user(
    current_user: UserIdentity | None = Depends(get_optional_dashboard_user),
) -> UserIdentity:
    """Require an authenticated dashboard operator."""
    if current_user:
        return current_user

    raise HTTPException(
        status_code=401,
        detail="Authentication required",
        headers={"WWW-Authenticate": 'Basic realm="SOAR Dashboard"'},
    )


def require_roles(*allowed_roles: str):
    """Create a dependency that enforces role-based authorization."""

    def dependency(
        current_user: UserIdentity = Depends(authenticate_dashboard_user),
    ) -> UserIdentity:
        if current_user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user

    return dependency


require_viewer = require_roles("admin", "operator", "viewer")
require_operator = require_roles("admin", "operator")
require_admin = require_roles("admin")


def _isoformat_utc(value: datetime) -> str:
    """Serialize database timestamps unambiguously for browser clients."""
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_decision_reasoning(value: str | None) -> dict:
    """Return stored decision reasoning without exposing malformed JSON errors."""
    if not value:
        return {}
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}

# ============================================================================
# Pydantic Models (Request/Response)
# ============================================================================


class DetectionRequest(BaseModel):
    """POST /detections endpoint accepts this JSON."""

    source_ip: IPvAnyAddress
    event_type: str = Field(min_length=1, max_length=50)
    severity: int = Field(ge=1, le=5)
    raw_log_line: str = Field(min_length=1, max_length=10_000)
    timestamp: datetime | None = None

    @field_validator("event_type", mode="before")
    @classmethod
    def normalize_event_type(cls, value):
        if isinstance(value, str):
            value = value.strip()
        if not value:
            raise ValueError("event_type must contain non-whitespace characters")
        return value

    @field_validator("raw_log_line")
    @classmethod
    def raw_log_must_not_be_blank(cls, value: str):
        if not value.strip():
            raise ValueError("raw_log_line must contain non-whitespace characters")
        return value

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_include_timezone(cls, value: datetime | None):
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("timestamp must include a timezone offset")
        return value


class ApprovalRequest(BaseModel):
    """POST /approvals/{event_id} endpoint."""

    approved: bool
    rejected_reason: str | None = Field(default=None, max_length=2_000)

    @field_validator("rejected_reason")
    @classmethod
    def normalize_rejected_reason(cls, value: str | None):
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @model_validator(mode="after")
    def rejection_requires_reason(self):
        if not self.approved and not self.rejected_reason:
            raise ValueError("rejected_reason is required when rejecting a decision")
        return self


class EventResponse(BaseModel):
    """Response model for event details."""

    id: int
    source_ip: str
    event_type: str
    severity: int
    status: str
    created_at: str


def apply_response_result(event: Event, response_result: dict) -> tuple[str, str]:
    """Set an accurate event status and return it with a user-facing message."""
    response_status = response_result.get("status", "unknown")

    if response_status in {"success", "simulation"}:
        event.status = "responded"
        message = (
            "Response executed"
            if response_status == "success"
            else "Response simulated"
        )
    elif response_status == "skipped":
        event.status = "closed"
        message = "No response action was required"
    else:
        event.status = "response_failed"
        message = "Response failed"

    return event.status, message


# ============================================================================
# Core Pipeline Endpoints
# ============================================================================


@app.post("/detections")
def post_detection(
    req: DetectionRequest,
    current_user: UserIdentity = Depends(require_operator),
    db: Session = Depends(get_db),
):
    """
    POST /detections: Intake a security event.

    Example:
    {
      "source_ip": "192.168.1.100",
      "event_type": "port_scan",
      "severity": 3,
      "raw_log_line": "SYN scan from 192.168.1.100 to ports 22,80,443",
      "timestamp": "2026-08-19T10:00:00Z"
    }

    Flow:
      1. Store event in DB with status="new"
      2. Audit the detection
      3. Trigger enrichment in the background
      4. Return event details
    """
    event_id = None
    try:
        # Step 1: Create event
        ts = req.timestamp or datetime.now(timezone.utc)
        event = Event(
            source_ip=str(req.source_ip),
            event_type=req.event_type,
            severity=req.severity,
            raw_log_line=req.raw_log_line,
            timestamp=ts,
            status="new",
        )
        db.add(event)
        db.flush()  # Get the ID
        event_id = event.id

        # Step 2: Audit detection
        audit_event_detection(event, db, actor=current_user.username)

        # Step 3: Enrich immediately (synchronously for simplicity; could be async)
        enrichment = enrich_ip(
            str(req.source_ip),
            db,
            event.id,
            cache_ttl_minutes=ENRICHMENT_CACHE_TTL_MINUTES,
        )
        event.status = "enriched"
        db.commit()
        audit_enrichment(event, enrichment, db, actor=current_user.username)

        # Step 4: Decide
        from decision_engine import decide

        decision_result = decide(event, enrichment)
        decision = persist_decision(event, enrichment, decision_result, db)
        event.status = "decided"
        db.commit()
        audit_decision(event, decision, db, actor=current_user.username)

        # Step 5: Check approval gate
        if decision.requires_approval:
            event.status = "pending_approval"
            db.commit()
            logger.info(f"Event {event.id} requires approval")
            return {
                "id": event.id,
                "source_ip": event.source_ip,
                "status": "pending_approval",
                "message": "Awaiting human approval",
                "decision": {
                    "action": decision.action,
                    "risk_score": decision.risk_score,
                    "confidence": decision.confidence,
                },
            }
        else:
            # Auto-approve: proceed to response
            event.status = "approved"
            approval = Approval(
                event_id=event.id,
                decision_id=decision.id,
                status="auto_approved",
                approved_by=current_user.username,
                approved_at=datetime.now(timezone.utc),
            )
            db.add(approval)
            db.commit()
            audit_approval(event, approval, db)

            # Execute response
            event.status = "responding"
            db.commit()
            resp_result = execute_response(
                event,
                decision,
                dry_run=RESPONDER_DRY_RUN,
                simulation_mode=RESPONDER_SIMULATION_MODE,
            )
            event_status, response_message = apply_response_result(event, resp_result)
            db.commit()
            audit_response(
                event, decision, resp_result, db, actor=current_user.username
            )

            return {
                "id": event.id,
                "source_ip": event.source_ip,
                "status": event_status,
                "message": f"Auto-approved. {response_message}",
                "response": resp_result,
            }

    except Exception as exc:
        db.rollback()
        logger.exception("Detection intake error")
        if event_id is not None:
            try:
                failed_event = db.get(Event, event_id)
                if failed_event is not None:
                    before_status = failed_event.status
                    failed_event.status = "processing_failed"
                    db.commit()
                    create_audit_entry(
                        event_id=event_id,
                        actor=current_user.username,
                        action="pipeline_error",
                        before_state={"status": before_status},
                        after_state={"status": "processing_failed"},
                        reasoning="Detection pipeline failed during processing",
                        session=db,
                    )
            except Exception:
                db.rollback()
                logger.exception(
                    "Failed to persist the processing failure for event %s", event_id
                )
        raise HTTPException(
            status_code=500, detail="Detection processing failed"
        ) from exc


@app.post("/approvals/{event_id}")
def approve_decision(
    event_id: int,
    req: ApprovalRequest,
    current_user: UserIdentity = Depends(require_operator),
    db: Session = Depends(get_db),
):
    """
    POST /approvals/{event_id}: Approve or reject a pending decision.

    Example:
    {
      "approved": true,
      "rejected_reason": null
    }
    """
    try:
        event = db.query(Event).filter_by(id=event_id).first()
        if not event:
            raise HTTPException(status_code=404, detail=f"Event {event_id} not found")

        decision = db.query(Decision).filter_by(event_id=event_id).first()
        if not decision:
            raise HTTPException(
                status_code=409,
                detail="Event has no decision available for review",
            )
        target_status = "responding" if req.approved else "rejected"
        claimed = (
            db.query(Event)
            .filter(Event.id == event_id, Event.status == "pending_approval")
            .update({Event.status: target_status}, synchronize_session=False)
        )
        if claimed != 1:
            db.rollback()
            raise HTTPException(status_code=409, detail="Event was already reviewed")

        # Create the unique approval row only after winning the atomic event
        # claim. Creating it before the UPDATE lets concurrent reviewers race
        # on the unique constraint and turns a normal conflict into a 500.
        approval = db.query(Approval).filter_by(event_id=event_id).first()
        if approval is None:
            approval = Approval(event_id=event_id, decision_id=decision.id)
            db.add(approval)
        approval.approved_by = current_user.username

        if req.approved:
            approval.status = "approved"
            approval.approved_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(event)
            audit_approval(event, approval, db)

            # Execute response
            resp_result = execute_response(
                event,
                decision,
                dry_run=RESPONDER_DRY_RUN,
                simulation_mode=RESPONDER_SIMULATION_MODE,
            )
            event_status, response_message = apply_response_result(event, resp_result)
            db.commit()
            audit_response(
                event, decision, resp_result, db, actor=current_user.username
            )

            return {
                "id": event.id,
                "status": event_status,
                "message": f"Approved. {response_message}",
                "response": resp_result,
            }
        else:
            approval.status = "rejected"
            approval.rejected_reason = req.rejected_reason or "No reason provided"
            db.commit()
            db.refresh(event)
            audit_approval(event, approval, db)

            return {
                "id": event.id,
                "status": "rejected",
                "message": "Decision rejected",
                "reason": approval.rejected_reason,
            }

    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        logger.exception("Approval error")
        raise HTTPException(
            status_code=500, detail="Approval processing failed"
        ) from exc


# ============================================================================
# Dashboard Endpoints
# ============================================================================
@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_page(
    request: Request,
    current_user: UserIdentity | None = Depends(get_optional_session_user),
):
    """Render the admin login page."""
    if current_user:
        return RedirectResponse(url="/", status_code=303)
    return _template_response(request, "login.html", {"error": None})


@app.post("/login", response_class=HTMLResponse, include_in_schema=False)
def login(
    request: Request,
    username: str = Form(..., min_length=1, max_length=128),
    password: str = Form(..., min_length=1, max_length=256),
):
    """Validate admin credentials and start a signed browser session."""
    if not _credentials_are_valid(username, password):
        return _template_response(
            request,
            "login.html",
            {
                "error": "Incorrect username or password.",
                "username": username,
            },
            status_code=401,
        )

    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=_create_session_token(username),
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=SESSION_COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return response


@app.post("/logout", include_in_schema=False)
def logout():
    """End the browser session and return to the login screen."""
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response


@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    current_user: UserIdentity | None = Depends(get_optional_session_user),
):
    """Render the authenticated SOAR command center."""
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    return _template_response(
        request,
        "dashboard.html",
        {
            "current_user": current_user.username,
            "current_role": current_user.role,
        },
    )


@app.get("/dashboard/data")
def dashboard_data(
    request: Request,
    response: Response,
    current_user: UserIdentity = Depends(require_viewer),
    db: Session = Depends(get_db),
):
    """Return dashboard data for live updates."""
    response.headers["Cache-Control"] = "no-store"

    pending = (
        db.query(
            Event.id,
            Event.source_ip,
            Event.event_type,
            Event.severity,
            Event.status,
        )
        .filter_by(status="pending_approval")
        .order_by(Event.id.desc())
        .all()
    )

    recent_events = (
        db.query(
            Event.id,
            Event.source_ip,
            Event.event_type,
            Event.severity,
            Event.status,
            Event.timestamp,
        )
        .order_by(Event.id.desc())
        .limit(20)
        .all()
    )

    recent_decisions = (
        db.query(
            Decision.event_id,
            Decision.action,
            Decision.risk_score,
            Decision.confidence,
            Decision.requires_approval,
        )
        .order_by(Decision.id.desc())
        .limit(10)
        .all()
    )

    recent_audit = (
        db.query(
            AuditLog.timestamp,
            AuditLog.actor,
            AuditLog.action,
            AuditLog.event_id,
            AuditLog.entry_hash,
        )
        .order_by(AuditLog.id.desc())
        .limit(20)
        .all()
    )

    payload = {
        "events": [
            {
                "id": e.id,
                "source_ip": e.source_ip,
                "event_type": e.event_type,
                "severity": e.severity,
                "status": e.status,
                "timestamp": _isoformat_utc(e.timestamp),
            }
            for e in recent_events
        ],
        "pending": [
            {
                "id": e.id,
                "source_ip": e.source_ip,
                "event_type": e.event_type,
                "severity": e.severity,
                "status": e.status,
            }
            for e in pending
        ],
        "decisions": [
            {
                "event_id": d.event_id,
                "action": d.action,
                "risk_score": d.risk_score,
                "confidence": d.confidence,
                "requires_approval": d.requires_approval,
            }
            for d in recent_decisions
        ],
        "audit": [
            {
                "timestamp": _isoformat_utc(a.timestamp),
                "actor": a.actor,
                "action": a.action,
                "event_id": a.event_id,
                "hash": f"{a.entry_hash[:16]}..." if a.entry_hash else "Unavailable",
            }
            for a in recent_audit
        ],
        "audit_chain_valid": verify_audit_chain(db),
    }
    payload_fingerprint = hashlib.sha256(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    etag = f'W/"{payload_fingerprint}"'
    response.headers["ETag"] = etag
    if request.headers.get("if-none-match") == etag:
        return Response(
            status_code=304,
            headers={"Cache-Control": "no-store", "ETag": etag},
        )
    return payload


@app.get("/events/{event_id}")
def get_event(
    event_id: int,
    current_user: UserIdentity = Depends(require_viewer),
    db: Session = Depends(get_db),
):
    """GET /events/{event_id}: Retrieve detailed event info + decision + audit trail."""
    event = db.query(Event).filter_by(id=event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found")

    enrichment = db.query(EnrichmentResult).filter_by(event_id=event_id).first()
    decision = db.query(Decision).filter_by(event_id=event_id).first()
    approval = db.query(Approval).filter_by(event_id=event_id).first()
    audit = get_audit_log_for_event(event_id, db)

    return {
        "event": {
            "id": event.id,
            "source_ip": event.source_ip,
            "event_type": event.event_type,
            "severity": event.severity,
            "status": event.status,
            "timestamp": _isoformat_utc(event.timestamp),
            "created_at": _isoformat_utc(event.created_at),
            "raw_log_line": event.raw_log_line,
        },
        "enrichment": {
            "abuse_score": enrichment.abuse_score if enrichment else None,
            "country": enrichment.country if enrichment else None,
            "isp": enrichment.isp if enrichment else None,
            "report_count": enrichment.report_count if enrichment else None,
            "is_vpn": enrichment.is_vpn if enrichment else None,
            "is_proxy": enrichment.is_proxy if enrichment else None,
            "error": enrichment.error if enrichment else None,
        }
        if enrichment
        else None,
        "decision": {
            "action": decision.action if decision else None,
            "risk_score": decision.risk_score if decision else None,
            "confidence": decision.confidence if decision else None,
            "requires_approval": decision.requires_approval if decision else None,
            "reasoning": _parse_decision_reasoning(decision.reasoning)
            if decision
            else {},
        }
        if decision
        else None,
        "approval": {
            "status": approval.status if approval else None,
            "approved_by": approval.approved_by if approval else None,
            "rejected_reason": approval.rejected_reason if approval else None,
            "approved_at": _isoformat_utc(approval.approved_at)
            if approval and approval.approved_at
            else None,
        }
        if approval
        else None,
        "audit_trail": [
            {
                "timestamp": _isoformat_utc(a.timestamp),
                "actor": a.actor,
                "action": a.action,
                "reasoning": a.reasoning,
            }
            for a in audit
        ],
    }


@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    """GET /health: Health check endpoint."""
    try:
        db.execute(text("SELECT 1"))
        audit_valid = verify_audit_chain(db, depth=100)
        if not audit_valid:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "unhealthy",
                    "database": "connected",
                    "audit_chain": "invalid",
                },
            )
        return {
            "status": "healthy",
            "database": "connected",
            "audit_chain": "valid",
        }
    except Exception:
        logger.exception("Health check failed")
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "error": "Health check failed"},
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", "8000")),
        reload=os.getenv("API_RELOAD", "True").lower() == "true",
    )
