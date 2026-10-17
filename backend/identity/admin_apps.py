"""Applications — a Global Admin adds and edits them from the panel.

Features already arrive from the apps themselves (OPEN-DECISIONS #23). With
this screen an application does too: a Global Admin adds it — key, name,
status, address — and the only step left on the server is its gate secret.

* The **key** is permanent. It is the app's identity everywhere: its gate
  header, its permission keys, the scope of roles held in it. It can never be
  changed, and since an application is never deleted, never reused.
* **No delete.** An application with history is set `inactive` instead: the
  gate refuses it and the launcher leaves it out, and everything recorded
  about it stays.
* Adding one also subscribes the organisation to it (uncapped), so a seat on
  it can be given at once — the same as the seed did for the first two.
* Whether its **gate secret** is configured is shown as yes or no. The secret
  itself is never read into a response.
"""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config, features
from .db import get_db
from .models import Application, Subscription, User
from .permissions import audit, require_global_admin

# Global Admin on the prefix is the floor: every route added here inherits
# it, and guard.py refuses each admin row a second time, independently.
router = APIRouter(prefix="/api/admin", tags=["admin"],
                   dependencies=[Depends(require_global_admin)])

STATUSES = ("live", "coming_soon", "inactive")


def _address(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    value = value.strip().rstrip("/")
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise ValueError("The address must be an http(s) URL.") from exc
    if parts.scheme not in ("http", "https") or not parts.hostname or len(value) > 500:
        raise ValueError("The address must be an http(s) URL, at most 500 characters.")
    return value


class AppCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str
    name: str = Field(min_length=1, max_length=120)
    status: str = "coming_soon"
    base_url: str | None = None
    description: str | None = Field(default=None, max_length=300)

    @field_validator("key")
    @classmethod
    def _key(cls, value: str) -> str:
        if not features.KEY.match(value):
            raise ValueError("key must match [a-z][a-z0-9_]{0,39}")
        return value

    @field_validator("status")
    @classmethod
    def _status(cls, value: str) -> str:
        if value not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        return value

    @field_validator("base_url")
    @classmethod
    def _url(cls, value: str | None) -> str | None:
        return _address(value)


class AppPatch(BaseModel):
    """Name, status and address only. Any other field — the key above all —
    is refused rather than ignored."""
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=120)
    status: str | None = None
    base_url: str | None = None

    @field_validator("status")
    @classmethod
    def _status(cls, value: str | None) -> str | None:
        if value is not None and value not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        return value

    @field_validator("base_url")
    @classmethod
    def _url(cls, value: str | None) -> str | None:
        return _address(value)


def _json(app: Application, secrets: dict[str, str]) -> dict:
    return {
        "key": app.key, "name": app.name, "description": app.description,
        "status": app.status, "base_url": app.base_url,
        # yes or no, never the secret
        "gate_secret_configured": app.key in secrets,
        "features_reported_at": (app.features_reported_at.isoformat()
                                 if app.features_reported_at else None),
        "features_version": app.features_version,
    }


def _state(app: Application) -> dict:
    return {"name": app.name, "status": app.status, "base_url": app.base_url}


# ------------------------------------------------------------------- routes
@router.get("/applications")
def list_applications(db: Session = Depends(get_db),
                      actor: User = Depends(require_global_admin)):
    secrets = config.gate_secrets()
    apps = db.scalars(select(Application).order_by(Application.name)).all()
    return {"applications": [_json(a, secrets) for a in apps],
            "statuses": list(STATUSES)}


@router.post("/applications", status_code=201)
def create_application(body: AppCreate, request: Request, db: Session = Depends(get_db),
                       actor: User = Depends(require_global_admin)):
    if db.scalar(select(Application).where(Application.key == body.key)) is not None:
        raise HTTPException(status_code=409,
                            detail=f"An application with the key {body.key!r} already exists. "
                                   "Keys are permanent and never reused; choose another.")
    app = Application(key=body.key, name=body.name.strip(), description=body.description,
                      status=body.status, base_url=body.base_url)
    db.add(app)
    db.flush()
    # subscribed, uncapped: so a seat on it can be given straight away
    db.add(Subscription(org_id=actor.org_id, application_id=app.id,
                        valid_from=datetime.now(timezone.utc)))
    audit(db, actor=actor, action="application.create", target_type="application",
          target_id=app.key, application_id=app.id, result="success", request=request,
          after=_state(app) | {"key": app.key}, commit=False)
    db.commit()
    return _json(app, config.gate_secrets())


@router.patch("/applications/{application_key}")
def edit_application(application_key: str, body: AppPatch, request: Request,
                     db: Session = Depends(get_db),
                     actor: User = Depends(require_global_admin)):
    app = db.scalar(select(Application).where(Application.key == application_key))
    if app is None:
        raise HTTPException(status_code=404, detail=f"Unknown application {application_key!r}.")
    before = _state(app)
    sent = body.model_dump(exclude_unset=True)
    if "name" in sent and sent["name"] is not None:
        app.name = sent["name"].strip()
    if "status" in sent and sent["status"] is not None:
        app.status = sent["status"]
    if "base_url" in sent:
        app.base_url = sent["base_url"]
    after = _state(app)
    if after != before:
        audit(db, actor=actor, action="application.update", target_type="application",
              target_id=app.key, application_id=app.id, result="success", request=request,
              before=before, after=after, commit=False)
    db.commit()
    return _json(app, config.gate_secrets())
