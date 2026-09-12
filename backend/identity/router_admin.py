"""/api/admin — the Global Admin API.

Empty on purpose: the five admin screens are the next build. What exists
now is the lock on the door. Every route that is ever added under this
prefix inherits `require_global_admin` from the router, and the guard in
`guard.py` refuses the whole prefix — including paths that do not exist
yet — to anyone who is not a Global Admin, and refuses any mutation without
the CSRF header. Two independent checks; the frontend is not one of them.

`GET /api/admin/whoami` is the one route present, so the lock can be
tested end to end before there is anything behind it.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from .models import User
from .permissions import require_global_admin

router = APIRouter(
    prefix="/api/admin",
    tags=["admin"],
    dependencies=[Depends(require_global_admin)],
)


@router.get("/whoami")
def whoami(user: User = Depends(require_global_admin)):
    """Proof the caller is a Global Admin — nothing more."""
    return {"id": str(user.id), "email": user.email, "is_global_admin": True}
