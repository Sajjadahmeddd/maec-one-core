"""/api/admin — the Global Admin API.

The lock on the door. Every route added under this prefix inherits
`require_global_admin` from its router, and `guard.py` independently refuses
each admin row in its access table to anyone who is not a Global Admin, and
any mutation without the CSRF header. A path with no row is refused outright.
Two independent checks; the frontend is not one of them.

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
