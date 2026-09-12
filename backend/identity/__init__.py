"""MAEC One Core — identity, entitlement and permissions.

This package is the seed of a separate service. It will be lifted out into
its own repository and deployed at auth.mirageaec.com once it has been proven
here, so it is built to be copied, not untangled:

* nothing in here imports from the HAP engines, the product routers or
  `backend/deps.py` — the only shared code is FastAPI and SQLAlchemy;
* the product side is allowed to import from here (the guard, the session
  helpers, the dependencies), never the reverse.

Layout:

    config.py        environment, .env loading, the session secret
    db.py            engine and session plumbing
    models.py        the schema — every table, including ones Prompt 2 fills
    security.py      argon2id hashing, password policy, session + CSRF helpers
    permissions.py   the resolution engine: can(), the dependencies, audit()
    accounts.py      the rules a change to a person must obey
    guard.py         the request-time gate main.py's middleware calls
    router_auth.py   /api/auth/login, /logout, /me
    router_admin.py  /api/admin — empty, but already locked
    seed.py          idempotent bootstrap data
    migrations/      Alembic
"""
