# MAEC One Core

Identity, entitlement and the Global Admin panel for the MAEC One platform.

This service owns **who someone is** and **what they may open**. It does not
own any product. Engineering Tools (HAPExt, AirSizer Pro, PDF Rebadging) is a
separate application and will become an OIDC client of this service; until
that handoff exists, each product still carries its own sign-in.

## What it does

- **Per-user accounts** — argon2id hashes, per-IP rate limiting, escalating
  lockout, session regenerated on sign-in, CSRF on every admin change.
- **A permission engine** — `can(user, "app:module:action", scope)` resolving
  entitlement → roles → scope → most-specific-wins with deny beating allow →
  per-organisation tool rules that may only narrow. Fails closed.
- **Six admin screens** — users and access, roles and permissions, tool
  access, audit log, onboarding import, provisioning.
- **An append-only audit log**, enforced by a database trigger rather than by
  convention.

## Running it locally

Needs Python 3.12, Node 20+, and a PostgreSQL you can create a database in.

```bash
# 1. a database
createdb -U postgres maec_identity

# 2. configuration
cp .env.example .env        # then fill it in — see below

# 3. python
python -m venv .venv
.venv/Scripts/python -m pip install -r backend/requirements.txt

# 4. schema and starting data
.venv/Scripts/python -m alembic -c backend/identity/alembic.ini upgrade head
.venv/Scripts/python -m backend.identity.seed

# 5. the frontend
npm --prefix frontend install
npm --prefix frontend run build

# 6. serve
.venv/Scripts/python -m uvicorn backend.main:app --port 8000
```

Then sign in at `http://127.0.0.1:8000` as `BOOTSTRAP_ADMIN_EMAIL`.

For frontend work, `npm --prefix frontend run dev` serves on `:5173` and
proxies `/api` to `:8000`.

## Environment

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL. `postgresql+psycopg://user:pass@host:5432/db` — a `postgresql://` URL from a provider is rewritten automatically. URL-encode special characters in the password (`@` → `%40`). |
| `SESSION_SECRET` | Signs the session cookie. Changing it signs everybody out. |
| `BOOTSTRAP_ADMIN_EMAIL` | The first Global Admin, created by the seed. |
| `BOOTSTRAP_ADMIN_PASSWORD` | That account's password. 8+ characters with upper, lower, digit and symbol. |
| `SEED_TEST_USER_EMAIL` | An ordinary engineer, for testing the non-admin path. |
| `SEED_TEST_USER_PASSWORD` | Set **both** or neither. Leave unset anywhere shared. |

`.env` is read at startup and gitignored; a real environment variable always
wins over the file, so a deployment with no `.env` is unaffected.

The seed is idempotent and safe to run on every boot. It never overwrites an
existing password — set `SEED_RESET_PASSWORDS=1` for a single run to re-apply
`BOOTSTRAP_ADMIN_PASSWORD` if an admin is locked out of their own account.

## Tests

```bash
.venv/Scripts/python -m pytest
```

202 tests. Most run against an in-memory SQLite; nine run against the
PostgreSQL in your `.env` and cover what SQLite cannot see — column widths,
CHECK constraints and the append-only trigger. Those nine skip themselves if
no PostgreSQL is configured.

## Before this is useful

`applications.base_url` is empty for every row. The launcher shows a tile per
product and opens it by URL, so **each product's address has to be set on its
row** before a tile does anything. See `EXTRACTION-LOG.md`, finding 6c.

## Reading

- `EXTRACTION-LOG.md` — what separating this from the product actually took,
  and what the boundary did not cover. Read this first if you are wondering
  why something is the way it is.
- `OPEN-DECISIONS.md` — ten things deliberately left unresolved, each with
  enough context to settle it without re-deriving the argument.
