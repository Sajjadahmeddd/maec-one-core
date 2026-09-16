# MAEC One Core

Identity, entitlement and the Global Admin panel for the MAEC One platform —
and the OIDC provider every MAEC One application signs in through.

This service owns **who someone is** and **what they may open**. It does not
own any product. Engineering Tools (HAPExt, AirSizer Pro, PDF Rebadging) is a
separate application. Core's side of the handoff is built; Engineering Tools'
client side is not yet, so its launcher tile still opens it directly.

## What it does

- **Per-user accounts** — argon2id hashes, per-IP rate limiting, escalating
  lockout, session regenerated on sign-in, CSRF on every admin change.
- **A permission engine** — `can(user, "app:module:action", scope)` resolving
  entitlement → roles → scope → most-specific-wins with deny beating allow →
  per-organisation tool rules that may only narrow. Fails closed. The
  resolution itself (`identity/resolution.py`) needs no database, so a product
  runs the same engine over a token's claims.
- **An OIDC provider** — authorization-code flow for confidential clients:
  `GET /oauth/authorize`, `POST /oauth/token`, `GET /.well-known/jwks.json`.
  RS256 tokens that carry the inputs to the permission decision for one
  application, and live fifteen minutes.
- **Six admin screens** — users and access, roles and permissions, tool
  access, audit log, onboarding import, provisioning.
- **An append-only audit log**, enforced by a database trigger rather than by
  convention.
- **One access table** — every route's requirement is declared in
  `identity/guard.py`; an unlisted path under `/api`, `/oauth` or
  `/.well-known` is refused.

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

### Registering an application as an OIDC client

```bash
.venv/Scripts/python -m backend.identity.clients register \
    --application engineering --name "Engineering Tools" \
    --redirect-uri http://et.maec.local:8080/auth/callback

.venv/Scripts/python -m backend.identity.clients list
```

The secret is printed once and only its hash is stored — put it in the
application's own configuration straight away. Redirect URIs are matched
exactly; plain `http` is accepted only for localhost, 127.0.0.1 and `.local`
hosts.

## Environment

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL. `postgresql+psycopg://user:pass@host:5432/db` — a `postgresql://` URL from a provider is rewritten automatically. URL-encode special characters in the password (`@` → `%40`). |
| `SESSION_SECRET` | Signs the session cookie. Changing it signs everybody out. Locally, one is generated if unset. On Render the service **refuses to start** without it — a generated secret differs per instance, so sessions would fail to validate on whichever instance did not mint them. `render.yaml` has Render generate and keep one. |
| `OIDC_PRIVATE_KEY` | The RSA key (PEM, 2048 bits or more) that signs tokens. Never in the database. Locally, an ephemeral key is generated if unset, and its tokens stop verifying at restart. On Render the service **refuses to start** without it. One line with literal `\n` is accepted. |
| `OIDC_KEY_ID` | The key's id in JWKS. A new id for every new key — Core refuses to start if an id is already published with a different key. Unset, the key's RFC 7638 thumbprint is used. |
| `OIDC_ISSUER` | The `iss` every token carries. `https://auth.mirageaec.com` by default; locally `http://auth.maec.local:8000`. |
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

343 tests. Most run against an in-memory SQLite; sixteen run against the
PostgreSQL in your `.env` and cover what SQLite cannot — column widths, CHECK
constraints, the append-only trigger, the migrations run up and down with data
present, and real concurrency on single-use authorization codes. Those sixteen
skip themselves if no PostgreSQL is configured.

## The launcher

The launcher shows a tile per product and opens it at `applications.base_url`,
so **each product's address has to be set on its row** before a tile does
anything (`EXTRACTION-LOG.md`, finding 6d). Once a product can receive the
authorization-code callback, its tile moves from opening the product directly
to starting the handoff at `/oauth/authorize`.

## Reading

- `EXTRACTION-LOG.md` — what separating this from the product actually took,
  and what the boundary did not cover. Read this first if you are wondering
  why something is the way it is.
- `OPEN-DECISIONS.md` — seventeen entries, each with enough context to settle
  or revisit it without re-deriving the argument. #11 is the token design,
  #15 key management, #16 token lifetime, #17 PKCE.
