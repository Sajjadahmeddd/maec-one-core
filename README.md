# MAEC One Core

Identity, entitlement and the Global Admin panel for the MAEC One platform —
the one sign-in every MAEC One application shares.

This service owns **who someone is** and **what they may open**. It does not
own any product. Engineering Tools (HAPExt, AirSizer Pro, PDF Rebadging) is a
separate application.

**How apps sign in (`OPEN-DECISIONS.md` #19).** Every app lives under
mirageaec.com. Core's session cookie is shared across that domain, and a gate
in front of each app asks Core on every request whether this person may use
it — so a sign-out, a revoked seat or a suspension takes effect on the next
click, everywhere. Core's side of that is being built in three runs: this
branch holds the first (revocable sessions, the shared cookie, CSRF on every
session route). The OIDC provider below stays, dormant, for any app that
cannot live under mirageaec.com.

## What it does

- **Per-user accounts** — argon2id hashes, per-IP rate limiting, an escalating
  fixed-window lockout.
- **Revocable sessions** — every sign-in is a row in `sessions`; the cookie
  carries only a random id, and no valid row means not signed in. 10 hours
  absolute, 2 hours idle. Sign-out, a password change, an admin reset, a
  suspension or "sign out everywhere" ends them on the next request.
- **A shareable cookie** — `SESSION_COOKIE_DOMAIN` lets every app under the
  domain receive it. HttpOnly, SameSite=Lax, Secure whenever the request came
  over https; CSRF required on every mutation that rides on it.
- **A permission engine** — `can(user, "app:module:action", scope)` resolving
  entitlement → roles → scope → most-specific-wins with deny beating allow →
  per-organisation tool rules that may only narrow. Fails closed. The
  resolution itself (`identity/resolution.py`) needs no database, so a product
  runs the same engine over a token's claims.
- **An OIDC provider, dormant** — authorization-code flow for confidential
  clients: `GET /oauth/authorize`, `POST /oauth/token` (rate limited),
  `GET /.well-known/jwks.json`. RS256 tokens that carry the inputs to the
  permission decision for one application, and live fifteen minutes. Not used
  by apps under mirageaec.com (#19); kept for those that cannot be.
- **Six admin screens** — users and access, roles and permissions, tool
  access, audit log, onboarding import, provisioning.
- **An append-only audit log**, enforced by a database trigger rather than by
  convention. Events that belong to no organisation — sign-in attempts for
  unknown addresses, refused client credentials — are shown to Global Admins
  under "Platform events".
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
.venv/Scripts/python -m uvicorn backend.main:app --port 8000 --no-proxy-headers
```

Then sign in at `http://127.0.0.1:8000` as `BOOTSTRAP_ADMIN_EMAIL`.

`--no-proxy-headers` leaves Core's own trusted-proxy list (`TRUSTED_PROXIES`)
as the only one; uvicorn's default would apply a second. With
`SESSION_COOKIE_DOMAIN=.maec.local` set, sign in at
`http://auth.maec.local:8000` instead — at `127.0.0.1` the sign-in succeeds
and the browser throws the cookie away, because its domain does not cover that
host. Map `auth.maec.local` (and each app's `*.maec.local` name) to
`127.0.0.1` in the hosts file first.

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
| `SESSION_SECRET` | Signs the session cookie. Changing it signs everybody out. Locally, one is generated if unset. On Render the service **refuses to start** without it — a generated secret differs per instance, so sessions would fail to validate on whichever instance did not mint them. `render.yaml` has Render generate and keep one. **Elsewhere, set it**: the refusal keys on Render's `RENDER` variable, which a VPS does not set. |
| `SESSION_COOKIE_DOMAIN` | The session cookie's Domain. Production `.mirageaec.com`, so every app's gate receives it; local `.maec.local`. Unset keeps a host-only cookie. Not a URL — a bare domain, or Core refuses to start. |
| `SESSION_ABSOLUTE_HOURS` | Longest a session lives, however busy. Default `10`. |
| `SESSION_IDLE_MINUTES` | How long a session survives with no request. Default `120`. A value that is set but not a positive number refuses to start. |
| `TRUSTED_PROXIES` | Comma-separated addresses or CIDR ranges whose `X-Forwarded-For` / `X-Forwarded-Proto` Core believes. Default `127.0.0.1`. **In Docker set it to the network's range** (e.g. `127.0.0.1,172.18.0.0/16`), or every visitor shares nginx's address and one login rate limit. `*` is refused. |
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
existing password or clears a lock. If an admin is locked out of their own
account, set `SEED_RESET_PASSWORDS=1` for a single run: it re-applies
`BOOTSTRAP_ADMIN_PASSWORD`, clears the failed-attempt count and any lockout,
and signs out the sessions minted under the old password. Then unset it.

## Tests

```bash
.venv/Scripts/python -m pytest
```

463 tests. 444 run against an in-memory SQLite; 19 run against the PostgreSQL
in your `.env` and cover what SQLite cannot — column widths, CHECK
constraints, the append-only trigger, the migrations run up and down with data
present, real concurrency on single-use authorization codes, and a session
revoked on one connection being refused on another at once. Those 19 skip
themselves if no PostgreSQL is configured — a green run with them skipped has
not tested any of that.

## The launcher

The launcher shows a tile per product and opens it at `applications.base_url`,
so **each product's address has to be set on its row** before a tile does
anything (`EXTRACTION-LOG.md`, finding 6d). With the shared cookie and the
gate (#19) there is no handoff: the tile opens the product, and the gate lets
the person straight in.

## Reading

- `EXTRACTION-LOG.md` — what separating this from the product actually took,
  and what the boundary did not cover. Read this first if you are wondering
  why something is the way it is.
- `OPEN-DECISIONS.md` — twenty entries, each with enough context to settle
  or revisit it without re-deriving the argument. #19 is how apps sign in
  (read it first), #5 revocable sessions, #6 client addresses behind a proxy,
  #20 every rate limit and the lockout. #11 and #15–#18 are the dormant OIDC
  design.
