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

### Deploying

`Dockerfile` builds one image: the API and the built frontend. It runs as
`MAEC_ENV=production` unless told otherwise, so it refuses to start without
`SESSION_SECRET` and `OIDC_PRIVATE_KEY`. On start it runs the migrations
(fatal if they fail), the seed (best-effort), then uvicorn with
`--no-proxy-headers` — Core applies its own trusted-proxy list.

`deploy/compose.example.yml` runs Core and its own PostgreSQL beside the
existing VPS setup without touching it. Core is published on `127.0.0.1:8001`
only, for the host's Caddy (`auth.mirageaec.com { reverse_proxy
localhost:8001 }`). It starts first and depends on no app. The network it
shares with the apps, `maec_core_net` (10.231.1.0/24), belongs to no stack: it
is created once on the host, before Core's first start —
`docker network create --subnet 10.231.1.0/24 --gateway 10.231.1.1 maec_core_net` — and Core and each app join it as external, reaching the gate at
`http://maec-core:8000`. No stack's `docker compose down` removes it. The database
sits on `maec_core_private` (10.231.0.0/24, internal) with Core alone; an app
cannot even resolve it. `TRUSTED_PROXIES` is `127.0.0.1,10.231.1.1` — the
gateway Caddy's traffic arrives from, never the range apps live in
(`OPEN-DECISIONS.md` #21).

An app joins Core's network in its own compose file:

```yaml
services:
  backend:
    networks: [default, maec_core_net]
networks:
  maec_core_net:
    external: true
    name: maec_core_net
```

On the VPS, Core is `auth.mirageaec.com` (127.0.0.1:8001) and the gated
Engineering Tools is `engtools.mirageaec.com` (127.0.0.1:8082) — both added to
Caddy beside what is already there. The old Engineering Tools keeps
`et.mirageaec.com` (8080) until it is retired; Project Management keeps
`promanage.mirageaec.com` (8081). The full go-live, step by step, is
`deploy/RUNBOOK.md`.

```bash
cp deploy/compose.example.yml deploy/compose.yml
cp deploy/env.production.example deploy/env.production   # fill in, on the server
chmod 600 deploy/env.production
docker compose -f deploy/compose.yml --env-file deploy/env.production up -d --build
```

`deploy/env.production.example` lists every production setting with the
command that generates each secret. Generate them on the server; never reuse
one that has been pasted anywhere. Keep `OIDC_PRIVATE_KEY` in single quotes —
unquoted, Docker Compose turns its `\n` into line breaks and refuses the file.
After the first sign-in, read `audit_logs.ip`: it should be your own public
address, not `10.231.…` (`OPEN-DECISIONS.md` #6).

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
| `MAEC_ENV` | `development` on a developer's machine — the only value that lets Core generate a session secret and a signing key for itself. **Unset, or anything else, is production:** Core refuses to start without `SESSION_SECRET` and `OIDC_PRIVATE_KEY`. Fail safe — forgetting it gets the refusals, not the fallbacks. |
| `DATABASE_URL` | PostgreSQL. `postgresql+psycopg://user:pass@host:5432/db` — a `postgresql://` URL from a provider is rewritten automatically. URL-encode special characters in the password (`@` → `%40`). |
| `SESSION_SECRET` | Signs the session cookie. Changing it signs everybody out. With `MAEC_ENV=development`, one is generated if unset. Otherwise Core **refuses to start** without it — a generated secret differs per worker, so sessions would fail to validate on whichever worker did not mint them. |
| `SESSION_COOKIE_DOMAIN` | The session cookie's Domain. Production `.mirageaec.com`, so every app's gate receives it; local `.maec.local`. Unset keeps a host-only cookie. Not a URL — a bare domain, or Core refuses to start. **In production Core refuses to start without it** — unset, single sign-on silently stops working. |
| `SESSION_ABSOLUTE_HOURS` | Longest a session lives, however busy. Default `10`. |
| `SESSION_IDLE_MINUTES` | How long a session survives with no request. Default `120`. A value that is set but not a positive number refuses to start. |
| `CORE_PUBLIC_URL` | The address people type to reach Core — what the gate's sign-in links start with. Production `https://auth.mirageaec.com`; local `http://auth.maec.local:8000`. **In production it is required and must be https; Core refuses to start otherwise.** In development, unset, the gate falls back to the address its caller used. |
| `GATE_SECRETS` | Each app's gate secret: `engineering=<secret>`, comma-separated for more. 32+ characters (`python -c "import secrets; print(secrets.token_urlsafe(32))"`). The same value goes into that app's own settings. A malformed entry refuses to start. |
| `TRUSTED_PROXIES` | Comma-separated addresses or CIDR ranges whose `X-Forwarded-For` / `X-Forwarded-Proto` Core believes. Default `127.0.0.1`. **In Docker set it to the network's range** (e.g. `127.0.0.1,172.18.0.0/16`), or every visitor shares nginx's address and one login rate limit. `*` is refused. |
| `OIDC_PRIVATE_KEY` | The RSA key (PEM, 2048 bits or more) that signs tokens. Never in the database. With `MAEC_ENV=development`, an ephemeral key is generated if unset, and its tokens stop verifying at restart. Otherwise Core **refuses to start** without it. One line with literal `\n` is accepted. |
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

614 tests. 589 run against an in-memory SQLite; 22 run against the PostgreSQL
in your `.env` and cover what SQLite cannot — column widths, CHECK
constraints, the append-only trigger, the migrations run up and down with data
present, real concurrency on single-use authorization codes, and a session
revoked on one connection being refused on another at once. Those 22 skip
themselves if no PostgreSQL is configured — a green run with them skipped has
not tested any of that. Three more run frontend rules under Node, so Node
must be installed: the sign-in page's `next` allowlist — the open-redirect
surface — (`node --test frontend/src/maecone/next.test.js`); where sign-in
lands, what each launcher tile does and who sees the Admin panel card
(`frontend/src/maecone/launcher.test.js`); and how the Global Admin screens
word, order and colour what the server sends
(`frontend/src/maecone/admin/present.test.js`).

## The gate — how an app lets people in

`GET /api/gate/check` answers one question for an app's server: who does this
browser's cookie belong to, and may they use this app? (`OPEN-DECISIONS.md`
#19.) The app sends, on every request a person makes to it:

| Header | Contents |
|---|---|
| `X-MAEC-App` | its application key, e.g. `engineering` |
| `X-MAEC-Gate-Secret` | its secret from `GATE_SECRETS` |
| `X-Original-URL` | the full URL the person asked for |
| `X-Original-Method` | that request's method |
| `X-Original-Origin` | the browser's `Origin` header, if it sent one |
| `Cookie` | the browser's cookie, unchanged |

Core checks, in order, and stops at the first failure: the secret and that the
app is live (403 `bad_app`); for anything but GET/HEAD/OPTIONS, that the
`Origin` is exactly the app's own `base_url` origin (403 `bad_origin`); a valid
session (401 `not_signed_in`); an active account (401 `not_signed_in`); no
password change outstanding (401 `password_change`); an active organisation
(403 `org_suspended`); a seat on the app (403 `no_access`).

Yes is 200:

```json
{"user": {"id": "…", "email": "…", "name": "…"},
 "org_id": "…",
 "permissions": ["engineering:hapext:convert", "…"],
 "nav_hidden": ["hapaudit"]}
```

No is 401 or 403 with `{"reason": "…", "login_url": "…"}`. On a page request
the app sends the browser to `login_url`; on an API call it returns the status
and the app's frontend does. The link comes back to the exact page after
sign-in — the sign-in page follows `next` only to a live app's own origin.

The app checks `permissions` for each action itself, and leaves the
`nav_hidden` modules out of its navigation. For the cookie to reach the app at
all, both must be under `SESSION_COOKIE_DOMAIN`, and the app's `base_url` must
be set:

```sql
UPDATE applications SET base_url = 'http://et.maec.local:8080' WHERE key = 'engineering';
```

An app's "Change password" link goes to `${CORE_PUBLIC_URL}/change-password`,
for everyone. Anyone signed in changes theirs there — the current password,
then the new one; every other session they hold is signed out — and lands on
the launcher. Someone not signed in signs in first and comes back to it.

## The launcher

Everyone lands on the launcher — a Global Admin too — after signing in, and
whenever they open Core while signed in. The one exception is a `next` the
sign-in page follows: an app's own address, `/change-password` or
`/oauth/authorize`. A Global Admin reaches the Admin panel from a card on the
launcher, or at `/admin`; nobody else is offered it.

There is a tile for every row in `applications`, from `GET /api/auth/me`
(`apps`: key, name, status, base_url, and `entitled` — a seat, under an
in-date subscription, in an active organisation: what the gate checks). One
query reads the catalogue, however many applications there are. A tile opens
its `base_url`, in the same tab, when the app is `live`, the person is
entitled, and the address is set. Otherwise it says why, and is not a control;
the first that applies wins:

1. Organisation suspended
2. Coming soon
3. No access – ask your administrator
4. Not available yet

So **each product's address has to be set on its row** before its tile opens
(`EXTRACTION-LOG.md`, finding 6d). With the shared cookie and the gate (#19)
there is no handoff: the tile opens the product, and the gate lets the person
straight in.

## Reading

- `EXTRACTION-LOG.md` — what separating this from the product actually took,
  and what the boundary did not cover. Read this first if you are wondering
  why something is the way it is.
- `OPEN-DECISIONS.md` — twenty-two entries, each with enough context to settle
  or revisit it without re-deriving the argument. #19 is how apps sign in
  (read it first), #5 revocable sessions, #6 client addresses behind a proxy,
  #20 every rate limit and the lockout. #11 and #15–#18 are the dormant OIDC
  design.
