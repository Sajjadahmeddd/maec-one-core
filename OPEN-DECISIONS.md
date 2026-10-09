# Open decisions

Things deliberately left unresolved, with enough context to settle them later
without re-deriving the argument. Nothing here is a bug; each is a choice
waiting on a person — a designer, a manager, or a second application existing.

Add to this file rather than leaving a decision in a commit message or a chat
log, because that is where they get lost.

**Read 19 first.** It decides how every app under mirageaec.com is signed in
and checked: one shared session cookie and a gate in front of each app, with
Core answering on every request. It partly reverses **11**, which is still the
design for any app that must live outside mirageaec.com — read 11 second. The
rest can wait as long as they like.

---

## 1. Badge vocabulary on Roles & Permissions — needs the designer

**Status:** UI correctness. Not a blocker, but it will matter before a client
sees the screen.

The Figma for screen 001 names badges the data model has no concept of:

| Figma says | Exists in the model? |
|---|---|
| View Only | yes, derivable |
| Full Access | yes, derivable |
| Personal Load | **no** |
| Full Team Load | **no** |
| Capacity View | **no** |
| System-wide | **no** |

The last four are resource-planning language. The model is allow/deny over
`app:module:action`, so the screen derives four badges from real rows instead:

    full     every action on that module is allowed
    partial  some are
    view     only `view` is
    none     nothing is

**To settle:** either the designer adopts these four, or the model grows the
concepts the Figma implies — which is a much larger change than a rename, and
should not be done to satisfy a label.

---

## 2. Module names on Tool-Level Settings — needs the designer

**Status:** same category as #1.

The Figma for screen 002 lists rows: *Engineering Workspace, Resource Planner,
Budget Console, Risk Matrix, Executive Dashboard*. None of these exist. The
real permission registry has four modules, seeded and enforced:

    hapext, airsizer, hapaudit, rebadge

The screen reads the registry, so it shows the real four. If those five names
are the intended future product surface, they need to become real applications
and modules first; if they are placeholder art, the Figma should be corrected.

---

## 3. The level list — decided: `edit` fixed, `hidden` kept, its reader is the product

**Status:** resolved in Prompt 5. Settled as one design problem, because it
was one: two of the five levels did nothing.

| Level | Permits at the API | Navigation | Defined as |
|---|---|---|---|
| `full` | every action, including future ones | shown | explicit |
| `edit` | view, convert, export | shown | derived from `LEVEL_IMPLIES` |
| `view` | view | shown | derived from `LEVEL_IMPLIES` |
| `hidden` | every action | not rendered | explicit — decluttering |
| `no_access` | nothing (403) | not rendered | explicit — the boundary |

**`edit` — fixed.** It was enforced exactly like `full`:
`_LEVEL_ALLOWS["edit"]` permitted every action while `LEVEL_IMPLIES["edit"]`
omitted configure. The write path accepted `edit` on a module where the role
grants configure, and configure stayed allowed — an administrator removing
configuration rights got no change and no warning. `edit` and `view` now
derive their enforcement from `LEVEL_IMPLIES`, `admin_tools.LEVELS` is read
from the same dict, and `test_the_two_level_tables_cannot_drift` fails if the
tables part again. `full`, `hidden` and `no_access` stay explicit, each with
its reason written at the definition.

**`hidden` — kept, and not surfaced in `/api/auth/me`.** That was the
suggested consumer, and it turned out not to be one. Core draws no module
navigation: its launcher shows applications, and the only use of
`hides_from_nav` in Core's frontend is a chip on the tool-rules matrix. The
navigation that shows modules is Engineering Tools' tab bar, which cannot read
Core's `/me` — CORS is closed and never allows credentials. A `/me` field would
have been a second decorative thing, and computing it correctly means
resolving every module without calling `can()` per module (#7), which is the
in-memory resolver arriving early.

The reader is the product. Under option b1 (#11) the token carries the
organisation's tool rules for the audience application, and the product applies
`HIDES_FROM_NAV` to its own navigation from them. Removing `hidden` now would
design the claim shape without it and force a token-format change to put it
back.

**What stays true until then:** Engineering Tools holds no token yet, so
`hidden` still hides nothing in the product. The difference is that the gap is
now owned — it closes with the OIDC client — and the screen states what the
level does ("removed from navigation; the API still answers").

**For the OIDC client:** drop a module from navigation when any tool rule on
the grants that win `module:view` is in `HIDES_FROM_NAV` — the same tie-break
as step 5 of `can()` (#12). Deciding "hidden" by a looser rule than the one
`can()` uses would be a second engine.

---

## 4. Are projects shared across applications, or private to each?

**Status:** carried from Prompt 1 §12. Still open, still deliberately unresolved.

If project `P-2291` in Engineering Tools is the same project as `P-2291` in
Timesheet, the project registry belongs in Core. If each application has its
own unrelated notion of a project, they stay local.

Nothing has been built that presumes either answer:

* there is **no `projects` table**;
* `user_roles.scope_id` is an opaque `String(120)`, **not** a foreign key.

One visible consequence today: the seeded test engineer holds `employee` at
**application** scope rather than project scope, because there is no project
registry to name. And `accounts._administers` lets an application-scoped lead
grant at project scope without being able to check *which* projects belong to
their application — that check needs writing the moment projects exist.

---

## 5. Session revocation is bounded by cookie lifetime

**Status: resolved in Prompt 9a — sessions are recorded on the server and can
be revoked.** Settled because #19 made it matter: one cookie now opens every
app, so "valid until it expires" would have meant every app.

**What replaced it.** A `sessions` row per sign-in. The cookie carries a
256-bit random session id; the row stores only its SHA-256. The row is the
authority — the guard, `/api/auth/*` and (from run 2) the gate all ask
`sessions.resolve()`, and no valid row means not signed in, whatever the
signed cookie says.

* **Lifetime:** 10 hours absolute, 2 hours idle — `SESSION_ABSOLUTE_HOURS` and
  `SESSION_IDLE_MINUTES`, replacing the old fixed 12 hours. Ten covers a
  working day; the idle limit is what makes a browser left signed in on a
  shared machine stop working within two hours of the last click. The idle
  clock is pushed forward at most once a minute per session, so a busy page
  is not a write per request.
* **Revoked on:** sign-out (that session); a person changing their own password
  (every session, and a new one is started for the browser that did it — the
  same thing as "every other session", with the fixation defence included);
  an administrator's reset, a suspension, and "sign out everywhere"
  (`POST /api/admin/users/{id}/sessions/revoke`) — every session. Deleting a
  person deletes their rows by `ON DELETE CASCADE`, which is the same outcome:
  no row.
* **Swept on write:** a sign-in deletes rows that ended more than a day ago.
  The day is kept so a refusal can still say *expired* rather than *never
  signed in*. No scheduler.

What follows is the entry as it stood before.

**Original status:** inherited property of signed-cookie sessions, which
Prompt 1 specified. Worth knowing, not currently wrong.

There is no server-side session store, so an individual session cannot be
revoked. A cookie copied before logout stays valid until it expires (12h).

Mitigations already in place: the cookie is `httponly`, `samesite=lax`,
`secure` on Render, and the guard re-reads the user on every request — so
**suspending an account cuts it off on the next call**, which is the practical
kill switch. Rotating `SESSION_SECRET` signs everybody out at once.

**To settle, if it ever matters:** a `session_epoch` column on `users`, bumped
on logout and password change, checked by the guard. That is a schema change,
so it wants doing alongside another migration rather than on its own.

---

## 6. Rate limiting keys on the socket address, which is a proxy on Render

**Status:** needs verifying after the first deploy.

Login is rate limited per IP via `slowapi`'s `get_remote_address`, which reads
the socket peer. Behind Render's proxy that is an internal address shared by
every visitor, so the per-IP limit behaves as a **global** limit — 10 attempts
a minute across the whole company, which would lock everyone out at 9am.

The audit writer already prefers the first `X-Forwarded-For` hop, which is
client-supplied and therefore spoofable.

**To verify after deploying:** sign in, then read `audit_logs.ip`. If it shows
your real public address, forwarding works and only the limiter needs its key
changing. If it shows a `10.x` address, both need it.

---

## 7. Screens must not call `can()` per cell — a rule, not a fix

**Status:** a constraint to hold to, deliberately not a code change.

`can()` resolves **one permission per call** and makes **8–9 queries** doing
it. Measured:

| | queries |
|---|---|
| one `can()` call, cold session | 9 |
| one `can()` call, warm session | 8 |
| a 16-cell module × action matrix, one user | **116** |
| the same for 50 users | **~5,800** |

There is no bulk API, and **none is being built yet**, on purpose. The
expensive path is not on any hot surface: the admin screens render from a
bulk read of `role_permissions`, not from `can()` per cell, so the N+1 this
invites is not currently firing anywhere. Building a batch API now would be
optimising something nothing calls at scale.

**The rule instead:**

> Screens bulk-read permissions for rendering. `can()` is for enforcement —
> one call per action actually being authorised, not one per thing displayed.

`require_permission(key)` on an endpoint is correct and costs one `can()`.
A grid that calls `can()` once per toggle is not, and is the thing this note
exists to prevent.

**When to build the bulk API:** the first screen that genuinely needs a
person's whole effective permission set — most likely a per-user override
view, or the product navigation honouring `hidden` (see #3). At that point
the shape is "give me this user's effective set for this application in one
pass", resolved in memory from three reads, exactly as `_apps_payload` now
does for entitlements.

**Already fixed, for contrast, because these *were* on the hot path:**

* `GET /api/auth/me` went from **22 queries to 8** — it called `entitled()`
  per application, and each re-read the application, its subscription and the
  licence. Every page load hits this endpoint.
* Every guarded request now reads the user **once** instead of twice. The
  guard parks its session and the resolved user on the request; the route
  dependency reads them back. Sharing the session alone was not enough —
  SQLAlchemy's identity map holds weak references, so the guard's local going
  out of scope let the entry be collected and the route re-queried. The
  instance has to be held deliberately.

---

## 8. The third interstitial state should be an enum, not a third boolean

**Status:** decided in advance. Do not act on it yet.

The guard now enforces "authenticated, but not yet allowed through" states,
which is the right place for them. There are already **two**, by two different
mechanisms:

| State | Stored as | Guard behaviour |
|---|---|---|
| suspended | `users.status = 'suspended'` | 401, session cleared |
| password must change | `users.must_change_password` bool | 403 on everything but `/api/auth/*` |

Two mechanisms for one class of state is tolerable. Three is not, and the
third is foreseeable: **MFA enrolment** is the likely one given enterprise
clients, and "has not accepted updated terms" is the other candidate.

**The decision, made now so it happens at the right moment:**

> When a third interstitial state arrives, fold `must_change_password`,
> suspension and the new state into a single `account_state` the guard
> checks. **Do not add a third boolean.**

Deliberately not done today: it works, MFA is not on the table, and a
speculative refactor is its own kind of premature. The trigger is written
down so the refactor happens one state early rather than one state late —
the point at which it stops being a rename and starts being archaeology.

**Note for Screen 004:** an audit row with nobody to name now stores the
sentinel `(anonymous)` (a login attempt that supplied no address at all).
Render that as `—` in the ACTOR column rather than showing the sentinel.

---

## 9. The guard has one path exception. The second one means restructure.

**Status: the trigger fired in Prompt 6, and the restructure is done.** The
OIDC provider needed three new access shapes at once — a fully public JWKS, a
token endpoint authenticated by client credentials, and an authorize endpoint
that needs a session and every interstitial check. That is not a second
exception; it is three, and the line below was drawn for exactly this moment.

**What replaced the prefix checks.** `PUBLIC_PREFIXES`, `DOCS_PREFIXES`,
`ADMIN_PREFIX`, `ADMIN_READER_PATHS` and `APP_PREFIXES` are gone as sources of
truth. `guard.ROUTES` maps every route path, written exactly as the route
declares it, to one `Access` value, and `inspect()` reads that table instead of
branching on prefixes:

* **Default-deny.** A path under `/api`, `/oauth` or `/.well-known` with no row
  is refused with 404 — for a Global Admin as much as a stranger. Every other
  path is the SPA. (Before, an unmatched `/api/` path simply required a
  session, and a stranger got 401 for it.)
* **The table cannot drift from the application.** `test_guard_table.py` walks
  the registered routes and fails in both directions: a route with no row, or a
  row with no route. That answers the objection written at the bottom of this
  entry — a table of paths *is* a second copy of the routing table, so it is
  held to the first by a test rather than by care.
* **The audit exception is four rows**, `ADMIN_AUDIT_READ`, and
  `ADMIN_READER_PATHS` is now derived from them. `may_read_audit()` and its
  tests are unchanged.
* **The order of checks is unchanged** for every route that needs a person:
  session, active account, `must_change_password`, route access, CSRF.
* **No `PRODUCT` access kind.** `APP_PREFIXES` mapped Engineering Tools' URL
  prefixes to entitlement, but no Core route has ever matched them. Under b1
  (#11) the product enforces its own entitlement from the token's `aud` and
  `entitled` claims, so a product kind here would be enforcement for routes
  Core does not serve. Its content — which product each prefix belongs to — is
  the `aud` the token carries.
* **Access kinds arrive with their first route.** Two more came with the OIDC
  provider. `CLIENT_CREDENTIALS` (`/oauth/token`): no session is read and no
  CSRF header asked for — the caller is a service, which the route
  authenticates by its secret. `SESSION_PAGE` (`/oauth/authorize`): every check
  a session route gets, but a refusal redirects the browser to
  `/?next=<that exact request>` instead of returning JSON, and the SPA follows
  `next` only to `/oauth/authorize` on the same origin. Chosen over a JSON
  refusal and over an error page, so someone arriving from Engineering Tools
  signs in — or changes an administrator-set password — once, and lands back
  where they were going.

**Why a table rather than a marker on each route**, which is what "what
restructure means concretely" below proposed: the brief that fired the trigger
asked for one explicit table, and the two-way test removes the drift that made
a table unattractive. A reader who wants to know what any route requires reads
one file.

What follows is the entry as written before the trigger fired.

**Original status:** a line drawn in advance. The exception itself is fine;
the second one is the problem, and it will not look like a problem when it
arrives.

`guard.inspect()` is one rule: **everything under `/api/admin/` requires
Global Admin**. It now has exactly one exception:

```python
ADMIN_READER_PATHS = frozenset({
    "/api/admin/audit", "/api/admin/audit/stats",
    "/api/admin/audit/controls", "/api/admin/audit/export",
})
SAFE_METHODS = frozenset({"GET", "HEAD"})
```

A Business & Commercial Lead may reach those four audit **reads** — GET or
HEAD only — and the endpoint checks again and scopes the query to the
applications they lead. Two independent checks, as everywhere else.

It is an **exact list, not a prefix**. It began as `startswith`, which would
have handed the exception to anything mounted under `/api/admin/audit/`
later — a retention endpoint, a purge, a per-actor drill-down — without
anyone deciding it should have it. Adding a path now means a deliberate line
in `guard.py`, which is the only form of "deliberate" that survives someone
who has not read this file. `may_read_audit()` is separated out so a test
can ask the question directly rather than reading the middleware.

**Why it exists.** Screen 004 was specified to give Business Admins
application-scoped audit visibility, but the guard and `require_global_admin`
both refused them entry. The two bad options were building scoping nothing
could reach (see #3, the same mistake) or quietly widening admin access to
make it reachable (a security regression dressed as a feature). This is the
narrow third: reachable, minimal, and checked twice.

**The decision, made now:**

> The guard is currently **one rule with one exception**. The second exception
> is the point at which it stops being a rule and becomes a policy table.
> When you reach for a second one, **stop and restructure**: replace the
> prefix checks with an explicit per-route access declaration, so what each
> route requires is stated at the route rather than inferred from a growing
> list of string prefixes in the middleware.

Write it down because **the second exception will look exactly as justified
as this one did.** Each will be defensible on its own terms; the cost is only
visible in aggregate, by which point the middleware is a place people are
afraid to change. A pre-committed line is the only defence against that kind
of drift, because the drift never announces itself.

**What "restructure" means concretely:** the access requirement moves onto the
route — a dependency or a declared marker the guard can read — and
`guard.inspect()` asks the route what it needs instead of pattern-matching
paths. The guard keeps its job (one check, before routing, fail-closed); it
stops keeping a second copy of the routing table.

---

## 10. Every control card must stay derived, not asserted

**Status:** a habit to hold, with the moment it usually breaks written down.

Two screens report the system's own state back to an administrator:

* **004** — the active security controls strip;
* **003** — Identity Provider, Provisioning Mode, Default Access Policy.

Both are honest today because each card is **derived** rather than typed:

| Card | Read from |
|---|---|
| Audit is append-only | `pg_trigger` — asked of the database |
| Sign-in rate limited | `router_auth.limiter.enabled` |
| Lockout after N failures | `router_auth.LOCK_AFTER` |
| Minimum password length | `security.MIN_PASSWORD_LENGTH` |
| Identity Provider | presence of `ENTRA_TENANT_ID` / `ENTRA_CLIENT_ID` |
| Provisioning Mode | follows from the above |
| Default Access Policy | the lowest-privilege role in the database |

Two on 004 — CSRF, and the per-request account re-read — are asserted `True`
with a file reference, because they are structural rather than configurable.
That is honest now and is the crack to watch: a card that says `True` because
someone believed it is indistinguishable, on screen, from one that says
`True` because it asked.

**The rule:**

> When a control becomes configurable, its card becomes derived **in the same
> change**. Never leave a card asserting what is now a setting.

A security card that claims a protection the running system does not have is
the most dangerous kind of fabrication in the panel, because it is the one an
administrator relies on when deciding they are safe. The append-only card
reporting **off** on SQLite, with the reason, is the shape all of them should
keep.

---

## 11. How does a separated Engineering Tools enforce anything? — decided: b1

**Status:** decided before the OIDC layer was built; Core's side was built in
Prompt 6 — `resolution.py`, the database-free engine; `permissions.load()`; the
signing key and JWKS (#15); `/oauth/authorize`; `/oauth/token`; a token that
lives fifteen minutes (#16). The token carries the *inputs* to the permission
decision, and the product re-runs the resolution itself. Not yet built: the
client side. Engineering Tools does not verify a token or resolve from its
claims.

**Superseded for same-domain apps by #19.** Every app under mirageaec.com is
now signed in by a shared cookie and checked by Core's gate on each request,
and the gate sends the *answer* — the b2 shape rejected below. #19 says why
that is acceptable today and what happens when project scopes arrive. This
entry, the OIDC provider it describes, and the vendored engine (#18) remain
the design for any app that cannot live under mirageaec.com. The provider is
dormant, not deleted.

**The problem, as it stood.** Every enforcement path takes a live `Session` on
the identity database: `can()`, `entitled()`, `is_global_admin()`,
`holds_business_admin()`, and the guard's `inspect()`. After the split Core
and the product share nothing, and the guard block that enforces entitlement
on `/api/hapext/`, `/api/airsizer/` and `/api/rebadge/` — the only entitlement
enforcement those routes have — is in Core, which does not host them. See
`EXTRACTION-LOG.md` finding 6b.

The set that has to change shape is smaller than "every enforcement path":
`entitled()`, `active_roles()` with `_covers()`, `can()`, the per-request
account re-read in `load_user()`, the guard's entitlement block, and
`audit()`. Everything else that takes a session is administration, and
administration stays in Core.

**Rejected — (a) a copy of `identity/` in each product, connected to the
identity database.** The extracted code would live in two repositories and
drift from the first hotfix, and a product would hold credentials to the
identity store, which the topology says applications must never touch. Every
further application repeats both costs.

**Rejected — (b2) the token carries the answer.** Core resolves and emits an
effective allow-set. The product code would be trivial, and it fails twice:

* **It cannot resolve at a scope learned at request time.** Core resolves
  before it knows which project a request concerns. A Business Admin allocates
  projects and a Project Lead runs one, so a project id in a URL is a planned
  requirement, not a hypothetical (#4). b2 works today only because nothing
  yet passes a scope other than the default.
* **It is two engines, one of them degenerate.** Deny beats allow, most
  specific wins, tool rules only narrow, and the equal-specificity decision in
  #12 would all live on Core's side only — the thing this entry pre-committed
  against.

**Token size is not the objection people expect.** Measured against the local
database in Prompt 6, for today's seeded Global Admin and engineer — one grant,
16 role permissions, no tool rules — the claims are a 1.2 KB payload and the
signed token 2.05 KB. A heavy but plausible person — four roles, every
engineering permission on each, a tool rule on every module for every role —
is a 5.2 KB payload and a 7.3 KB signed token. That last figure is over a
browser's 4 KB cookie limit, which is exactly why the product holds the token
server-side in its own session and never in a cookie. Held there, size does
not matter.

**Decided — (b1) the token carries the inputs.** For its audience application
only:

| Claim | Stands in for the read of | Why it has to be there |
|---|---|---|
| `aud` | `applications` by key | a token for Engineering Tools is refused by Timesheet |
| subject and organisation | `users` | the account the decision is about |
| entitlement: organisation active, subscription in date, seat held | `organizations`, `subscriptions`, `user_licenses` | step 1 — organisation status is an input since #14 |
| grants in force: role id, level, scope type, scope id, expiry | `user_roles`, `roles` | steps 2–3 — **role identity is required**: tool rules key on `role_id`, and the tie-break needs each grant's tier |
| role permissions for that application: allow or deny, per role and permission | `permissions`, `role_permissions` | step 4 |
| the organisation's tool rules for that application, per role and module | `tool_rules` | step 5, and navigation — `hidden` is read from here (#3) |
| `permissions_version` | — | how a product learns its claims are stale |

The product re-runs the same five steps in memory. **One engine, two sources,
never two engines:** the resolution should be one pure function over those
inputs, fed from rows by `can()` and from claims by the product, so that no
tie-break is ever implemented twice. Splitting `can()` into "load the inputs"
and "resolve them" is the first piece of the OIDC work, not a later cleanup.

**Freshness — the trade, made deliberately.** Today a suspension or a revoked
seat bites on the very next request. A token with any lifetime gives some of
that up. It is bounded three ways:

* Core refuses to mint a token for an inactive account or a suspended
  organisation;
* the token's lifetime is the longest a revoked access can outlive its
  revocation in a product — **not chosen yet**; set it with the OIDC layer,
  as the answer to "how long after I suspend someone";
* `permissions_version` is bumped by every change to a person's access — role
  grant or revoke, account status, licence assign or remove, role permission
  edits, and tool rules set **or cleared** (#13) — so a refresh can tell a
  stale token from a current one by comparing a number.

**Still open under b1:** how a product writes to the audit trail, since
`audit()` is Core's; whether a product ever needs admin-ness (probably not —
administration stays in Core); and automated key rotation, which is manual for
now (#15). Settled since: the token lifetime and the absence of refresh tokens
(#16), and PKCE for confidential clients (#17).

**Settled first, so the claims are built on a stable engine** (Prompt 5):
`edit` is enforced as it claims (#3); a rejected tool-rule batch writes nothing
and a cleared rule bumps the version (#13); a suspended organisation holds
nothing (#14). Each would otherwise have been inherited by the claims, or
silently dropped from them.

---

## 12. Tool rules at equal specificity — decided, revisit deliberately

When two role grants tie at the top specificity tier and both allow, a
`no_access` tool rule on **either** refuses — even though the other grant
carries no restriction. So **gaining a role can take access away**: someone
with full access to a module, later also granted a role restricted from it at
the same scope, loses the access they had.

**Decided: the restrictive rule wins.** For consistency with the tie-break
one step earlier, where deny already beats allow at equal specificity. An
engine whose two tie-breaks disagree is worse than one whose single tie-break
is occasionally surprising.

Named in code at `permissions.py` step 5 and pinned by
`test_a_no_access_rule_on_one_tied_role_refuses_for_both`.

**The coherent alternative**, if the surprise proves worse in practice than
the inconsistency: read a tool rule as narrowing *the grant it attaches to*
rather than the request, so the permission is allowed if any tied grant
survives its own rule. That is a privilege-widening change — it must be a
deliberate migration with the test renamed to assert the opposite, never a
quiet loosening because someone reported the surprise as a bug.

**Worth doing either way:** screen 002 can see this case at configuration
time and say so, which is cheaper than anyone diagnosing it from the symptom.

---

## 13. A refusal commits on its own only when nothing else is pending — decided

**Status:** decided in Prompt 5, after a batch endpoint broke it.

`audit()` commits by default, and it commits *the session*, not the row. The
guard, the dependencies and the route share one session per request (#7), so
"commit this refusal" means "commit everything this request has written so
far". At almost every refusal site that is harmless, because the refusal comes
before any write. It was wrong at three:

| Site | What was pending | Reachable |
|---|---|---|
| `admin_tools.put_tool_rules` | earlier changes in the same batch | **yes** — a batch whose second change overreached committed the first and still answered 409 |
| `admin_roles.patch_role` | the rename, and earlier permission changes | no — Global Admin only, and one never refuses |
| `accounts._refuse` under `grant_role(commit=False)` | the caller's unit of work: the CSV import's created people | no — the import is Global Admin only, and `may_grant` never refuses one |

**The rule:**

> Check everything before writing anything. A refusal that happens before any
> write may commit its own audit row. A function that takes `commit=False`
> passes it to its refusal audits as well: the caller owns the transaction,
> rolls it back on the exception, and the refusal row goes with it.

`put_tool_rules` and `patch_role` now validate before they write — the
`plan()` / `apply()` shape `admin_import` already had. `put_tool_rules` also
collects every overreaching change into one 409, with one blocked audit row
each, so an administrator sees everything wrong with a set at once. A change
naming something that does not exist — an unknown application, role or module
— is still refused on the spot with no audit row: nothing was written, and
there is no rule to record. `accounts._refuse` and both of
`assign_license`'s refusals honour `commit`.

The other sixteen `audit()` calls that commit by default were each read, not
grepped: every one runs before its function or route has written anything.

**The cost accepted:** under `commit=False`, a refusal's audit row is lost when
the caller rolls back. A durable refusal record and the caller's
all-or-nothing cannot both win inside one transaction, and the caller's
atomicity does. A caller that needs the record writes it after its rollback.

**Fixed before merge:** clearing a tool rule did not bump its holders'
`permissions_version`, though setting one did. First filed as a nit, because
nothing reads the version today; under b1 (#11) it is a correctness bug. The
version is how a product learns its tool-rule claims are stale, so a clear
that does not bump leaves a removed rule enforced for the token's whole
lifetime with no signal — the same shape as the `edit` defect in #3, an
access-control change that silently does not take effect. Clearing an
existing rule now bumps its holders; clearing one that does not exist bumps
nobody. Pinned by `test_clearing_a_rule_bumps_the_holders_too`.

---

## 14. A suspended organisation holds nothing — decided

**Status:** decided and enforced in Prompt 5. Before it, `organizations.status`
had a CHECK permitting `suspended` and no reader anywhere, so suspending a
tenant did nothing at all.

| Who, in a suspended organisation | Applications | Admin panel | Sign in |
|---|---|---|---|
| any member | none | — | yes, to a launcher that says why |
| Business Admin | none | **refused** — the audit-read exception is tenant-scoped | yes |
| Global Admin | none | **kept** | yes |

**Enforced in** `permissions.organization_active()`, which is read by:

* `entitled()`, before the subscription window — so `can()` and the guard's
  product block inherit it;
* `holds_business_admin()` — the guard's audit-read exception;
* `admin_audit.require_audit_reader` — the endpoint's own second check, which
  now asks the guard's question rather than restating it;
* `router_auth._apps_payload`, which resolves entitlement in bulk for
  `/api/auth/me` and would otherwise disagree with `entitled()`.

It bites on the next request, by the same per-request re-read that makes a
person's suspension immediate. No migration: the column and its CHECK already
existed.

**Why the Global Admin keeps the panel.** It is a platform role, not a tenant
one — the seed describes it as spanning every organisation — and it is the
person who would restore the account. Locking them out of the only place that
could do it is the foot-gun. They lose the applications like everyone else,
because entitlement is the commercial lever, and holding a platform role does
not make a suspended tenant's access paid for.

**Why members can still sign in.** The login endpoint deliberately says nothing
about *why* a sign-in failed, so refusing it would tell someone whose
organisation's access lapsed that their password is wrong. Signed in, they get
an empty launcher with one line saying the organisation is suspended.

**Nothing is removed.** Subscriptions stay in date, seats stay assigned, roles
stay granted. Setting `status = 'active'` restores everything on the next
request.

**For the token (b1):** organisation status is an input to `entitled()`, so it
is an input to the decision the token reproduces. The simplest shape is that
Core refuses to mint a token for a suspended organisation, and the token's
lifetime bounds how long an already-issued one outlives a suspension.

**Follow-ups, deliberately not built:**

* nothing sets `status = 'suspended'` — there is no admin surface, only SQL;
* `accounts.assign_license` still assigns seats in a suspended organisation;
  the seat does nothing until it is restored, but a screen could say so;
* `can()` and `/api/auth/me` each read one more row, the organisation — once
  per request, then served from the session's identity map.

---

## 15. Signing keys: the private half in the environment, the public half in the database — decided

**Status:** decided and built in Prompt 6.

**The private key lives in `OIDC_PRIVATE_KEY`, never in a table.** Three
reasons: Render's `generateValue` cannot make an RSA key; every instance must
sign with the same key; and a private key in a table is one SQL injection from
being read. On Render a missing key refuses to start, raised inside the
accessor `main.py` calls at import — the same shape, and the same reason, as
`SESSION_SECRET`. Locally an absent key means an ephemeral one, generated per
process and logged as such. Tokens it signed stop verifying at a restart, and
the previous throwaway is retired rather than published forever.

**The public half lives in `signing_keys`**, upserted at startup and again
before any token is signed, so Core can never issue a token whose key JWKS does
not publish. JWKS serves every `active` row. `active` means *published*, not
*signing*: the table exists so a key can go on being published after it stops
signing, until every token it signed has expired.

**Key ids.** `OIDC_KEY_ID` when it is set, otherwise the key's RFC 7638
thumbprint. Verifiers cache keys by id, so an id already published with a
different key refuses to start (`SigningKeyConflict`), and a retired id cannot
sign again. New key, old id is the mistake a rotation most often makes; it is
caught at boot rather than surfacing as tokens that intermittently fail to
verify.

**Rotation, when it is needed** — not automated:

1. Generate a new key. Set `OIDC_PRIVATE_KEY` and a **new** `OIDC_KEY_ID`, and
   deploy. The new key signs and its row is added; the old row stays `active`,
   so tokens signed before the deploy still verify.
2. Once the token lifetime (#16) has passed, set the old row to `retired`.

There is no admin surface for step 2 — it is SQL, deliberately not built yet.

**Compromise** is rotation without the wait: retire the old row at once. Every
token it signed stops verifying immediately, which is the point.

---

## 16. Token lifetime: fifteen minutes, never past the subscription — decided

**Status:** decided and built in Prompt 6. **Applies only to the dormant OIDC
path since #19:** an app under mirageaec.com holds no token, and a revocation
reaches it on its next request through the gate, not within fifteen minutes.

In Core every request re-reads the account, so a suspension or a revoked seat
bites on the very next request. A token is a copy of the decision's inputs
taken at issue, and nothing in it changes when the rows do. Its lifetime is
therefore the longest a revocation can take to reach a product. That is the
trade, and this entry is where its size is chosen.

* **Fifteen minutes** (`tokens.TOKEN_TTL`). Long enough that a product is not
  back at Core on every page; short enough that "how long after I suspend
  someone does it take effect in Engineering Tools" has an answer an
  administrator can accept.
* **`exp` never exceeds the subscription's `valid_to`** when one is set, and is
  floored to the second so the cap cannot round past it.
* **`pv` is the freshness epoch.** It is `permissions_version` at issue, bumped
  by every change to a person's access, tool-rule clears included (#13). A
  product that compares it can learn its claims are stale before `exp`.
  Nothing compares it yet: that is the client side's work.
* **No refresh tokens.** When a token expires the product sends the person
  back through authorize. While Core's session lives, that is a redirect with
  no sign-in screen.

**If fifteen minutes proves too slow** for suspension, the shape is a shorter
token or a back-channel check of `pv` — not a longer token with a revocation
list bolted on.

---

## 17. PKCE: not required for confidential clients — decided, with a trigger

**Status:** decided in Prompt 6.

Engineering Tools is a confidential client. It has a backend, keeps its client
secret there, and exchanges the code server-to-server. PKCE exists to bind the
code exchange to the client that started the flow when that client cannot keep
a secret. Here the secret already does that, and the code is additionally bound
to the client, the redirect URI and the nonce, and lives thirty seconds.

**The trigger:** the first public client — a single-page app, a mobile app,
anything that would have to ship its secret to a person's device — needs PKCE
(S256) before it is registered. The token endpoint would then require a
`code_verifier` for that client, and `oauth_clients` would gain a client type.
Registering a public client without it is the mistake this entry exists to
prevent.

---

## 18. The shared engine is vendored, not packaged — decided, with triggers

**Status:** decided in Prompt 7, with step 1 of the Engineering Tools client.

#11 settled *what* a product runs: this engine, over a token's claims — one
engine, two sources, never two engines. It left open *how* the second
repository gets the engine.

**Decided: a byte-identical vendored copy, guarded by a published hash.**
`resolution.py` is copied into the product repository beside a copy of
`resolution.sha256`, and the product's suite fails when the two disagree.
Core's own suite fails if the engine changes and the published hash does not
(`test_resolution_hash_matches`), so the hash can never fall behind the file it
describes.

**Why not a package.** For a single product a package earns nothing and costs a
build, a version, a release step and somewhere to publish it — and it moves the
failure from "a test fails now" to "somebody forgot to bump a pin". A vendored
copy with a structural guard is the weight this codebase already puts on
invariants of this kind: the guard table, the `inspect.getsource` checks that
keep preview and commit on one code path, the scan that proves nothing updates
an audit row.

**What the guard cannot do.** The product cannot see Core's *current* hash. Core
changing the engine while nobody re-vendors it leaves the product's tests green
against the copy it already holds. Closing that needs something able to reach
both repositories at once.

**The triggers — either one:**

* **A third product needs the engine.** Three copies is where a copying ritual
  stops being reliable and a published package starts to earn its keep.
* **The two repositories share a CI.** Then promote the drift check from
  within-repo to cross-repo: fetch Core's `resolution.sha256` at that commit and
  compare, so a stale vendored copy fails instead of passing quietly.

Until then the update ritual lives where the copy does, in Engineering Tools'
`backend/maec_auth/README.md`: replace the file and its hash from Core, never
edit it in place.

---

## 19. Same-domain apps use a forward-auth gate, not the token handshake — decided

**Status:** decided in Prompt 9. Core's side is built across three runs: 9a
(revocable sessions, the shared cookie, CSRF on every session route), 9b (the
gate endpoint and the reference front doors), 9c (the launcher and sign-out).

(#19–#21 in the Engineering Tools repository are that repository's own entries;
the numbers are not shared.)

**The design.** Every MAEC One app lives under mirageaec.com, so:

* **One login cookie for every app.** Core's session cookie carries
  `Domain=.mirageaec.com` (`SESSION_COOKIE_DOMAIN`), and the browser sends it to
  every `*.mirageaec.com` app.
* **Every request is checked by Core.** Each app's front door — nginx
  `auth_request`, or a small middleware inside the app where there is no nginx
  of ours — asks Core: is this browser signed in, and may this person use this
  app? Core answers 200 with the person's identity and their permissions for
  that app, or 401 (not signed in) or 403 (not allowed).
* **Apps contain no login code.** No sign-in page, no handshake, no token
  verification, no session store. They read who the person is from headers
  the front door sets, and check a permission key.

**Why it replaced the handshake (#11).** Core's side of the handshake was built
and tested, but Engineering Tools' side never worked on the developer's
machine, and finishing it still needed refresh tokens, a Redis session store
and more handshake fixes — in every app, in every language.

**What it gains:**

* Removing access takes effect on the person's next request. The token design
  allowed up to fifteen minutes (#16).
* One sign-out ends every app: it revokes the server-side session (#5), and
  every app asks about that session on its next request.
* It works in any language. Timesheet's backend is Node; it needs a header
  read, not a port of the engine.
* Apps need no login, token or session code.

**What it costs:**

* **Core is in the path of every request, and fails closed.** If Core cannot
  answer, no app lets anyone in. That is the right failure for an access
  check, and it makes Core's availability every app's availability.
* **It only works for apps under the cookie's domain.**
* **Every request costs a check.** No cache in Core, because instant
  revocation is the point. Run 2 measures the cost; keeping hashed static
  assets out of the check is the obvious first saving, and is run 2's to
  decide.

**The cookie domain — decided: `.mirageaec.com`,** so no address changes.

* *Accepted cost:* the company website (Hostinger) and any other
  `*.mirageaec.com` host receive the cookie whenever a signed-in person visits
  it. A compromised website could record and replay it.
* *Mitigated by:* revocable server-side sessions (#5), a 10-hour lifetime with
  a 2-hour idle limit, and `HttpOnly`, so no script on any of those hosts can
  read it.
* *Alternative kept open until launch:* a dedicated zone such as
  `.one.mirageaec.com`, which the website would never see. Before launch,
  switching is DNS records plus one environment variable,
  `SESSION_COOKIE_DOMAIN`. After launch it is an address change for every user.

**Sibling subdomains are same-site.** `SameSite=Lax` does not stop a page on
another `*.mirageaec.com` host from sending a request with the cookie attached.
So every state-changing route in Core that relies on the session requires the
CSRF header — not only `/api/admin/*` (Prompt 9a, A3). **Open for run 2:**
each app's own state-changing routes face the same exposure, because the gate
will approve any request that carries the cookie. The cheap defence is for the
gate to refuse a mutating request whose `Origin` is not that app's own
`base_url`; whichever is chosen, it must be decided before an app with a
state-changing route goes behind the gate.

**It partly reverses #11.** The gate sends each app the *answer* — the
effective permission keys for that app, worked out by Core. That is option
b2, which #11 rejected because it cannot handle a permission that depends on a
project id known only at request time.

* *Acceptable today:* no project registry exists (#4), and no caller passes a
  scope other than the default.
* *When projects arrive:* a project-scoped action makes its own
  server-to-server call to Core's check with the project as the scope, and
  Core runs the same engine at that scope. Apps never re-implement the engine.
  Core still holds the one engine; it only answers in two shapes.

**The dormant OIDC provider.** `/oauth/authorize`, `/oauth/token`, JWKS and the
vendored engine (#11, #15–#18) stay in the codebase and keep their tests. They
are not used by same-domain apps. No refresh tokens are built for them.

**The trigger for waking it:** any app that cannot live under mirageaec.com — a
product sold to a client on their own domain, or a partner's service.
