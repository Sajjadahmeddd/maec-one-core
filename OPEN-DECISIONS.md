# Open decisions

Things deliberately left unresolved, with enough context to settle them later
without re-deriving the argument. Nothing here is a bug; each is a choice
waiting on a person — a designer, a manager, or a second application existing.

Add to this file rather than leaving a decision in a commit message or a chat
log, because that is where they get lost.

**Read 11 first.** It is decided — option b1 — and it shapes everything the
OIDC layer builds: what the token carries, and why `can()` becomes one
resolver fed from two sources. The rest can wait as long as they like.

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

**Status:** inherited property of signed-cookie sessions, which Prompt 1
specified. Worth knowing, not currently wrong.

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
* **Access kinds arrive with their first route.** `CLIENT_CREDENTIALS` and
  `SESSION_PAGE` are added in the stages that add the token and authorize
  endpoints, not ahead of them.

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

**Status:** decided before the OIDC layer is built. The token carries the
*inputs* to the permission decision, and the product re-runs the resolution
itself. Engineering Tools can split on this basis; nothing for it exists yet —
no keypair, no JWKS, no client registration, no authorize or token endpoints.

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

**Still open under b1, for the OIDC work to settle:** the token lifetime and
refresh; how a product writes to the audit trail, since `audit()` is Core's;
key rotation; and whether a product needs admin-ness at all (probably not —
administration stays in Core).

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
