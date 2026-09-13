# Open decisions

Things deliberately left unresolved, with enough context to settle them later
without re-deriving the argument. Nothing here is a bug; each is a choice
waiting on a person — a designer, a manager, or a second application existing.

Add to this file rather than leaving a decision in a commit message or a chat
log, because that is where they get lost.

**Read 11 first.** It is the only one that blocks something: Engineering
Tools cannot become its own service until it is settled, and settling it
changes the shape of `can()`. The rest can wait as long as they like.

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

**Status:** a line drawn in advance. The exception itself is fine; the second
one is the problem, and it will not look like a problem when it arrives.

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

## 11. How does a separated Engineering Tools enforce anything? — blocking

Every enforcement path takes a live `Session` on the identity database:
`can()`, `entitled()`, `is_global_admin()`, `holds_business_admin()`, and the
guard's `inspect()`. That signature assumes Core and the product share a
process. They do today. After the split they share nothing, and the guard
block that enforces entitlement on `/api/hapext/`, `/api/airsizer/` and
`/api/rebadge/` is the only entitlement enforcement those routes have — and
it is in Core, which does not host them.

See `EXTRACTION-LOG.md` finding 6b for the full statement.

**Option (a): Engineering Tools keeps a copy of `identity/` and connects to
the identity database.**

Works on day one with no new machinery. Costs: the code just extracted into
one place now lives in two repositories and drifts from the first hotfix; and
a product holds credentials to the identity store, which the topology says
applications must never touch. Every future application repeats both costs.

**Option (b): Core mints a signed token; each product verifies it locally and
enforces from its claims.**

The design the architecture implies, and the one that scales to eight
applications. Nothing for it exists yet — no minting, no `aud`, no JWKS
endpoint, no client registration, no rotation. It also needs an answer for
freshness, because the current model's best property is that a suspension or
a revoked seat bites on the *very next request*; a token with any lifetime at
all trades some of that away, and how much is part of this decision.

**What is not in question:** `can()` stays the resolution engine. Under (b)
it grows a sibling that resolves from claims rather than rows, and the two
must share the tie-break rules — one engine with two sources, never two
engines.

**Settle this before Engineering Tools splits, not after.** Nothing signals
it in the meantime: the whole suite passes, because the tests and the engine
are on the same side of the split.

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

**Noticed, not changed:** clearing a tool rule does not bump its holders'
`permissions_version`, though setting one does. Harmless today — nothing reads
the version — but it will matter the day a token carries it.
