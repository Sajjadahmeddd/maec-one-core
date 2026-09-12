# Extraction log

What it took to lift MAEC One Core out of `HAP_mirageaec` and stand it up
alone. Written while doing it, not afterwards.

**Verdict: the boundary held for Python, and broke for CSS and for tests.**

The backend was a pure copy — `backend/identity/` moved across untouched and
every module imported cleanly with the four product routers deleted. Nothing
in it reached for a HAP module, `deps.py`, or a product router. That part of
the discipline paid off exactly as intended.

The two places it did not hold are worth more than the part that did, and
neither would have failed a test in the original repository.

---

## 1. Files copied from outside `backend/identity/` and `frontend/src/maecone/`

| File | From | Why Core needed it |
|---|---|---|
| `frontend/src/maecone/screens.css` | `frontend/src/theme.css` (87 of 275 rules) | **See finding 2 — the significant one.** |
| `frontend/vite.config.js` | unchanged | Build config, shared infrastructure rather than either half's |
| `frontend/public/maec-logo.png` | unchanged | The only asset `maecone/` references |
| `frontend/public/favicon.png` | unchanged | Referenced by `index.html` |
| `.env.example`, `OPEN-DECISIONS.md` | unchanged | Repository furniture |
| `.gitignore` | **trimmed** | Carried the product's PyInstaller rules — `build/*`, `*.spec`, `installer.iss`, `output/`, `design-references/` — for directories Core does not have and a desktop bundle it will never produce. Reduced to Python, the Vite build and `.env`. |

Written fresh rather than copied: `backend/main.py`, `frontend/src/App.jsx`,
`frontend/src/main.jsx`, `frontend/index.html`, `package.json`,
`requirements.txt`, `pytest.ini`, `backend/alembic.ini`, `render.yaml`,
`README.md`.

---

## 2. `maecone/` depended on styles defined above it — the real finding

**The JavaScript boundary was complete. The CSS boundary did not exist.**

`maecone/theme.css` holds the Global Admin design tokens and every `.maec-*`
class. But the sign-in card, the launcher and the password-change gate use a
different vocabulary entirely:

    .signin  .signin-card  .signin-field  .signin-badges  .signin-footer
    .module-grid  .module-tile  .module-icon  .tone-blue …
    .launch-list  .launch-open  .launch-card  .launch-signout

Every one of those was defined in the **product's** `frontend/src/theme.css`,
above the boundary, because both halves shared one stylesheet.

**Nothing failed.** `npm run build` succeeded. The pages rendered. They
rendered *unstyled* — an unformatted list of eight links where the tile grid
should be. The only signal was the bundled stylesheet coming out at 10.9 kB
instead of 35 kB, which is the sort of thing you notice only if you look.

Resolved by extracting the 87 rules `maecone/` actually uses into
`maecone/screens.css`, together with the base element rules and the `:root`
design tokens they resolve against. `main.jsx` imports both stylesheets.

**What this means going forward:** a component directory is not self-contained
because its imports are. Styles, assets and CSS custom properties cross
boundaries silently, and no import graph shows it. If Core and the products
are to keep diverging visually, the shared vocabulary needs to become an
explicit thing — a package, or a deliberately duplicated file — rather than
an accident of both halves loading one sheet.

---

## 3. `main.py` — what was ambiguous

Three things were not clearly Core's or clearly Engineering Tools':

**`/api/health`** called `hapext_config()` and `airsizer_config()` from
`deps.py`. It reported that the HAP mapping and the AirSizer catalogs parsed
— Engineering Tools' readiness, answered by a shared process. Core has no
catalogs. Rewritten to report what Core's readiness actually is: whether the
identity database answers `SELECT 1`. It returns `degraded` rather than an
error string, so a health probe never leaks a connection string.

**`__version__`** came from `hap_converter`, the product's version number
standing in for the service's. Core now has its own, starting at `1.0.0`.

**The SPA catch-all** contained a path-traversal shape:

```python
candidate = FRONTEND_DIST / full_path      # full_path is attacker-controlled
if full_path and candidate.is_file():
    return FileResponse(candidate)
```

`dist / "../../.env"` resolves to a real file. Core's version resolves the
candidate and checks it is inside the bundle before serving it. **The original
still has this**, and this extraction was told not to modify that repository —
so it is recorded here rather than fixed there. It is worth fixing in
`HAP_mirageaec` separately.

---

## 4. Imports that broke when the product routers were removed

**None.** `backend/identity/` imported nothing from them. Deleting the four
`app.include_router(...)` lines and their imports left a working application.

---

## 5. Config and environment read from a shared location

**None that needed changing.** `identity/config.py` locates `.env` with
`Path(__file__).resolve().parents[2]`, which is the repository root at the
same depth in both layouts. `alembic.ini`'s `prepend_sys_path` likewise.

One addition: the original relied on a `conftest.py` at the repository root —
Engineering Tools' file, which incidentally put the root on `sys.path` for
Core's tests. Core now states that for itself in `pytest.ini`
(`pythonpath = .`).

---

## 6. Assumptions that Core and Engineering Tools share a process

This is the section that matters, because none of these fail a test — they
fail on the day the two are separate hosts.

### 6a. Three tests proved Core's guard using an Engineering Tools endpoint

`test_a_created_user_can_actually_sign_in`,
`test_removing_a_seat_takes_the_product_away_at_once` and
`test_suspending_someone_cuts_them_off_on_the_next_call` each asserted
Core's behaviour — the forced password change, seat removal, suspension — by
calling **`/api/airsizer/config`** and watching the status code change.

They were testing the right thing through the wrong door, and they passed
only because a product router was in the same process. In Core they fail
outright: the endpoint does not exist.

Rewritten against Core's own surface. Two now use `/api/admin/whoami`, where
the distinction is still visible and sharper than before — a suspended
account goes **403 → 401**, no longer merely un-privileged but no longer
signed in at all. The third asserts `entitled()` and `can()` directly,
because entitlement is the decision Core owns; watching a product endpoint
turn 403 was testing the *product's* enforcement of Core's decision.

### 6b. Core's guard still carries Engineering Tools' URL map

`guard.py` holds:

```python
APP_PREFIXES = {
    "/api/hapext/": "engineering",
    "/api/airsizer/": "engineering",
    "/api/rebadge/": "engineering",
}
```

Copied unchanged, deliberately — the brief asked for couplings recorded
rather than quietly patched, and this is the clearest one. In Core it is dead
configuration: no route matches any of those prefixes, so the entitlement
branch never runs.

It is not harmful, and it is misleading, which is its own cost. **The right
resolution is not to delete it but to decide where it belongs**: once
Engineering Tools verifies a Core-issued token, *it* enforces its own seat
requirement, using an entitlement claim in the token. That table is the
product's knowledge, sitting in Core because they used to be one process.

### 6c. The launcher cannot open anything

`applications.base_url` is `NULL` for every row, because until now the one
product was in the same process and the launcher opened it in place. Core
hosts nothing, so a tile with no URL is a tile that does nothing.

**This needs populating before Core is useful**: set `base_url` on the
`engineering` row to Engineering Tools' address. The model always intended
this — the column exists and `isOpenable()` already requires it — but the
value has never been needed.

---

## 7. Tests that failed in the new repository

193 → 202 passing, after six fixes. Five failures and one silent skip:

| Test | Cause |
|---|---|
| 3 in `test_admin_users.py` | Called `/api/airsizer/config` — finding 6a |
| `test_the_migration_installs_the_append_only_trigger` | `parents[1]` was the repo root only while tests lived at `<repo>/tests/` |
| `test_the_routes_are_read_only_in_the_source` | Same path assumption |
| `test_nothing_in_the_backend_updates_or_deletes_an_audit_row` | Its scan excluded tests **by accident** — they sat outside `backend/`. With the suite inside the package it caught its own `delete(AuditLog)` assertions. Now scoped to application code explicitly. |
| **9 skipped silently** | `test_postgres_integrity.py` located `.env` by `parents[1]`. Wrong path → no URL found → the whole module skips. **The most dangerous of the three**: a wrong path there does not fail, it quietly stops testing PostgreSQL. |

Paths are now derived from the package (`Path(backend.identity.__file__)`)
rather than counted upward from the test file, so moving the suite again
cannot repeat this.

---

## 8. Anything in `maecone/` referencing above itself

Only finding 2 (CSS). Every JavaScript import resolved inside `maecone/` —
the `../api` in `admin/*.jsx` is `maecone/api.js`. One asset,
`/maec-logo.png`.

---

## 9. What surprised me

**That the Python side was genuinely mechanical.** `backend/identity/` copied
across and worked. After six months of habits like "no cross-imports", it
would have been easy for one convenience import to have crept in. None had.

**That the CSS was invisible.** I expected the failures to be import errors,
which announce themselves. Instead the build passed, the app served, the
tests passed, and the login page was unstyled. If this extraction had been
done by copying and shipping rather than copying and *looking*, that is what
would have reached a client.

**That the tests encoded their own location.** Four separate tests knew where
they sat in the tree. Three failed loudly. One skipped silently and would
have reported a green suite with nine PostgreSQL tests quietly not running —
including the two that exist because SQLite could not catch a production bug.

**The honest summary**: the boundary discipline worked for the thing it was
written for — imports — and did not extend to the two things nobody wrote a
rule about. Neither would have been found by a test. Both were found by
assembling the thing and looking at it.
