# Joining MAEC One — the standard every app follows

This is for the developers of any app that signs people in through MAEC One
(Engineering Tools today, Project Management next, and whatever comes after).
It says what your app must do, and what MAEC One Core does in return.

**In one paragraph.** Core decides *who may open which part of your app*. Your
app decides *what they see inside it*. Every request your app serves asks Core
about the person first. Your app tells Core, when it starts, which parts
("features") it has. A Global Admin then switches each feature on or off per
role in Core's panel (Tool-Level Settings), and it takes effect from the
person's next click — no code change, no restart, on either side.

---

## 1. Ask the gate on every request

Use the gate client: copy `maec_auth/` from the Engineering Tools repository
(`HAP_engtool`) into your app. Do not write your own.

* **Every request goes through it.** On each request your server forwards the
  browser's cookie to Core (`GET /api/gate/check`) with your app's key and
  secret, and gets back who the person is, the permission keys they hold
  (`<app>:<feature>:<action>`) and `nav_hidden` — the features to leave out of
  your navigation. Nothing is cached: an administrator's change shows on the
  next request.
* **It fails closed.** If Core cannot be reached, or answers anything you do
  not expect, the request is refused. Never "let them in for now".
* A `401` answer means "send the browser to `login_url`". A `403` means no.

## 2. Feature keys

A *feature* is a part of your app a Global Admin can switch on or off for a
role — a screen, a section, a tool. Each one has a **key** and a **name**.

| | Rule |
|---|---|
| Key | `[a-z][a-z0-9_]{0,39}` — lowercase letters, digits, underscore; a letter first; at most 40 characters |
| New keys | `task<number>`, e.g. `task71`. Engineering Tools keeps its existing keys. |
| Permanent | A key is **never renamed and never reused** for something else. Once an administrator removes a feature, its key is retired and Core refuses it for ever. |
| Name | Display text only, e.g. "Project Lead". Change it whenever you like. |
| Actions | From a fixed list: `use`, `view`, `convert`, `export`, `configure`. Most features need only `use`. |
| Permission key | `<app>:<feature key>:<action>`, e.g. `projects:task71:use`. This is what the gate sends back. |

## 3. Write each key exactly once

Your app keeps **one** list of its features — `features.py` — with each key and
its name, written exactly once:

```python
# features.py — the only place a feature key is written
PROJECT_LEAD = Feature("task71", "Project Lead", actions=["use"])
TIMESHEETS   = Feature("task72", "Timesheets",   actions=["use", "export"])
```

Everything else refers to that one definition, never to the key's text:

* backend routes: `@maec_feature(F.PROJECT_LEAD)`;
* frontend: `<Feature id={F.PROJECT_LEAD}>…</Feature>` — the frontend gets the
  list from your backend, or from one file generated from `features.py`.

Ship a test that fails if a key's text appears anywhere else in your app. Core
never contains your keys at all — it has its own test for that.

## 4. Every route is marked, or common

Each route either carries a feature marker (`@maec_feature(...)`) or is listed
as *common* — the few every signed-in person may reach, such as health and
`/me`. **Anything else is refused.** A route someone forgot to mark must fail
safe, not open.

## 5. Each feature stands on its own

Each feature must work — or be cleanly hidden — with **any other feature
switched off**. A switched-off feature is both hidden (`nav_hidden`) and blocked
(its key is missing from the person's permissions).

Ship a test that switches each feature off in turn and checks the rest of the
app still works.

## 6. Tell Core your features when you start

At startup, your app sends its whole feature list to Core. Run it in the
background: **never block startup on it**, and retry with a back-off if Core
is down — Core keeps everything it already knows in the meantime.

```http
PUT /api/gate/features
X-MAEC-App: projects
X-MAEC-Gate-Secret: <your app's gate secret>
Content-Type: application/json

{
  "app_version": "93e6aee",
  "features": [
    {"key": "task71", "name": "Project Lead", "actions": ["use"]},
    {"key": "task72", "name": "Timesheets",   "actions": ["use", "export"]}
  ]
}
```

* `app_version`: optional, at most 64 printable characters — your commit or
  release, so the panel can show which version last reported.
* `features`: the **whole** list, every time, at most 200, no key twice.

Answers:

| Status | Body | Meaning |
|---|---|---|
| `200` | `{"registered": 2, "new": 1, "not_reported": 0}` | Applied. `new`: features Core had not seen. `not_reported`: features Core knows that this list leaves out. |
| `422` | `{"detail": "<what is wrong>"}` | The whole report was refused — nothing was applied. Fix and resend. Includes a retired key: `"task71 was retired on 2026-10-17 and can't be reused; use a new key."` |
| `403` | `{"reason": "bad_app", ...}` | Wrong app key or secret. |
| `429` | `{"reason": "too_many_failures"}` | Too many wrong secrets from your address; wait a minute. A correct secret is never limited. |

Sending the same list again changes nothing. It is safe on every restart.

What Core does with it:

* **A new feature** appears in Tool-Level Settings as "*<App>* – *<name>*",
  marked **New**, switched **on for Global Admin only**, off for every other
  role. A Global Admin switches it on per role: Full Access then gives that
  role every action you reported for it except `configure` — configure stays
  with admin roles (Global Admin, Business & Commercial Lead).
* **A known feature** keeps every rule an administrator set; only its name
  follows your list.
* **A feature you stop sending** is never deleted. It is marked "No longer
  reported by the app". Only then can a Global Admin remove it — and its key is
  retired.
* Core shows, above your app's rows, when it last reported, the version, and
  how many features are new or no longer reported. Silence for over 24 hours
  shows in amber.

## 6a. Ask who holds a feature

When your app needs to offer a choice of people — for example a picker of who
may lead a project — ask Core who holds the feature, rather than keeping your
own copy of everyone's roles:

```http
GET /api/gate/holders?key=task2&action=use
X-MAEC-App: projects
X-MAEC-Gate-Secret: <your app's gate secret>
```

| Status | Body | Meaning |
|---|---|---|
| `200` | `{"core_user_ids": ["<uuid>", ...]}` | Active people with a seat on your app whose roles — including roles scoped to your app — allow `<app>:<key>:<action>`, decided exactly as the gate decides. Ids only: match them to your own users by the id the gate gives you (`user.id`). |
| `422` | `{"detail": "..."}` | `key` is not one of **your** app's reported feature keys (another app's key, a key you never reported, a bad key), or `action` is not one it reported. |
| `403` | `{"reason": "bad_app", ...}` | Wrong app key or secret. |

`action` defaults to `use`. The answer is never cached by Core: switching a
role off in Tool-Level Settings takes its holders out of the list at once.

## 7. Your own data rules still apply

Core decides **which sections** a person may open. Your app still decides
**which records** they see inside them — for example which projects someone
leads, or whose timesheets they approve. Keep those rules in your app.

To give one person a different role in your app than in another app, an
administrator uses User & Role Access with your app as the scope: the gate's
answer for your app then carries only that role's keys.

## 8. Going live — the checklist

1. **Added in Core, and its gate secret.** A Global Admin adds your app on
   the **Applications** screen (key, name, status, address); that also
   subscribes the organisation to it. Then, on the server, generate a secret,
   add `,<app>=<secret>` to Core's `GATE_SECRETS` and restart Core — the
   screen shows "Gate secret: Yes". Give the same secret to your app. The
   runbook's "Bringing a new application into MAEC One" has every command.
2. **Network.** Join the shared Docker network `maec_core_net` (external), and
   call Core at `http://maec-core:8000`. Use **your own subnet** for your
   stack's other networks and **your own host port**, not one already taken
   (Core 8001, Engineering Tools 8082 — check with `sudo ss -ltnp`).
3. **Address and status.** On the Applications screen, your app's address
   and status **Live**. Until it is live the gate refuses your app (it may
   still report its features). Retiring it later means status **Inactive** —
   applications are never deleted.
4. **Seats.** People need a seat on it (Users) and a role that reaches it
   (User & Role Access).
5. **DNS and Caddy.** An A record and a Caddy block for your host, proxying to
   your port.
6. **Start your app** and watch Tool-Level Settings: your features appear,
   New, on for Global Admin only. Switch them on per role.
