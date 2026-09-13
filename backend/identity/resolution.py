"""The permission resolution — steps 1 to 5, and nothing that touches a database.

    resolve(data, "engineering:hapext:convert", scope=("project", "P-2291"))

`data` is a `ResolutionInput`: everything the decision reads, gathered in
advance. Core builds one from rows (`permissions.load`); a product builds one
from the claims of a token Core signed (`from_claims`). Both then ask this
module the same question and get the same answer. One engine, two sources —
never two engines (OPEN-DECISIONS #11).

This module imports nothing beyond the standard library, on purpose. A
product imports it with no SQLAlchemy, no FastAPI and no database driver in
sight, and `test_resolve_imports_with_no_database_driver` proves it can.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("maec.identity")


def fail_closed(where: str, exc: BaseException) -> None:
    """Record that a refusal was caused by an error, not by a rule.

    Every `except` in the engine answers False, which is the right answer —
    an engine that cannot read its own data must not guess. But refusing
    silently makes a total outage indistinguishable from ordinary denial:
    a dropped connection, a migration mid-flight and a typo'd attribute all
    reach the user as "Sign in required", and the logs say nothing at all.
    These are the most load-bearing except blocks in the service and they
    were the quietest. Fail closed, and be loud about it.

    Only the first line of the message is kept, deliberately. SQLAlchemy
    appends `[SQL: ...]` and `[parameters: ...]` after a newline, and those
    carry whatever was bound into the statement — an address, a password
    hash. The first line is the driver's own reason, which is the part worth
    having and the part that is safe to write down.
    """
    reason = (str(exc).splitlines() or [""])[0].strip()[:200]
    log.warning("identity: %s failed closed — %s: %s",
                where, type(exc).__name__, reason)


# Higher number: more specific. Most specific wins.
SPECIFICITY = {"platform": 1, "organization": 2, "application": 3, "project": 4}

# What each level implies a role must already allow. The write path in
# admin_tools refuses a rule that promises more than the role grants.
#
# For the two levels that restrict — `edit` and `view` — this is also exactly
# what they permit at enforcement. `_LEVEL_ALLOWS` below derives from it rather
# than restating it, because the two tables once disagreed: `edit` omitted
# configure here and permitted it there, so an administrator who set `edit` to
# take configuration away got no change and no warning.
LEVEL_IMPLIES: dict[str, frozenset[str]] = {
    "full": frozenset({"view", "convert", "export", "configure"}),
    "edit": frozenset({"view", "convert", "export"}),
    "view": frozenset({"view"}),
    "hidden": frozenset(),
    "no_access": frozenset(),
}


def _permits_only_what_it_implies(level: str) -> Callable[[str], bool]:
    listed = LEVEL_IMPLIES[level]
    return lambda action: action in listed


# What each tool-rule level still permits. A rule can only ever narrow what
# the role already allowed — nothing here can turn a denial into a grant,
# which is structural rather than a check: this runs after the role has
# already decided, and it can only subtract.
#
# Three levels are special and stay explicit:
#
#   full       every action, including one added to the registry later. Not
#              derived from LEVEL_IMPLIES on purpose: that lists today's four
#              actions for the write-path check, and a module gaining a fifth
#              must not have its full-access rules quietly start refusing it.
#   hidden     the module is not offered in the navigation, but the API still
#              answers. Decluttering, not a boundary. Anyone who knows the
#              URL can still call it — which is the point: it is for tools a
#              team simply does not use, not for tools they must not reach.
#   no_access  the API refuses. This is the security boundary.
#
# `hidden` and `no_access` are NOT the same thing, and collapsing them is the
# mistake this table exists to prevent. `hidden` permits here and is filtered
# in the navigation; `no_access` denies.
_LEVEL_ALLOWS: dict[str, Callable[[str], bool]] = {
    "full": lambda action: True,
    "edit": _permits_only_what_it_implies("edit"),
    "view": _permits_only_what_it_implies("view"),
    "hidden": lambda action: True,        # UX only — see above
    "no_access": lambda action: False,    # the boundary
}

# Levels that take a module out of the navigation, whatever the API does.
#
# Core renders no module navigation — its launcher shows applications — so the
# reader of this is the product's own navigation. Under the token design the
# product receives the organisation's tool rules for its application and
# applies this set itself. See OPEN-DECISIONS #3.
HIDES_FROM_NAV = frozenset({"hidden", "no_access"})


def now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes; treat them as UTC."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


# ------------------------------------------------------------- the key
def split_key(permission_key: str) -> tuple[str, str, str]:
    """`app:module:action`, or ValueError. Three parts, no more, no less."""
    parts = permission_key.split(":")
    if len(parts) != 3 or not all(parts):
        raise ValueError(f"malformed permission key {permission_key!r}")
    return parts[0], parts[1], parts[2]


def app_of(permission_key: str) -> str:
    return split_key(permission_key)[0]


# ------------------------------------------------------------ the inputs
@dataclass(frozen=True)
class Grant:
    """A role held at a scope, as the decision needs it.

    `role_id` travels because tool rules are keyed on it; `role_key` travels
    because a product's navigation and its logs need a name a person reads.
    """
    role_id: str
    role_key: str
    scope_type: str
    scope_id: str | None
    expires_at: datetime | None = None

    def in_force(self, at: datetime) -> bool:
        return self.expires_at is None or _utc(self.expires_at) > at


@dataclass(frozen=True)
class ResolutionInput:
    """Everything one person's decisions about one application read.

    Scoped to a single application: `app_key` is the token's audience, and a
    question about any other application is refused rather than answered from
    rules that were never loaded.
    """
    app_key: str
    org_id: str
    # step 1, decided when the input was built: organisation active,
    # subscription in its window, seat held
    entitled: bool
    # the subscription's end, if it has one: an input used after this moment
    # is no longer entitled, however long its token claims to live
    entitled_until: datetime | None = None
    grants: tuple[Grant, ...] = ()
    # (role_id, permission_key) -> "allow" | "deny", for this application only
    role_permissions: Mapping[tuple[str, str], str] = field(default_factory=dict)
    # (module_key, role_id) -> access level, this organisation, this application
    tool_rules: Mapping[tuple[str, str], str] = field(default_factory=dict)


def covers(grant: Grant, org_id: str, app_key: str,
           requested: tuple[str, str | None]) -> bool:
    """Does this grant's scope reach the requested one?

    platform reaches everything. organization reaches everything in that
    organisation. application reaches that application and any project
    request made within it. project reaches that one project.
    """
    kind, ident = requested
    if grant.scope_type == "platform":
        return True
    if grant.scope_type == "organization":
        return grant.scope_id == org_id
    if grant.scope_type == "application":
        return grant.scope_id == app_key
    if grant.scope_type == "project":
        return kind == "project" and ident is not None and grant.scope_id == ident
    return False


# ------------------------------------------------------------- resolve()
def resolve(data: ResolutionInput, permission_key: str,
            scope: tuple[str, str | None] | None = None, *,
            at: datetime | None = None) -> bool:
    """May the person `data` describes do this thing, here? False on any doubt.

    `at` is the moment the question is asked, for grants and subscriptions
    that end. It defaults to now; tests pass it to prove an input stops
    counting when its grants do.
    """
    try:
        moment = at or now()
        app_key, module_key, action = split_key(permission_key)

        # An input answers for its own application only.
        if app_key != data.app_key:
            return False

        # 1. entitlement
        if not data.entitled:
            return False
        if data.entitled_until is not None and _utc(data.entitled_until) < moment:
            return False

        # 2. + 3. roles in force whose scope reaches the request
        requested = scope or ("application", app_key)
        if requested[0] not in SPECIFICITY:
            return False
        grants = [g for g in data.grants
                  if g.in_force(moment) and covers(g, data.org_id, app_key, requested)]
        if not grants:
            return False

        # 4. resolve: most specific wins; deny beats allow on a tie. Only a
        # grant whose role says something about this permission takes part.
        matches: list[tuple[int, str, Grant]] = []
        for grant in grants:
            effect = data.role_permissions.get((grant.role_id, permission_key))
            if effect is not None:
                matches.append((SPECIFICITY[grant.scope_type], effect, grant))
        if not matches:
            return False
        top = max(spec for spec, _, _ in matches)
        decisive = [(effect, grant) for spec, effect, grant in matches if spec == top]
        if any(effect == "deny" for effect, _ in decisive):
            return False
        allowing = [grant for effect, grant in decisive if effect == "allow"]
        if not allowing:
            return False

        # 5. tool rules may narrow what the winning roles allowed, never widen
        #
        # Decided, not incidental: when two roles tie at the top specificity
        # and both allow, a no_access tool rule on EITHER of them refuses.
        # The restrictive rule wins even though the other role carries no
        # restriction at all.
        #
        # The cost of that is real and worth naming, because it will be
        # reported as a bug one day: someone with full access to a module,
        # later also granted a role that is restricted from it at the same
        # scope, LOSES access by gaining a role. See
        # test_a_no_access_rule_on_one_tied_role_refuses_for_both.
        #
        # It is decided this way because the step immediately above already
        # settles a tie the same direction — deny beats allow at equal
        # specificity — and an engine whose two tie-breaks disagree is worse
        # than one whose single tie-break is occasionally surprising. The
        # coherent alternative is "allow if any tied grant survives its own
        # rule", which reads tool rules as narrowing the grant they attach to
        # rather than the request; it is written up in OPEN-DECISIONS.md.
        # Either is defensible. Only being undecided is not.
        for grant in allowing:
            level = data.tool_rules.get((module_key, grant.role_id))
            if level is None:
                continue
            allows = _LEVEL_ALLOWS.get(level)
            if allows is None or not allows(action):
                return False
        return True
    except Exception as exc:
        fail_closed("resolve", exc)
        return False


# ------------------------------------------------------------ the claims
def _iso(value: datetime | None) -> str | None:
    return _utc(value).isoformat() if value is not None else None


def _parse(value: str | None) -> datetime | None:
    return _utc(datetime.fromisoformat(value)) if value else None


def to_claims(data: ResolutionInput) -> dict[str, Any]:
    """The inputs as JSON-ready token claims. `from_claims` reads them back.

    Everything here is what `resolve` reads, and nothing it does not: a token
    that carried the answer instead would be option b2, which #11 rejected.
    """
    by_role: dict[str, dict[str, str]] = {}
    for (role_id, key), effect in data.role_permissions.items():
        by_role.setdefault(role_id, {})[key] = effect
    return {
        "aud": data.app_key,
        "org": data.org_id,
        "entitled": data.entitled,
        "entitled_until": _iso(data.entitled_until),
        "grants": [
            {"role": g.role_key, "role_id": g.role_id, "scope_type": g.scope_type,
             "scope_id": g.scope_id, "expires_at": _iso(g.expires_at)}
            for g in data.grants
        ],
        "role_permissions": by_role,
        "tool_rules": [
            {"module_key": module_key, "role_id": role_id, "access_level": level}
            for (module_key, role_id), level in data.tool_rules.items()
        ],
    }


def from_claims(claims: Mapping[str, Any]) -> ResolutionInput:
    """A ResolutionInput from verified token claims.

    Verify the signature, the audience and the expiry first; this reads
    claims, it does not decide whether to trust them.
    """
    return ResolutionInput(
        app_key=claims["aud"],
        org_id=claims["org"],
        entitled=bool(claims["entitled"]),
        entitled_until=_parse(claims.get("entitled_until")),
        grants=tuple(
            Grant(role_id=g["role_id"], role_key=g["role"], scope_type=g["scope_type"],
                  scope_id=g.get("scope_id"), expires_at=_parse(g.get("expires_at")))
            for g in claims.get("grants", [])
        ),
        role_permissions={
            (role_id, key): effect
            for role_id, effects in claims.get("role_permissions", {}).items()
            for key, effect in effects.items()
        },
        tool_rules={
            (rule["module_key"], rule["role_id"]): rule["access_level"]
            for rule in claims.get("tool_rules", [])
        },
    )
