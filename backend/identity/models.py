"""The identity schema.

Every table is created now, including the ones the Global Admin screens fill
in the next build, so there is one migration to reason about rather than a
trail of them. Conventions:

* UUID primary keys, timestamps with time zone;
* `org_id` wherever a row belongs to a tenant. A second customer is a data
  change, not a migration;
* enumerations are plain strings with a CHECK, not native enums — adding a
  value is then an ALTER of a constraint rather than a type migration;
* `user_roles.scope_id` is an opaque string, deliberately not a foreign key.
  Whether projects live in Core or in each application is undecided, and
  this column has to work under either answer (see the brief, §12).

`audit_logs` is append-only. Nothing in this codebase updates or deletes a
row, and the migration installs a database trigger that refuses to, so the
rule holds even for someone with a psql prompt.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON, Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer,
    String, Text, UniqueConstraint, Uuid, text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


def _pk() -> Mapped[uuid.UUID]:
    return mapped_column(Uuid, primary_key=True, default=uuid.uuid4)


def _created() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), nullable=False, default=now)


# ------------------------------------------------------------------ tenancy
class Organization(Base):
    __tablename__ = "organizations"
    __table_args__ = (
        CheckConstraint("status IN ('active','suspended')", name="ck_organizations_status"),
    )

    id: Mapped[uuid.UUID] = _pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    domain: Mapped[str] = mapped_column(String(253), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    created_at: Mapped[datetime] = _created()


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("org_id", "email", name="uq_users_org_email"),
        CheckConstraint("status IN ('active','suspended','invited')", name="ck_users_status"),
        CheckConstraint("email = lower(email)", name="ck_users_email_lower"),
    )

    id: Mapped[uuid.UUID] = _pk()
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(254), nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    department: Mapped[str | None] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    # Bumped on any change to this user's roles, licences or applicable tool
    # rules. Sessions carry the value they were issued with; a mismatch is
    # how a change takes effect in seconds rather than at cookie expiry.
    permissions_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Set when an administrator creates the account or resets the password.
    # Cleared once the person chooses their own, so an admin-known password is
    # never the one guarding the account long-term.
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = _created()
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    org: Mapped[Organization] = relationship()
    roles: Mapped[list["UserRole"]] = relationship(
        back_populates="user", foreign_keys="UserRole.user_id", cascade="all, delete-orphan")
    licenses: Mapped[list["UserLicense"]] = relationship(
        back_populates="user", foreign_keys="UserLicense.user_id", cascade="all, delete-orphan")


# ------------------------------------------------------------ the products
class Application(Base):
    __tablename__ = "applications"
    __table_args__ = (
        CheckConstraint("status IN ('live','coming_soon')", name="ck_applications_status"),
    )

    id: Mapped[uuid.UUID] = _pk()
    key: Mapped[str] = mapped_column(String(40), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(String(300))
    base_url: Mapped[str | None] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="coming_soon")


class Subscription(Base):
    """An organisation's right to an application, for a period."""
    __tablename__ = "subscriptions"
    __table_args__ = (
        UniqueConstraint("org_id", "application_id", name="uq_subscriptions_org_app"),
    )

    id: Mapped[uuid.UUID] = _pk()
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    application_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    seats: Mapped[int | None] = mapped_column(Integer)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=now)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    application: Mapped[Application] = relationship()


class UserLicense(Base):
    """One seat of a subscription, held by a person."""
    __tablename__ = "user_licenses"
    __table_args__ = (
        UniqueConstraint("user_id", "application_id", name="uq_user_licenses_user_app"),
    )

    id: Mapped[uuid.UUID] = _pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    application_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    assigned_at: Mapped[datetime] = _created()
    assigned_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"))

    user: Mapped[User] = relationship(back_populates="licenses", foreign_keys=[user_id])
    application: Mapped[Application] = relationship()


# ---------------------------------------------------------- authorisation
class Role(Base):
    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint("org_id", "key", name="uq_roles_org_key"),
    )

    id: Mapped[uuid.UUID] = _pk()
    key: Mapped[str] = mapped_column(String(60), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(String(300))
    # 1 is the top. Lower numbers administer higher ones.
    level: Mapped[int] = mapped_column(Integer, nullable=False)
    # NULL means a system role, shared by every organisation.
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    application_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("applications.id", ondelete="CASCADE"))
    is_custom: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    permissions: Mapped[list["RolePermission"]] = relationship(
        back_populates="role", cascade="all, delete-orphan")


class Permission(Base):
    """One thing that can be done. Keyed `app:module:action`, always three
    parts, so the application is derivable from the key alone."""
    __tablename__ = "permissions"
    __table_args__ = (
        UniqueConstraint("key", name="uq_permissions_key"),
    )

    id: Mapped[uuid.UUID] = _pk()
    key: Mapped[str] = mapped_column(String(120), nullable=False)
    application_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True)
    module_key: Mapped[str] = mapped_column(String(40), nullable=False)
    action: Mapped[str] = mapped_column(String(40), nullable=False)
    description: Mapped[str | None] = mapped_column(String(300))


class RolePermission(Base):
    __tablename__ = "role_permissions"
    __table_args__ = (
        CheckConstraint("effect IN ('allow','deny')", name="ck_role_permissions_effect"),
    )

    role_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)
    effect: Mapped[str] = mapped_column(String(10), nullable=False)

    role: Mapped[Role] = relationship(back_populates="permissions")
    permission: Mapped[Permission] = relationship()


SCOPE_TYPES = ("platform", "organization", "application", "project")


class UserRole(Base):
    """A person holds a role at a scope. The same role at several scopes is
    several rows — a lead of two applications has two of these."""
    __tablename__ = "user_roles"
    __table_args__ = (
        CheckConstraint(
            "scope_type IN ('platform','organization','application','project')",
            name="ck_user_roles_scope_type"),
        # platform has no id; every other scope needs one
        CheckConstraint(
            "(scope_type = 'platform' AND scope_id IS NULL) OR "
            "(scope_type <> 'platform' AND scope_id IS NOT NULL)",
            name="ck_user_roles_scope_id"),
        UniqueConstraint("user_id", "role_id", "scope_type", "scope_id",
                         name="uq_user_roles_grant"),
    )

    id: Mapped[uuid.UUID] = _pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    scope_type: Mapped[str] = mapped_column(String(20), nullable=False)
    scope_id: Mapped[str | None] = mapped_column(String(120))
    granted_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"))
    granted_at: Mapped[datetime] = _created()
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="roles", foreign_keys=[user_id])
    role: Mapped[Role] = relationship()


class ToolRule(Base):
    """A per-organisation adjustment to what a role may do with one module.
    It can only take away: nothing here grants what the role did not allow."""
    __tablename__ = "tool_rules"
    __table_args__ = (
        CheckConstraint(
            "access_level IN ('full','edit','view','hidden','no_access')",
            name="ck_tool_rules_access_level"),
        CheckConstraint("status IN ('active','controlled')", name="ck_tool_rules_status"),
        UniqueConstraint("org_id", "application_id", "module_key", "role_id",
                         name="uq_tool_rules_target"),
    )

    id: Mapped[uuid.UUID] = _pk()
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    application_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    module_key: Mapped[str] = mapped_column(String(40), nullable=False)
    role_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    access_level: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now, onupdate=now)


# --------------------------------------------------- filled by Prompt 2
class ProvisioningMap(Base):
    """A directory group, and what arriving in it confers.

    One row per group per organisation, enforced: two rows for the same group
    would confer two roles and nothing would say which wins. "There should
    only be one" guaranteed by nothing is how the audit_logs foreign key went
    wrong, so it is a constraint.
    """
    __tablename__ = "provisioning_map"
    __table_args__ = (
        UniqueConstraint("org_id", "directory_group",
                         name="uq_provisioning_map_group"),
        CheckConstraint("status IN ('active','disabled')",
                        name="ck_provisioning_map_status"),
    )

    id: Mapped[uuid.UUID] = _pk()
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    directory_group: Mapped[str] = mapped_column(String(200), nullable=False)
    role_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    default_modules: Mapped[list | None] = mapped_column(JSON)
    approval_type: Mapped[str | None] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")


class ImportBatch(Base):
    __tablename__ = "import_batches"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','success','warnings','failed')",
            name="ck_import_batches_status"),
    )

    id: Mapped[uuid.UUID] = _pk()
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    filename: Mapped[str] = mapped_column(String(300), nullable=False)
    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"))
    records_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_valid: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    report: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = _created()


# ----------------------------------------------------------------- audit
class AuditLog(Base):
    """APPEND ONLY. There is no code path that updates or deletes a row, and
    the migration adds a trigger so the database refuses to as well.

    `actor_email` is copied in rather than joined, so the record of who did
    something survives that account being renamed or removed.
    """
    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint("result IN ('success','warning','blocked')", name="ck_audit_logs_result"),
        # The audit screen always reads one organisation newest-first; this is
        # the index that query wants, and this is the table that grows fastest.
        Index("ix_audit_logs_org_created", "org_id", created_at_desc := text("created_at DESC")),
    )

    # These three carry NO foreign key, deliberately. A SET NULL is an UPDATE,
    # and the append-only trigger refuses UPDATEs — so with them in place,
    # deleting a user, an organisation or an application became impossible as
    # soon as it appeared in one audit row. Referential actions and an
    # immutable log cannot both be right, and the log wins: it is the record
    # of what happened, and what happened does not change because an account
    # was later removed. `actor_email` is copied in for exactly this reason.
    id: Mapped[uuid.UUID] = _pk()
    org_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    # NOT NULL: with no foreign key on actor_id, this is the only identity a
    # row is guaranteed to keep. See ANONYMOUS_ACTOR in permissions.py for the
    # one case with nobody to name.
    actor_email: Mapped[str] = mapped_column(String(254), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    # Which product the event belongs to, where that is meaningful. Signing in
    # is not about one application, so this stays NULL for those; a role grant
    # or a tool rule is, and a Business Admin may only read their own.
    application_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    target_type: Mapped[str | None] = mapped_column(String(60))
    target_id: Mapped[str | None] = mapped_column(String(120))
    source: Mapped[str | None] = mapped_column(String(40))
    result: Mapped[str] = mapped_column(String(20), nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(400))
    before: Mapped[dict | None] = mapped_column(JSON)
    after: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=now, index=True)


# ----------------------------------------------------------- OIDC provider
class OAuthClient(Base):
    """A service Core hands a verified identity to.

    One per application for now; nothing here limits it to one. The secret is
    argon2id-hashed like a password and shown once, at registration.
    `redirect_uris` is a list of exact absolute URIs: authorize compares whole
    strings, never prefixes, because a prefix match is the classic OIDC open
    redirect.
    """
    __tablename__ = "oauth_clients"
    __table_args__ = (
        CheckConstraint("status IN ('active','disabled')", name="ck_oauth_clients_status"),
    )

    id: Mapped[uuid.UUID] = _pk()
    client_id: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    client_secret_hash: Mapped[str] = mapped_column(Text, nullable=False)
    application_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    redirect_uris: Mapped[list] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    created_at: Mapped[datetime] = _created()
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    application: Mapped[Application] = relationship()


class AuthorizationCode(Base):
    """A one-time code between authorize and token: 30 seconds, single use.

    Only the SHA-256 of the code is stored. The code is 256 bits of randomness,
    so a fast hash already makes a leaked table useless — and it must be looked
    up by that hash, which a salted password hash could not be. Consumed and
    expired rows are kept briefly for the audit trail and swept when new codes
    are written.
    """
    __tablename__ = "authorization_codes"

    id: Mapped[uuid.UUID] = _pk()
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # The client row, not its public client_id string — named so the two are
    # never confused.
    oauth_client_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("oauth_clients.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    application_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    redirect_uri: Mapped[str] = mapped_column(String(500), nullable=False)
    nonce: Mapped[str] = mapped_column(String(255), nullable=False)
    state_echo: Mapped[str | None] = mapped_column(String(500))
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _created()


class SigningKey(Base):
    """The PUBLIC half of a key Core signs tokens with, for JWKS to publish.

    The private key never touches the database; it lives in OIDC_PRIVATE_KEY.
    `active` means published. A key being rotated out stays active until every
    token it signed has expired, and is then retired. OPEN-DECISIONS #15.
    """
    __tablename__ = "signing_keys"
    __table_args__ = (
        CheckConstraint("status IN ('active','retired')", name="ck_signing_keys_status"),
        CheckConstraint("algorithm IN ('RS256')", name="ck_signing_keys_algorithm"),
    )

    id: Mapped[uuid.UUID] = _pk()
    kid: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    public_pem: Mapped[str] = mapped_column(Text, nullable=False)
    algorithm: Mapped[str] = mapped_column(String(10), nullable=False, default="RS256")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    created_at: Mapped[datetime] = _created()
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
