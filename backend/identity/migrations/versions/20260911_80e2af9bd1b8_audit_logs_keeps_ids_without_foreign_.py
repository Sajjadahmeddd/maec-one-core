"""audit_logs keeps ids without foreign keys

Found by accident while cleaning up after a browser test: deleting a user
failed with "audit_logs is append-only: UPDATE is not permitted".

`audit_logs.actor_id` referenced `users.id` with ON DELETE SET NULL. A SET
NULL is an UPDATE, and the append-only trigger refuses UPDATEs — so as soon
as a person appeared in a single audit row, their account could never be
deleted. The same held for `org_id` and `application_id`: deleting an
organisation or an application was equally impossible.

Referential actions and an immutable log cannot both be right. The log wins:
it records what happened, and what happened does not change because an
account was removed afterwards. That is also why `actor_email` is copied into
each row rather than joined — the record was always meant to outlive the
account.

The columns stay, indexed, so the audit screen can still filter by actor,
organisation and application. They are simply no longer enforced references.

Autogenerate produced this one correctly; only the dialect guard and this
note were added by hand.

Revision ID: 80e2af9bd1b8
Revises: 1cb6f946f716
Create Date: 2026-09-11 18:24:49.032190+00:00
"""
from __future__ import annotations

from alembic import op

revision = '80e2af9bd1b8'
down_revision = '1cb6f946f716'
branch_labels = None
depends_on = None

CONSTRAINTS = (
    'audit_logs_org_id_fkey',
    'fk_audit_logs_application_id',
    'audit_logs_actor_id_fkey',
)


def upgrade() -> None:
    # SQLite cannot drop a constraint, and never had these to begin with —
    # the test database is built from the models, not from this migration.
    if op.get_bind().dialect.name != "postgresql":
        return
    for name in CONSTRAINTS:
        op.drop_constraint(name, 'audit_logs', type_='foreignkey')


def downgrade() -> None:
    """Restores the references — and with them the inability to delete a user
    who has ever done anything. Present for completeness, not because going
    back is a good idea."""
    if op.get_bind().dialect.name != "postgresql":
        return
    op.create_foreign_key('audit_logs_actor_id_fkey', 'audit_logs', 'users',
                          ['actor_id'], ['id'], ondelete='SET NULL')
    op.create_foreign_key('fk_audit_logs_application_id', 'audit_logs', 'applications',
                          ['application_id'], ['id'], ondelete='SET NULL')
    op.create_foreign_key('audit_logs_org_id_fkey', 'audit_logs', 'organizations',
                          ['org_id'], ['id'], ondelete='SET NULL')
