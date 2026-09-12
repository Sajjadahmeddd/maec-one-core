"""admin panel: password change flag, audit app scope, audit index

Reviewed by hand after autogenerate. Three corrections, all of which would
have failed against a database that already has rows in it:

* `must_change_password` is NOT NULL, so it needs a server default — without
  one, adding it to a populated `users` table fails outright. The default is
  false: nobody is forced to change a password they chose themselves. It is
  left in place rather than dropped afterwards, so a future INSERT that omits
  the column still works.
* the foreign key was generated unnamed. `op.drop_constraint(None, ...)` in
  the downgrade cannot work, so both directions now use an explicit name.
* the index keeps `created_at DESC`: the audit screen reads one organisation
  newest-first, and a DESC index is what serves that without a sort.

Revision ID: 1cb6f946f716
Revises: 81e586581063
Create Date: 2026-09-11 17:41:10.857345+00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = '1cb6f946f716'
down_revision = '81e586581063'
branch_labels = None
depends_on = None

FK_AUDIT_APP = "fk_audit_logs_application_id"


def upgrade() -> None:
    # Which product an event belongs to, where that is meaningful. Signing in
    # is not about one application, so it stays NULL there; a role grant or a
    # tool rule is, and a Business Admin may only read their own application's
    # events. Existing rows cannot be backfilled — they predate the column.
    op.add_column('audit_logs', sa.Column('application_id', sa.Uuid(), nullable=True))
    op.create_foreign_key(FK_AUDIT_APP, 'audit_logs', 'applications',
                          ['application_id'], ['id'], ondelete='SET NULL')

    # The audit screen's one query: this organisation, newest first.
    op.create_index('ix_audit_logs_org_created', 'audit_logs',
                    ['org_id', sa.literal_column('created_at DESC')], unique=False)

    op.add_column('users', sa.Column(
        'must_change_password', sa.Boolean(), nullable=False,
        server_default=sa.false()))


def downgrade() -> None:
    op.drop_column('users', 'must_change_password')
    op.drop_index('ix_audit_logs_org_created', table_name='audit_logs')
    op.drop_constraint(FK_AUDIT_APP, 'audit_logs', type_='foreignkey')
    op.drop_column('audit_logs', 'application_id')
