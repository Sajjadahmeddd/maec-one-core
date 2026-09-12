"""actor_email is never null

`audit_logs.actor_id` lost its foreign key in 80e2af9bd1b8, which made
`actor_email` the only identity a row is guaranteed to keep. One write path
could still leave it NULL: a login attempt that supplied no address at all.
"Should always be populated", enforced by nothing, is precisely the shape of
the bug that FK removal fixed — so it becomes a constraint.

Two corrections to what autogenerate produced:

* it emitted the ALTER with no backfill. Any database holding a NULL row —
  every deployment that has seen an empty login attempt — would have failed
  on it. The backfill below runs first.
* that backfill is an UPDATE, and audit_logs carries a BEFORE UPDATE trigger
  that raises. The trigger is disabled for the length of the statement and
  re-enabled immediately. This is the one place in the codebase permitted to
  do that, and it is a schema migration rather than application code: the
  append-only guarantee is about what the running system may do.

Revision ID: 85a5ffc2b8fe
Revises: 80e2af9bd1b8
Create Date: 2026-09-11 19:02:00.000000+00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = '85a5ffc2b8fe'
down_revision = '80e2af9bd1b8'
branch_labels = None
depends_on = None

# Mirrors permissions.ANONYMOUS_ACTOR. No "@", so it cannot collide with a
# real address.
SENTINEL = "(anonymous)"


def upgrade() -> None:
    postgres = op.get_bind().dialect.name == "postgresql"

    if postgres:
        op.execute("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_append_only")
    op.execute(sa.text(
        "UPDATE audit_logs SET actor_email = :sentinel WHERE actor_email IS NULL"
    ).bindparams(sentinel=SENTINEL))
    if postgres:
        op.execute("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_append_only")

    op.alter_column('audit_logs', 'actor_email',
                    existing_type=sa.VARCHAR(length=254), nullable=False)


def downgrade() -> None:
    """Only relaxes the constraint. The sentinel rows stay as they are —
    turning them back into NULLs would be another UPDATE on an append-only
    table, and they are now the honest record of what those rows say."""
    op.alter_column('audit_logs', 'actor_email',
                    existing_type=sa.VARCHAR(length=254), nullable=True)
