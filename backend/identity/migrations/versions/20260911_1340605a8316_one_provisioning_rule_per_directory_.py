"""one provisioning rule per directory group

Two rows for the same group would confer two roles with nothing to say which
wins. That is the same shape as the `audit_logs.actor_email` problem — a rule
everybody assumes and nothing enforces — so it becomes a constraint.

Autogenerate found the unique constraint and **not** the CHECK on `status`:
Alembic does not detect check constraints, so it is added here by hand. Third
migration in this series where autogenerate was incomplete in a way that only
shows up against a real database.

Revision ID: 1340605a8316
Revises: 85a5ffc2b8fe
Create Date: 2026-09-11 21:20:00.824785+00:00
"""
from __future__ import annotations

from alembic import op

revision = '1340605a8316'
down_revision = '85a5ffc2b8fe'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint('uq_provisioning_map_group', 'provisioning_map',
                                ['org_id', 'directory_group'])
    # SQLite cannot add a constraint to an existing table, and the test
    # database is built from the models rather than from these migrations.
    if op.get_bind().dialect.name == "postgresql":
        op.create_check_constraint('ck_provisioning_map_status', 'provisioning_map',
                                   "status IN ('active','disabled')")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.drop_constraint('ck_provisioning_map_status', 'provisioning_map',
                           type_='check')
    op.drop_constraint('uq_provisioning_map_group', 'provisioning_map',
                       type_='unique')
