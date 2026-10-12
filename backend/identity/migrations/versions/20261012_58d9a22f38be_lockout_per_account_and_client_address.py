"""lockout per account and client address

Reviewed by hand after autogenerate, and changed in one place. The new table
and its CHECKs came out complete — a CHECK on a new table is rendered inside
create_table. The downgrade did not: it re-added users.failed_login_count as
NOT NULL with no default, which fails on any database that has a user. It now
adds the column with a server default of 0 and then drops the default, so the
column ends exactly as the identity schema first made it. Round-tripped up,
down and up again with rows present, on a copy of a seeded database and in
test_postgres_integrity.

* login_locks: one row per (account, client address) — failures, the locks
  they caused (strikes), and the lock in force. OPEN-DECISIONS #20.
* users.failed_login_count and users.locked_until are dropped: one count per
  account is what let anyone lock anyone out, and leaving the columns would
  leave a second, stale answer to "is this account locked?".
* No data is carried over. An account-wide lock in force at upgrade is
  released — it would have lasted thirty minutes at most — and the failure
  counts start again from zero. A downgrade likewise starts every account at
  zero and unlocked.

Revision ID: 58d9a22f38be
Revises: 5c27d299e7a4
Create Date: 2026-10-12 07:19:16.001248+00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = '58d9a22f38be'
down_revision = '5c27d299e7a4'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('login_locks',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('address', sa.String(length=64), nullable=False),
    sa.Column('failed_count', sa.Integer(), nullable=False),
    sa.Column('strikes', sa.Integer(), nullable=False),
    sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint('failed_count >= 0', name='ck_login_locks_failed_count'),
    sa.CheckConstraint('strikes >= 0', name='ck_login_locks_strikes'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('user_id', 'address', name='uq_login_locks_user_address')
    )
    op.create_index(op.f('ix_login_locks_user_id'), 'login_locks', ['user_id'], unique=False)
    op.drop_column('users', 'locked_until')
    op.drop_column('users', 'failed_login_count')


def downgrade() -> None:
    # NOT NULL needs a value for every existing user: add with a default, then
    # drop the default so the column is what 81e586581063 made it.
    op.add_column('users', sa.Column('failed_login_count', sa.Integer(), nullable=False,
                                     server_default=sa.text('0')))
    op.alter_column('users', 'failed_login_count', server_default=None)
    op.add_column('users', sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True))
    op.drop_index(op.f('ix_login_locks_user_id'), table_name='login_locks')
    op.drop_table('login_locks')
