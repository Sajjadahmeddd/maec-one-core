"""sessions: server-side sign-ins that can be revoked

Reviewed by hand after autogenerate. The table is new, so both CHECKs were
rendered inside create_table — the CHECKs autogenerate has missed in this repo
were added to tables that already existed. Checked against models.py, and
round-tripped up, down and up again with rows present, on a copy of a seeded
database and in test_postgres_integrity. Nothing changed beyond this note and
removing the "auto generated" markers.

* session_hash is the SHA-256 of the cookie's session id, never the id.
* user_id cascades: deleting a person deletes their sessions, which signs
  them out as surely as revoking would.
* No data migration. Cookies issued before this revision carry no session id
  the table knows, so everyone signs in once more. OPEN-DECISIONS #5.

Revision ID: 5c27d299e7a4
Revises: 12c431aabf3e
Create Date: 2026-10-09 12:37:37.034077+00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = '5c27d299e7a4'
down_revision = '12c431aabf3e'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('sessions',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('session_hash', sa.String(length=64), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('absolute_expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('idle_expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('user_agent', sa.String(length=400), nullable=True),
    sa.CheckConstraint('absolute_expires_at > created_at', name='ck_sessions_ends_after_it_starts'),
    sa.CheckConstraint('idle_expires_at <= absolute_expires_at', name='ck_sessions_idle_within_absolute'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('session_hash')
    )
    op.create_index(op.f('ix_sessions_user_id'), 'sessions', ['user_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_sessions_user_id'), table_name='sessions')
    op.drop_table('sessions')
