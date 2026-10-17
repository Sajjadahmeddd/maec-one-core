"""applications may be inactive

Written by hand. Prompt 19 Part B: a Global Admin adds and edits applications
on the Applications screen; none is ever deleted, and one with history is set
inactive instead. The status constraint gains 'inactive'. A downgrade sets any
inactive application back to coming_soon first, which the old constraint
accepts. Round-tripped in test_postgres_integrity.

Revision ID: 9e4c2a7d5b16
Revises: 7b2e5d1f9c40
Create Date: 2026-10-18 09:00:00+00:00
"""
from __future__ import annotations

from alembic import op


revision = '9e4c2a7d5b16'
down_revision = '7b2e5d1f9c40'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint('ck_applications_status', 'applications', type_='check')
    op.create_check_constraint('ck_applications_status', 'applications',
                               "status IN ('live','coming_soon','inactive')")


def downgrade() -> None:
    op.execute("UPDATE applications SET status = 'coming_soon' WHERE status = 'inactive'")
    op.drop_constraint('ck_applications_status', 'applications', type_='check')
    op.create_check_constraint('ck_applications_status', 'applications',
                               "status IN ('live','coming_soon')")
