"""tool settings: full or no access, and a status per tool

Written by hand. OPEN-DECISIONS #22: the Tool-Level Settings grid decides,
and a tool is all or nothing.

* tool_rules.access_level is 'full' or 'no_access'. Existing 'edit', 'view'
  and 'hidden' rules all left the role able to use the tool, so they become
  'full'; 'no_access' stays. A downgrade keeps the values, which the old
  constraint also accepts.
* tool_settings: one row per (organisation, application, module) whose Status
  an administrator has set. 'inactive' switches the tool off for everyone in
  the organisation; no row is 'active'.

Round-tripped up, down and up again with rows present in test_postgres_integrity.

Revision ID: 3d7a1c9e4b20
Revises: 58d9a22f38be
Create Date: 2026-10-16 12:00:00+00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = '3d7a1c9e4b20'
down_revision = '58d9a22f38be'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("UPDATE tool_rules SET access_level = 'full' "
               "WHERE access_level IN ('edit', 'view', 'hidden')")
    op.drop_constraint('ck_tool_rules_access_level', 'tool_rules', type_='check')
    op.create_check_constraint('ck_tool_rules_access_level', 'tool_rules',
                               "access_level IN ('full','no_access')")

    op.create_table('tool_settings',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('org_id', sa.Uuid(), nullable=False),
    sa.Column('application_id', sa.Uuid(), nullable=False),
    sa.Column('module_key', sa.String(length=40), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("status IN ('active','inactive')", name='ck_tool_settings_status'),
    sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['updated_by'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('org_id', 'application_id', 'module_key', name='uq_tool_settings_target')
    )
    op.create_index(op.f('ix_tool_settings_org_id'), 'tool_settings', ['org_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_tool_settings_org_id'), table_name='tool_settings')
    op.drop_table('tool_settings')
    op.drop_constraint('ck_tool_rules_access_level', 'tool_rules', type_='check')
    op.create_check_constraint('ck_tool_rules_access_level', 'tool_rules',
                               "access_level IN ('full','edit','view','hidden','no_access')")
