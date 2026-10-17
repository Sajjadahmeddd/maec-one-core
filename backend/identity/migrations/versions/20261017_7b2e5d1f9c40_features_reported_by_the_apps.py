"""features reported by the apps

Written by hand. OPEN-DECISIONS #23: an application tells Core its features
(PUT /api/gate/features); Core's code names none of them.

* features: one row per (application, key) — the name to show, "new" until an
  administrator first changes a rule on it, and "not reported since" when the
  app's report leaves it out.
* retired_features: keys an administrator removed; never accepted again.
* applications.features_reported_at, features_version, features_report: when
  the app last reported, the version it gave, and what the report did.

No data is moved. The permissions and role rules already in the database stay
exactly as they are; when an app next reports, its features are simply
"existing" and gain a features row then. Round-tripped up, down and up again
with rows present in test_postgres_integrity.

Revision ID: 7b2e5d1f9c40
Revises: 3d7a1c9e4b20
Create Date: 2026-10-17 09:00:00+00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = '7b2e5d1f9c40'
down_revision = '3d7a1c9e4b20'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('features',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('application_id', sa.Uuid(), nullable=False),
    sa.Column('key', sa.String(length=40), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('is_new', sa.Boolean(), nullable=False),
    sa.Column('not_reported_since', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('application_id', 'key', name='uq_features_app_key')
    )
    op.create_index(op.f('ix_features_application_id'), 'features', ['application_id'], unique=False)
    op.create_table('retired_features',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('application_id', sa.Uuid(), nullable=False),
    sa.Column('key', sa.String(length=40), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=True),
    sa.Column('retired_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('retired_by', sa.Uuid(), nullable=True),
    sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['retired_by'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('application_id', 'key', name='uq_retired_features_app_key')
    )
    op.create_index(op.f('ix_retired_features_application_id'), 'retired_features',
                    ['application_id'], unique=False)
    op.add_column('applications', sa.Column('features_reported_at', sa.DateTime(timezone=True),
                                            nullable=True))
    op.add_column('applications', sa.Column('features_version', sa.String(length=64), nullable=True))
    op.add_column('applications', sa.Column('features_report', sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column('applications', 'features_report')
    op.drop_column('applications', 'features_version')
    op.drop_column('applications', 'features_reported_at')
    op.drop_index(op.f('ix_retired_features_application_id'), table_name='retired_features')
    op.drop_table('retired_features')
    op.drop_index(op.f('ix_features_application_id'), table_name='features')
    op.drop_table('features')
