"""oidc provider: clients, authorization codes and signing keys

Reviewed by hand after autogenerate. Unlike the three migrations it follows,
autogenerate got this one complete: every table here is new, and a CHECK on a
new table is rendered inside create_table — the CHECKs it has missed were
added to tables that already existed. Checked against models.py all the same,
and round-tripped up, down and up again with rows present, both on a copy of a
populated database and in test_postgres_integrity. Nothing was changed by hand
beyond this note and removing the "auto generated" markers.

* signing_keys holds public keys only. The private key is OIDC_PRIVATE_KEY.
* authorization_codes stores the SHA-256 of each code, never the code.
* No data migration: every table starts empty. A client is registered with
  `python -m backend.identity.clients register`.

Revision ID: 12c431aabf3e
Revises: 1340605a8316
Create Date: 2026-09-13 20:36:12.400659+00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = '12c431aabf3e'
down_revision = '1340605a8316'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('signing_keys',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('kid', sa.String(length=64), nullable=False),
    sa.Column('public_pem', sa.Text(), nullable=False),
    sa.Column('algorithm', sa.String(length=10), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('retired_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("algorithm IN ('RS256')", name='ck_signing_keys_algorithm'),
    sa.CheckConstraint("status IN ('active','retired')", name='ck_signing_keys_status'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('kid')
    )
    op.create_table('oauth_clients',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('client_id', sa.String(length=80), nullable=False),
    sa.Column('client_secret_hash', sa.Text(), nullable=False),
    sa.Column('application_id', sa.Uuid(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('redirect_uris', sa.JSON(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("status IN ('active','disabled')", name='ck_oauth_clients_status'),
    sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('client_id')
    )
    op.create_index(op.f('ix_oauth_clients_application_id'), 'oauth_clients', ['application_id'], unique=False)
    op.create_table('authorization_codes',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('code_hash', sa.String(length=64), nullable=False),
    sa.Column('oauth_client_id', sa.Uuid(), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('application_id', sa.Uuid(), nullable=False),
    sa.Column('redirect_uri', sa.String(length=500), nullable=False),
    sa.Column('nonce', sa.String(length=255), nullable=False),
    sa.Column('state_echo', sa.String(length=500), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('consumed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['oauth_client_id'], ['oauth_clients.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('code_hash')
    )
    op.create_index(op.f('ix_authorization_codes_expires_at'), 'authorization_codes', ['expires_at'], unique=False)
    op.create_index(op.f('ix_authorization_codes_oauth_client_id'), 'authorization_codes', ['oauth_client_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_authorization_codes_oauth_client_id'), table_name='authorization_codes')
    op.drop_index(op.f('ix_authorization_codes_expires_at'), table_name='authorization_codes')
    op.drop_table('authorization_codes')
    op.drop_index(op.f('ix_oauth_clients_application_id'), table_name='oauth_clients')
    op.drop_table('oauth_clients')
    op.drop_table('signing_keys')
