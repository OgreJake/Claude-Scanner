"""Add device_groups, device_group_members tables and ibmi OS type.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-03-31
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'b2c3d4e5f6a7'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add 'ibmi' to the ostype enum.
    # IF NOT EXISTS requires PostgreSQL 9.3+; safe to re-run.
    op.execute(sa.text("ALTER TYPE ostype ADD VALUE IF NOT EXISTS 'ibmi'"))

    # device_groups
    op.create_table(
        'device_groups',
        sa.Column('id', postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('color', sa.String(16), nullable=True),   # hex colour for UI, e.g. "#4f46e5"
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index('ix_device_groups_name', 'device_groups', ['name'], unique=True)

    # device_group_members  (many-to-many join table)
    op.create_table(
        'device_group_members',
        sa.Column('group_id', postgresql.UUID(as_uuid=False),
                  sa.ForeignKey('device_groups.id', ondelete='CASCADE'), nullable=False),
        sa.Column('device_id', postgresql.UUID(as_uuid=False),
                  sa.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False),
        sa.PrimaryKeyConstraint('group_id', 'device_id', name='pk_device_group_members'),
    )
    op.create_index('ix_dgm_group_id',  'device_group_members', ['group_id'])
    op.create_index('ix_dgm_device_id', 'device_group_members', ['device_id'])


def downgrade() -> None:
    op.drop_table('device_group_members')
    op.drop_table('device_groups')
    # PostgreSQL does not support DROP VALUE from an enum; leave 'ibmi' in place.
