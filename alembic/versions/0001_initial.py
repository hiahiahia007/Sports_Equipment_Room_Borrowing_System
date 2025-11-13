"""initial

Revision ID: 0001_initial
Revises: 
Create Date: 2025-11-08 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Baseline initial migration.
    # This migration intentionally left minimal to act as a stamp.
    pass


def downgrade():
    pass
