"""initial schema

Revision ID: 7d04104b4154
Revises: 
Create Date: 2026-03-15 16:16:00.455713

"""
from alembic import op

import app.models  # noqa: F401  # ensure model metadata is registered
from app.extensions import db


# revision identifiers, used by Alembic.
revision = '7d04104b4154'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    db.metadata.create_all(bind=bind)


def downgrade():
    bind = op.get_bind()
    db.metadata.drop_all(bind=bind)
