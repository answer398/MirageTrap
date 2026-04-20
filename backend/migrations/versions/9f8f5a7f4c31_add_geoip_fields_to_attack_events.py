"""add geoip fields to attack events

Revision ID: 9f8f5a7f4c31
Revises: 7d04104b4154
Create Date: 2026-04-14 11:30:00.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "9f8f5a7f4c31"
down_revision = "7d04104b4154"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("attack_events", schema=None) as batch_op:
        batch_op.add_column(sa.Column("country_code", sa.String(length=8), nullable=True))
        batch_op.add_column(sa.Column("region_code", sa.String(length=32), nullable=True))
        batch_op.add_column(sa.Column("timezone", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("latitude", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("longitude", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("accuracy_radius", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("asn_org", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("geo_source", sa.String(length=32), nullable=True))


def downgrade():
    with op.batch_alter_table("attack_events", schema=None) as batch_op:
        batch_op.drop_column("geo_source")
        batch_op.drop_column("asn_org")
        batch_op.drop_column("accuracy_radius")
        batch_op.drop_column("longitude")
        batch_op.drop_column("latitude")
        batch_op.drop_column("timezone")
        batch_op.drop_column("region_code")
        batch_op.drop_column("country_code")
