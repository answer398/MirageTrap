from __future__ import annotations

from sqlalchemy import inspect, text

from app.extensions import db


def ensure_runtime_schema_compatibility() -> None:
    inspector = inspect(db.engine)
    dialect = db.engine.dialect.name

    if inspector.has_table("attack_events"):
        _ensure_attack_events_compatibility(inspector=inspector, dialect=dialect)

    inspector = inspect(db.engine)
    if inspector.has_table("honeypot_instances"):
        _ensure_honeypot_instances_compatibility(inspector=inspector, dialect=dialect)


def _ensure_attack_events_compatibility(*, inspector, dialect: str) -> None:
    columns = {item["name"] for item in inspector.get_columns("attack_events")}
    float_type = "DOUBLE PRECISION" if dialect == "postgresql" else "REAL"

    statements = []
    add_column = statements.append

    if "country_code" not in columns:
        add_column("ALTER TABLE attack_events ADD COLUMN country_code VARCHAR(8)")
    if "region_code" not in columns:
        add_column("ALTER TABLE attack_events ADD COLUMN region_code VARCHAR(32)")
    if "timezone" not in columns:
        add_column("ALTER TABLE attack_events ADD COLUMN timezone VARCHAR(64)")
    if "latitude" not in columns:
        add_column(f"ALTER TABLE attack_events ADD COLUMN latitude {float_type}")
    if "longitude" not in columns:
        add_column(f"ALTER TABLE attack_events ADD COLUMN longitude {float_type}")
    if "accuracy_radius" not in columns:
        add_column("ALTER TABLE attack_events ADD COLUMN accuracy_radius INTEGER")
    if "asn_org" not in columns:
        add_column("ALTER TABLE attack_events ADD COLUMN asn_org VARCHAR(255)")
    if "geo_source" not in columns:
        add_column("ALTER TABLE attack_events ADD COLUMN geo_source VARCHAR(32)")

    for statement in statements:
        db.session.execute(text(statement))

    if "ioc_hit" in columns and dialect == "postgresql":
        db.session.execute(text("ALTER TABLE attack_events ALTER COLUMN ioc_hit SET DEFAULT false"))
        db.session.execute(text("UPDATE attack_events SET ioc_hit = false WHERE ioc_hit IS NULL"))
    if statements or "ioc_hit" in columns:
        db.session.commit()


def _ensure_honeypot_instances_compatibility(*, inspector, dialect: str) -> None:
    columns = {item["name"] for item in inspector.get_columns("honeypot_instances")}
    json_default = "'{}'::json" if dialect == "postgresql" else "'{}'"
    json_array_default = "'[]'::json" if dialect == "postgresql" else "'[]'"

    statements = []
    add_column = statements.append

    if "honeypot_id" not in columns:
        add_column("ALTER TABLE honeypot_instances ADD COLUMN honeypot_id VARCHAR(64)")
    if "honeypot_type" not in columns:
        add_column("ALTER TABLE honeypot_instances ADD COLUMN honeypot_type VARCHAR(16)")
    if "image_key" not in columns:
        add_column("ALTER TABLE honeypot_instances ADD COLUMN image_key VARCHAR(64)")
    if "image_name" not in columns:
        add_column("ALTER TABLE honeypot_instances ADD COLUMN image_name VARCHAR(255)")
    if "container_name" not in columns:
        add_column("ALTER TABLE honeypot_instances ADD COLUMN container_name VARCHAR(128)")
    if "bind_host" not in columns:
        add_column("ALTER TABLE honeypot_instances ADD COLUMN bind_host VARCHAR(64)")
    if "container_port" not in columns:
        add_column("ALTER TABLE honeypot_instances ADD COLUMN container_port INTEGER")
    if "honeypot_profile" not in columns:
        add_column("ALTER TABLE honeypot_instances ADD COLUMN honeypot_profile VARCHAR(32)")
    if "desired_state" not in columns:
        add_column("ALTER TABLE honeypot_instances ADD COLUMN desired_state VARCHAR(16)")
    if "runtime_status" not in columns:
        add_column("ALTER TABLE honeypot_instances ADD COLUMN runtime_status VARCHAR(16)")
    if "container_id" not in columns:
        add_column("ALTER TABLE honeypot_instances ADD COLUMN container_id VARCHAR(128)")
    if "last_heartbeat_at" not in columns:
        add_column("ALTER TABLE honeypot_instances ADD COLUMN last_heartbeat_at TIMESTAMPTZ")
    if "last_runtime_sync_at" not in columns:
        add_column("ALTER TABLE honeypot_instances ADD COLUMN last_runtime_sync_at TIMESTAMPTZ")
    if "last_seen_ip" not in columns:
        add_column("ALTER TABLE honeypot_instances ADD COLUMN last_seen_ip VARCHAR(64)")
    if "last_error" not in columns:
        add_column("ALTER TABLE honeypot_instances ADD COLUMN last_error TEXT")
    if "runtime_meta" not in columns:
        add_column(f"ALTER TABLE honeypot_instances ADD COLUMN runtime_meta JSON DEFAULT {json_default}")

    for statement in statements:
        db.session.execute(text(statement))

    if dialect == "postgresql":
        if "type" in columns:
            db.session.execute(text("ALTER TABLE honeypot_instances ALTER COLUMN type SET DEFAULT 'web'"))
            db.session.execute(text("UPDATE honeypot_instances SET type = 'web' WHERE type IS NULL"))
        if "image" in columns:
            db.session.execute(
                text("ALTER TABLE honeypot_instances ALTER COLUMN image SET DEFAULT 'miragetrap/web-honeypot:latest'")
            )
            db.session.execute(
                text("UPDATE honeypot_instances SET image = 'miragetrap/web-honeypot:latest' WHERE image IS NULL")
            )
        if "status" in columns:
            db.session.execute(text("ALTER TABLE honeypot_instances ALTER COLUMN status SET DEFAULT 'stopped'"))
            db.session.execute(text("UPDATE honeypot_instances SET status = 'stopped' WHERE status IS NULL"))
        if "tags" in columns:
            db.session.execute(text(f"ALTER TABLE honeypot_instances ALTER COLUMN tags SET DEFAULT {json_array_default}"))
            db.session.execute(text(f"UPDATE honeypot_instances SET tags = {json_array_default} WHERE tags IS NULL"))

    legacy_columns = {"type", "image", "status"} & columns
    if statements or legacy_columns:
        id_text = "id::text" if dialect == "postgresql" else "CAST(id AS TEXT)"
        legacy_type_expr = "type" if "type" in columns else "'web'"
        legacy_image_expr = "image" if "image" in columns else "'miragetrap/web-honeypot:latest'"
        legacy_status_expr = "status" if "status" in columns else "'stopped'"
        db.session.execute(
            text(
                f"""
                UPDATE honeypot_instances
                SET honeypot_id = COALESCE(honeypot_id, 'legacy-hp-' || {id_text}),
                    honeypot_type = COALESCE(honeypot_type, {legacy_type_expr}, 'web'),
                    image_key = COALESCE(
                        image_key,
                        CASE WHEN COALESCE({legacy_type_expr}, 'web') = 'web' THEN 'web_portal' ELSE COALESCE({legacy_type_expr}, 'web') || '_default' END
                    ),
                    image_name = COALESCE(image_name, {legacy_image_expr}, 'miragetrap/web-honeypot:latest'),
                    container_name = COALESCE(container_name, 'legacy-honeypot-' || {id_text}),
                    bind_host = COALESCE(bind_host, '0.0.0.0'),
                    container_port = COALESCE(container_port, 80),
                    honeypot_profile = COALESCE(honeypot_profile, 'portal'),
                    desired_state = COALESCE(
                        desired_state,
                        CASE WHEN COALESCE({legacy_status_expr}, 'stopped') IN ('running', 'online') THEN 'running' ELSE 'stopped' END
                    ),
                    runtime_status = COALESCE(
                        runtime_status,
                        CASE WHEN COALESCE({legacy_status_expr}, 'stopped') IN ('running', 'online') THEN 'running' ELSE COALESCE({legacy_status_expr}, 'stopped') END
                    ),
                    runtime_meta = COALESCE(runtime_meta, {json_default})
                """
            )
        )
    db.session.commit()
