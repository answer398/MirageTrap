from flask import current_app

from app.infrastructure import (
    build_geoip_lookup_adapter,
    build_honeypot_runtime_adapter,
    build_object_storage_adapter,
)
from app.repositories import (
    AdminRepository,
    AttackEventRepository,
    AttackSessionRepository,
    EvidenceRepository,
    HoneypotRepository,
)
from app.services import (
    AttackCommandService,
    AttackIngestService,
    AttackQueryService,
    AuthService,
    DashboardService,
    EvidenceService,
    HealthService,
    HoneypotService,
    ReplayService,
    RiskEngineService,
    SessionService,
)


def init_container(app) -> None:
    admin_repository = AdminRepository()
    event_repository = AttackEventRepository()
    session_repository = AttackSessionRepository()
    evidence_repository = EvidenceRepository()
    honeypot_repository = HoneypotRepository()

    risk_engine_service = RiskEngineService(
        ruleset_paths=app.config["ATTACK_RULESET_PATHS"],
    )
    session_service = SessionService(
        session_repository=session_repository,
        window_minutes=app.config["SESSION_AGGREGATION_MINUTES"],
    )

    security_store = app.extensions["security_store"]
    object_storage_adapter = build_object_storage_adapter(app.config)
    geoip_lookup_adapter = build_geoip_lookup_adapter(app.config)
    honeypot_runtime_adapter = build_honeypot_runtime_adapter(app.config)
    app.extensions["object_storage"] = object_storage_adapter
    app.extensions["geoip_lookup"] = geoip_lookup_adapter
    app.extensions["honeypot_runtime"] = honeypot_runtime_adapter

    auth_service = AuthService(
        admin_repository=admin_repository,
        security_store=security_store,
        max_attempts=app.config["LOGIN_MAX_ATTEMPTS"],
        lock_minutes=app.config["LOGIN_LOCK_MINUTES"],
        rate_limit_attempts=app.config["AUTH_RATE_LIMIT_ATTEMPTS"],
        rate_limit_window_seconds=app.config["AUTH_RATE_LIMIT_WINDOW_SECONDS"],
        default_token_ttl_seconds=_resolve_access_token_ttl_seconds(app.config["JWT_ACCESS_TOKEN_EXPIRES"]),
    )
    dashboard_service = DashboardService(event_repository=event_repository)
    health_service = HealthService(
        app_name=app.config["APP_NAME"],
        security_store=security_store,
        object_storage=object_storage_adapter,
        geoip_lookup=geoip_lookup_adapter,
        honeypot_runtime=honeypot_runtime_adapter,
    )
    attack_ingest_service = AttackIngestService(
        event_repository=event_repository,
        session_service=session_service,
        risk_engine_service=risk_engine_service,
        geoip_lookup=geoip_lookup_adapter,
    )
    attack_query_service = AttackQueryService(
        event_repository=event_repository,
        risk_engine_service=risk_engine_service,
    )
    attack_command_service = AttackCommandService(
        event_repository=event_repository,
        session_repository=session_repository,
        evidence_repository=evidence_repository,
    )
    replay_service = ReplayService(
        event_repository=event_repository,
        session_repository=session_repository,
        risk_engine_service=risk_engine_service,
    )
    evidence_service = EvidenceService(
        evidence_repository=evidence_repository,
        session_repository=session_repository,
        event_repository=event_repository,
        object_storage=object_storage_adapter,
    )
    honeypot_service = HoneypotService(
        honeypot_repository=honeypot_repository,
        runtime_adapter=honeypot_runtime_adapter,
        controller_base_url=app.config["HONEYPOT_CONTROLLER_BASE_URL"],
        controller_public_base_url=app.config["HONEYPOT_CONTROLLER_PUBLIC_BASE_URL"],
        control_token=app.config["HONEYPOT_CONTROL_TOKEN"],
        ingest_token=app.config["INGEST_TOKEN"],
        heartbeat_timeout_seconds=app.config["HONEYPOT_HEARTBEAT_TIMEOUT_SECONDS"],
        startup_verify_seconds=app.config["HONEYPOT_STARTUP_VERIFY_SECONDS"],
    )

    app.extensions["service_container"] = {
        "auth_service": auth_service,
        "risk_engine_service": risk_engine_service,
        "health_service": health_service,
        "session_service": session_service,
        "attack_ingest_service": attack_ingest_service,
        "attack_query_service": attack_query_service,
        "attack_command_service": attack_command_service,
        "dashboard_service": dashboard_service,
        "replay_service": replay_service,
        "evidence_service": evidence_service,
        "honeypot_service": honeypot_service,
    }


def get_service(name: str):
    return current_app.extensions["service_container"][name]


def _resolve_access_token_ttl_seconds(raw) -> int:
    if hasattr(raw, "total_seconds"):
        try:
            return max(int(raw.total_seconds()), 60)
        except Exception:  # noqa: BLE001
            return 8 * 3600
    return 8 * 3600
