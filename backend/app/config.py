import os
from datetime import timedelta


class Config:
    APP_NAME = "mirage-trap-backend"
    APP_PORT = int(os.getenv("APP_PORT", "15000"))
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me-please-replace")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-jwt-secret-key-change-me-please-replace")

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg2://honeypot:honeypot@localhost:15432/honeypot_db",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    AUTO_CREATE_TABLES = os.getenv("AUTO_CREATE_TABLES", "true").lower() == "true"

    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=8)

    LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
    LOGIN_LOCK_MINUTES = int(os.getenv("LOGIN_LOCK_MINUTES", "15"))
    INGEST_TOKEN = os.getenv("INGEST_TOKEN", "dev-ingest-token")
    HONEYPOT_CONTROL_TOKEN = os.getenv(
        "HONEYPOT_CONTROL_TOKEN",
        os.getenv("INGEST_TOKEN", "dev-ingest-token"),
    )
    SESSION_AGGREGATION_MINUTES = int(os.getenv("SESSION_AGGREGATION_MINUTES", "30"))
    EVIDENCE_STORAGE_DRIVER = os.getenv("EVIDENCE_STORAGE_DRIVER", "local")
    EVIDENCE_LOCAL_PATH = os.getenv("EVIDENCE_LOCAL_PATH", "instance/evidence")
    AUTH_RATE_LIMIT_ATTEMPTS = int(os.getenv("AUTH_RATE_LIMIT_ATTEMPTS", "10"))
    AUTH_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("AUTH_RATE_LIMIT_WINDOW_SECONDS", "300"))
    HONEYPOT_ORCHESTRATION_ENABLED = os.getenv("HONEYPOT_ORCHESTRATION_ENABLED", "false").lower() == "true"
    HONEYPOT_CONTROLLER_BASE_URL = os.getenv("HONEYPOT_CONTROLLER_BASE_URL", "http://backend-api:15000")
    HONEYPOT_DOCKER_HOST = os.getenv("HONEYPOT_DOCKER_HOST", "")
    HONEYPOT_DOCKER_NETWORK = os.getenv("HONEYPOT_DOCKER_NETWORK", "miragetrap-net")
    HONEYPOT_DOCKER_READ_ONLY_ROOTFS = (
        os.getenv("HONEYPOT_DOCKER_READ_ONLY_ROOTFS", "false").lower() == "true"
    )
    HONEYPOT_HEARTBEAT_INTERVAL_SECONDS = int(os.getenv("HONEYPOT_HEARTBEAT_INTERVAL_SECONDS", "15"))
    HONEYPOT_HEARTBEAT_TIMEOUT_SECONDS = int(os.getenv("HONEYPOT_HEARTBEAT_TIMEOUT_SECONDS", "45"))

    ADMIN_DEFAULT_USERNAME = os.getenv("ADMIN_DEFAULT_USERNAME", "admin")
    ADMIN_DEFAULT_PASSWORD = os.getenv("ADMIN_DEFAULT_PASSWORD", "Admin@123456")
    CORS_ALLOWED_ORIGINS = tuple(
        item.strip()
        for item in os.getenv(
            "CORS_ALLOWED_ORIGINS",
            "http://127.0.0.1:15173,http://localhost:15173",
        ).split(",")
        if item.strip()
    )


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.getenv("TEST_DATABASE_URI", "sqlite:///:memory:")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
    AUTO_CREATE_TABLES = os.getenv("AUTO_CREATE_TABLES", "true").lower() == "true"
    HONEYPOT_ORCHESTRATION_ENABLED = False
