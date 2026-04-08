import os

import click
from flask import Flask, request
from sqlalchemy import inspect

from app.api import register_blueprints
from app.config import Config, TestConfig
from app.container import init_container
from app.extensions import db, jwt, migrate
from app.infrastructure import build_security_store
from app.models import AdminUser
from app.schema_compat import ensure_runtime_schema_compatibility


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__)

    if config_name == "test":
        app.config.from_object(TestConfig)
        app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
            "TEST_DATABASE_URI",
            app.config["SQLALCHEMY_DATABASE_URI"],
        )
        app.config["AUTO_CREATE_TABLES"] = os.getenv("AUTO_CREATE_TABLES", "true").lower() == "true"
    else:
        app.config.from_object(Config)

    _init_extensions(app)
    _configure_jwt_blocklist(app)
    init_container(app)
    register_blueprints(app)
    _register_cli_commands(app)

    with app.app_context():
        if app.config["AUTO_CREATE_TABLES"]:
            db.create_all()

        ensure_runtime_schema_compatibility()

        if _schema_ready():
            _ensure_default_admin(app)

    return app


def _init_extensions(app: Flask) -> None:
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    _configure_cors(app)


def _configure_cors(app: Flask) -> None:
    allowed_origins = set(app.config.get("CORS_ALLOWED_ORIGINS", ()) or ())
    allow_all = "*" in allowed_origins

    def _is_allowed(origin: str) -> bool:
        if allow_all:
            return True
        return origin in allowed_origins

    def _apply_headers(response):
        if not request.path.startswith("/api/"):
            return response

        origin = request.headers.get("Origin")
        if not origin:
            return response

        if not _is_allowed(origin):
            return response

        response.headers["Access-Control-Allow-Origin"] = "*" if allow_all else origin
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-Ingest-Token"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Max-Age"] = "3600"
        response.headers["Vary"] = "Origin"
        return response

    @app.before_request
    def _handle_preflight():
        if request.method == "OPTIONS" and request.path.startswith("/api/"):
            return _apply_headers(app.make_default_options_response())
        return None

    @app.after_request
    def _append_cors_headers(response):
        return _apply_headers(response)


def _configure_jwt_blocklist(app: Flask) -> None:
    security_store = build_security_store(app.config)
    app.extensions["security_store"] = security_store

    @jwt.token_in_blocklist_loader
    def is_token_revoked(jwt_header, jwt_payload):
        return security_store.is_token_revoked(jti=jwt_payload.get("jti", ""))


def _ensure_default_admin(app: Flask) -> None:
    username = app.config["ADMIN_DEFAULT_USERNAME"]
    password = app.config["ADMIN_DEFAULT_PASSWORD"]

    user = AdminUser.query.filter_by(username=username).first()
    if user is None:
        user = AdminUser(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()


def _register_cli_commands(app: Flask) -> None:
    @app.cli.command("init-db")
    def init_db_command():
        db.create_all()
        _ensure_default_admin(app)
        click.echo("Database initialized.")


def _schema_ready() -> bool:
    inspector = inspect(db.engine)
    return inspector.has_table("admin_users")
