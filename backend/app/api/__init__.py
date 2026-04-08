from flask import Blueprint

from app.api.attack_controller import attack_bp
from app.api.auth_controller import auth_bp
from app.api.dashboard_controller import dashboard_bp
from app.api.evidence_controller import evidence_bp
from app.api.health_controller import health_bp
from app.api.honeypot_controller import honeypot_bp
from app.api.ingest_controller import ingest_bp
from app.api.replay_controller import replay_bp
from app.api.session_controller import session_bp


api_bp = Blueprint("api", __name__, url_prefix="/api")


def register_blueprints(app):
    api_bp.register_blueprint(health_bp)
    api_bp.register_blueprint(auth_bp)
    api_bp.register_blueprint(ingest_bp)
    api_bp.register_blueprint(honeypot_bp)
    api_bp.register_blueprint(attack_bp)
    api_bp.register_blueprint(session_bp)
    api_bp.register_blueprint(replay_bp)
    api_bp.register_blueprint(evidence_bp)
    api_bp.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp)
