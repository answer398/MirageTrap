from flask import Blueprint, request
from flask_jwt_extended import jwt_required

from app.container import get_service
from app.utils import api_error, api_success

session_bp = Blueprint("sessions", __name__)


@session_bp.get("/sessions")
@jwt_required()
def list_sessions():
    page = request.args.get("page", default=1, type=int)
    page_size = request.args.get("page_size", default=20, type=int)

    source_ip = request.args.get("source_ip")
    honeypot_type = request.args.get("honeypot_type")
    risk_level = request.args.get("risk_level")

    session_service = get_service("session_service")
    data = session_service.list_sessions(
        page=page,
        page_size=page_size,
        source_ip=source_ip,
        honeypot_type=honeypot_type,
        risk_level=risk_level,
    )

    return api_success(data)


@session_bp.get("/sessions/<string:session_id>")
@jwt_required()
def get_session(session_id: str):
    session_service = get_service("session_service")
    session = session_service.get_session(session_id)

    if session is None:
        return api_error("攻击会话不存在", status=404, code="NOT_FOUND")

    return api_success(session.to_dict())


@session_bp.get("/sessions/ip/<string:source_ip>")
@jwt_required()
def get_sessions_by_ip(source_ip: str):
    page = request.args.get("page", default=1, type=int)
    page_size = request.args.get("page_size", default=20, type=int)

    session_service = get_service("session_service")
    data = session_service.list_sessions(page=page, page_size=page_size, source_ip=source_ip)

    return api_success(data)
