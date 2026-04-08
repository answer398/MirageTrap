from flask import Blueprint
from flask_jwt_extended import jwt_required

from app.container import get_service
from app.utils import api_error, api_success

replay_bp = Blueprint("replay", __name__)


@replay_bp.get("/replay/<string:session_id>/timeline")
@jwt_required()
def get_session_timeline(session_id: str):
    replay_service = get_service("replay_service")
    data = replay_service.get_session_timeline(session_id)

    if data is None:
        return api_error("攻击会话不存在", status=404, code="NOT_FOUND")

    return api_success(data)


@replay_bp.get("/replay/<string:source_ip>")
@jwt_required()
def get_ip_replay(source_ip: str):
    replay_service = get_service("replay_service")
    return api_success(replay_service.get_ip_replay(source_ip))
