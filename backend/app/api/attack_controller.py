from flask import Blueprint, request
from flask_jwt_extended import jwt_required

from app.container import get_service
from app.utils import api_error, api_success, parse_iso_datetime

attack_bp = Blueprint("attacks", __name__)


@attack_bp.get("/attacks")
@jwt_required()
def list_attacks():
    data, error = _query_attacks()
    if error:
        return api_error(error, status=422, code="VALIDATION_ERROR")
    return api_success(data)


@attack_bp.get("/attacks/search")
@jwt_required()
def search_attacks():
    data, error = _query_attacks()
    if error:
        return api_error(error, status=422, code="VALIDATION_ERROR")
    return api_success(data)


@attack_bp.get("/attacks/<int:event_id>")
@jwt_required()
def get_attack(event_id: int):
    attack_query_service = get_service("attack_query_service")
    event = attack_query_service.get_attack(event_id)

    if event is None:
        return api_error("攻击事件不存在", status=404, code="NOT_FOUND")

    return api_success(event)


@attack_bp.get("/attacks/<int:event_id>/traffic")
@jwt_required()
def get_attack_traffic(event_id: int):
    attack_query_service = get_service("attack_query_service")
    event = attack_query_service.get_attack(event_id)

    if event is None:
        return api_error("攻击事件不存在", status=404, code="NOT_FOUND")

    return api_success(
        {
            "event_id": event["id"],
            "request_preview": event["request_preview"],
            "request": event["request"],
            "response": event["response"],
        }
    )


def _query_attacks() -> tuple[dict | None, str | None]:
    page = request.args.get("page", default=1, type=int)
    page_size = request.args.get("page_size", default=20, type=int)

    source_ip = request.args.get("source_ip")
    honeypot_type = request.args.get("honeypot_type")
    risk_level = request.args.get("risk_level")
    session_id = request.args.get("session_id")

    start_time = parse_iso_datetime(request.args.get("start_time"))
    end_time = parse_iso_datetime(request.args.get("end_time"))

    attack_query_service = get_service("attack_query_service")
    data = attack_query_service.list_attacks(
        page=page,
        page_size=page_size,
        source_ip=source_ip,
        honeypot_type=honeypot_type,
        risk_level=risk_level,
        start_time=start_time,
        end_time=end_time,
        session_id=session_id,
    )
    return data, None
