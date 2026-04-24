from datetime import datetime
from io import BytesIO

from flask import Blueprint, request, send_file
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


@attack_bp.get("/attacks/export")
@jwt_required()
def export_attacks():
    filters, error = _collect_attack_filters()
    if error:
        return api_error(error, status=422, code="VALIDATION_ERROR")

    attack_query_service = get_service("attack_query_service")
    payload = attack_query_service.export_attacks(**filters)
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")

    return send_file(
        BytesIO(payload),
        mimetype="text/csv; charset=utf-8",
        as_attachment=True,
        download_name=f"attacks-export-{timestamp}.csv",
    )


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


@attack_bp.delete("/attacks/<int:event_id>")
@jwt_required()
def delete_attack(event_id: int):
    attack_command_service = get_service("attack_command_service")
    data, error = attack_command_service.delete_attack(event_id)

    if error:
        status = 404 if error == "攻击事件不存在" else 422
        code = "NOT_FOUND" if status == 404 else "VALIDATION_ERROR"
        return api_error(error, status=status, code=code)

    return api_success(data, message="攻击事件删除成功")


@attack_bp.post("/attacks/bulk-delete")
@jwt_required()
def bulk_delete_attacks():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        payload = {}

    attack_command_service = get_service("attack_command_service")
    data, error = attack_command_service.delete_attacks(payload.get("ids") or [])

    if error:
        status = 404 if error == "攻击事件不存在" else 422
        code = "NOT_FOUND" if status == 404 else "VALIDATION_ERROR"
        return api_error(error, status=status, code=code)

    return api_success(data, message="攻击事件批量删除成功")


def _query_attacks() -> tuple[dict | None, str | None]:
    page = request.args.get("page", default=1, type=int)
    page_size = request.args.get("page_size", default=20, type=int)
    filters, error = _collect_attack_filters()
    if error:
        return None, error

    attack_query_service = get_service("attack_query_service")
    data = attack_query_service.list_attacks(
        page=page,
        page_size=page_size,
        **filters,
    )
    return data, None


def _collect_attack_filters() -> tuple[dict | None, str | None]:
    event_ids, event_ids_error = _parse_event_ids_arg(request.args.get("ids"))
    if event_ids_error:
        return None, event_ids_error

    source_ip = request.args.get("source_ip")
    honeypot_id = request.args.get("honeypot_id")
    honeypot_type = request.args.get("honeypot_type")
    risk_level = request.args.get("risk_level")
    event_type = request.args.get("event_type")
    session_id = request.args.get("session_id")
    keyword = request.args.get("keyword")
    sort_by = request.args.get("sort_by")
    sort_dir = request.args.get("sort_dir")

    start_time = parse_iso_datetime(request.args.get("start_time"))
    end_time = parse_iso_datetime(request.args.get("end_time"))
    if start_time and end_time and start_time > end_time:
        return None, "开始时间不能晚于结束时间"

    return (
        {
            "event_ids": event_ids,
            "source_ip": source_ip,
            "honeypot_id": honeypot_id,
            "honeypot_type": honeypot_type,
            "risk_level": risk_level,
            "event_type": event_type,
            "session_id": session_id,
            "keyword": keyword,
            "sort_by": sort_by,
            "sort_dir": sort_dir,
            "start_time": start_time,
            "end_time": end_time,
        },
        None,
    )


def _parse_event_ids_arg(raw_value: str | None) -> tuple[list[int] | None, str | None]:
    text = str(raw_value or "").strip()
    if not text:
        return None, None

    event_ids = []
    seen = set()
    for item in text.split(","):
        candidate = item.strip()
        if not candidate:
            continue
        try:
            event_id = int(candidate)
        except ValueError:
            return None, "导出事件 ID 参数无效"
        if event_id <= 0 or event_id in seen:
            continue
        seen.add(event_id)
        event_ids.append(event_id)

    if not event_ids:
        return None, "至少选择一条攻击事件"
    return event_ids, None
