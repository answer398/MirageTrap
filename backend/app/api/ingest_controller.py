from flask import Blueprint, current_app, request

from app.container import get_service
from app.utils import api_error, api_success, get_client_ip

ingest_bp = Blueprint("ingest", __name__)


@ingest_bp.post("/ingest/events")
def ingest_event():
    ingest_token = request.headers.get("X-Ingest-Token", "")
    if ingest_token != current_app.config["INGEST_TOKEN"]:
        return api_error("采集令牌无效", status=401, code="INVALID_INGEST_TOKEN")

    payload = request.get_json(silent=True) or {}

    attack_ingest_service = get_service("attack_ingest_service")
    result, error = attack_ingest_service.ingest_event(payload=payload, collector_ip=get_client_ip(request))

    if error:
        return api_error(error, status=422, code="VALIDATION_ERROR")

    return api_success(result, message="事件接收成功", status=201)
