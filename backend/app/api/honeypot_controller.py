from flask import Blueprint, current_app, request
from flask_jwt_extended import jwt_required

from app.container import get_service
from app.utils import api_error, api_success, get_client_ip

honeypot_bp = Blueprint("honeypots", __name__)


@honeypot_bp.get("/honeypots/catalog")
@jwt_required()
def honeypot_catalog():
    honeypot_service = get_service("honeypot_service")
    return api_success(honeypot_service.catalog())


@honeypot_bp.get("/honeypots")
@jwt_required()
def list_honeypots():
    page = request.args.get("page", default=1, type=int)
    page_size = request.args.get("page_size", default=20, type=int)

    honeypot_service = get_service("honeypot_service")
    data = honeypot_service.list_instances(page=page, page_size=page_size)
    return api_success(data)


@honeypot_bp.post("/honeypots")
@jwt_required()
def create_honeypot():
    payload = request.get_json(silent=True) or {}

    honeypot_service = get_service("honeypot_service")
    data, error = honeypot_service.create_instance(payload)
    if error:
        return api_error(error, status=422, code="VALIDATION_ERROR")
    return api_success(data, message="蜜罐实例创建成功", status=201)


@honeypot_bp.get("/honeypots/<int:instance_id>")
@jwt_required()
def get_honeypot(instance_id: int):
    honeypot_service = get_service("honeypot_service")
    item = honeypot_service.get_instance(instance_id)
    if item is None:
        return api_error("蜜罐实例不存在", status=404, code="NOT_FOUND")
    return api_success(item.to_dict(timeout_seconds=current_app.config["HONEYPOT_HEARTBEAT_TIMEOUT_SECONDS"]))


@honeypot_bp.post("/honeypots/<int:instance_id>/start")
@jwt_required()
def start_honeypot(instance_id: int):
    honeypot_service = get_service("honeypot_service")
    data, error, status_code = honeypot_service.start_instance(instance_id)
    if error:
        return api_error(
            error,
            status=status_code or 422,
            code="RUNTIME_ERROR" if status_code == 502 else "NOT_FOUND" if status_code == 404 else "VALIDATION_ERROR",
        )
    return api_success(data, message="蜜罐实例已启动")


@honeypot_bp.post("/honeypots/<int:instance_id>/stop")
@jwt_required()
def stop_honeypot(instance_id: int):
    honeypot_service = get_service("honeypot_service")
    data, error, status_code = honeypot_service.stop_instance(instance_id)
    if error:
        return api_error(
            error,
            status=status_code or 422,
            code="RUNTIME_ERROR" if status_code == 502 else "NOT_FOUND" if status_code == 404 else "VALIDATION_ERROR",
        )
    return api_success(data, message="蜜罐实例已停止")


@honeypot_bp.delete("/honeypots/<int:instance_id>")
@jwt_required()
def delete_honeypot(instance_id: int):
    honeypot_service = get_service("honeypot_service")
    data, error, status_code = honeypot_service.delete_instance(instance_id)
    if error:
        return api_error(
            error,
            status=status_code or 422,
            code="RUNTIME_ERROR" if status_code == 502 else "NOT_FOUND" if status_code == 404 else "VALIDATION_ERROR",
        )
    return api_success(data, message="蜜罐实例已删除")


@honeypot_bp.post("/honeypots/heartbeat")
def honeypot_heartbeat():
    control_token = request.headers.get("X-Honeypot-Token", "") or request.headers.get("X-Ingest-Token", "")
    if control_token != current_app.config["HONEYPOT_CONTROL_TOKEN"]:
        return api_error("控制令牌无效", status=401, code="INVALID_CONTROL_TOKEN")

    payload = request.get_json(silent=True) or {}
    honeypot_service = get_service("honeypot_service")
    data, error = honeypot_service.record_heartbeat(payload, collector_ip=get_client_ip(request))
    if error:
        return api_error(error, status=422, code="VALIDATION_ERROR")
    return api_success(data, message="心跳接收成功")
