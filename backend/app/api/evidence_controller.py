from io import BytesIO

from flask import Blueprint, send_file
from flask_jwt_extended import jwt_required

from app.container import get_service
from app.utils import api_error, api_success

evidence_bp = Blueprint("evidence", __name__)


@evidence_bp.get("/evidence/<string:session_id>")
@jwt_required()
def get_evidence(session_id: str):
    evidence_service = get_service("evidence_service")
    data = evidence_service.get_session_evidence(session_id)

    if data is None:
        return api_error("攻击会话不存在", status=404, code="NOT_FOUND")

    return api_success(data)


@evidence_bp.post("/evidence/<string:session_id>/export")
@jwt_required()
def export_evidence(session_id: str):
    from flask import request

    export_format = request.args.get("format", default="json", type=str) or "json"
    evidence_service = get_service("evidence_service")
    data, error = evidence_service.export_session_evidence(
        session_id,
        export_format=export_format,
    )

    if error:
        if error == "攻击会话不存在":
            return api_error(error, status=404, code="NOT_FOUND")
        if error == "仅支持 json/pcap 导出格式":
            return api_error(error, status=422, code="VALIDATION_ERROR")
        return api_error(error, status=500, code="STORAGE_ERROR")

    return api_success(data, message="证据包导出成功", status=201)


@evidence_bp.get("/files/<int:file_id>")
@jwt_required()
def get_file(file_id: int):
    evidence_service = get_service("evidence_service")
    item = evidence_service.get_file(file_id)

    if item is None:
        return api_error("证据文件不存在", status=404, code="NOT_FOUND")

    return api_success(item.to_dict())


@evidence_bp.get("/files/<int:file_id>/download")
@jwt_required()
def download_file(file_id: int):
    evidence_service = get_service("evidence_service")
    data, error = evidence_service.get_file_download(file_id)
    if error:
        if error == "证据文件不存在":
            return api_error(error, status=404, code="NOT_FOUND")
        return api_error(error, status=500, code="STORAGE_ERROR")

    return send_file(
        BytesIO(data["bytes"]),
        mimetype=data["content_type"],
        as_attachment=True,
        download_name=data["download_name"],
    )


@evidence_bp.get("/files/<int:file_id>/verify")
@jwt_required()
def verify_file(file_id: int):
    evidence_service = get_service("evidence_service")
    data, error = evidence_service.verify_file_integrity(file_id)
    if error:
        if error == "证据文件不存在":
            return api_error(error, status=404, code="NOT_FOUND")
        return api_error(error, status=500, code="STORAGE_ERROR")
    return api_success(data)
