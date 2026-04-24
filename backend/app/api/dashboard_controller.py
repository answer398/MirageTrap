from datetime import datetime, timedelta, timezone

from flask import Blueprint, request
from flask_jwt_extended import jwt_required

from app.container import get_service
from app.utils import api_error, api_success

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.get("/dashboard/overview")
@jwt_required()
def get_overview():
    hours, _, error = _parse_window_args(default_limit=20)
    if error:
        return api_error(error, status=422, code="VALIDATION_ERROR")

    dashboard_service = get_service("dashboard_service")
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
    data = dashboard_service.get_overview(start_time=start_time)
    return api_success(data)


@dashboard_bp.get("/dashboard/global-map")
@jwt_required()
def get_global_map():
    hours, limit, error = _parse_window_args()
    if error:
        return api_error(error, status=422, code="VALIDATION_ERROR")

    dashboard_service = get_service("dashboard_service")
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
    return api_success(dashboard_service.get_global_map(start_time=start_time, limit=limit))


@dashboard_bp.get("/dashboard/trends")
@jwt_required()
def get_trends():
    hours, _, error = _parse_window_args(default_limit=24)
    if error:
        return api_error(error, status=422, code="VALIDATION_ERROR")

    dashboard_service = get_service("dashboard_service")
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
    return api_success(dashboard_service.get_trends(start_time=start_time, window_hours=hours))


@dashboard_bp.get("/dashboard/top-attackers")
@jwt_required()
def get_top_attackers():
    hours, limit, error = _parse_window_args()
    if error:
        return api_error(error, status=422, code="VALIDATION_ERROR")

    dashboard_service = get_service("dashboard_service")
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
    return api_success(dashboard_service.get_top_attackers(start_time=start_time, limit=limit))


@dashboard_bp.get("/dashboard/attack-types")
@jwt_required()
def get_attack_types():
    hours, limit, error = _parse_window_args()
    if error:
        return api_error(error, status=422, code="VALIDATION_ERROR")

    dashboard_service = get_service("dashboard_service")
    start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
    return api_success(
        dashboard_service.get_attack_type_distribution(start_time=start_time, limit=limit)
    )


def _parse_window_args(default_hours: int = 24, default_limit: int = 20) -> tuple[int, int, str | None]:
    hours = request.args.get("hours", default=default_hours, type=int)
    limit = request.args.get("limit", default=default_limit, type=int)

    if hours is None or hours <= 0 or hours > 720:
        return 0, 0, "hours 取值范围为 1~720"
    if limit is None or limit <= 0 or limit > 200:
        return 0, 0, "limit 取值范围为 1~200"

    return hours, limit, None
