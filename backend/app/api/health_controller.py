from flask import Blueprint

from app.container import get_service
from app.utils import api_success

health_bp = Blueprint("health", __name__)


@health_bp.get("/health")
def health_check():
    health_service = get_service("health_service")
    return api_success(health_service.liveness())


@health_bp.get("/health/details")
def health_details():
    health_service = get_service("health_service")
    return api_success(health_service.readiness())
