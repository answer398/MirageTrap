from flask import Blueprint, request
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required

from app.container import get_service
from app.utils import api_error, api_success, get_client_ip

auth_bp = Blueprint("auth", __name__)


@auth_bp.post("/auth/login")
def login():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        payload = request.form.to_dict() if request.form else {}

    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""

    if not username or not password:
        return api_error("username 和 password 不能为空", status=422, code="VALIDATION_ERROR")

    auth_service = get_service("auth_service")
    result, error = auth_service.authenticate(
        username=username,
        password=password,
        source_ip=get_client_ip(request),
    )

    if error:
        if error == auth_service.RATE_LIMITED_MESSAGE:
            return api_error(error, status=429, code="RATE_LIMITED")
        return api_error(error, status=401, code="AUTH_FAILED")

    return api_success(result, message="登录成功")


@auth_bp.post("/auth/logout")
@jwt_required()
def logout():
    claims = get_jwt()
    username = claims.get("username", "unknown")
    user_id = str(get_jwt_identity())

    auth_service = get_service("auth_service")
    auth_service.logout(
        jti=claims["jti"],
        username=username,
        user_id=user_id,
        source_ip=get_client_ip(request),
        token_exp=claims.get("exp"),
    )

    return api_success(message="退出成功")


@auth_bp.get("/auth/profile")
@jwt_required()
def profile():
    user_id = int(get_jwt_identity())
    auth_service = get_service("auth_service")

    user = auth_service.get_profile(user_id)
    if user is None:
        return api_error("用户不存在", status=404, code="NOT_FOUND")

    return api_success(user.to_profile())
