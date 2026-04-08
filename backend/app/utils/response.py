from flask import jsonify


def api_success(data=None, message: str = "ok", status: int = 200):
    return (
        jsonify(
            {
                "success": True,
                "message": message,
                "data": data,
            }
        ),
        status,
    )


def api_error(message: str, status: int = 400, code: str = "BAD_REQUEST", errors=None):
    return (
        jsonify(
            {
                "success": False,
                "message": message,
                "code": code,
                "errors": errors,
            }
        ),
        status,
    )
