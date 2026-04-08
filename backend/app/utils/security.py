from flask import Request


def get_client_ip(request: Request) -> str:
    x_forwarded_for = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if x_forwarded_for:
        return x_forwarded_for
    return request.remote_addr or "unknown"
