from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlsplit


def build_request_record(payload: dict) -> dict:
    method = str(payload.get("method") or "GET").strip().upper() or "GET"
    raw_path = str(payload.get("path") or payload.get("url") or "/").strip() or "/"
    split = urlsplit(raw_path)
    path = split.path or "/"
    query_string = str(payload.get("query_string") or split.query or "").strip()

    headers = _normalize_mapping(payload.get("headers"))
    params = _normalize_mapping(payload.get("params"))
    if not params and query_string:
        params = {key: value for key, value in parse_qsl(query_string, keep_blank_values=True)}

    body = str(payload.get("body") or payload.get("request_body") or "").strip()
    raw_request = str(payload.get("raw_request") or "").strip()

    return {
        "request_id": str(payload.get("request_id") or "").strip() or None,
        "method": method,
        "path": path,
        "query_string": query_string,
        "headers": headers,
        "params": params,
        "body": body,
        "raw_request": raw_request,
    }


def build_response_record(payload: dict) -> dict:
    status = payload.get("response_status")
    try:
        status_code = int(status) if status is not None else 200
    except (TypeError, ValueError):
        status_code = 200

    headers = _normalize_mapping(payload.get("response_headers"))
    body = str(payload.get("response_body") or payload.get("response_content") or "").strip()

    return {
        "status": status_code,
        "headers": headers,
        "body": body,
    }


def serialize_request_record(record: dict) -> str:
    return json.dumps(record, ensure_ascii=False, sort_keys=True)


def serialize_response_record(record: dict) -> str:
    return json.dumps(record, ensure_ascii=False, sort_keys=True)


def parse_request_content(raw: str | None) -> dict:
    text = str(raw or "").strip()
    if not text:
        return {
            "request_id": None,
            "method": "",
            "path": "",
            "query_string": "",
            "headers": {},
            "params": {},
            "body": "",
            "raw_request": "",
        }

    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return {
                "request_id": parsed.get("request_id"),
                "method": str(parsed.get("method") or "").strip().upper(),
                "path": str(parsed.get("path") or "").strip(),
                "query_string": str(parsed.get("query_string") or "").strip(),
                "headers": _normalize_mapping(parsed.get("headers")),
                "params": _normalize_mapping(parsed.get("params")),
                "body": str(parsed.get("body") or "").strip(),
                "raw_request": str(parsed.get("raw_request") or "").strip(),
            }
    except json.JSONDecodeError:
        pass

    return _parse_legacy_request_text(text)


def parse_response_content(raw: str | None) -> dict:
    text = str(raw or "").strip()
    if not text:
        return {"status": 200, "headers": {}, "body": ""}

    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return {
                "status": int(parsed.get("status") or 200),
                "headers": _normalize_mapping(parsed.get("headers")),
                "body": str(parsed.get("body") or "").strip(),
            }
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    return {"status": 200, "headers": {}, "body": text}


def build_analysis_text(record: dict) -> str:
    parts = [
        str(record.get("method") or ""),
        str(record.get("path") or ""),
        str(record.get("query_string") or ""),
        json.dumps(record.get("params") or {}, ensure_ascii=False, sort_keys=True),
        json.dumps(record.get("headers") or {}, ensure_ascii=False, sort_keys=True),
        str(record.get("body") or ""),
        str(record.get("raw_request") or ""),
    ]
    return "\n".join(item for item in parts if item)


def request_preview(record: dict) -> str:
    method = str(record.get("method") or "").strip().upper() or "GET"
    path = str(record.get("path") or "").strip() or "/"
    query_string = str(record.get("query_string") or "").strip()
    return f"{method} {path}{('?' + query_string) if query_string else ''}"


def _normalize_mapping(value) -> dict:
    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items()}

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, dict):
            return {str(key): str(item) for key, item in parsed.items()}

    return {}


def _parse_legacy_request_text(text: str) -> dict:
    lines = [line.rstrip() for line in text.splitlines()]
    first_line = lines[0] if lines else ""
    method = ""
    path = ""
    if " " in first_line:
        maybe_method, maybe_path = first_line.split(" ", 1)
        if maybe_method.isalpha():
            method = maybe_method.upper()
            path = maybe_path.strip()

    headers = {}
    body = ""
    for line in lines[1:]:
        if line.startswith("host="):
            headers["Host"] = line.split("=", 1)[1]
        elif line.startswith("user_agent="):
            headers["User-Agent"] = line.split("=", 1)[1]
        elif line.startswith("referer="):
            headers["Referer"] = line.split("=", 1)[1]
        elif line.startswith("content_type="):
            headers["Content-Type"] = line.split("=", 1)[1]
        elif line.startswith("body="):
            body = line.split("=", 1)[1]

    split = urlsplit(path or "/")
    return {
        "request_id": None,
        "method": method,
        "path": split.path or path or "/",
        "query_string": split.query,
        "headers": headers,
        "params": {key: value for key, value in parse_qsl(split.query, keep_blank_values=True)},
        "body": body,
        "raw_request": text,
    }
