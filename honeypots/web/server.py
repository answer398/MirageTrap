from __future__ import annotations

import json
import os
import re
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import error, request
from urllib.parse import parse_qsl, urlsplit
from uuid import uuid4

INGEST_API_URL = os.getenv("INGEST_API_URL", "http://backend-api:15000/api/ingest/events")
HEARTBEAT_API_URL = os.getenv("HEARTBEAT_API_URL", "http://backend-api:15000/api/honeypots/heartbeat")
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "dev-ingest-token")
HONEYPOT_CONTROL_TOKEN = os.getenv("HONEYPOT_CONTROL_TOKEN", INGEST_TOKEN)
HONEYPOT_ID = os.getenv("HONEYPOT_ID", "hp-web-compose-001")
HONEYPOT_NAME = os.getenv("HONEYPOT_NAME", HONEYPOT_ID)
HONEYPOT_IMAGE_KEY = os.getenv("HONEYPOT_IMAGE_KEY", "web_portal")
HONEYPOT_IMAGE_NAME = os.getenv("HONEYPOT_IMAGE_NAME", "miragetrap/web-honeypot:latest")
HONEYPOT_CONTAINER_NAME = os.getenv("HONEYPOT_CONTAINER_NAME", os.getenv("HOSTNAME", HONEYPOT_ID))
HONEYPOT_PROFILE = os.getenv("HONEYPOT_PROFILE", "portal").strip().lower() or "portal"
HONEYPOT_EXPOSED_PORT = int(os.getenv("HONEYPOT_EXPOSED_PORT", "18080"))
WEB_HONEYPOT_PORT = int(os.getenv("WEB_HONEYPOT_PORT", "80"))
WEB_HONEYPOT_MAX_BODY = max(int(os.getenv("WEB_HONEYPOT_MAX_BODY", "8192")), 512)
HEARTBEAT_INTERVAL_SECONDS = max(int(os.getenv("HEARTBEAT_INTERVAL_SECONDS", "15")), 5)
SESSION_TTL_SECONDS = max(int(os.getenv("SESSION_TTL_SECONDS", "21600")), 1800)

_SESSION_COOKIE = "NBSESSID"
_SESSION_LOCK = threading.Lock()
_SESSIONS: dict[str, dict] = {}
_UPLOADS: list[dict] = []

_PROFILE_CONFIG = {
    "portal": {
        "brand": "Northbridge Identity Hub",
        "subtitle": "Federated access for employees, vendors and regional operations teams.",
        "accent": "Identity Service",
        "landing_path": "/login",
    },
    "search": {
        "brand": "Atlas Knowledge Exchange",
        "subtitle": "Cross-region search for runbooks, contracts and service advisories.",
        "accent": "Knowledge Service",
        "landing_path": "/search",
    },
    "admin": {
        "brand": "Aegis Operations Suite",
        "subtitle": "Operations orchestration, billing exceptions and incident response workflows.",
        "accent": "Operations Service",
        "landing_path": "/admin",
    },
}

_FAKE_USERS = [
    {"username": "amy.chen", "display_name": "Amy Chen", "role": "Identity Admin", "region": "APAC"},
    {"username": "leon.wu", "display_name": "Leon Wu", "role": "Billing Reviewer", "region": "CN-North"},
    {"username": "d.smith", "display_name": "Daniel Smith", "role": "Vendor Ops", "region": "EU-West"},
]

_FAKE_REPORTS = [
    {"name": "Quarterly License Reconciliation", "owner": "Billing Ops", "status": "scheduled", "updated_at": "2026-04-08 09:00"},
    {"name": "SSO Failure Domain Audit", "owner": "IAM", "status": "ready", "updated_at": "2026-04-08 08:20"},
    {"name": "Supplier Certificate Rollup", "owner": "Vendor Access", "status": "exporting", "updated_at": "2026-04-08 07:55"},
]

_FAKE_DOCUMENTS = [
    {"title": "SAML Certificate Rotation Runbook", "owner": "IAM", "tags": ["sso", "certificate"], "classification": "internal"},
    {"title": "Vendor Federation Onboarding Checklist", "owner": "Vendor Access", "tags": ["supplier", "federation"], "classification": "internal"},
    {"title": "Invoice Hold Release SOP", "owner": "Billing Ops", "tags": ["billing", "invoice"], "classification": "restricted"},
    {"title": "Legacy XML Adapter Mapping", "owner": "Integration Team", "tags": ["xml", "mapping"], "classification": "restricted"},
    {"title": "Escalation Matrix 2026", "owner": "Operations", "tags": ["support", "incident"], "classification": "internal"},
]

_FAKE_INVOICES = [
    {"invoice_no": "INV-20260408-101", "supplier": "BluePeak Logistics", "status": "pending", "amount": "$18,245.32"},
    {"invoice_no": "INV-20260408-114", "supplier": "ClearVector Networks", "status": "on_hold", "amount": "$7,912.00"},
    {"invoice_no": "INV-20260408-118", "supplier": "TransHarbor Systems", "status": "approved", "amount": "$4,563.79"},
]

_FAKE_ALERTS = [
    {"time": "08:42", "title": "SSO sync latency elevated", "severity": "medium"},
    {"time": "08:27", "title": "Vendor certificate expiring within 72h", "severity": "high"},
    {"time": "07:58", "title": "XML adapter backlog recovered", "severity": "low"},
]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _truncate(text: str) -> str:
    if len(text) <= WEB_HONEYPOT_MAX_BODY:
        return text
    return text[:WEB_HONEYPOT_MAX_BODY] + "...(truncated)"


def _extract_source_ip(handler: BaseHTTPRequestHandler) -> str:
    xff = (handler.headers.get("X-Forwarded-For") or "").strip()
    if xff:
        return xff.split(",")[0].strip()
    return handler.client_address[0] if handler.client_address else "unknown"


def _normalize_headers(handler: BaseHTTPRequestHandler) -> dict:
    return {str(key): str(value) for key, value in handler.headers.items()}


def _parse_json_body(handler: BaseHTTPRequestHandler, body: str):
    content_type = (handler.headers.get("Content-Type") or "").lower()
    if "application/json" not in content_type:
        return None
    try:
        return json.loads(body or "{}")
    except json.JSONDecodeError:
        return None


def _parse_params(handler: BaseHTTPRequestHandler, body: str) -> dict:
    split = urlsplit(handler.path)
    params = {key: value for key, value in parse_qsl(split.query, keep_blank_values=True)}
    content_type = (handler.headers.get("Content-Type") or "").lower()

    if "application/x-www-form-urlencoded" in content_type:
        for key, value in parse_qsl(body, keep_blank_values=True):
            params[key] = value

    json_body = _parse_json_body(handler, body)
    if isinstance(json_body, dict):
        for key, value in json_body.items():
            params[str(key)] = "" if value is None else str(value)

    return params


def _parse_multipart_filename(handler: BaseHTTPRequestHandler, body: str) -> str | None:
    content_type = (handler.headers.get("Content-Type") or "").lower()
    if "multipart/form-data" not in content_type:
        return None
    match = re.search(r'filename="([^"]+)"', body)
    if match:
        return match.group(1)
    return None


def _build_raw_request(handler: BaseHTTPRequestHandler, body: str) -> str:
    request_line = f"{handler.command} {handler.path} HTTP/1.1"
    headers = "\r\n".join(f"{key}: {value}" for key, value in handler.headers.items())
    return f"{request_line}\r\n{headers}\r\n\r\n{body}"


def _resolve_host_ip() -> str:
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


def _profile_meta() -> dict:
    return _PROFILE_CONFIG.get(HONEYPOT_PROFILE, _PROFILE_CONFIG["portal"])


def _html_escape(value) -> str:
    text = str(value or "")
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _table_html(columns: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{_html_escape(item)}</th>" for item in columns)
    if not rows:
        body = f'<tr><td colspan="{len(columns)}" class="empty">No records available.</td></tr>'
    else:
        body = "".join(
            "<tr>" + "".join(f"<td>{_html_escape(value)}</td>" for value in row) + "</tr>"
            for row in rows
        )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _cookie_sid(handler: BaseHTTPRequestHandler) -> str | None:
    raw_cookie = handler.headers.get("Cookie") or ""
    if not raw_cookie:
        return None
    jar = SimpleCookie()
    try:
        jar.load(raw_cookie)
    except Exception:  # noqa: BLE001
        return None
    if _SESSION_COOKIE not in jar:
        return None
    return jar[_SESSION_COOKIE].value.strip() or None


def _prune_runtime_state() -> None:
    cutoff = _utc_now() - timedelta(seconds=SESSION_TTL_SECONDS)
    with _SESSION_LOCK:
        expired = [sid for sid, item in _SESSIONS.items() if item["expires_at"] <= cutoff]
        for sid in expired:
            _SESSIONS.pop(sid, None)
        while len(_UPLOADS) > 40:
            _UPLOADS.pop(0)


def _create_session(username: str, source_ip: str) -> dict:
    clean_username = str(username or "guest").strip() or "guest"
    sid = uuid4().hex
    session = {
        "sid": sid,
        "username": clean_username,
        "display_name": clean_username.replace(".", " ").title(),
        "source_ip": source_ip,
        "created_at": _utc_now(),
        "expires_at": _utc_now() + timedelta(seconds=SESSION_TTL_SECONDS),
        "csrf": uuid4().hex,
    }
    with _SESSION_LOCK:
        _SESSIONS[sid] = session
    return session


def _resolve_session(handler: BaseHTTPRequestHandler) -> dict | None:
    sid = _cookie_sid(handler)
    if not sid:
        return None
    with _SESSION_LOCK:
        session = _SESSIONS.get(sid)
        if session is None:
            return None
        if session["expires_at"] <= _utc_now():
            _SESSIONS.pop(sid, None)
            return None
        session["expires_at"] = _utc_now() + timedelta(seconds=SESSION_TTL_SECONDS)
        return dict(session)


def _destroy_session(handler: BaseHTTPRequestHandler) -> None:
    sid = _cookie_sid(handler)
    if not sid:
        return
    with _SESSION_LOCK:
        _SESSIONS.pop(sid, None)


def _session_cookie_value(session: dict, *, expired: bool = False) -> str:
    if expired:
        return f"{_SESSION_COOKIE}=deleted; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
    return (
        f"{_SESSION_COOKIE}={session['sid']}; Path=/; HttpOnly; SameSite=Lax; "
        f"Max-Age={SESSION_TTL_SECONDS}"
    )


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def _search_results(query: str) -> list[dict]:
    term = str(query or "").strip().lower()
    if not term:
        return list(_FAKE_DOCUMENTS)
    hits = []
    for item in _FAKE_DOCUMENTS:
        corpus = " ".join(
            [
                item["title"],
                item["owner"],
                " ".join(item["tags"]),
                item["classification"],
            ]
        ).lower()
        if term in corpus:
            hits.append(item)
    return hits


def _record_upload(filename: str, session: dict | None) -> dict:
    item = {
        "upload_id": f"UP-{uuid4().hex[:8].upper()}",
        "filename": filename,
        "uploader": (session or {}).get("display_name") or "Guest Upload",
        "status": "queued",
        "created_at": _utc_now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    with _SESSION_LOCK:
        _UPLOADS.append(item)
    return item


def _uploads_snapshot() -> list[dict]:
    with _SESSION_LOCK:
        return list(_UPLOADS[-6:])


def _nav_html(active: str, session: dict | None) -> str:
    items = [
        ("Overview", "/dashboard", "dashboard"),
        ("Reports", "/reports", "reports"),
        ("Search", "/search", "search"),
        ("Uploads", "/upload", "upload"),
        ("XML Gateway", "/api/xml", "xml"),
        ("Ops", "/admin", "admin"),
        ("Status", "/support/status", "status"),
    ]
    links = []
    for label, href, key in items:
        class_name = "nav-link active" if active == key else "nav-link"
        links.append(f'<a href="{href}" class="{class_name}">{_html_escape(label)}</a>')
    auth_link = (
        '<form method="post" action="/logout"><button class="ghost-btn" type="submit">Sign out</button></form>'
        if session
        else '<a href="/login" class="ghost-btn">Sign in</a>'
    )
    return "".join(links) + auth_link


def _render_shell(
    *,
    title: str,
    subtitle: str,
    active_nav: str,
    content_html: str,
    session: dict | None,
    status_html: str = "",
) -> str:
    meta = _profile_meta()
    user_text = (session or {}).get("display_name") or "Guest Session"
    role_text = "Authenticated Session" if session else "Public Entry"
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{_html_escape(title)}</title>
    <style>
      :root {{
        --bg0: #061322;
        --bg1: #0b1e33;
        --bg2: #102843;
        --card: rgba(9, 24, 42, 0.82);
        --line: rgba(110, 201, 244, 0.18);
        --line-strong: rgba(110, 201, 244, 0.34);
        --text: #ebf8ff;
        --muted: rgba(214, 239, 255, 0.72);
        --accent: #7be1ff;
        --warn: #ffd27a;
        --ok: #7effc5;
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        min-height: 100vh;
        color: var(--text);
        font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
        background:
          radial-gradient(circle at 10% 12%, rgba(67, 199, 255, 0.18), transparent 24%),
          radial-gradient(circle at 88% 18%, rgba(83, 123, 255, 0.14), transparent 22%),
          linear-gradient(145deg, var(--bg0), var(--bg1) 46%, var(--bg2));
      }}
      .frame {{
        width: min(1460px, 100%);
        margin: 0 auto;
        padding: 22px;
        display: grid;
        gap: 18px;
      }}
      .topbar, .sidebar, .panel, .card {{
        border: 1px solid var(--line);
        border-radius: 22px;
        background: linear-gradient(180deg, rgba(8, 22, 40, 0.94), rgba(7, 18, 34, 0.9));
        box-shadow: inset 0 0 22px rgba(74, 189, 255, 0.08), 0 20px 60px rgba(0, 0, 0, 0.22);
      }}
      .topbar {{
        padding: 20px 24px;
        display: flex;
        justify-content: space-between;
        gap: 16px;
        align-items: center;
      }}
      .badge {{
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 7px 12px;
        border-radius: 999px;
        border: 1px solid var(--line-strong);
        color: var(--accent);
        font-size: 12px;
        letter-spacing: 0.12em;
        text-transform: uppercase;
      }}
      .title {{
        margin: 10px 0 6px;
        font-size: clamp(30px, 4vw, 50px);
        letter-spacing: 0.03em;
      }}
      .subtitle {{
        margin: 0;
        max-width: 70ch;
        color: var(--muted);
        line-height: 1.6;
      }}
      .hero-meta {{
        min-width: 320px;
        display: grid;
        gap: 6px;
        justify-items: end;
        font-size: 13px;
        color: var(--muted);
      }}
      .layout {{
        display: grid;
        grid-template-columns: 280px minmax(0, 1fr);
        gap: 18px;
      }}
      .sidebar {{
        padding: 18px;
        display: grid;
        gap: 14px;
        align-content: start;
      }}
      .nav-link, .ghost-btn {{
        display: flex;
        align-items: center;
        justify-content: center;
        min-height: 42px;
        border-radius: 14px;
        border: 1px solid rgba(123, 225, 255, 0.12);
        background: rgba(10, 35, 66, 0.58);
        color: var(--text);
        text-decoration: none;
        font: inherit;
        cursor: pointer;
      }}
      .nav-link.active {{
        border-color: var(--line-strong);
        background: linear-gradient(135deg, rgba(25, 112, 185, 0.46), rgba(17, 51, 108, 0.3));
      }}
      .sidebar-card {{
        padding: 14px 16px;
        border-radius: 18px;
        background: rgba(8, 28, 52, 0.72);
        border: 1px solid rgba(123, 225, 255, 0.1);
      }}
      .sidebar-card h3, .panel h2, .card h3 {{
        margin: 0 0 10px;
        font-size: 15px;
        letter-spacing: 0.04em;
      }}
      .sidebar-card p {{
        margin: 0;
        color: var(--muted);
        line-height: 1.6;
        font-size: 13px;
      }}
      .main {{
        display: grid;
        gap: 18px;
      }}
      .panel {{
        padding: 20px;
      }}
      .hero-grid {{
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 14px;
      }}
      .card {{
        padding: 16px;
      }}
      .metric-label {{
        color: var(--muted);
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
      }}
      .metric-value {{
        display: block;
        margin-top: 10px;
        font-size: 30px;
        font-weight: 700;
      }}
      .grid-two {{
        display: grid;
        grid-template-columns: 1.15fr 0.85fr;
        gap: 18px;
      }}
      table {{
        width: 100%;
        border-collapse: collapse;
      }}
      th, td {{
        padding: 12px 10px;
        border-bottom: 1px solid rgba(123, 225, 255, 0.08);
        text-align: left;
        font-size: 13px;
        vertical-align: top;
      }}
      th {{
        color: var(--muted);
      }}
      .pill {{
        display: inline-flex;
        align-items: center;
        padding: 4px 9px;
        border-radius: 999px;
        border: 1px solid rgba(123, 225, 255, 0.18);
        background: rgba(13, 45, 79, 0.62);
        color: var(--accent);
        font-size: 12px;
      }}
      .severity-high {{ color: #ff8e79; }}
      .severity-medium {{ color: var(--warn); }}
      .severity-low {{ color: var(--ok); }}
      .form-grid {{
        display: grid;
        gap: 12px;
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }}
      label {{
        display: grid;
        gap: 6px;
        color: var(--muted);
        font-size: 12px;
      }}
      input, select, textarea, button {{
        width: 100%;
        border-radius: 14px;
        border: 1px solid rgba(123, 225, 255, 0.16);
        background: rgba(9, 28, 51, 0.88);
        color: var(--text);
        padding: 11px 12px;
        font: inherit;
      }}
      button.primary {{
        cursor: pointer;
        background: linear-gradient(135deg, rgba(33, 129, 203, 0.92), rgba(28, 78, 161, 0.88));
      }}
      .stack {{
        display: grid;
        gap: 10px;
      }}
      .muted {{
        color: var(--muted);
      }}
      .status-box {{
        padding: 14px;
        border-radius: 16px;
        border: 1px solid rgba(123, 225, 255, 0.12);
        background: rgba(8, 29, 54, 0.65);
      }}
      .notice-list {{
        display: grid;
        gap: 10px;
      }}
      .notice-item {{
        display: flex;
        justify-content: space-between;
        gap: 12px;
        border-bottom: 1px solid rgba(123, 225, 255, 0.08);
        padding-bottom: 10px;
      }}
      .notice-item:last-child {{
        border-bottom: none;
        padding-bottom: 0;
      }}
      .empty {{
        color: var(--muted);
      }}
      .status-strip {{
        display: grid;
        gap: 8px;
      }}
      .help {{
        font-size: 12px;
        color: var(--muted);
      }}
      @media (max-width: 1080px) {{
        .layout, .grid-two, .hero-grid, .form-grid {{
          grid-template-columns: 1fr;
        }}
        .hero-meta {{
          justify-items: start;
          min-width: 0;
        }}
        .topbar {{
          flex-direction: column;
          align-items: flex-start;
        }}
      }}
    </style>
  </head>
  <body>
    <div class="frame">
      <header class="topbar">
        <div>
          <span class="badge">{_html_escape(meta["accent"])}</span>
          <h1 class="title">{_html_escape(meta["brand"])}</h1>
          <p class="subtitle">{_html_escape(subtitle)}</p>
        </div>
        <div class="hero-meta">
          <div>Instance { _html_escape(HONEYPOT_ID) }</div>
          <div>User { _html_escape(user_text) }</div>
          <div>Access { _html_escape(role_text) }</div>
          <div>Node { _html_escape(HONEYPOT_CONTAINER_NAME) }:{_html_escape(HONEYPOT_EXPOSED_PORT)}</div>
        </div>
      </header>
      <div class="layout">
        <aside class="sidebar">
          {_nav_html(active_nav, session)}
          <div class="sidebar-card">
            <h3>Platform Summary</h3>
            <p>{_html_escape(meta["subtitle"])}</p>
          </div>
          <div class="sidebar-card">
            <h3>Regional Sync</h3>
            <p>APAC identity graph 99.94% healthy. XML relay backlog under 2 minutes. Supplier federation sync at 08:40 UTC.</p>
          </div>
          {status_html}
        </aside>
        <main class="main">
          {content_html}
        </main>
      </div>
    </div>
  </body>
</html>"""


def _status_html() -> str:
    lines = [
        '<div class="sidebar-card status-strip"><h3>Service Notices</h3>',
    ]
    for item in _FAKE_ALERTS:
        lines.append(
            f'<div class="notice-item"><span>{_html_escape(item["time"])}</span>'
            f'<span class="severity-{_html_escape(item["severity"])}">{_html_escape(item["title"])}</span></div>'
        )
    lines.append("</div>")
    return "".join(lines)


def _metrics_cards(session: dict | None) -> str:
    values = [
        ("Active Sessions", len(_SESSIONS) if session else 14),
        ("Queued Exports", 3),
        ("Pending Invoices", 7),
        ("XML Jobs", 12),
    ]
    cards = []
    for label, value in values:
        cards.append(
            f'<article class="card"><span class="metric-label">{_html_escape(label)}</span>'
            f'<strong class="metric-value">{_html_escape(value)}</strong></article>'
        )
    return f'<section class="hero-grid">{"".join(cards)}</section>'


def _dashboard_page(session: dict | None) -> str:
    reports = _table_html(
        ["Report", "Owner", "Status", "Updated"],
        [[item["name"], item["owner"], item["status"], item["updated_at"]] for item in _FAKE_REPORTS],
    )
    invoices = _table_html(
        ["Invoice", "Supplier", "Status", "Amount"],
        [[item["invoice_no"], item["supplier"], item["status"], item["amount"]] for item in _FAKE_INVOICES],
    )
    alerts = "".join(
        f'<div class="notice-item"><strong>{_html_escape(item["title"])}</strong><span class="severity-{_html_escape(item["severity"])}">{_html_escape(item["severity"])}</span></div>'
        for item in _FAKE_ALERTS
    )
    return (
        _metrics_cards(session)
        + f"""
        <section class="grid-two">
          <article class="panel">
            <h2>Operational Reports</h2>
            <p class="muted">Scheduled reconciliations, identity audit outputs and vendor certificate reviews.</p>
            {reports}
          </article>
          <article class="panel">
            <h2>Incident Notes</h2>
            <div class="notice-list">{alerts}</div>
          </article>
        </section>
        <section class="grid-two">
          <article class="panel">
            <h2>Invoice Exceptions</h2>
            {invoices}
          </article>
          <article class="panel">
            <h2>Authenticated Access</h2>
            <div class="status-box">
              <div class="pill">Session Context</div>
              <p class="muted">Signed in as {_html_escape((session or {}).get("display_name") or "Guest")} from {_html_escape((session or {}).get("source_ip") or "external gateway")}.</p>
              <p class="muted">Token refresh window 30 minutes. Attachment and XML export workflows require elevated approval.</p>
            </div>
          </article>
        </section>
        """
    )


def _login_page(next_path: str = "/dashboard", error_text: str = "") -> str:
    error_html = (
        f'<div class="status-box"><strong class="severity-high">Authentication Failed</strong><p class="muted">{_html_escape(error_text)}</p></div>'
        if error_text
        else ""
    )
    return f"""
      <section class="panel">
        <h2>Federated Login</h2>
        <p class="muted">Use enterprise credentials or supplier access tokens to continue.</p>
        {error_html}
        <form class="form-grid" method="post" action="/login">
          <input type="hidden" name="next" value="{_html_escape(next_path)}" />
          <label>Username
            <input name="username" type="text" placeholder="amy.chen" />
          </label>
          <label>Password
            <input name="password" type="password" placeholder="Password" />
          </label>
          <label>Tenant
            <select name="tenant">
              <option value="corp">corp</option>
              <option value="supplier">supplier</option>
              <option value="legacy">legacy</option>
            </select>
          </label>
          <label>MFA Mode
            <select name="mfa">
              <option value="push">push</option>
              <option value="totp">totp</option>
              <option value="sms">sms</option>
            </select>
          </label>
          <div class="stack">
            <button class="primary" type="submit">Sign in</button>
            <span class="help">Emergency access is temporarily restricted during backend maintenance.</span>
          </div>
        </form>
      </section>
      <section class="grid-two">
        <article class="panel">
          <h2>Identity Domains</h2>
          {_table_html(
              ["Domain", "Region", "Trust State"],
              [
                  ["corp.northbridge.local", "APAC", "healthy"],
                  ["vendor.federation.partner", "Global", "review"],
                  ["legacy-xml.zone", "CN-North", "migrating"],
              ],
          )}
        </article>
        <article class="panel">
          <h2>Maintenance Window</h2>
          <div class="status-box">
            <div class="pill">Live Notice</div>
            <p class="muted">Service maintenance is active for the SAML certificate store and invoice routing queue. Interactive authentication remains available for approved users.</p>
          </div>
        </article>
      </section>
    """


def _reports_page() -> str:
    return f"""
      <section class="panel">
        <h2>Export Queue</h2>
        <p class="muted">Generate CSV exports for invoice exceptions, certificate expirations and federation activity.</p>
        <form class="form-grid" method="post" action="/api/reports/export">
          <label>Report
            <select name="report_name">
              <option value="invoice_exceptions">invoice_exceptions</option>
              <option value="federation_activity">federation_activity</option>
              <option value="certificate_review">certificate_review</option>
            </select>
          </label>
          <label>Region
            <select name="region">
              <option value="global">global</option>
              <option value="apac">apac</option>
              <option value="emea">emea</option>
            </select>
          </label>
          <div class="stack">
            <button class="primary" type="submit">Export CSV</button>
            <span class="help">Large jobs may be staged via background queue.</span>
          </div>
        </form>
      </section>
      <section class="panel">
        <h2>Recent Report Definitions</h2>
        {_table_html(
            ["Name", "Owner", "Status", "Updated"],
            [[item["name"], item["owner"], item["status"], item["updated_at"]] for item in _FAKE_REPORTS],
        )}
      </section>
    """


def _search_page(query: str = "") -> str:
    results = _search_results(query)
    table = _table_html(
        ["Title", "Owner", "Tags", "Class"],
        [[item["title"], item["owner"], ", ".join(item["tags"]), item["classification"]] for item in results],
    )
    return f"""
      <section class="panel">
        <h2>Knowledge Search</h2>
        <form class="form-grid" method="get" action="/search">
          <label>Keyword
            <input name="q" type="text" value="{_html_escape(query)}" placeholder="certificate, invoice, xml" />
          </label>
          <label>Classification
            <select name="scope">
              <option value="all">all</option>
              <option value="internal">internal</option>
              <option value="restricted">restricted</option>
            </select>
          </label>
          <div class="stack">
            <button class="primary" type="submit">Run Search</button>
            <span class="help">Index refresh occurs every 20 minutes.</span>
          </div>
        </form>
      </section>
      <section class="panel">
        <h2>Search Results</h2>
        <p class="muted">{_html_escape(len(results))} results returned for query "{_html_escape(query or '*')}".</p>
        {table}
      </section>
    """


def _upload_page(last_upload: dict | None = None) -> str:
    uploads = _uploads_snapshot()
    note = ""
    if last_upload:
        note = (
            '<div class="status-box"><div class="pill">Upload Accepted</div>'
            f'<p class="muted">File {_html_escape(last_upload["filename"])} was queued as {_html_escape(last_upload["upload_id"])}.</p></div>'
        )
    return f"""
      <section class="panel">
        <h2>Secure File Exchange</h2>
        <p class="muted">Upload contracts, billing evidence and XML samples for controlled review.</p>
        {note}
        <form class="form-grid" method="post" action="/upload" enctype="multipart/form-data">
          <label>Reference
            <input name="reference_id" type="text" placeholder="REQ-240408-01" />
          </label>
          <label>Attachment
            <input name="file" type="file" />
          </label>
          <div class="stack">
            <button class="primary" type="submit">Submit File</button>
            <span class="help">Uploads larger than 25 MB are routed to async validation.</span>
          </div>
        </form>
      </section>
      <section class="panel">
        <h2>Recent Uploads</h2>
        {_table_html(
            ["Upload ID", "Filename", "Uploader", "Status", "Created"],
            [[item["upload_id"], item["filename"], item["uploader"], item["status"], item["created_at"]] for item in uploads],
        )}
      </section>
    """


def _xml_page() -> str:
    return """
      <section class="panel">
        <h2>Legacy XML Gateway</h2>
        <p class="muted">Submit partner XML payloads for downstream adapter validation.</p>
        <form class="stack" method="post" action="/api/xml">
          <label>Payload
            <textarea name="xml" rows="10" placeholder="<request><tenant>corp</tenant><job>invoice</job></request>"></textarea>
          </label>
          <button class="primary" type="submit">Submit XML</button>
        </form>
      </section>
    """


def _admin_page(session: dict | None) -> str:
    auth_hint = (
        "Administrative actions are available for authenticated operations users."
        if session
        else "Read-only preview exposed while live admin cluster is unavailable."
    )
    return f"""
      <section class="grid-two">
        <article class="panel">
          <h2>Operations Console</h2>
          <p class="muted">{_html_escape(auth_hint)}</p>
          {_table_html(
              ["Username", "Display Name", "Role", "Region"],
              [[item["username"], item["display_name"], item["role"], item["region"]] for item in _FAKE_USERS],
          )}
        </article>
        <article class="panel">
          <h2>Control Flags</h2>
          <div class="status-box">
            <div class="pill">Cluster State</div>
            <p class="muted">Invoice hold automation is in guarded mode. XML replay jobs require manual approval and break-glass review.</p>
          </div>
        </article>
      </section>
    """


def _status_page() -> str:
    return """
      <section class="panel">
        <h2>Support Status</h2>
        <div class="status-box">
          <div class="pill">Current State</div>
          <p class="muted">Identity sync, invoice routing and XML adapters are operating in degraded but available mode.</p>
        </div>
      </section>
    """


def _not_found_page(path: str) -> str:
    return f"""
      <section class="panel">
        <h2>Resource Not Found</h2>
        <p class="muted">The requested path {_html_escape(path)} is not registered in the current service partition.</p>
      </section>
    """


def _build_response(
    *,
    status: int,
    content_type: str,
    body,
    headers: dict | None = None,
) -> dict:
    if isinstance(body, str):
        body_bytes = body.encode("utf-8")
    else:
        body_bytes = body

    default_headers = {
        "Cache-Control": "no-store",
        "X-Request-Id": uuid4().hex[:16],
        "X-Service-Profile": HONEYPOT_PROFILE,
        "X-Frame-Options": "SAMEORIGIN",
    }
    if headers:
        default_headers.update(headers)

    return {
        "status": status,
        "content_type": content_type,
        "body": body_bytes,
        "headers": default_headers,
    }


def _redirect(location: str, headers: dict | None = None) -> dict:
    merged = {"Location": location}
    if headers:
        merged.update(headers)
    return _build_response(status=302, content_type="text/html; charset=utf-8", body=b"", headers=merged)


def _unauthorized_json() -> dict:
    return _build_response(
        status=401,
        content_type="application/json; charset=utf-8",
        body=_json_bytes({"success": False, "message": "authentication required"}),
    )


def _landing_page(session: dict | None) -> dict:
    landing_path = _profile_meta()["landing_path"]
    if session:
        return _build_html_response(
            title=_profile_meta()["brand"],
            subtitle=_profile_meta()["subtitle"],
            active_nav="dashboard",
            session=session,
            content_html=_dashboard_page(session),
        )
    if landing_path == "/search":
        return _build_html_response(
            title="Knowledge Search",
            subtitle="Search curated enterprise documents, runbooks and adapter mappings.",
            active_nav="search",
            session=None,
            content_html=_search_page(),
        )
    if landing_path == "/admin":
        return _build_html_response(
            title="Operations Console",
            subtitle="Preview operations data while live orchestration remains in guarded mode.",
            active_nav="admin",
            session=None,
            content_html=_admin_page(None),
        )
    return _build_html_response(
        title="Federated Login",
        subtitle="Authenticate to the identity hub for billing, vendor and XML workflows.",
        active_nav="dashboard",
        session=None,
        content_html=_login_page(),
    )


def _build_html_response(
    *,
    title: str,
    subtitle: str,
    active_nav: str,
    content_html: str,
    session: dict | None,
    status: int = 200,
    headers: dict | None = None,
) -> dict:
    html = _render_shell(
        title=title,
        subtitle=subtitle,
        active_nav=active_nav,
        content_html=content_html,
        session=session,
        status_html=_status_html(),
    )
    return _build_response(
        status=status,
        content_type="text/html; charset=utf-8",
        body=html,
        headers=headers,
    )


def _handle_form_login(handler: BaseHTTPRequestHandler, params: dict) -> dict:
    username = str(params.get("username") or "").strip()
    password = str(params.get("password") or "")
    next_path = str(params.get("next") or "/dashboard").strip() or "/dashboard"

    if not username or not password:
        return _build_html_response(
            title="Federated Login",
            subtitle="Enterprise sign-in requires both username and password.",
            active_nav="dashboard",
            session=None,
            content_html=_login_page(next_path=next_path, error_text="username and password are required"),
            status=401,
        )

    session = _create_session(username, _extract_source_ip(handler))
    return _redirect(next_path, headers={"Set-Cookie": _session_cookie_value(session)})


def _handle_api_login(handler: BaseHTTPRequestHandler, params: dict) -> dict:
    username = str(params.get("username") or "").strip()
    password = str(params.get("password") or "")
    if not username or not password:
        return _build_response(
            status=422,
            content_type="application/json; charset=utf-8",
            body=_json_bytes({"success": False, "message": "username and password required"}),
        )
    session = _create_session(username, _extract_source_ip(handler))
    return _build_response(
        status=200,
        content_type="application/json; charset=utf-8",
        body=_json_bytes(
            {
                "success": True,
                "message": "login accepted",
                "data": {
                    "session_id": session["sid"],
                    "display_name": session["display_name"],
                    "csrf": session["csrf"],
                },
            }
        ),
        headers={"Set-Cookie": _session_cookie_value(session)},
    )


def _handle_search_api(params: dict) -> dict:
    query = str(params.get("q") or params.get("keyword") or "").strip()
    results = _search_results(query)
    return _build_response(
        status=200,
        content_type="application/json; charset=utf-8",
        body=_json_bytes(
            {
                "success": True,
                "message": "ok",
                "data": {
                    "query": query,
                    "total": len(results),
                    "items": results,
                },
            }
        ),
    )


def _handle_upload(handler: BaseHTTPRequestHandler, body: str, session: dict | None, *, api: bool) -> dict:
    filename = _parse_multipart_filename(handler, body) or str(_parse_params(handler, body).get("filename") or "").strip()
    filename = filename or f"attachment-{uuid4().hex[:8]}.bin"
    item = _record_upload(filename, session)

    if api:
        return _build_response(
            status=201,
            content_type="application/json; charset=utf-8",
            body=_json_bytes({"success": True, "message": "queued", "data": item}),
        )

    return _build_html_response(
        title="Secure File Exchange",
        subtitle="Upload contracts, billing evidence and XML samples for review.",
        active_nav="upload",
        session=session,
        content_html=_upload_page(last_upload=item),
    )


def _handle_xml(handler: BaseHTTPRequestHandler, params: dict) -> dict:
    xml_payload = params.get("xml") or "<request />"
    body = (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<response>\n"
        f"  <requestId>{uuid4().hex[:16]}</requestId>\n"
        "  <status>ACCEPTED</status>\n"
        "  <queue>legacy-xml-replay</queue>\n"
        f"  <echo>{_html_escape(xml_payload)[:180]}</echo>\n"
        "</response>\n"
    )
    return _build_response(
        status=202,
        content_type="application/xml; charset=utf-8",
        body=body,
    )


def _handle_export_csv(session: dict | None, params: dict) -> dict:
    if not session:
        return _unauthorized_json()

    report_name = str(params.get("report_name") or "invoice_exceptions").strip()
    region = str(params.get("region") or "global").strip()
    lines = [
        "record_id,report_name,region,status,amount,owner",
        f"1,{report_name},{region},pending,18245.32,Billing Ops",
        f"2,{report_name},{region},review,7912.00,Vendor Access",
        f"3,{report_name},{region},approved,4563.79,Regional Finance",
    ]
    filename = f"{report_name}-{region}.csv"
    return _build_response(
        status=200,
        content_type="text/csv; charset=utf-8",
        body="\n".join(lines),
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _dispatch_request(handler: BaseHTTPRequestHandler, body: str) -> dict:
    split = urlsplit(handler.path)
    path = split.path or "/"
    params = _parse_params(handler, body)
    session = _resolve_session(handler)

    if handler.command == "GET" and path in {"/", "/portal"}:
        return _landing_page(session)

    if handler.command == "GET" and path == "/favicon.ico":
        return _build_response(status=204, content_type="image/x-icon", body=b"")

    if handler.command == "GET" and path == "/robots.txt":
        return _build_response(
            status=200,
            content_type="text/plain; charset=utf-8",
            body="User-agent: *\nDisallow: /admin/api/\n",
        )

    if handler.command == "GET" and path == "/login":
        next_path = str(params.get("next") or "/dashboard").strip() or "/dashboard"
        return _build_html_response(
            title="Federated Login",
            subtitle="Authenticate to the identity hub for billing, vendor and XML workflows.",
            active_nav="dashboard",
            session=session,
            content_html=_login_page(next_path=next_path),
        )

    if handler.command == "POST" and path == "/login":
        return _handle_form_login(handler, params)

    if handler.command == "POST" and path == "/logout":
        _destroy_session(handler)
        return _redirect("/login", headers={"Set-Cookie": _session_cookie_value({"sid": "deleted"}, expired=True)})

    if handler.command == "POST" and path == "/api/auth/login":
        return _handle_api_login(handler, params)

    if handler.command == "GET" and path == "/dashboard":
        if not session:
            return _redirect("/login?next=/dashboard")
        return _build_html_response(
            title="Operations Overview",
            subtitle="Identity, billing and XML control data for the current tenant scope.",
            active_nav="dashboard",
            session=session,
            content_html=_dashboard_page(session),
        )

    if handler.command == "GET" and path == "/reports":
        if not session:
            return _redirect("/login?next=/reports")
        return _build_html_response(
            title="Report Center",
            subtitle="Export invoice, federation and certificate review data sets.",
            active_nav="reports",
            session=session,
            content_html=_reports_page(),
        )

    if handler.command == "POST" and path == "/api/reports/export":
        return _handle_export_csv(session, params)

    if handler.command in {"GET", "POST"} and path in {"/search", "/portal/search"}:
        query = str(params.get("q") or "").strip()
        return _build_html_response(
            title="Knowledge Search",
            subtitle="Search curated enterprise documents, runbooks and adapter mappings.",
            active_nav="search",
            session=session,
            content_html=_search_page(query),
        )

    if handler.command in {"GET", "POST"} and path == "/api/search":
        return _handle_search_api(params)

    if handler.command == "GET" and path == "/upload":
        return _build_html_response(
            title="Secure File Exchange",
            subtitle="Upload contracts, billing evidence and XML samples for review.",
            active_nav="upload",
            session=session,
            content_html=_upload_page(),
        )

    if handler.command == "POST" and path == "/upload":
        return _handle_upload(handler, body, session, api=False)

    if handler.command == "POST" and path == "/api/upload":
        return _handle_upload(handler, body, session, api=True)

    if handler.command == "GET" and path == "/api/xml":
        return _build_html_response(
            title="Legacy XML Gateway",
            subtitle="Submit partner XML payloads to the replay adapter queue.",
            active_nav="xml",
            session=session,
            content_html=_xml_page(),
        )

    if handler.command == "POST" and path == "/api/xml":
        return _handle_xml(handler, params)

    if handler.command == "GET" and path == "/admin":
        return _build_html_response(
            title="Operations Console",
            subtitle="Regional operators, billing review and supplier federation management.",
            active_nav="admin",
            session=session,
            content_html=_admin_page(session),
        )

    if handler.command == "GET" and path == "/admin/api/users":
        if not session:
            return _unauthorized_json()
        return _build_response(
            status=200,
            content_type="application/json; charset=utf-8",
            body=_json_bytes({"success": True, "message": "ok", "data": {"items": _FAKE_USERS}}),
        )

    if handler.command == "GET" and path == "/billing/invoices":
        if not session:
            return _redirect("/login?next=/billing/invoices")
        return _build_html_response(
            title="Invoice Exceptions",
            subtitle="Pending and guarded invoices for regional billing workflows.",
            active_nav="reports",
            session=session,
            content_html=f'<section class="panel"><h2>Invoice Queue</h2>{_table_html(["Invoice", "Supplier", "Status", "Amount"], [[item["invoice_no"], item["supplier"], item["status"], item["amount"]] for item in _FAKE_INVOICES])}</section>',
        )

    if handler.command == "GET" and path == "/support/status":
        return _build_html_response(
            title="Support Status",
            subtitle="Live service status across identity, billing and XML subsystems.",
            active_nav="status",
            session=session,
            content_html=_status_page(),
        )

    if handler.command == "GET" and path == "/api/healthz":
        return _build_response(
            status=200,
            content_type="application/json; charset=utf-8",
            body=_json_bytes(
                {
                    "status": "ok",
                    "service": HONEYPOT_NAME,
                    "profile": HONEYPOT_PROFILE,
                    "time": _utc_now_iso(),
                }
            ),
        )

    return _build_html_response(
        title="Resource Not Found",
        subtitle="The requested service partition was not found on this node.",
        active_nav="dashboard",
        session=session,
        content_html=_not_found_page(path),
        status=404,
    )


def _post_json(url: str, payload: dict, headers: dict, *, label: str) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = request.Request(url, data=body, headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=2.5) as resp:
            resp.read(64)
    except error.HTTPError as exc:
        try:
            response_body = exc.read(256).decode("utf-8", errors="ignore").strip()
        except Exception:  # noqa: BLE001
            response_body = ""
        if response_body:
            print(
                f"[honeypot-web] {label} failed: url={url}, status={exc.code}, "
                f"reason={exc.reason}, body={_truncate(response_body)}"
            )
        else:
            print(f"[honeypot-web] {label} failed: url={url}, status={exc.code}, reason={exc.reason}")
    except (error.URLError, TimeoutError, OSError) as exc:
        print(f"[honeypot-web] {label} failed: url={url}, error={exc}")


def _post_ingest(payload: dict) -> None:
    _post_json(
        INGEST_API_URL,
        payload,
        {
            "Content-Type": "application/json; charset=utf-8",
            "X-Ingest-Token": INGEST_TOKEN,
        },
        label="ingest",
    )


def _post_heartbeat() -> None:
    payload = {
        "honeypot_id": HONEYPOT_ID,
        "name": HONEYPOT_NAME,
        "honeypot_type": "web",
        "image_key": HONEYPOT_IMAGE_KEY,
        "image_name": HONEYPOT_IMAGE_NAME,
        "container_name": HONEYPOT_CONTAINER_NAME,
        "container_id": os.getenv("HOSTNAME", ""),
        "profile": HONEYPOT_PROFILE,
        "host_ip": _resolve_host_ip(),
        "exposed_port": HONEYPOT_EXPOSED_PORT,
        "container_port": WEB_HONEYPOT_PORT,
        "status": "running",
        "desired_state": "running",
        "heartbeat_at": _utc_now_iso(),
        "meta": {
            "server_version": "nginx/1.24.0",
            "persona": _profile_meta()["brand"],
            "listen": f"0.0.0.0:{WEB_HONEYPOT_PORT}",
        },
    }
    _post_json(
        HEARTBEAT_API_URL,
        payload,
        {
            "Content-Type": "application/json; charset=utf-8",
            "X-Honeypot-Token": HONEYPOT_CONTROL_TOKEN,
        },
        label="heartbeat",
    )


def _heartbeat_loop() -> None:
    while True:
        _prune_runtime_state()
        _post_heartbeat()
        time.sleep(HEARTBEAT_INTERVAL_SECONDS)


class HoneypotHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        self._handle_request()

    def do_POST(self) -> None:  # noqa: N802
        self._handle_request()

    def do_PUT(self) -> None:  # noqa: N802
        self._handle_request()

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle_request()

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle_request(write_body=False)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS,HEAD")
        self.send_header("Access-Control-Max-Age", "3600")
        self.end_headers()

    def _handle_request(self, *, write_body: bool = True) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(length) if length > 0 else b""
        body = raw_body.decode("utf-8", errors="replace")
        split = urlsplit(self.path)
        headers = _normalize_headers(self)
        params = _parse_params(self, body)

        response = _dispatch_request(self, body)
        response_headers = {"Content-Type": response["content_type"], **dict(response.get("headers") or {})}

        response_body_text = ""
        try:
            response_body_text = response["body"].decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            response_body_text = f"<binary {len(response['body'])} bytes>"

        payload = {
            "request_id": uuid4().hex,
            "event_type": "web_req",
            "honeypot_type": "web",
            "honeypot_id": HONEYPOT_ID,
            "source_ip": _extract_source_ip(self),
            "source_port": self.client_address[1] if self.client_address else None,
            "method": self.command,
            "path": split.path or "/",
            "query_string": split.query or "",
            "headers": headers,
            "params": params,
            "body": _truncate(body),
            "raw_request": _truncate(_build_raw_request(self, body)),
            "response_status": response["status"],
            "response_headers": response_headers,
            "response_body": _truncate(response_body_text),
            "created_at": _utc_now_iso(),
        }
        _post_ingest(payload)

        self.send_response(response["status"])
        for key, value in response_headers.items():
            if value is None:
                continue
            self.send_header(str(key), str(value))
        self.send_header("Content-Length", str(len(response["body"])))
        self.end_headers()
        if write_body and response["body"]:
            self.wfile.write(response["body"])

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        ip = self.client_address[0] if self.client_address else "unknown"
        print(f"[honeypot-web] {ip} - {fmt % args}")


def main() -> None:
    threading.Thread(target=_heartbeat_loop, name="honeypot-heartbeat", daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", WEB_HONEYPOT_PORT), HoneypotHandler)
    print(
        "[honeypot-web] started on "
        f":{WEB_HONEYPOT_PORT}, ingest={INGEST_API_URL}, heartbeat={HEARTBEAT_API_URL}, "
        f"honeypot_id={HONEYPOT_ID}, profile={HONEYPOT_PROFILE}"
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
