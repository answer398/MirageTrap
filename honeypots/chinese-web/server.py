from __future__ import annotations

import json
import os
import socket
import threading
import time
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import error, request
from urllib.parse import parse_qsl, quote, urlsplit
from uuid import uuid4

INGEST_API_URL = os.getenv("INGEST_API_URL", "http://backend-api:15000/api/ingest/events")
HEARTBEAT_API_URL = os.getenv("HEARTBEAT_API_URL", "http://backend-api:15000/api/honeypots/heartbeat")
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "dev-ingest-token")
HONEYPOT_CONTROL_TOKEN = os.getenv("HONEYPOT_CONTROL_TOKEN", INGEST_TOKEN)
HONEYPOT_ID = os.getenv("HONEYPOT_ID", "hp-cn-web-001")
HONEYPOT_NAME = os.getenv("HONEYPOT_NAME", HONEYPOT_ID)
HONEYPOT_IMAGE_KEY = os.getenv("HONEYPOT_IMAGE_KEY", "cn_cms_portal")
HONEYPOT_IMAGE_NAME = os.getenv("HONEYPOT_IMAGE_NAME", "miragetrap/cn-cms-honeypot:latest")
HONEYPOT_CONTAINER_NAME = os.getenv("HONEYPOT_CONTAINER_NAME", os.getenv("HOSTNAME", HONEYPOT_ID))
HONEYPOT_PROFILE = os.getenv("HONEYPOT_PROFILE", "cms").strip().lower() or "cms"
HONEYPOT_EXPOSED_PORT = int(os.getenv("HONEYPOT_EXPOSED_PORT", "18080"))
WEB_HONEYPOT_PORT = int(os.getenv("WEB_HONEYPOT_PORT", "80"))
WEB_HONEYPOT_MAX_BODY = max(int(os.getenv("WEB_HONEYPOT_MAX_BODY", "8192")), 512)
HEARTBEAT_INTERVAL_SECONDS = max(int(os.getenv("HEARTBEAT_INTERVAL_SECONDS", "15")), 5)

_SESSION_COOKIE = "JSESSIONID"
_SESSION_LOCK = threading.Lock()
_SESSIONS: dict[str, dict] = {}
_UPLOADS: list[dict] = []

_PROFILES = {
    "cms": {
        "brand": "江海市一体化政务服务门户",
        "short": "政务门户",
        "subtitle": "政务公开 · 一网通办 · 数据共享 · 便民服务",
        "accent": "市行政审批和数据资源管理局",
        "server": "nginx/1.22.1",
        "login_path": "/admin/login.php",
        "admin_path": "/admin/index.php",
        "theme": "gov",
        "powered_by": "PHP/7.4.33",
    },
    "oa": {
        "brand": "启明协同办公平台",
        "short": "OA 协同",
        "subtitle": "统一待办 · 流程审批 · 公文流转 · 知识文档",
        "accent": "启明协同 V10",
        "server": "nginx/1.20.2",
        "login_path": "/login",
        "admin_path": "/oa/index.do",
        "theme": "oa",
        "powered_by": "Servlet/3.1 JSP/2.3",
    },
    "gateway": {
        "brand": "蓝盾边缘工业物联网网关",
        "short": "边缘网关",
        "subtitle": "PLC 接入 · 设备监控 · 告警联动 · 远程运维",
        "accent": "EdgeGateway Pro 4.8",
        "server": "openresty/1.21.4.1",
        "login_path": "/login.html",
        "admin_path": "/console",
        "theme": "iot",
        "powered_by": "OpenResty Lua/5.1",
    },
}

_GOV_NOTICES = [
    {"title": "关于开展全市政务外网应用系统资产复核工作的通知", "dept": "数字资源处", "date": "2026-04-23", "tag": "通知公告"},
    {"title": "江海市工程建设项目审批系统接口维护公告", "dept": "审批服务处", "date": "2026-04-21", "tag": "系统运维"},
    {"title": "2026 年第一季度政务公开目录质量抽查情况通报", "dept": "办公室", "date": "2026-04-18", "tag": "政务公开"},
    {"title": "法人办事电子证照共享调用清单更新说明", "dept": "数据共享处", "date": "2026-04-15", "tag": "数据共享"},
    {"title": "互联网政务服务门户内容安全巡检结果", "dept": "安全运维组", "date": "2026-04-12", "tag": "安全通报"},
]

_GOV_SERVICES = [
    ("个人服务", "社保、公积金、户籍、不动产、医疗保障", "1284"),
    ("法人服务", "企业开办、项目审批、资质认定、年报申报", "936"),
    ("一件事一次办", "出生、入学、退休、企业注销等主题套餐", "72"),
    ("政策直达", "惠企政策、申报指南、兑现进度查询", "318"),
]

_OA_TASKS = [
    {"title": "江海智慧园区弱电改造合同审批", "flow": "合同审批", "node": "法务复核", "owner": "张敏", "deadline": "今日 18:00", "level": "紧急"},
    {"title": "三季度安全运维外包付款申请", "flow": "付款申请", "node": "部门负责人", "owner": "李强", "deadline": "明日 12:00", "level": "普通"},
    {"title": "政务云数据库扩容采购立项", "flow": "采购立项", "node": "信息中心会签", "owner": "王磊", "deadline": "04-26", "level": "重要"},
    {"title": "数据共享交换平台账号开通", "flow": "权限申请", "node": "安全员审批", "owner": "陈佳", "deadline": "04-26", "level": "普通"},
]

_OA_MAILS = [
    ("信息中心", "VPN 网关双因子认证策略调整说明", "09:20"),
    ("综合办公室", "关于补充报送二季度值班表的提醒", "08:45"),
    ("财务部", "电子发票归档接口测试窗口确认", "昨天"),
]

_DOCS = [
    {"title": "政务外网应用系统安全基线 v3.2", "owner": "信息中心", "level": "内部", "updated": "2026-04-22 16:31"},
    {"title": "统一身份认证平台接口规范", "owner": "数据资源处", "level": "受限", "updated": "2026-04-20 10:05"},
    {"title": "合同审批流节点配置说明", "owner": "办公室", "level": "内部", "updated": "2026-04-18 14:12"},
    {"title": "工控网关远程维护白名单清单", "owner": "运维组", "level": "受限", "updated": "2026-04-16 09:40"},
]

_DEVICES = [
    {"name": "一号泵站 PLC-01", "ip": "10.18.3.21", "proto": "Modbus TCP", "status": "在线", "load": 67, "risk": "低"},
    {"name": "配电室 RTU-07", "ip": "10.18.7.44", "proto": "IEC104", "status": "在线", "load": 81, "risk": "中"},
    {"name": "污水处理 HMI", "ip": "10.19.2.15", "proto": "S7", "status": "离线", "load": 0, "risk": "高"},
    {"name": "视频网关 NVR-03", "ip": "10.20.6.9", "proto": "RTSP", "status": "在线", "load": 42, "risk": "低"},
    {"name": "冷却塔 2# 采集器", "ip": "10.21.5.32", "proto": "MQTT", "status": "在线", "load": 58, "risk": "低"},
]

_ALARMS = [
    {"time": "09:42:18", "level": "高", "asset": "污水处理 HMI", "message": "设备离线超过 12 分钟，自动切换旁路策略"},
    {"time": "09:18:06", "level": "中", "asset": "配电室 RTU-07", "message": "A 相电流波动超过阈值，建议现场复核"},
    {"time": "08:52:44", "level": "低", "asset": "一号泵站 PLC-01", "message": "采集延迟恢复，平均延迟 86ms"},
]

_USERS = [
    {"name": "张敏", "dept": "综合办公室", "role": "流程管理员", "last": "2026-04-24 09:18"},
    {"name": "李强", "dept": "信息中心", "role": "系统管理员", "last": "2026-04-24 08:55"},
    {"name": "王磊", "dept": "财务部", "role": "审批主管", "last": "2026-04-23 18:42"},
]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _profile() -> dict:
    return _PROFILES.get(HONEYPOT_PROFILE, _PROFILES["cms"])


def _truncate(text: str) -> str:
    return text if len(text) <= WEB_HONEYPOT_MAX_BODY else text[:WEB_HONEYPOT_MAX_BODY] + "...(truncated)"


def _html_escape(value) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _response(status: int, body: str | bytes, content_type: str = "text/html; charset=utf-8", headers: dict | None = None) -> dict:
    body_bytes = body if isinstance(body, bytes) else body.encode("utf-8")
    return {"status": status, "body": body_bytes, "content_type": content_type, "headers": headers or {}}


def _json_response(data: dict, status: int = 200) -> dict:
    return _response(status, json.dumps(data, ensure_ascii=False, indent=2), "application/json; charset=utf-8")


def _redirect(location: str) -> dict:
    return _response(302, "", headers={"Location": location, "Cache-Control": "no-store"})


def _extract_source_ip(handler: BaseHTTPRequestHandler) -> str:
    xff = (handler.headers.get("X-Forwarded-For") or "").strip()
    if xff:
        return xff.split(",")[0].strip()
    real_ip = (handler.headers.get("X-Real-IP") or "").strip()
    return real_ip or (handler.client_address[0] if handler.client_address else "unknown")


def _normalize_headers(handler: BaseHTTPRequestHandler) -> dict:
    return {str(key): str(value) for key, value in handler.headers.items()}


def _parse_params(handler: BaseHTTPRequestHandler, body: str) -> dict:
    split = urlsplit(handler.path)
    params = {key: value for key, value in parse_qsl(split.query, keep_blank_values=True)}
    content_type = (handler.headers.get("Content-Type") or "").lower()
    if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        for key, value in parse_qsl(body, keep_blank_values=True):
            params[key] = value
    if "application/json" in content_type:
        try:
            data = json.loads(body or "{}")
            if isinstance(data, dict):
                params.update({str(k): v if isinstance(v, str) else json.dumps(v, ensure_ascii=False) for k, v in data.items()})
        except json.JSONDecodeError:
            pass
    return params


def _build_raw_request(handler: BaseHTTPRequestHandler, body: str) -> str:
    lines = [f"{handler.command} {handler.path} {handler.request_version}"]
    lines.extend(f"{key}: {value}" for key, value in handler.headers.items())
    lines.append("")
    if body:
        lines.append(body)
    return "\r\n".join(lines)


def _parse_cookies(handler: BaseHTTPRequestHandler) -> SimpleCookie:
    cookie = SimpleCookie()
    raw = handler.headers.get("Cookie")
    if raw:
        try:
            cookie.load(raw)
        except Exception:
            pass
    return cookie


def _get_session(handler: BaseHTTPRequestHandler) -> dict | None:
    morsel = _parse_cookies(handler).get(_SESSION_COOKIE)
    if not morsel:
        return None
    with _SESSION_LOCK:
        return _SESSIONS.get(morsel.value)


def _new_session(username: str, source_ip: str) -> tuple[str, dict]:
    session_id = uuid4().hex
    display_name = username.strip() or "admin"
    session = {"username": display_name, "display_name": display_name, "source_ip": source_ip, "created_at": _utc_now_iso()}
    with _SESSION_LOCK:
        _SESSIONS[session_id] = session
    return session_id, session


def _clear_session(handler: BaseHTTPRequestHandler) -> None:
    morsel = _parse_cookies(handler).get(_SESSION_COOKIE)
    if morsel:
        with _SESSION_LOCK:
            _SESSIONS.pop(morsel.value, None)


def _resolve_host_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def _post_json(url: str, payload: dict, headers: dict, *, label: str) -> None:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = request.Request(url, data=data, headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=4) as resp:
            resp.read(256)
            if resp.status >= 300:
                print(f"[cn-honeypot] {label} status={resp.status} url={url}")
    except error.HTTPError as exc:
        print(f"[cn-honeypot] {label} failed: status={exc.code}, reason={exc.reason}")
    except (error.URLError, TimeoutError, OSError) as exc:
        print(f"[cn-honeypot] {label} failed: {exc}")


def _post_ingest(payload: dict) -> None:
    _post_json(INGEST_API_URL, payload, {"Content-Type": "application/json; charset=utf-8", "X-Ingest-Token": INGEST_TOKEN}, label="ingest")


def _post_heartbeat() -> None:
    profile = _profile()
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
            "server_version": profile["server"],
            "persona": profile["brand"],
            "language": "zh-CN",
            "theme": profile["theme"],
            "listen": f"0.0.0.0:{WEB_HONEYPOT_PORT}",
        },
    }
    _post_json(HEARTBEAT_API_URL, payload, {"Content-Type": "application/json; charset=utf-8", "X-Honeypot-Token": HONEYPOT_CONTROL_TOKEN}, label="heartbeat")


def _heartbeat_loop() -> None:
    while True:
        _post_heartbeat()
        time.sleep(HEARTBEAT_INTERVAL_SECONDS)


def _base_style(theme: str) -> str:
    return f"""
    * {{ box-sizing: border-box; }}
    html {{ color-scheme: light; }}
    body {{ margin:0; min-height:100vh; font-family:"Microsoft YaHei","PingFang SC",Arial,sans-serif; }}
    a {{ color:inherit; text-decoration:none; }}
    button,input,select,textarea {{ font:inherit; }}
    .muted {{ color:var(--muted); }} .danger {{ color:var(--danger); }} .ok {{ color:var(--ok); }}
    .tag {{ display:inline-flex; align-items:center; padding:3px 9px; border-radius:999px; font-size:12px; background:var(--tag); color:var(--tag-text); }}
    table {{ width:100%; border-collapse:collapse; }} th,td {{ padding:11px 10px; border-bottom:1px solid var(--line); text-align:left; font-size:14px; }} th {{ color:var(--muted); font-weight:500; }}
    input,textarea,select {{ width:100%; border:1px solid var(--input-line); border-radius:8px; padding:10px 12px; background:var(--input); color:var(--text); outline:none; }}
    input:focus,textarea:focus,select:focus {{ border-color:var(--focus); box-shadow:0 0 0 3px var(--focus-ring); }}
    .btn {{ display:inline-flex; align-items:center; justify-content:center; border:0; border-radius:8px; padding:10px 16px; color:white; background:var(--primary); cursor:pointer; }}
    .btn.secondary {{ color:var(--primary); background:var(--soft); border:1px solid var(--line); }}
    .layout-card {{ background:var(--card); border:1px solid var(--line); border-radius:14px; box-shadow:0 14px 32px var(--shadow); }}
    .metric {{ display:block; margin-top:8px; font-size:30px; font-weight:700; color:var(--primary); }}
    .grid-4 {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; }}
    .grid-3 {{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:14px; }}
    .split {{ display:grid; grid-template-columns:1.35fr .65fr; gap:16px; }}
    .bar {{ height:8px; border-radius:999px; background:var(--soft); overflow:hidden; }} .bar > i {{ display:block; height:100%; background:var(--primary); }}
    @media (max-width:900px) {{ .grid-4,.grid-3,.split {{ grid-template-columns:1fr; }} }}
    """


def _gov_shell(title: str, active: str, content: str, session: dict | None = None) -> str:
    profile = _profile()
    nav = [("首页", "/", "home"), ("政务公开", "/zwgk", "open"), ("政务服务", "/service", "service"), ("政民互动", "/interaction", "interact"), ("数据目录", "/data/catalog", "data"), ("后台管理", profile["login_path"], "login")]
    links = "".join(f'<a class="{"on" if key == active else ""}" href="{href}">{label}</a>' for label, href, key in nav)
    today = datetime.now().strftime("%Y年%m月%d日")
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{_html_escape(title)} - {_html_escape(profile['brand'])}</title><style>
    :root{{--primary:#b7191f;--primary-2:#0b5cad;--bg:#f4f7fb;--card:#fff;--text:#1f2937;--muted:#687385;--line:#e4e9f1;--input:#fff;--input-line:#cbd5e1;--focus:#b7191f;--focus-ring:rgba(183,25,31,.14);--soft:#fff4f4;--tag:#eef5ff;--tag-text:#1d4f91;--danger:#b42318;--ok:#147a4a;--shadow:rgba(18,38,63,.08)}}
    {_base_style('gov')}
    body{{background:linear-gradient(180deg,#eef4fb,#f8fafc 30%,#edf2f7)}} .gov-top{{background:#fff;border-bottom:1px solid var(--line)}} .gov-util{{max-width:1280px;margin:auto;display:flex;justify-content:space-between;padding:8px 24px;color:#667085;font-size:13px}} .gov-head{{background:linear-gradient(110deg,#b7191f,#d9423f 48%,#1b5ea9);color:white}} .gov-head-inner{{max-width:1280px;margin:auto;padding:28px 24px;display:flex;align-items:center;justify-content:space-between;gap:20px}} .emblem{{width:58px;height:58px;border-radius:50%;background:rgba(255,255,255,.18);display:grid;place-items:center;border:1px solid rgba(255,255,255,.35)}} .emblem svg{{width:34px;height:34px}} .gov-title{{display:flex;align-items:center;gap:16px}} .gov-title h1{{margin:0 0 6px;font-size:32px;letter-spacing:.04em}} .searchbox{{min-width:360px;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.28);border-radius:12px;padding:10px}} .searchbox input{{border:0}} .gov-nav{{background:#fff;box-shadow:0 5px 18px rgba(16,24,40,.08)}} .gov-nav .inner{{max-width:1280px;margin:auto;display:flex;padding:0 24px}} .gov-nav a{{padding:15px 22px;border-bottom:3px solid transparent}} .gov-nav a.on,.gov-nav a:hover{{color:var(--primary);border-bottom-color:var(--primary);background:#fff8f8}} main{{max-width:1280px;margin:22px auto 50px;padding:0 24px}} .gov-hero{{display:grid;grid-template-columns:1.1fr .9fr;gap:16px}} .focus-card{{min-height:320px;padding:28px;color:white;background:linear-gradient(135deg,rgba(183,25,31,.95),rgba(31,94,169,.92)),radial-gradient(circle at 80% 20%,rgba(255,255,255,.25),transparent 32%);border-radius:16px}} .focus-card h2{{font-size:34px;margin:8px 0 14px}} .service-tile,.panel{{padding:18px}} .service-tile strong{{font-size:18px}} .quick-links{{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}} .quick-links a{{padding:14px;border-radius:10px;background:#f8fbff;border:1px solid var(--line)}} footer{{padding:20px;text-align:center;color:#667085;background:#fff;border-top:1px solid var(--line)}}
    </style></head><body><div class="gov-top"><div class="gov-util"><span>{today}　晴　无障碍浏览　移动版</span><span>统一认证入口 · 政务服务监督热线 12345</span></div></div><header class="gov-head"><div class="gov-head-inner"><div class="gov-title"><span class="emblem"><svg viewBox="0 0 24 24" fill="none"><path d="M12 3l8 4v5c0 5-3.4 8.7-8 10-4.6-1.3-8-5-8-10V7l8-4z" stroke="white" stroke-width="1.8"/><path d="M8 12h8M9 16h6M12 7v13" stroke="white" stroke-width="1.5"/></svg></span><div><h1>{_html_escape(profile['brand'])}</h1><p>{_html_escape(profile['subtitle'])}</p></div></div><form class="searchbox" method="get" action="/search"><input name="q" placeholder="请输入事项、政策、办件编号或部门名称"></form></div></header><nav class="gov-nav"><div class="inner">{links}</div></nav><main>{content}</main><footer>{_html_escape(profile['accent'])}　版权所有　ICP备案号：苏ICP备20260424号</footer></body></html>"""


def _oa_shell(title: str, active: str, content: str, session: dict | None = None) -> str:
    profile = _profile()
    user = session.get("display_name") if session else "未登录"
    nav = [("工作台", "/oa/index.do", "home"), ("流程中心", "/workflow/list", "flow"), ("公文管理", "/document/list", "doc"), ("知识库", "/kb/search", "kb"), ("通讯录", "/api/addressbook", "book"), ("系统设置", "/sys/admin", "sys")]
    links = "".join(f'<a class="{"on" if key == active else ""}" href="{href}"><span></span>{label}</a>' for label, href, key in nav)
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{_html_escape(title)} - {_html_escape(profile['brand'])}</title><style>
    :root{{--primary:#2563eb;--primary-2:#7c3aed;--bg:#eef4ff;--card:#fff;--text:#172033;--muted:#6b7280;--line:#e5eaf3;--input:#fff;--input-line:#cbd5e1;--focus:#2563eb;--focus-ring:rgba(37,99,235,.16);--soft:#eff6ff;--tag:#eef2ff;--tag-text:#3730a3;--danger:#d92d20;--ok:#16803c;--shadow:rgba(30,64,175,.10)}}
    {_base_style('oa')}
    body{{background:radial-gradient(circle at 12% 8%,rgba(37,99,235,.18),transparent 28%),linear-gradient(135deg,#f8fbff,#edf4ff)}} .oa-frame{{min-height:100vh;display:grid;grid-template-columns:246px minmax(0,1fr)}} aside{{background:#10213d;color:#dbeafe;padding:22px 16px;display:grid;align-content:start;gap:18px}} .oa-logo{{padding:12px 12px 18px;border-bottom:1px solid rgba(255,255,255,.12)}} .oa-logo h1{{margin:0;font-size:22px}} aside a{{display:flex;gap:10px;align-items:center;padding:12px 14px;border-radius:10px;color:#cbd5e1}} aside a span{{width:8px;height:8px;border-radius:50%;background:#60a5fa}} aside a.on,aside a:hover{{background:rgba(96,165,250,.16);color:white}} .oa-main{{padding:22px}} .oa-top{{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}} .oa-top h2{{margin:0;font-size:26px}} .identity{{display:flex;gap:12px;align-items:center;background:#fff;border:1px solid var(--line);border-radius:999px;padding:8px 12px}} .avatar{{width:34px;height:34px;border-radius:50%;display:grid;place-items:center;background:linear-gradient(135deg,var(--primary),var(--primary-2));color:white}} .work-card{{padding:18px}} .task-row{{display:grid;grid-template-columns:1fr 110px 110px 90px;gap:12px;align-items:center;padding:13px 0;border-bottom:1px solid var(--line)}} .calendar{{display:grid;grid-template-columns:repeat(7,1fr);gap:6px}} .calendar b{{display:grid;place-items:center;height:36px;border-radius:9px;background:#f8fafc;color:#64748b}} .calendar .hot{{background:var(--primary);color:white}} @media(max-width:900px){{.oa-frame{{grid-template-columns:1fr}} aside{{display:none}}}}
    </style></head><body><div class="oa-frame"><aside><div class="oa-logo"><h1>{_html_escape(profile['brand'])}</h1><p>{_html_escape(profile['subtitle'])}</p></div>{links}</aside><section class="oa-main"><header class="oa-top"><div><h2>{_html_escape(title)}</h2><p class="muted">{_html_escape(profile['accent'])} · 今日待办自动同步</p></div><div class="identity"><span class="avatar">{_html_escape(user[:1] if user else '访')}</span><strong>{_html_escape(user)}</strong></div></header>{content}</section></div></body></html>"""


def _iot_shell(title: str, active: str, content: str, session: dict | None = None) -> str:
    profile = _profile()
    nav = [("运行总览", "/console", "home"), ("设备资产", "/devices", "device"), ("协议通道", "/channels", "channel"), ("告警日志", "/logs", "logs"), ("配置备份", "/api/device/config", "config"), ("登录", profile["login_path"], "login")]
    links = "".join(f'<a class="{"on" if key == active else ""}" href="{href}">{label}</a>' for label, href, key in nav)
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{_html_escape(title)} - {_html_escape(profile['brand'])}</title><style>
    :root{{--primary:#22c55e;--primary-2:#06b6d4;--bg:#07111f;--card:rgba(12,26,45,.86);--text:#e6f6ff;--muted:#8ba6bf;--line:rgba(148,196,255,.16);--input:#0b1b2f;--input-line:rgba(148,196,255,.22);--focus:#22c55e;--focus-ring:rgba(34,197,94,.16);--soft:rgba(34,197,94,.1);--tag:rgba(34,197,94,.12);--tag-text:#9af7c2;--danger:#ff8a80;--ok:#7dffb2;--shadow:rgba(0,0,0,.26)}}
    {_base_style('iot')}
    body{{background:radial-gradient(circle at 12% 8%,rgba(6,182,212,.20),transparent 26%),radial-gradient(circle at 86% 18%,rgba(34,197,94,.14),transparent 26%),linear-gradient(135deg,#07111f,#0b1628 58%,#07111f);color:var(--text)}} .iot-frame{{min-height:100vh;display:grid;grid-template-columns:250px minmax(0,1fr)}} aside{{padding:22px 16px;border-right:1px solid var(--line);background:rgba(5,13,25,.78);backdrop-filter:blur(14px)}} .iot-brand{{padding:14px 12px 18px;border-bottom:1px solid var(--line);margin-bottom:16px}} .iot-brand h1{{margin:0;font-size:21px}} aside a{{display:block;margin:7px 0;padding:12px 14px;border:1px solid transparent;border-radius:12px;color:#b8c9d9}} aside a.on,aside a:hover{{border-color:rgba(34,197,94,.28);background:rgba(34,197,94,.10);color:#eafff2}} .iot-main{{padding:22px}} .iot-top{{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:18px}} .iot-top h2{{margin:0;font-size:28px}} .live-dot{{display:inline-flex;gap:8px;align-items:center;color:#9af7c2}} .live-dot i{{width:9px;height:9px;border-radius:50%;background:#22c55e;box-shadow:0 0 18px #22c55e}} .glass{{background:var(--card);border:1px solid var(--line);border-radius:16px;box-shadow:0 20px 50px rgba(0,0,0,.22);backdrop-filter:blur(14px)}} .asset-row{{display:grid;grid-template-columns:1fr 110px 100px 90px 120px;gap:10px;align-items:center;padding:12px 0;border-bottom:1px solid var(--line)}} .terminal{{font-family:"Consolas","Fira Code",monospace;background:#04101d;border-radius:12px;padding:14px;color:#9af7c2;line-height:1.7;min-height:190px}} @media(max-width:900px){{.iot-frame{{grid-template-columns:1fr}} aside{{display:none}}}}
    </style></head><body><div class="iot-frame"><aside><div class="iot-brand"><h1>{_html_escape(profile['brand'])}</h1><p class="muted">{_html_escape(profile['subtitle'])}</p></div>{links}</aside><section class="iot-main"><header class="iot-top"><div><h2>{_html_escape(title)}</h2><p class="muted">{_html_escape(profile['accent'])} · 内网节点 EG-JH-02</p></div><span class="live-dot"><i></i>采集链路在线</span></header>{content}</section></div></body></html>"""


def _gov_home(session: dict | None) -> str:
    service_cards = "".join(f'<article class="layout-card service-tile"><strong>{name}</strong><p class="muted">{desc}</p><span class="metric">{count}</span><small class="muted">可办事项</small></article>' for name, desc, count in _GOV_SERVICES)
    notice_rows = "".join(f'<tr><td><a href="/article/{idx}">{_html_escape(n["title"])}</a></td><td>{n["dept"]}</td><td><span class="tag">{n["tag"]}</span></td><td>{n["date"]}</td></tr>' for idx, n in enumerate(_GOV_NOTICES, 1))
    content = f"""
    <section class="gov-hero"><article class="focus-card"><span class="tag">一网通办专题</span><h2>企业群众高频事项统一入口</h2><p>围绕个人服务、法人服务、工程建设、惠企政策与政民互动，提供事项检索、在线申报、进度查询和电子证照调用。</p><p style="margin-top:34px"><a class="btn" href="/service">进入办事大厅</a> <a class="btn secondary" href="/admin/login.php">管理后台</a></p></article><div class="grid-3" style="grid-template-columns:1fr 1fr"><article class="layout-card panel"><span class="muted">今日办件</span><span class="metric">3,482</span></article><article class="layout-card panel"><span class="muted">接口调用</span><span class="metric">91,206</span></article><article class="layout-card panel"><span class="muted">待公开目录</span><span class="metric">128</span></article><article class="layout-card panel"><span class="muted">群众来信</span><span class="metric">46</span></article></div></section>
    <section class="grid-4" style="margin-top:16px">{service_cards}</section>
    <section class="split" style="margin-top:16px"><article class="layout-card panel"><h2>政务公开动态</h2><table><thead><tr><th>标题</th><th>发布部门</th><th>类型</th><th>日期</th></tr></thead><tbody>{notice_rows}</tbody></table></article><article class="layout-card panel"><h2>快捷入口</h2><div class="quick-links"><a href="/admin/login.php">内容管理</a><a href="/editor/upload.php">附件上传</a><a href="/api/users">用户接口</a><a href="/data/catalog">数据目录</a><a href="/search?q=电子证照">全文检索</a><a href="/download/notice.doc">下载通知</a></div></article></section>"""
    return _gov_shell("首页", "home", content, session)


def _gov_admin(session: dict | None) -> str:
    rows = "".join(f'<tr><td>{n["title"]}</td><td>{n["dept"]}</td><td><span class="tag">待审核</span></td><td>{n["date"]}</td></tr>' for n in _GOV_NOTICES[:4])
    content = f"""
    <section class="grid-4"><article class="layout-card panel"><span class="muted">待审稿件</span><span class="metric">27</span></article><article class="layout-card panel"><span class="muted">敏感词命中</span><span class="metric">6</span></article><article class="layout-card panel"><span class="muted">附件转换</span><span class="metric">41</span></article><article class="layout-card panel"><span class="muted">站点节点</span><span class="metric">12</span></article></section>
    <section class="split" style="margin-top:16px"><article class="layout-card panel"><h2>内容审核队列</h2><table><tbody>{rows}</tbody></table></article><article class="layout-card panel"><h2>系统巡检</h2><p class="muted">发现旧版编辑器插件兼容模式运行，建议在维护窗口升级上传组件。</p><p><span class="tag">/editor/upload.php</span></p><p><span class="tag">/admin/api/users</span></p></article></section>"""
    return _gov_shell("内容管理后台", "login", content, session)


def _oa_login(message: str = "") -> str:
    profile = _profile()
    content = f"""
    <style>body{{background:linear-gradient(135deg,#10213d,#2563eb)}} .login-wrap{{min-height:100vh;display:grid;place-items:center;padding:24px}} .login-box{{width:min(960px,100%);display:grid;grid-template-columns:1.1fr .9fr;overflow:hidden;background:white;border-radius:22px;box-shadow:0 30px 80px rgba(0,0,0,.25)}} .login-brand{{padding:44px;color:white;background:linear-gradient(145deg,#1e3a8a,#2563eb)}} .login-brand h1{{font-size:34px;margin:0 0 16px}} .login-form{{padding:44px;display:grid;gap:16px}} .login-form h2{{margin:0}} @media(max-width:760px){{.login-box{{grid-template-columns:1fr}}}}</style>
    <div class="login-wrap"><section class="login-box"><div class="login-brand"><h1>{_html_escape(profile['brand'])}</h1><p>{_html_escape(profile['subtitle'])}</p><div class="grid-3" style="margin-top:40px"><span>流程</span><span>公文</span><span>门户</span></div></div><form class="login-form" method="post" action="{profile['login_path']}"><h2>统一身份认证</h2><p class="muted">请输入域账号、动态口令或短信验证码登录。</p><label>账号<input name="username" autocomplete="username" placeholder="zhangmin"></label><label>密码<input name="password" type="password" autocomplete="current-password"></label><label>动态码<input name="otp" placeholder="6 位动态口令"></label><button class="btn" type="submit">登录工作台</button><p class="danger">{_html_escape(message)}</p></form></section></div>"""
    return f"<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>登录 - {_html_escape(profile['brand'])}</title><style>:root{{--primary:#2563eb;--muted:#6b7280;--line:#e5eaf3;--input:#fff;--input-line:#cbd5e1;--focus:#2563eb;--focus-ring:rgba(37,99,235,.16);--text:#172033;--danger:#d92d20;--soft:#eff6ff;--card:#fff;--tag:#eef2ff;--tag-text:#3730a3;--ok:#16803c;--shadow:rgba(30,64,175,.10)}}{_base_style('oa')}</style></head><body>{content}</body></html>"


def _oa_home(session: dict | None) -> str:
    task_rows = "".join(f'<div class="task-row"><strong>{t["title"]}<br><small class="muted">{t["flow"]} · {t["owner"]}</small></strong><span>{t["node"]}</span><span>{t["deadline"]}</span><span class="tag">{t["level"]}</span></div>' for t in _OA_TASKS)
    mails = "".join(f'<tr><td>{src}</td><td>{title}</td><td>{time_text}</td></tr>' for src, title, time_text in _OA_MAILS)
    days = "".join(f'<b class="{"hot" if d in {5, 9, 18, 24} else ""}">{d}</b>' for d in range(1, 29))
    content = f"""
    <section class="grid-4"><article class="layout-card work-card"><span class="muted">待办事项</span><span class="metric">18</span></article><article class="layout-card work-card"><span class="muted">待阅公文</span><span class="metric">34</span></article><article class="layout-card work-card"><span class="muted">今日会议</span><span class="metric">5</span></article><article class="layout-card work-card"><span class="muted">流程超时</span><span class="metric">3</span></article></section>
    <section class="split" style="margin-top:16px"><article class="layout-card work-card"><h3>统一待办中心</h3>{task_rows}</article><article class="layout-card work-card"><h3>日程提醒</h3><div class="calendar">{days}</div></article></section>
    <section class="split" style="margin-top:16px"><article class="layout-card work-card"><h3>内部邮件</h3><table><tbody>{mails}</tbody></table></article><article class="layout-card work-card"><h3>常用入口</h3><p><a class="btn secondary" href="/workflow/new">新建流程</a> <a class="btn secondary" href="/api/addressbook">通讯录</a></p><p class="muted">支持转办、会签、退回、催办、流程日志追踪。</p></article></section>"""
    return _oa_shell("我的工作台", "home", content, session)


def _iot_login(message: str = "") -> str:
    profile = _profile()
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>登录 - {_html_escape(profile['brand'])}</title><style>:root{{--primary:#22c55e;--primary-2:#06b6d4;--bg:#07111f;--card:rgba(12,26,45,.86);--text:#e6f6ff;--muted:#8ba6bf;--line:rgba(148,196,255,.16);--input:#0b1b2f;--input-line:rgba(148,196,255,.22);--focus:#22c55e;--focus-ring:rgba(34,197,94,.16);--soft:rgba(34,197,94,.1);--tag:rgba(34,197,94,.12);--tag-text:#9af7c2;--danger:#ff8a80;--ok:#7dffb2;--shadow:rgba(0,0,0,.26)}}{_base_style('iot')} body{{background:radial-gradient(circle at 80% 10%,rgba(34,197,94,.25),transparent 30%),linear-gradient(135deg,#06101c,#0b1728);color:var(--text)}} .login{{min-height:100vh;display:grid;place-items:center;padding:24px}} .box{{width:min(440px,100%);padding:28px;background:var(--card);border:1px solid var(--line);border-radius:18px;box-shadow:0 28px 80px rgba(0,0,0,.35)}} h1{{margin:0 0 8px}} form{{display:grid;gap:14px;margin-top:20px}}</style></head><body><main class="login"><section class="box"><h1>{_html_escape(profile['brand'])}</h1><p class="muted">{_html_escape(profile['subtitle'])}</p><form method="post" action="{profile['login_path']}"><label>运维账号<input name="username" placeholder="ops_admin"></label><label>访问密钥<input name="password" type="password"></label><label>验证码<input name="captcha" placeholder="请输入图片验证码"></label><button class="btn" type="submit">进入控制台</button><p class="danger">{_html_escape(message)}</p></form></section></main></body></html>"""


def _iot_home(session: dict | None) -> str:
    rows = "".join(f'<div class="asset-row"><strong>{d["name"]}<br><small class="muted">{d["ip"]} · {d["proto"]}</small></strong><span class="{"ok" if d["status"] == "在线" else "danger"}">{d["status"]}</span><span>{d["risk"]}</span><div class="bar"><i style="width:{d["load"]}%"></i></div><a class="tag" href="/api/device/config?ip={quote(d["ip"])}">配置</a></div>' for d in _DEVICES)
    alarms = "".join(f'<p><span class="tag">{a["level"]}</span> {a["time"]} {a["asset"]}：{a["message"]}</p>' for a in _ALARMS)
    terminal = "\n".join(["$ tail -f /var/log/edge-gateway/audit.log", "09:42:18 WARN  HMI-10.19.2.15 heartbeat timeout", "09:43:02 INFO  Modbus channel ch-01 reconnect ok", "09:43:37 INFO  MQTT publish /jh/pump/telemetry qos=1", "09:44:11 DENY  config export requires admin role"])
    content = f"""
    <section class="grid-4"><article class="glass layout-card work-card"><span class="muted">接入设备</span><span class="metric">156</span></article><article class="glass layout-card work-card"><span class="muted">在线通道</span><span class="metric">24</span></article><article class="glass layout-card work-card"><span class="muted">未确认告警</span><span class="metric">7</span></article><article class="glass layout-card work-card"><span class="muted">数据点/分钟</span><span class="metric">12.8k</span></article></section>
    <section class="split" style="margin-top:16px"><article class="glass layout-card work-card"><h3>关键资产运行状态</h3>{rows}</article><article class="glass layout-card work-card"><h3>实时告警</h3>{alarms}<h3>协议通道</h3><p><span class="tag">Modbus TCP</span> <span class="tag">OPC UA</span> <span class="tag">IEC104</span> <span class="tag">MQTT</span></p></article></section>
    <section class="split" style="margin-top:16px"><article class="glass layout-card work-card"><h3>审计终端</h3><pre class="terminal">{_html_escape(terminal)}</pre></article><article class="glass layout-card work-card"><h3>远程维护</h3><p class="muted">维护窗口：09:00-11:30 / 14:00-17:00</p><p><a class="btn secondary" href="/logs/export">导出日志</a> <a class="btn secondary" href="/api/devices">设备 API</a></p></article></section>"""
    return _iot_shell("运行总览", "home", content, session)


def _search_page(params: dict, session: dict | None) -> str:
    keyword = str(params.get("q") or params.get("keyword") or "").strip()
    rows = "".join(f'<tr><td>{_html_escape(d["title"])}</td><td>{d["owner"]}</td><td><span class="tag">{d["level"]}</span></td><td>{d["updated"]}</td></tr>' for d in _DOCS)
    content = f"<section class='layout-card panel'><h2>全文检索</h2><form method='get' action='/search' style='display:grid;grid-template-columns:1fr 120px;gap:12px'><input name='q' value='{_html_escape(keyword)}' placeholder='标题、编号、IP、部门'><button class='btn'>查询</button></form></section><section class='layout-card panel' style='margin-top:16px'><h2>查询结果</h2><table><tbody>{rows}</tbody></table></section>"
    if HONEYPOT_PROFILE == "oa":
        return _oa_shell("知识检索", "kb", content, session)
    if HONEYPOT_PROFILE == "gateway":
        return _iot_shell("资产检索", "device", content, session)
    return _gov_shell("站内搜索", "open", content, session)


def _upload_page(session: dict | None) -> str:
    rows = "".join(f"<tr><td>{_html_escape(item['name'])}</td><td>{item['size']}</td><td>{item['time']}</td></tr>" for item in _UPLOADS[-8:]) or "<tr><td colspan='3' class='muted'>暂无上传记录</td></tr>"
    content = f"<section class='split'><article class='layout-card panel'><h2>附件上传</h2><form method='post' action='/upload' enctype='multipart/form-data' style='display:grid;gap:12px'><label>材料标题<input name='title'></label><label>选择文件<input name='file' type='file'></label><button class='btn'>上传</button></form></article><article class='layout-card panel'><h2>最近上传</h2><table><tbody>{rows}</tbody></table></article></section>"
    return _gov_shell("附件上传", "open", content, session)


def _api_users() -> dict:
    return _json_response({"code": 0, "message": "success", "data": _USERS, "serverTime": _utc_now_iso()})


def _api_devices() -> dict:
    return _json_response({"code": 0, "message": "ok", "items": _DEVICES, "total": len(_DEVICES)})


def _not_found(path: str, session: dict | None) -> dict:
    content = f"<section class='layout-card panel'><h2>404 未找到</h2><p class='muted'>请求地址 <code>{_html_escape(path)}</code> 不存在或需要更高权限。</p></section>"
    if HONEYPOT_PROFILE == "oa":
        return _response(404, _oa_shell("页面不存在", "", content, session))
    if HONEYPOT_PROFILE == "gateway":
        return _response(404, _iot_shell("页面不存在", "", content, session))
    return _response(404, _gov_shell("页面不存在", "", content, session))


def _dispatch_request(handler: BaseHTTPRequestHandler, body: str) -> dict:
    split = urlsplit(handler.path)
    path = split.path or "/"
    params = _parse_params(handler, body)
    session = _get_session(handler)
    profile = _profile()

    if handler.command == "GET" and path == "/robots.txt":
        return _response(200, "User-agent: *\nDisallow: /admin/\nDisallow: /api/\nDisallow: /console/\nDisallow: /sys/\n", "text/plain; charset=utf-8")
    if handler.command == "GET" and path == "/favicon.ico":
        return _response(204, b"", "image/x-icon")

    if handler.command == "GET" and path in {"/", "/index.php", "/portal"}:
        if HONEYPOT_PROFILE == "oa":
            return _redirect(profile["login_path"])
        if HONEYPOT_PROFILE == "gateway":
            return _redirect(profile["admin_path"])
        return _response(200, _gov_home(session))

    if handler.command == "GET" and path in {"/login", "/login.html", "/admin/login.php", "/user-login.html"}:
        if HONEYPOT_PROFILE == "oa":
            return _response(200, _oa_login())
        if HONEYPOT_PROFILE == "gateway":
            return _response(200, _iot_login())
        return _response(200, _gov_shell("后台登录", "login", "<section class='layout-card panel'><h2>后台管理登录</h2><form method='post' action='/admin/login.php' style='display:grid;gap:12px;max-width:420px'><label>账号<input name='username' placeholder='admin'></label><label>密码<input name='password' type='password'></label><label>验证码<input name='captcha'></label><button class='btn'>登录</button></form></section>", session))

    if handler.command == "POST" and path in {"/login", "/login.html", "/admin/login.php", "/user-login.html", "/api/auth/login"}:
        username = str(params.get("username") or params.get("user") or params.get("account") or "admin")
        session_id, _session = _new_session(username, _extract_source_ip(handler))
        if path == "/api/auth/login":
            response = _json_response({"code": 401, "message": "密码错误或验证码已过期", "traceId": uuid4().hex}, 401)
        else:
            response = _redirect(profile["admin_path"])
        response["headers"]["Set-Cookie"] = f"{_SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Lax"
        return response

    if handler.command == "POST" and path == "/logout":
        _clear_session(handler)
        response = _redirect(profile["login_path"])
        response["headers"]["Set-Cookie"] = f"{_SESSION_COOKIE}=deleted; Path=/; Max-Age=0"
        return response

    if handler.command == "GET" and path in {"/admin/index.php", "/admin", "/cms/admin"}:
        return _response(200, _gov_admin(session))
    if handler.command == "GET" and path in {"/oa/index.do", "/workflow/list", "/workflow/new", "/document/list"}:
        return _response(200, _oa_home(session))
    if handler.command == "GET" and path in {"/console", "/devices", "/channels", "/logs"}:
        return _response(200, _iot_home(session))

    if handler.command in {"GET", "POST"} and path in {"/search", "/zwgk", "/service", "/interaction", "/data/catalog", "/kb/search"}:
        return _response(200, _search_page(params, session))

    if handler.command == "GET" and path.startswith("/article/"):
        article_id = path.rsplit("/", 1)[-1]
        return _response(200, _gov_shell("信息公开详情", "open", f"<section class='layout-card panel'><span class='tag'>信息公开</span><h2>政务公开正文 #{_html_escape(article_id)}</h2><p>为进一步提升政务服务事项办理质量，请各部门按统一模板完成系统账号、接口资产、公开栏目与附件材料自查。</p><p class='muted'>附件：政务公开目录质量检查表.xlsx、应用系统资产清单模板.docx</p></section>", session))

    if handler.command == "GET" and path in {"/download/notice.doc", "/logs/export"}:
        filename = "政务公开目录质量检查通知.doc" if path.endswith(".doc") else "edge-gateway-audit.log"
        content = "内部资料\n政务公开目录质量检查通知\n" if path.endswith(".doc") else "2026-04-24 09:44:11 DENY config export requires admin role\n"
        return _response(200, content, "application/octet-stream", {"Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}"})

    if handler.command == "GET" and path in {"/upload", "/editor/upload.php"}:
        return _response(200, _upload_page(session))
    if handler.command == "POST" and path in {"/upload", "/editor/upload.php", "/api/file/upload"}:
        name = str(params.get("filename") or params.get("title") or "upload.bin")[:120]
        _UPLOADS.append({"name": name, "size": len(body), "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
        if path.startswith("/api/") or path.endswith("upload.php"):
            return _json_response({"code": 0, "msg": "上传成功", "url": f"/uploads/{uuid4().hex}.dat"})
        return _response(200, _upload_page(session))

    if handler.command == "GET" and path in {"/api/users", "/admin/api/users", "/api/addressbook"}:
        return _api_users()
    if handler.command == "GET" and path in {"/api/devices", "/api/device/list"}:
        return _api_devices()
    if handler.command in {"GET", "POST", "PUT"} and path in {"/api/device/config", "/api/config/save", "/api/xml", "/service/soap", "/sys/admin"}:
        return _json_response({"code": 403, "message": "当前账号无权执行该操作", "requestId": uuid4().hex})
    if handler.command == "GET" and path in {"/phpinfo.php", "/.env", "/config.php.bak", "/backup.zip", "/WEB-INF/web.xml"}:
        return _response(403, "Forbidden", "text/plain; charset=utf-8")

    return _not_found(path, session)


class HoneypotHandler(BaseHTTPRequestHandler):
    server_version = _profile()["server"]
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self._handle_request()

    def do_POST(self) -> None:
        self._handle_request()

    def do_PUT(self) -> None:
        self._handle_request()

    def do_DELETE(self) -> None:
        self._handle_request()

    def do_HEAD(self) -> None:
        self._handle_request(write_body=False)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS,HEAD")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _handle_request(self, *, write_body: bool = True) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(length) if length > 0 else b""
        body = raw_body.decode("utf-8", errors="replace")
        split = urlsplit(self.path)
        response = _dispatch_request(self, body)
        response_headers = {"Content-Type": response["content_type"], "X-Powered-By": _profile()["powered_by"], **dict(response.get("headers") or {})}
        try:
            response_body_text = response["body"].decode("utf-8", errors="replace")
        except Exception:
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
            "headers": _normalize_headers(self),
            "params": _parse_params(self, body),
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
            if value is not None:
                self.send_header(str(key), str(value))
        self.send_header("Content-Length", str(len(response["body"])))
        self.end_headers()
        if write_body and response["body"]:
            self.wfile.write(response["body"])

    def log_message(self, fmt: str, *args) -> None:
        ip = self.client_address[0] if self.client_address else "unknown"
        print(f"[cn-honeypot] {ip} - {fmt % args}")


def main() -> None:
    threading.Thread(target=_heartbeat_loop, name="honeypot-heartbeat", daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", WEB_HONEYPOT_PORT), HoneypotHandler)
    print(
        "[cn-honeypot] started "
        f"profile={HONEYPOT_PROFILE} port={WEB_HONEYPOT_PORT} ingest={INGEST_API_URL} heartbeat={HEARTBEAT_API_URL}"
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
