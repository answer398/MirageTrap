from __future__ import annotations

import re


class RiskEngineService:
    _WEB_VULN_PATTERNS = [
        {
            "event_type": "web_sqli",
            "title": "SQL 注入",
            "description": "请求中出现 UNION SELECT、恒真条件、延时函数或 information_schema 等 SQL 注入特征。",
            "score": 50,
            "rule": "web_sqli",
            "regex": re.compile(
                r"(union\s+select|(\bor\b|\band\b)\s+\d+\s*=\s*\d+|sleep\s*\(|benchmark\s*\(|information_schema)",
                re.IGNORECASE,
            ),
        },
        {
            "event_type": "web_xss",
            "title": "跨站脚本",
            "description": "请求中包含 script、javascript:、onerror/onload 等 XSS 注入特征。",
            "score": 45,
            "rule": "web_xss",
            "regex": re.compile(
                r"(<script\b|javascript:|onerror\s*=|onload\s*=|<img[^>]+onerror)",
                re.IGNORECASE,
            ),
        },
        {
            "event_type": "web_path_traversal",
            "title": "路径遍历",
            "description": "请求中包含 ../、/etc/passwd、win.ini 等敏感路径遍历访问特征。",
            "score": 35,
            "rule": "web_path_traversal",
            "regex": re.compile(
                r"(\.\./|\.\.\\|/etc/passwd|/windows/win\.ini|/proc/self/environ)",
                re.IGNORECASE,
            ),
        },
        {
            "event_type": "web_cmd_exec",
            "title": "命令执行",
            "description": "请求中包含 shell 管道、命令拼接、反引号或 powershell 等命令执行特征。",
            "score": 48,
            "rule": "web_cmd_exec",
            "regex": re.compile(
                r"(;\s*(cat|id|whoami|uname|wget|curl)\b|\|\s*(cat|id|whoami)\b|`[^`]+`|\$\(.*\)|cmd\s*=|/bin/sh|powershell)",
                re.IGNORECASE,
            ),
        },
        {
            "event_type": "web_file_upload",
            "title": "恶意文件上传",
            "description": "请求中包含 multipart、文件名、PHP WebShell 或表单上传头部等可疑上传特征。",
            "score": 35,
            "rule": "web_file_upload",
            "regex": re.compile(
                r"(multipart/form-data|filename\s*=|\.php[3457]?(\b|$)|webshell|content-disposition:\s*form-data)",
                re.IGNORECASE,
            ),
        },
        {
            "event_type": "web_ssrf",
            "title": "服务端请求伪造",
            "description": "请求中出现元数据地址、内网地址或 file/gopher/dict 等 SSRF 常见探测目标。",
            "score": 35,
            "rule": "web_ssrf",
            "regex": re.compile(
                r"(url\s*=\s*https?://|169\.254\.169\.254|localhost:|127\.0\.0\.1|file://|gopher://|dict://)",
                re.IGNORECASE,
            ),
        },
        {
            "event_type": "web_ssti",
            "title": "模板注入",
            "description": "请求中出现 {{ }}, ${ }, <% %> 或 __class__ 等服务端模板注入特征。",
            "score": 35,
            "rule": "web_ssti",
            "regex": re.compile(
                r"(\{\{.*\}\}|\$\{.*\}|<%=?\s*.*\s*%>|__class__|config\[['\"])",
                re.IGNORECASE,
            ),
        },
        {
            "event_type": "web_xxe",
            "title": "XML 外部实体",
            "description": "请求中包含 XML 外部实体、非 HTML DOCTYPE 或 file:// 等 XXE 注入特征。",
            "score": 40,
            "rule": "web_xxe",
            "regex": re.compile(
                r"(<!doctype\s+(?!html\b)|<!entity|system\s+[\"']file://|expect://)",
                re.IGNORECASE,
            ),
        },
        {
            "event_type": "web_scan",
            "title": "恶意扫描",
            "description": "请求中包含 sqlmap、nikto、dirsearch、gobuster 等自动化扫描器特征。",
            "score": 20,
            "rule": "web_scan",
            "regex": re.compile(
                r"(sqlmap|acunetix|nikto|nmap|masscan|wpscan|dirsearch|gobuster|zgrab)",
                re.IGNORECASE,
            ),
        },
    ]

    _RULE_INDEX = {item["rule"]: item for item in _WEB_VULN_PATTERNS}

    def evaluate(
        self,
        *,
        event_type: str,
        honeypot_type: str,
        request_content: str | None,
        response_content: str | None,
    ) -> dict:
        score = 5
        matched_rules: list[str] = []
        detected_event_type: str | None = None
        normalized_event_type = str(event_type or "").strip().lower() or "web_req"
        content = f"{request_content or ''} {(response_content or '')}"
        content_lower = content.lower()

        if honeypot_type == "web":
            for item in self._WEB_VULN_PATTERNS:
                if item["regex"].search(content):
                    score += int(item["score"])
                    matched_rules.append(str(item["rule"]))
                    if detected_event_type is None:
                        detected_event_type = str(item["event_type"])

        if "http://" in content_lower or "https://" in content_lower:
            score += 8
            matched_rules.append("external_reference")

        score = min(score, 100)

        return {
            "risk_score": score,
            "risk_level": self._to_level(score),
            "matched_rules": matched_rules,
            "detected_event_type": detected_event_type or normalized_event_type,
        }

    def describe_rules(self, rule_keys: list[str] | tuple[str, ...] | None) -> list[dict]:
        items = []
        for rule_key in rule_keys or []:
            meta = self._RULE_INDEX.get(str(rule_key))
            if meta is None:
                items.append(
                    {
                        "key": str(rule_key),
                        "title": str(rule_key),
                        "description": "未配置规则说明",
                    }
                )
                continue
            items.append(
                {
                    "key": meta["rule"],
                    "title": meta["title"],
                    "description": meta["description"],
                }
            )
        return items

    def type_catalog(self) -> list[dict]:
        return [
            {
                "event_type": item["event_type"],
                "title": item["title"],
                "description": item["description"],
                "rule": item["rule"],
            }
            for item in self._WEB_VULN_PATTERNS
        ]

    @staticmethod
    def _to_level(score: int) -> str:
        if score >= 80:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 20:
            return "medium"
        return "low"
