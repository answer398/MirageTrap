from __future__ import annotations

from pathlib import Path

from app.utils.web_request import parse_request_content, parse_response_content

from .rule_loader import evaluate_condition, load_compiled_rules


class RiskEngineService:
    _TYPE_CATALOG = {
        "web_req": {
            "title": "普通请求",
            "description": "未命中高风险攻击规则，保留为普通 Web 请求。",
        },
        "web_sqli": {
            "title": "SQL 注入",
            "description": "请求中出现 SQL 语句拼接、注释、联合查询、延时函数等数据库攻击特征。",
        },
        "web_xss": {
            "title": "跨站脚本",
            "description": "请求中出现 script、事件处理器、javascript 协议或其他脚本注入特征。",
        },
        "web_path_traversal": {
            "title": "路径遍历",
            "description": "请求中出现目录回溯、敏感文件探测或本地文件包含特征。",
        },
        "web_cmd_exec": {
            "title": "命令执行",
            "description": "请求中出现 shell 元字符、命令替换或系统命令执行特征。",
        },
        "web_file_upload": {
            "title": "恶意文件上传",
            "description": "请求中出现 multipart 上传、可执行脚本扩展名或 WebShell 载荷特征。",
        },
        "web_ssrf": {
            "title": "服务端请求伪造",
            "description": "请求中包含内网资源、云元数据或危险协议等 SSRF 特征。",
        },
        "web_ssti": {
            "title": "模板注入",
            "description": "请求中出现 Jinja、Twig、Velocity、EL 等服务端模板表达式特征。",
        },
        "web_xxe": {
            "title": "XML 外部实体",
            "description": "请求中出现 DOCTYPE、ENTITY、SYSTEM file:// 等 XXE 特征。",
        },
        "web_scan": {
            "title": "恶意扫描",
            "description": "请求中出现自动化扫描器、目录爆破或漏洞探测路径特征。",
        },
    }

    _EVENT_PRIORITY = {
        "web_sqli": 90,
        "web_cmd_exec": 85,
        "web_xxe": 80,
        "web_ssrf": 75,
        "web_ssti": 74,
        "web_file_upload": 73,
        "web_path_traversal": 70,
        "web_xss": 68,
        "web_scan": 40,
        "web_req": 0,
    }

    def __init__(
        self,
        *,
        ruleset_paths: tuple[str, ...] | list[str] | None = None,
        base_dir: str | Path | None = None,
    ):
        backend_root = Path(base_dir or Path(__file__).resolve().parents[2]).resolve()
        self._rules = load_compiled_rules(
            ruleset_paths=tuple(ruleset_paths or ()),
            base_dir=backend_root,
        )
        self._rule_index = {item.rule_id: item.to_meta() for item in self._rules}

    def evaluate(
        self,
        *,
        event_type: str,
        honeypot_type: str,
        request_record: dict | None = None,
        response_record: dict | None = None,
        request_content: str | None = None,
        response_content: str | None = None,
    ) -> dict:
        normalized_event_type = str(event_type or "").strip().lower() or "web_req"
        if honeypot_type != "web":
            return {
                "risk_score": 5,
                "risk_level": "low",
                "matched_rules": [],
                "detected_event_type": normalized_event_type,
            }

        compiled_request = request_record or parse_request_content(request_content)
        compiled_response = response_record or parse_response_content(response_content)

        score = 5
        type_scores: dict[str, int] = {}
        matched_rules = []

        for rule in self._rules:
            if not evaluate_condition(
                rule.match,
                request_record=compiled_request,
                response_record=compiled_response,
            ):
                continue

            if rule.exclude and evaluate_condition(
                rule.exclude,
                request_record=compiled_request,
                response_record=compiled_response,
            ):
                continue

            matched_rules.append(rule)
            score += int(rule.score)
            type_scores[rule.event_type] = type_scores.get(rule.event_type, 0) + int(rule.score)

        matched_rules.sort(key=lambda item: (-item.score, -self._EVENT_PRIORITY.get(item.event_type, 0), item.rule_id))
        score = min(score, 100)

        detected_event_type = normalized_event_type
        if type_scores:
            detected_event_type = max(
                type_scores.items(),
                key=lambda item: (item[1], self._EVENT_PRIORITY.get(item[0], 0)),
            )[0]

        return {
            "risk_score": score,
            "risk_level": self._to_level(score),
            "matched_rules": [item.rule_id for item in matched_rules],
            "detected_event_type": detected_event_type,
        }

    def describe_rules(self, rule_keys: list[str] | tuple[str, ...] | None) -> list[dict]:
        items = []
        for rule_key in rule_keys or []:
            meta = self._rule_index.get(str(rule_key))
            if meta is None:
                items.append(
                    {
                        "key": str(rule_key),
                        "title": str(rule_key),
                        "description": "未配置规则说明",
                    }
                )
                continue
            items.append(meta)
        return items

    def type_catalog(self) -> list[dict]:
        return [
            {
                "event_type": event_type,
                "title": meta["title"],
                "description": meta["description"],
            }
            for event_type, meta in self._TYPE_CATALOG.items()
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
