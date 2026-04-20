from __future__ import annotations

import html
import json
import posixpath
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote_plus


_REGEX_FLAGS = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
}

_MODSECURITY_SEVERITY_SCORES = {
    "critical": 55,
    "error": 45,
    "high": 45,
    "warning": 28,
    "medium": 28,
    "notice": 18,
    "low": 18,
}

_MODSECURITY_TRANSFORMS = {
    "urldecode": "url_decode",
    "urldecodeuni": "url_decode",
    "htmlentitydecode": "html_unescape",
    "lowercase": "lowercase",
    "compresswhitespace": "collapse_whitespace",
    "removenulls": "strip_nulls",
    "normalisepath": "normalize_path",
    "normalizepath": "normalize_path",
    "cmdline": "cmdline",
}


@dataclass(frozen=True)
class CompiledMatcher:
    fields: tuple[str, ...]
    operator: str
    transforms: tuple[str, ...]
    pattern: re.Pattern[str] | None = None
    value: str | None = None
    values: tuple[str, ...] = ()


@dataclass(frozen=True)
class CompiledRule:
    rule_id: str
    source: str
    title: str
    description: str
    event_type: str
    score: int
    severity: str
    confidence: str
    tags: tuple[str, ...]
    match: dict | CompiledMatcher
    exclude: dict | CompiledMatcher | None
    import_path: str | None = None

    def to_meta(self) -> dict:
        return {
            "key": self.rule_id,
            "title": self.title,
            "description": self.description,
            "event_type": self.event_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "score": self.score,
            "source": self.source,
            "import_path": self.import_path,
            "tags": list(self.tags),
        }


@dataclass(frozen=True)
class ParsedSecRule:
    variables: tuple[str, ...]
    operator: str
    operator_value: str | tuple[str, ...]
    actions: dict[str, tuple[str, ...]]
    line_no: int


def load_compiled_rules(
    *,
    ruleset_paths: tuple[str, ...] | list[str] | None,
    base_dir: str | Path,
) -> list[CompiledRule]:
    discovered_files = _discover_rule_files(ruleset_paths=ruleset_paths, base_dir=base_dir)
    rules: list[CompiledRule] = []

    for file_path in discovered_files:
        if file_path.suffix.lower() == ".json":
            rules.extend(_load_json_rules(file_path))
            continue
        if file_path.suffix.lower() == ".conf":
            rules.extend(_load_modsecurity_rules(file_path))

    rules.sort(key=lambda item: (item.event_type, -item.score, item.rule_id))
    return rules


def evaluate_condition(
    compiled: dict | CompiledMatcher | None,
    *,
    request_record: dict,
    response_record: dict,
) -> bool:
    if compiled is None:
        return False

    if isinstance(compiled, CompiledMatcher):
        return _evaluate_matcher(
            compiled,
            request_record=request_record,
            response_record=response_record,
        )

    logic = str(compiled.get("logic") or "any").strip().lower() or "any"
    children = compiled.get("matchers") or ()
    if not children:
        return False

    results = [
        evaluate_condition(
            item,
            request_record=request_record,
            response_record=response_record,
        )
        for item in children
    ]
    if logic == "all":
        return all(results)
    return any(results)


def _load_json_rules(file_path: Path) -> list[CompiledRule]:
    payload = json.loads(file_path.read_text(encoding="utf-8"))
    package_source = file_path.stem
    package_rules = payload

    if isinstance(payload, dict):
        package_source = str(payload.get("source") or package_source)
        package_rules = payload.get("rules") or []

    if not isinstance(package_rules, list):
        return []

    compiled: list[CompiledRule] = []
    for index, item in enumerate(package_rules, start=1):
        if not isinstance(item, dict):
            continue
        rule = _compile_rule(
            item,
            default_source=package_source,
            import_path=f"{file_path.name}:{index}",
        )
        if rule is not None:
            compiled.append(rule)

    return compiled


def _load_modsecurity_rules(file_path: Path) -> list[CompiledRule]:
    lines = _read_rule_lines(file_path)
    compiled: list[CompiledRule] = []
    index = 0

    while index < len(lines):
        current = _parse_sec_rule_line(lines[index]["content"], line_no=lines[index]["line_no"])
        index += 1
        if current is None:
            continue

        chain = [current]
        while "chain" in current.actions and index < len(lines):
            current = _parse_sec_rule_line(lines[index]["content"], line_no=lines[index]["line_no"])
            index += 1
            if current is None:
                break
            chain.append(current)

        rule = _compile_modsecurity_rule(
            chain,
            import_path=f"{file_path.name}:{chain[0].line_no}",
        )
        if rule is not None:
            compiled.append(rule)

    return compiled


def _compile_rule(spec: dict, *, default_source: str, import_path: str | None) -> CompiledRule | None:
    rule_id = str(spec.get("id") or "").strip()
    event_type = str(spec.get("event_type") or "").strip().lower()
    if not rule_id or not event_type:
        return None

    score = max(int(spec.get("score") or 0), 1)
    match_spec = spec.get("match")
    if not isinstance(match_spec, dict):
        return None

    match = _compile_condition(match_spec)
    exclude_spec = spec.get("exclude")
    exclude = _compile_condition(exclude_spec) if isinstance(exclude_spec, dict) else None

    return CompiledRule(
        rule_id=rule_id,
        source=str(spec.get("source") or default_source).strip() or default_source,
        title=str(spec.get("title") or rule_id).strip() or rule_id,
        description=str(spec.get("description") or "Imported attack rule").strip(),
        event_type=event_type,
        score=score,
        severity=str(spec.get("severity") or _severity_from_score(score)).strip().lower(),
        confidence=str(spec.get("confidence") or "medium").strip().lower() or "medium",
        tags=tuple(str(item).strip() for item in (spec.get("tags") or []) if str(item).strip()),
        match=match,
        exclude=exclude,
        import_path=import_path,
    )


def _compile_condition(spec: dict) -> dict | CompiledMatcher:
    if "matchers" in spec:
        return {
            "logic": str(spec.get("logic") or "any").strip().lower() or "any",
            "matchers": [_compile_condition(item) for item in spec.get("matchers") or [] if isinstance(item, dict)],
        }

    fields = tuple(
        str(item).strip()
        for item in (spec.get("fields") or ["all"])
        if str(item).strip()
    ) or ("all",)
    transforms = tuple(
        str(item).strip().lower()
        for item in (spec.get("transforms") or [])
        if str(item).strip()
    )
    operator = str(spec.get("operator") or "regex").strip().lower()

    if operator == "regex":
        flags = 0
        for item in spec.get("flags") or []:
            flags |= _REGEX_FLAGS.get(str(item).strip().upper(), 0)
        pattern = re.compile(str(spec.get("pattern") or ""), flags)
        return CompiledMatcher(
            fields=fields,
            operator=operator,
            transforms=transforms,
            pattern=pattern,
        )

    if operator == "contains":
        return CompiledMatcher(
            fields=fields,
            operator=operator,
            transforms=transforms,
            value=str(spec.get("value") or ""),
        )

    values = spec.get("values")
    if operator == "phrase_match" and isinstance(values, list):
        phrases = tuple(str(item) for item in values if str(item))
        return CompiledMatcher(
            fields=fields,
            operator=operator,
            transforms=transforms,
            values=phrases,
        )

    raise ValueError(f"Unsupported rule operator: {operator}")


def _compile_modsecurity_rule(
    chain: list[ParsedSecRule],
    *,
    import_path: str,
) -> CompiledRule | None:
    if not chain:
        return None

    root = chain[0]
    actions = root.actions
    rule_id = _first_action(actions, "id") or import_path
    severity = (_first_action(actions, "severity") or "warning").strip().lower()
    title = _first_action(actions, "msg") or rule_id
    tags = _collect_actions(chain, "tag")
    event_type = _map_modsecurity_event_type(tags=tags, message=title)
    if event_type is None:
        return None

    transforms = _collect_modsecurity_transforms(chain)
    matchers = []
    for item in chain:
        matcher = _compile_modsecurity_matcher(item, transforms=transforms)
        if matcher is None:
            return None
        matchers.append(matcher)

    match: dict | CompiledMatcher
    if len(matchers) == 1:
        match = matchers[0]
    else:
        match = {
            "logic": "all",
            "matchers": matchers,
        }

    return CompiledRule(
        rule_id=str(rule_id).strip() or import_path,
        source="modsecurity",
        title=str(title).strip() or rule_id,
        description=f"Imported ModSecurity rule from {import_path}",
        event_type=event_type,
        score=_MODSECURITY_SEVERITY_SCORES.get(severity, 28),
        severity=severity,
        confidence="medium",
        tags=tuple(tags),
        match=match,
        exclude=None,
        import_path=import_path,
    )


def _compile_modsecurity_matcher(
    rule: ParsedSecRule,
    *,
    transforms: tuple[str, ...],
) -> CompiledMatcher | None:
    fields = _map_modsecurity_variables(rule.variables)
    if not fields:
        return None

    operator = rule.operator.strip().lower()
    if operator == "regex":
        return CompiledMatcher(
            fields=fields,
            operator="regex",
            transforms=transforms,
            pattern=re.compile(str(rule.operator_value), re.IGNORECASE),
        )
    if operator == "contains":
        return CompiledMatcher(
            fields=fields,
            operator="contains",
            transforms=transforms,
            value=str(rule.operator_value),
        )
    if operator == "phrase_match":
        return CompiledMatcher(
            fields=fields,
            operator="phrase_match",
            transforms=transforms,
            values=tuple(str(item) for item in rule.operator_value if str(item)),
        )
    return None


def _evaluate_matcher(
    matcher: CompiledMatcher,
    *,
    request_record: dict,
    response_record: dict,
) -> bool:
    for field in matcher.fields:
        for raw_value in _iter_field_values(
            field,
            request_record=request_record,
            response_record=response_record,
        ):
            value = _apply_transforms(raw_value, matcher.transforms)
            if not value:
                continue
            if matcher.operator == "regex" and matcher.pattern is not None and matcher.pattern.search(value):
                return True
            if matcher.operator == "contains" and matcher.value is not None and matcher.value in value:
                return True
            if matcher.operator == "phrase_match" and matcher.values and any(item in value for item in matcher.values):
                return True
    return False


def _iter_field_values(
    field: str,
    *,
    request_record: dict,
    response_record: dict,
):
    field_name = str(field or "").strip()
    if not field_name:
        return

    request_headers = _normalize_mapping(request_record.get("headers"))
    response_headers = _normalize_mapping(response_record.get("headers"))
    params = _normalize_mapping(request_record.get("params"))
    cookies = _parse_cookie_header(request_headers.get("cookie", ""))

    if field_name == "all":
        for item in (
            request_record.get("method"),
            request_record.get("path"),
            request_record.get("query_string"),
            request_record.get("body"),
            request_record.get("raw_request"),
            response_record.get("body"),
            response_record.get("status"),
        ):
            if item is not None:
                yield str(item)
        for item in _iter_field_values("params", request_record=request_record, response_record=response_record):
            yield item
        for item in _iter_field_values("headers", request_record=request_record, response_record=response_record):
            yield item
        for item in _iter_field_values("cookies", request_record=request_record, response_record=response_record):
            yield item
        return

    if field_name == "uri":
        path = str(request_record.get("path") or "").strip()
        query_string = str(request_record.get("query_string") or "").strip()
        value = f"{path}?{query_string}" if query_string else path
        if value:
            yield value
        return

    if field_name == "method":
        value = str(request_record.get("method") or "").strip()
        if value:
            yield value
        return

    if field_name == "path":
        value = str(request_record.get("path") or "").strip()
        if value:
            yield value
        return

    if field_name == "query_string":
        value = str(request_record.get("query_string") or "").strip()
        if value:
            yield value
        return

    if field_name == "body":
        value = str(request_record.get("body") or "").strip()
        if value:
            yield value
        return

    if field_name == "raw_request":
        value = str(request_record.get("raw_request") or "").strip()
        if value:
            yield value
        return

    if field_name == "params":
        for key, value in params.items():
            if key:
                yield key
            if value:
                yield value
            if key or value:
                yield f"{key}={value}"
        return

    if field_name == "param_names":
        for key in params:
            if key:
                yield key
        return

    if field_name == "headers":
        for key, value in request_headers.items():
            if key:
                yield key
            if value:
                yield value
            yield f"{key}: {value}"
        return

    if field_name == "header_names":
        for key in request_headers:
            if key:
                yield key
        return

    if field_name.startswith("headers:"):
        header_name = field_name.split(":", 1)[1].strip().lower()
        value = request_headers.get(header_name, "")
        if value:
            yield value
        return

    if field_name == "cookies":
        for key, value in cookies.items():
            if key:
                yield key
            if value:
                yield value
            yield f"{key}={value}"
        return

    if field_name == "cookie_names":
        for key in cookies:
            if key:
                yield key
        return

    if field_name == "response_body":
        value = str(response_record.get("body") or "").strip()
        if value:
            yield value
        return

    if field_name == "response_status":
        value = response_record.get("status")
        if value is not None:
            yield str(value)
        return

    if field_name == "response_headers":
        for key, value in response_headers.items():
            if key:
                yield key
            if value:
                yield value
            yield f"{key}: {value}"


def _apply_transforms(value: str, transforms: tuple[str, ...]) -> str:
    text = str(value or "")
    for transform in transforms:
        if transform == "lowercase":
            text = text.lower()
            continue
        if transform == "url_decode":
            for _ in range(3):
                decoded = unquote_plus(text)
                if decoded == text:
                    break
                text = decoded
            continue
        if transform == "html_unescape":
            for _ in range(2):
                decoded = html.unescape(text)
                if decoded == text:
                    break
                text = decoded
            continue
        if transform == "collapse_whitespace":
            text = re.sub(r"\s+", " ", text).strip()
            continue
        if transform == "strip_nulls":
            text = text.replace("\x00", "")
            continue
        if transform == "normalize_slashes":
            text = text.replace("\\", "/")
            continue
        if transform == "normalize_path":
            normalized = text.replace("\\", "/")
            normalized = re.sub(r"/{2,}", "/", normalized)
            try:
                normalized = posixpath.normpath(normalized)
            except Exception:  # noqa: BLE001
                pass
            text = normalized
            continue
        if transform == "cmdline":
            text = text.lower()
            text = re.sub(r"[\"'`^]", "", text)
            text = re.sub(r"\s+", " ", text).strip()
    return text


def _discover_rule_files(
    *,
    ruleset_paths: tuple[str, ...] | list[str] | None,
    base_dir: str | Path,
) -> list[Path]:
    root = Path(base_dir).resolve()
    files: list[Path] = []

    for item in ruleset_paths or ():
        raw_path = Path(str(item).strip())
        if not str(item).strip():
            continue
        candidate = raw_path if raw_path.is_absolute() else root / raw_path
        if not candidate.exists():
            continue
        if candidate.is_dir():
            files.extend(
                path
                for path in sorted(candidate.rglob("*"))
                if path.is_file() and path.suffix.lower() in {".json", ".conf"}
            )
            continue
        if candidate.suffix.lower() in {".json", ".conf"}:
            files.append(candidate)

    return files


def _read_rule_lines(file_path: Path) -> list[dict]:
    result: list[dict] = []
    buffer = ""
    buffer_line_no = 0

    for line_no, raw_line in enumerate(file_path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        current = stripped
        if buffer:
            current = f"{buffer} {current}".strip()

        if current.endswith("\\"):
            buffer = current[:-1].rstrip()
            if not buffer_line_no:
                buffer_line_no = line_no
            continue

        result.append(
            {
                "line_no": buffer_line_no or line_no,
                "content": current,
            }
        )
        buffer = ""
        buffer_line_no = 0

    if buffer:
        result.append({"line_no": buffer_line_no or 1, "content": buffer})

    return result


def _parse_sec_rule_line(raw_line: str, *, line_no: int) -> ParsedSecRule | None:
    if not raw_line.startswith("SecRule "):
        return None

    try:
        tokens = shlex.split(raw_line, posix=True)
    except ValueError:
        return None

    if len(tokens) < 4 or tokens[0] != "SecRule":
        return None

    variables = tuple(item.strip() for item in tokens[1].split("|") if item.strip() and not item.startswith("!"))
    operator, operator_value = _parse_modsecurity_operator(tokens[2])
    if operator is None:
        return None

    actions = _parse_modsecurity_actions(tokens[3])
    return ParsedSecRule(
        variables=variables,
        operator=operator,
        operator_value=operator_value,
        actions=actions,
        line_no=line_no,
    )


def _parse_modsecurity_operator(raw: str) -> tuple[str | None, str | tuple[str, ...]]:
    text = str(raw or "").strip()
    if not text.startswith("@"):
        return None, ""

    if text.startswith("@rx "):
        return "regex", text[4:].strip()
    if text.startswith("@contains "):
        return "contains", text[10:].strip()
    if text.startswith("@pm "):
        values = tuple(item.strip() for item in text[4:].split() if item.strip())
        return "phrase_match", values
    return None, ""


def _parse_modsecurity_actions(raw: str) -> dict[str, tuple[str, ...]]:
    parsed: dict[str, list[str]] = {}

    for item in _split_preserving_quotes(raw):
        if not item:
            continue
        if ":" in item:
            key, value = item.split(":", 1)
            parsed.setdefault(key.strip().lower(), []).append(value.strip().strip("'\""))
            continue
        parsed.setdefault(item.strip().lower(), []).append("true")

    return {key: tuple(values) for key, values in parsed.items()}


def _split_preserving_quotes(raw: str) -> list[str]:
    items: list[str] = []
    buffer: list[str] = []
    quote: str | None = None

    for char in str(raw or ""):
        if char in {"'", '"'}:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
            buffer.append(char)
            continue
        if char == "," and quote is None:
            item = "".join(buffer).strip()
            if item:
                items.append(item)
            buffer = []
            continue
        buffer.append(char)

    item = "".join(buffer).strip()
    if item:
        items.append(item)
    return items


def _collect_modsecurity_transforms(chain: list[ParsedSecRule]) -> tuple[str, ...]:
    transforms: list[str] = []
    for item in chain:
        for raw_transform in item.actions.get("t", ()):
            normalized = _MODSECURITY_TRANSFORMS.get(str(raw_transform).strip().lower())
            if normalized and normalized not in transforms:
                transforms.append(normalized)
    return tuple(transforms)


def _map_modsecurity_variables(variables: tuple[str, ...]) -> tuple[str, ...]:
    mapped: list[str] = []
    variable_map = {
        "REQUEST_URI": ("uri",),
        "REQUEST_URI_RAW": ("uri",),
        "REQUEST_METHOD": ("method",),
        "REQUEST_LINE": ("raw_request",),
        "ARGS": ("params",),
        "ARGS_GET": ("query_string",),
        "ARGS_POST": ("body", "params"),
        "ARGS_NAMES": ("param_names",),
        "REQUEST_HEADERS": ("headers",),
        "REQUEST_HEADERS_NAMES": ("header_names",),
        "REQUEST_BODY": ("body",),
        "REQUEST_COOKIES": ("cookies",),
        "REQUEST_COOKIES_NAMES": ("cookie_names",),
    }

    for item in variables:
        normalized = item.strip()
        if normalized.startswith("REQUEST_HEADERS:"):
            header_name = normalized.split(":", 1)[1].strip()
            if header_name:
                mapped.append(f"headers:{header_name}")
            continue
        mapped.extend(variable_map.get(normalized, ()))

    deduped: list[str] = []
    for item in mapped:
        if item not in deduped:
            deduped.append(item)
    return tuple(deduped)


def _map_modsecurity_event_type(*, tags: list[str], message: str) -> str | None:
    haystack = " ".join(tags + [message]).lower()
    mapping = (
        ("attack-sqli", "web_sqli"),
        ("sql injection", "web_sqli"),
        ("attack-xss", "web_xss"),
        ("cross site scripting", "web_xss"),
        (" xss", "web_xss"),
        ("attack-lfi", "web_path_traversal"),
        ("path traversal", "web_path_traversal"),
        ("directory traversal", "web_path_traversal"),
        ("attack-rce", "web_cmd_exec"),
        ("command injection", "web_cmd_exec"),
        ("command execution", "web_cmd_exec"),
        ("remote command", "web_cmd_exec"),
        ("file upload", "web_file_upload"),
        ("web shell", "web_file_upload"),
        ("attack-ssrf", "web_ssrf"),
        ("server side request forgery", "web_ssrf"),
        (" attack-ssti", "web_ssti"),
        ("template injection", "web_ssti"),
        ("xxe", "web_xxe"),
        ("xml external entity", "web_xxe"),
        ("scanner", "web_scan"),
        ("automation", "web_scan"),
        ("protocol attack", "web_scan"),
        ("protocol violation", "web_scan"),
    )

    for keyword, event_type in mapping:
        if keyword in haystack:
            return event_type
    return None


def _first_action(actions: dict[str, tuple[str, ...]], key: str) -> str | None:
    values = actions.get(key, ())
    return values[0] if values else None


def _collect_actions(chain: list[ParsedSecRule], key: str) -> list[str]:
    items: list[str] = []
    for rule in chain:
        for value in rule.actions.get(key, ()):
            clean = str(value).strip()
            if clean:
                items.append(clean)
    return items


def _normalize_mapping(value) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key).strip().lower(): str(item or "").strip() for key, item in value.items() if str(key).strip()}


def _parse_cookie_header(raw: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in str(raw or "").split(";"):
        item = part.strip()
        if not item or "=" not in item:
            continue
        key, value = item.split("=", 1)
        cookies[key.strip().lower()] = value.strip()
    return cookies


def _severity_from_score(score: int) -> str:
    if score >= 50:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 25:
        return "medium"
    return "low"
