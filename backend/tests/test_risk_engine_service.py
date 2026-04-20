from pathlib import Path
import unittest

from app.services.risk_engine_service import RiskEngineService


BACKEND_ROOT = Path(__file__).resolve().parents[1]


def request_record(
    *,
    method: str = "GET",
    path: str = "/",
    query_string: str = "",
    params: dict | None = None,
    headers: dict | None = None,
    body: str = "",
    raw_request: str = "",
) -> dict:
    return {
        "method": method,
        "path": path,
        "query_string": query_string,
        "params": params or {},
        "headers": headers or {},
        "body": body,
        "raw_request": raw_request,
    }


class RiskEngineServiceTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.service = RiskEngineService(
            ruleset_paths=("rules",),
            base_dir=BACKEND_ROOT,
        )

    def evaluate(self, request: dict, response: dict | None = None) -> dict:
        return self.service.evaluate(
            event_type="web_req",
            honeypot_type="web",
            request_record=request,
            response_record=response or {"status": 200, "headers": {}, "body": ""},
        )

    def test_detects_sql_injection(self):
        result = self.evaluate(
            request_record(
                path="/admin",
                query_string="id=1%20UNION%20SELECT%201,2--",
                params={"id": "1 UNION SELECT 1,2--"},
            )
        )
        self.assertEqual(result["detected_event_type"], "web_sqli")
        self.assertGreaterEqual(result["risk_score"], 50)

    def test_detects_cross_site_scripting(self):
        result = self.evaluate(
            request_record(
                path="/search",
                query_string="q=%3Cscript%3Ealert(1)%3C/script%3E",
                params={"q": "<script>alert(1)</script>"},
            )
        )
        self.assertEqual(result["detected_event_type"], "web_xss")

    def test_detects_path_traversal(self):
        result = self.evaluate(
            request_record(
                path="/download",
                query_string="file=../../../../etc/passwd",
                params={"file": "../../../../etc/passwd"},
            )
        )
        self.assertEqual(result["detected_event_type"], "web_path_traversal")

    def test_detects_command_execution(self):
        result = self.evaluate(
            request_record(
                method="POST",
                path="/run",
                body="cmd=cat+/etc/passwd;id",
                params={"cmd": "cat /etc/passwd;id"},
            )
        )
        self.assertEqual(result["detected_event_type"], "web_cmd_exec")

    def test_detects_file_upload(self):
        body = (
            "------boundary\r\n"
            "Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n"
            "<?php system($_GET['cmd']); ?>\r\n"
            "------boundary--\r\n"
        )
        result = self.evaluate(
            request_record(
                method="POST",
                path="/upload",
                headers={"Content-Type": "multipart/form-data; boundary=----boundary"},
                body=body,
                raw_request=body,
            )
        )
        self.assertEqual(result["detected_event_type"], "web_file_upload")

    def test_detects_ssrf(self):
        result = self.evaluate(
            request_record(
                path="/fetch",
                query_string="url=http://169.254.169.254/latest/meta-data/",
                params={"url": "http://169.254.169.254/latest/meta-data/"},
            )
        )
        self.assertEqual(result["detected_event_type"], "web_ssrf")

    def test_detects_ssti(self):
        result = self.evaluate(
            request_record(
                method="POST",
                path="/render",
                body="{{7*7}} {{ config['SECRET_KEY'] }}",
            )
        )
        self.assertEqual(result["detected_event_type"], "web_ssti")

    def test_detects_xxe(self):
        body = (
            "<?xml version=\"1.0\"?>"
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>"
            "<root>&xxe;</root>"
        )
        result = self.evaluate(
            request_record(
                method="POST",
                path="/api/xml",
                headers={"Content-Type": "application/xml"},
                body=body,
                raw_request=body,
            )
        )
        self.assertEqual(result["detected_event_type"], "web_xxe")

    def test_detects_scanner_probe(self):
        result = self.evaluate(
            request_record(
                path="/.git/config",
                headers={"User-Agent": "sqlmap/1.8.4"},
            )
        )
        self.assertEqual(result["detected_event_type"], "web_scan")

    def test_prefers_specific_attack_type_over_scanner_signature(self):
        result = self.evaluate(
            request_record(
                path="/admin",
                query_string="id=1 UNION SELECT 1,2--",
                params={"id": "1 UNION SELECT 1,2--"},
                headers={"User-Agent": "sqlmap/1.8.4"},
            )
        )
        self.assertEqual(result["detected_event_type"], "web_sqli")
        self.assertIn("crs-scan-automation-user-agent", result["matched_rules"])

    def test_keeps_benign_request_as_normal_web_request(self):
        result = self.evaluate(
            request_record(
                method="POST",
                path="/login",
                params={"username": "alice", "password": "safe-password"},
                body="username=alice&password=safe-password",
                headers={"User-Agent": "Mozilla/5.0"},
            )
        )
        self.assertEqual(result["detected_event_type"], "web_req")
        self.assertEqual(result["risk_level"], "low")
        self.assertEqual(result["matched_rules"], [])


if __name__ == "__main__":
    unittest.main()
