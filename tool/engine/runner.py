from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from tool.client.http_client import HttpClient
from tool.engine.comparator import deduplicate_findings
from tool.parser.openapi_parser import OpenAPIParser, list_endpoints
from tool.report.reporter import write_json_report
from tool.rules import bola, missing_role_check, no_auth, sensitive_data
from tool.utils.helpers import load_yaml


def run_scan(config_path: Path) -> Dict[str, Any]:
    cfg = load_yaml(config_path)
    base_url = cfg["base_url"]
    openapi_path = Path(cfg["openapi_path"])
    report_path = Path(cfg.get("report_path", "samples/reports/latest_report.json"))

    openapi_doc = OpenAPIParser.load(openapi_path)
    endpoints = list_endpoints(openapi_doc)
    users = cfg.get("users", [])

    client = HttpClient(base_url=base_url)

    findings = []
    findings.extend(no_auth.run(client, endpoints, users))
    findings.extend(missing_role_check.run(client, endpoints, users))
    findings.extend(bola.run(client, users))

    sensitive_cfg = load_yaml(Path("configs/sensitive_fields.yaml"))
    sensitive_fields = sensitive_cfg.get("sensitive_fields", [])
    if users:
        findings.extend(sensitive_data.run(client, users[0], sensitive_fields))

    findings = deduplicate_findings(findings)

    report: Dict[str, Any] = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "base_url": base_url,
            "openapi_path": str(openapi_path),
            "report_path": str(report_path),
            "total_findings": len(findings),
        },
        "findings": findings,
    }

    write_json_report(report_path, report)
    return report
