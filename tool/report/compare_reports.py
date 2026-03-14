from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable


def _load_json(path: str | Path) -> Dict[str, Any]:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Report file not found: {file_path}")
    return json.loads(file_path.read_text(encoding="utf-8"))


def _extract_rule_ids(findings: Iterable[Dict[str, Any]]) -> set[str]:
    rule_ids: set[str] = set()
    for finding in findings:
        value = finding.get("rule_id")
        if isinstance(value, str) and value.strip():
            rule_ids.add(value)
    return rule_ids


def summarize_report_diff(
    vulnerable_report: Dict[str, Any],
    fixed_report: Dict[str, Any],
) -> Dict[str, Any]:
    vulnerable_findings = vulnerable_report.get("findings", [])
    fixed_findings = fixed_report.get("findings", [])

    vuln_rule_ids = _extract_rule_ids(vulnerable_findings)
    fixed_rule_ids = _extract_rule_ids(fixed_findings)

    disappeared = sorted(vuln_rule_ids - fixed_rule_ids)
    added = sorted(fixed_rule_ids - vuln_rule_ids)
    remaining = sorted(vuln_rule_ids & fixed_rule_ids)

    return {
        "vulnerable_findings_count": len(vulnerable_findings),
        "fixed_findings_count": len(fixed_findings),
        "disappeared_rule_ids": disappeared,
        "added_rule_ids": added,
        "remaining_rule_ids": remaining,
    }


def _format_text(summary: Dict[str, Any]) -> str:
    lines = [
        "Report Diff Summary",
        f"- vulnerable findings: {summary['vulnerable_findings_count']}",
        f"- fixed findings: {summary['fixed_findings_count']}",
        f"- disappeared rule_id: {', '.join(summary['disappeared_rule_ids']) or '(none)'}",
        f"- added rule_id: {', '.join(summary['added_rule_ids']) or '(none)'}",
        f"- remaining rule_id: {', '.join(summary['remaining_rule_ids']) or '(none)'}",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare vulnerable/fixed scan reports")
    parser.add_argument(
        "--vulnerable",
        default="samples/reports/vulnerable_report.json",
        help="Path to vulnerable report JSON",
    )
    parser.add_argument(
        "--fixed",
        default="samples/reports/fixed_report.json",
        help="Path to fixed report JSON",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    args = parser.parse_args()

    vulnerable_report = _load_json(args.vulnerable)
    fixed_report = _load_json(args.fixed)
    summary = summarize_report_diff(vulnerable_report, fixed_report)

    if args.format == "json":
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(_format_text(summary))


if __name__ == "__main__":
    main()
