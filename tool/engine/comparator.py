from __future__ import annotations

from typing import Any, Dict, List


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    output: List[Dict[str, Any]] = []

    for item in findings:
        key = (
            str(item.get("rule_id", "")),
            str(item.get("method", "")),
            str(item.get("endpoint", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(item)

    return output
