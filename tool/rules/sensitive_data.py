from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from tool.client.http_client import HttpClient


def _extract_response_keys(resp_text: str, content_type: str) -> list[str]:
    if "application/json" not in content_type:
        return []

    try:
        payload = json.loads(resp_text)
    except Exception:
        return []

    if isinstance(payload, dict):
        return sorted(str(k) for k in payload.keys())
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        return sorted(str(k) for k in payload[0].keys())
    return []


def _extract_actor_info(user: Dict[str, Any]) -> Dict[str, Any]:
    actor_id: Optional[int] = None
    for key in ("id", "expected_user_id"):
        value = user.get(key)
        if isinstance(value, int):
            actor_id = value
            break

    return {
        "username": user.get("username"),
        "id": actor_id,
    }


def run(
    client: HttpClient,
    user: Dict[str, Any],
    sensitive_fields: List[str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    token = client.login(user["username"], user["password"])
    if not token:
        return findings

    resp = client.request("GET", "/profile", token=token)
    if resp.status_code != 200:
        return findings

    data = resp.json() if "application/json" in resp.headers.get("content-type", "") else {}
    matched_sensitive_fields = [field for field in sensitive_fields if field in data]
    if matched_sensitive_fields:
        findings.append(
            {
                "rule_id": "sensitive_data",
                "title": "Potential Sensitive Data Exposure",
                "severity": "medium",
                "confidence": "high",
                "endpoint": "/profile",
                "method": "GET",
                "evidence": {
                    "actor": _extract_actor_info(user),
                    "response_status": resp.status_code,
                    "response_keys": _extract_response_keys(
                        resp.text,
                        resp.headers.get("content-type", ""),
                    ),
                    "matched_sensitive_fields": matched_sensitive_fields,
                },
                "recommendation": "Minimize response fields and avoid returning sensitive attributes by default.",
            }
        )

    return findings
