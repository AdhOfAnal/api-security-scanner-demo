from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from tool.client.http_client import HttpClient


def evaluate_bola_result(status_code: int) -> bool:
    """Return True if status code indicates potential BOLA success."""
    return status_code == 200


def determine_confidence(
    status_code: int,
    actor_id: Optional[int],
    resource_owner: Optional[int],
) -> str:
    """Confidence is high only when owner mismatch is directly observed."""
    if status_code == 200 and actor_id is not None and resource_owner is not None and actor_id != resource_owner:
        return "high"
    return "medium"


def _extract_response_json(resp_text: str, content_type: str) -> Any:
    if "application/json" not in content_type:
        return None

    try:
        return json.loads(resp_text)
    except Exception:
        return None


def _extract_response_keys(payload: Any) -> list[str]:
    if isinstance(payload, dict):
        return sorted(str(k) for k in payload.keys())
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        return sorted(str(k) for k in payload[0].keys())
    return []


def _extract_resource_owner(payload: Any) -> Optional[int]:
    if not isinstance(payload, dict):
        return None

    for key in ("owner_id", "owner", "user_id"):
        value = payload.get(key)
        if isinstance(value, int):
            return value
    return None


def _extract_actor_id(actor: Dict[str, Any]) -> Optional[int]:
    for key in ("id", "expected_user_id"):
        value = actor.get(key)
        if isinstance(value, int):
            return value
    return None


def run(client: HttpClient, users: List[Dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if len(users) < 2:
        return findings

    actor = users[0]
    victim = users[1]

    actor_token = client.login(actor["username"], actor["password"])
    if not actor_token:
        return findings

    tested_resource_id = victim.get("expected_user_id", 2)
    resp = client.request("GET", f"/orders/{tested_resource_id}", token=actor_token)

    if evaluate_bola_result(resp.status_code):
        response_payload = _extract_response_json(resp.text, resp.headers.get("content-type", ""))
        actor_id = _extract_actor_id(actor)
        resource_owner = _extract_resource_owner(response_payload)

        findings.append(
            {
                "rule_id": "bola",
                "title": "Possible Broken Object Level Authorization",
                "severity": "high",
                "confidence": determine_confidence(resp.status_code, actor_id, resource_owner),
                "endpoint": "/orders/{order_id}",
                "method": "GET",
                "evidence": {
                    "actor": {
                        "username": actor.get("username"),
                        "id": actor_id,
                    },
                    "tested_input": {
                        "order_id": tested_resource_id,
                    },
                    "resource_owner": resource_owner,
                    "response_status": resp.status_code,
                    "response_keys": _extract_response_keys(response_payload),
                },
                "recommendation": "Verify resource ownership before returning object data.",
            }
        )

    return findings
