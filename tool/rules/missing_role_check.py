from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from tool.client.http_client import HttpClient


def _materialize_path(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "1", path)


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


def _extract_actor_info(user: Dict[str, Any], role: Optional[str]) -> Dict[str, Any]:
    actor_id: Optional[int] = None
    for key in ("id", "expected_user_id"):
        value = user.get(key)
        if isinstance(value, int):
            actor_id = value
            break

    return {
        "username": user.get("username"),
        "id": actor_id,
        "role": role,
    }


def _select_non_admin_actor(
    client: HttpClient,
    users: List[Dict[str, Any]],
) -> Optional[Tuple[Dict[str, Any], str, Optional[str]]]:
    fallback: Optional[Tuple[Dict[str, Any], str, Optional[str]]] = None

    for user in users:
        username = user.get("username")
        password = user.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            continue

        token = client.login(username, password)
        if not token:
            continue

        role: Optional[str] = None
        profile_resp = client.request("GET", "/profile", token=token)
        if profile_resp.status_code == 200:
            profile_payload = _extract_response_json(
                profile_resp.text,
                profile_resp.headers.get("content-type", ""),
            )
            if isinstance(profile_payload, dict):
                raw_role = profile_payload.get("role")
                if isinstance(raw_role, str):
                    role = raw_role

        if fallback is None:
            fallback = (user, token, role)
        if role is not None and role.lower() != "admin":
            return user, token, role

    return fallback


def run(
    client: HttpClient,
    endpoints: List[Dict[str, str]],
    users: List[Dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    actor_context = _select_non_admin_actor(client, users)
    if actor_context is None:
        return findings

    actor_user, token, actor_role = actor_context
    actor = _extract_actor_info(actor_user, actor_role)

    for endpoint in endpoints:
        method = endpoint.get("method", "").upper()
        path_template = endpoint.get("path", "")

        if method != "GET":
            continue
        if not path_template.startswith("/admin"):
            continue

        path = _materialize_path(path_template)
        resp = client.request(method, path, token=token)

        if resp.status_code != 200:
            continue

        response_payload = _extract_response_json(resp.text, resp.headers.get("content-type", ""))
        confidence = "high" if actor_role is not None and actor_role.lower() != "admin" else "medium"

        findings.append(
            {
                "rule_id": "missing_role_check",
                "title": "Possible Missing Role-Based Access Control",
                "severity": "high",
                "confidence": confidence,
                "endpoint": path_template,
                "method": method,
                "evidence": {
                    "actor": actor,
                    "required_role": "admin",
                    "response_status": resp.status_code,
                    "response_keys": _extract_response_keys(response_payload),
                },
                "recommendation": "Enforce role checks for admin endpoints and return 403 for non-admin users.",
            }
        )

    return findings
