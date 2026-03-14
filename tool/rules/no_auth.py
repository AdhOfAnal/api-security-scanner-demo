from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from tool.client.http_client import HttpClient


PUBLIC_PATHS = {"/docs", "/redoc", "/openapi.json"}


def _materialize_path(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "1", path)


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
    endpoints: List[Dict[str, str]],
    users: Optional[List[Dict[str, Any]]] = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    auth_token: Optional[str] = None
    authenticated_actor: Optional[Dict[str, Any]] = None

    if users:
        actor_candidate = users[0]
        username = actor_candidate.get("username")
        password = actor_candidate.get("password")
        if isinstance(username, str) and isinstance(password, str):
            auth_token = client.login(username, password)
            if auth_token:
                authenticated_actor = _extract_actor_info(actor_candidate)

    for endpoint in endpoints:
        method = endpoint.get("method", "").upper()
        path_template = endpoint.get("path", "")

        if method != "GET":
            continue
        if path_template in PUBLIC_PATHS:
            continue

        path = _materialize_path(path_template)
        unauth_resp = client.request(method, path)

        if unauth_resp.status_code in (401, 403):
            continue

        authenticated_status: Optional[int] = None
        authenticated_response_keys: list[str] = []

        if auth_token:
            auth_resp = client.request(method, path, token=auth_token)
            authenticated_status = auth_resp.status_code
            authenticated_response_keys = _extract_response_keys(
                auth_resp.text,
                auth_resp.headers.get("content-type", ""),
            )

        findings.append(
            {
                "rule_id": "no_auth",
                "title": "Possible Missing Authentication Enforcement",
                "severity": "high",
                "confidence": "high",
                "endpoint": path_template,
                "method": method,
                "evidence": {
                    "tested_endpoint": path,
                    "unauthenticated_status": unauth_resp.status_code,
                    "authenticated_status": authenticated_status,
                    "unauthenticated_response_keys": _extract_response_keys(
                        unauth_resp.text,
                        unauth_resp.headers.get("content-type", ""),
                    ),
                    "authenticated_response_keys": authenticated_response_keys,
                    "authenticated_actor": authenticated_actor,
                },
                "recommendation": "Require authentication and enforce access checks for this endpoint.",
            }
        )

    return findings
