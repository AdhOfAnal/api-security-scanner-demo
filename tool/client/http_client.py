from __future__ import annotations

from typing import Any, Dict, Optional

import httpx


class HttpClient:
    def __init__(self, base_url: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        token: Optional[str] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> httpx.Response:
        headers: Dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        with httpx.Client(base_url=self.base_url, timeout=self.timeout) as client:
            return client.request(method.upper(), path, headers=headers, json=json_body)

    def login(self, username: str, password: str) -> Optional[str]:
        resp = self.request("POST", "/login", json_body={"username": username, "password": password})
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data.get("access_token")
