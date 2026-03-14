from __future__ import annotations

from typing import Optional

from fastapi import HTTPException, Header

from testbed.data import USERS


def make_token(username: str) -> str:
    return f"token-{username}"


def parse_username_from_token(token: str) -> Optional[str]:
    if not token.startswith("token-"):
        return None
    username = token[len("token-") :]
    return username if username in USERS else None


def get_current_username(authorization: Optional[str] = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = authorization.split(" ", 1)[1].strip()
    username = parse_username_from_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")

    return username
