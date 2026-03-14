from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class User:
    id: int
    username: str
    password: str
    role: str
    email: str


USERS: Dict[str, User] = {
    "alice": User(id=1, username="alice", password="alice123", role="user", email="alice@example.local"),
    "bob": User(id=2, username="bob", password="bob123", role="admin", email="bob@example.local"),
}

ORDERS: List[dict] = [
    {"order_id": 1, "owner_id": 1, "item": "book", "amount": 10},
    {"order_id": 2, "owner_id": 2, "item": "laptop", "amount": 1200},
]
