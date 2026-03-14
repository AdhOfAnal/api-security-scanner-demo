from __future__ import annotations

import os

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from testbed.auth import get_current_username, make_token
from testbed.data import ORDERS, USERS

app = FastAPI(title="Vulnerable API Testbed", version="0.1.0")
FIX_USERS_AUTH = os.getenv("FIX_USERS_AUTH", "0") == "1"


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(payload: LoginRequest) -> dict:
    user = USERS.get(payload.username)
    if not user or user.password != payload.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {"access_token": make_token(payload.username), "token_type": "bearer"}


if FIX_USERS_AUTH:
    @app.get("/users")
    def list_users(username: str = Depends(get_current_username)) -> list[dict]:
        _ = username
        return [
            {"id": user.id, "username": user.username, "email": user.email}
            for user in USERS.values()
        ]
else:
    @app.get("/users")
    def list_users() -> list[dict]:
        # Intentionally vulnerable: no auth check.
        return [
            {"id": user.id, "username": user.username, "email": user.email}
            for user in USERS.values()
        ]


@app.get("/orders/{order_id}")
def get_order(order_id: int, username: str = Depends(get_current_username)) -> dict:
    _ = username
    for order in ORDERS:
        if order["order_id"] == order_id:
            return order
    raise HTTPException(status_code=404, detail="Order not found")


@app.get("/admin/stats")
def get_admin_stats(username: str = Depends(get_current_username)) -> dict:
    user = USERS[username]

    if os.getenv("FIX_ADMIN_ROLE", "0") == "1" and user.role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")

    return {
        "total_users": len(USERS),
        "total_orders": len(ORDERS),
        "service": "api-security-testbed",
    }


@app.get("/profile")
def get_profile(username: str = Depends(get_current_username)) -> dict:
    user = USERS[username]
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "email": user.email,
    }
