"""
Intentionally Vulnerable API — Fuzzer Test Target
===================================================

This is NOT production code. Every "bug" here is deliberate and exists
so the fuzzer has real, reproducible vulnerabilities to find during
development. Each vulnerable spot is commented with what's wrong and
why, so you can map fuzzer findings back to root causes.

Run it:
    uvicorn app.main:app --reload --port 8001

Then its OpenAPI spec is available at:
    http://localhost:8001/openapi.json
"""

import asyncio
from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel
from typing import Optional

app = FastAPI(
    title="Vulnerable Shop API",
    description="Intentionally vulnerable API used as a fuzzer test target.",
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# Fake in-memory "database"
# ---------------------------------------------------------------------------

USERS = {
    1: {"id": 1, "username": "alice", "email": "alice@example.com", "is_admin": False},
    2: {"id": 2, "username": "bob", "email": "bob@example.com", "is_admin": False},
    3: {"id": 3, "username": "root_admin", "email": "admin@example.com", "is_admin": True},
}

# token -> user_id  (a stand-in for real auth)
TOKENS = {
    "alice-token": 1,
    "bob-token": 2,
}

ORDERS = {
    101: {"id": 101, "user_id": 1, "item": "Keyboard", "amount": 49.99},
    102: {"id": 102, "user_id": 2, "item": "Monitor", "amount": 199.99},
}

_next_order_id = 103


class UserCreate(BaseModel):
    username: str
    email: str
    age: int


class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    age: Optional[int] = None


class OrderCreate(BaseModel):
    item: str
    amount: float


def get_current_user_id(x_api_token: Optional[str] = Header(default=None)) -> Optional[int]:
    """Resolves a bearer-style token to a user id. Returns None if invalid/missing."""
    return TOKENS.get(x_api_token)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/slow")
async def slow(delay: float = 2.0):
    """
    Deliberately slow endpoint — used to test the runner's timeout
    handling. Not a "vulnerability" in itself, just a controlled way to
    exercise a real network-level timeout without waiting on a flaky
    external target.
    """
    await asyncio.sleep(delay)
    return {"waited_seconds": delay}


@app.get("/text", response_class=Response)
def text_response():
    """Returns a plain-text, non-JSON body — used to prove the runner
    doesn't crash when a response isn't JSON."""
    return Response(content="this is a plain text response, not JSON", media_type="text/plain")


@app.api_route("/echo", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def echo(request: Request):
    """
    Pure test scaffolding, not a vulnerability: echoes back exactly what
    it received (method, query params, headers, body). Used by the
    runner's test suite to prove every request component the runner
    constructs actually arrives at the target intact.
    """
    try:
        body = await request.json()
    except Exception:
        body = None
    return {
        "method": request.method,
        "query_params": dict(request.query_params),
        "headers": dict(request.headers),
        "body": body,
    }


# ---------------------------------------------------------------------------
# VULN #1 — IDOR (Insecure Direct Object Reference)
# Any authenticated user can fetch ANY other user's profile by guessing IDs.
# There's no check that the caller's user_id matches the requested user_id.
# ---------------------------------------------------------------------------
@app.get("/users/{user_id}")
def get_user(user_id: int, x_api_token: Optional[str] = Header(default=None)):
    caller_id = get_current_user_id(x_api_token)
    if caller_id is None:
        raise HTTPException(status_code=401, detail="Missing or invalid token")

    # BUG: no check that caller_id == user_id or that caller is admin.
    user = USERS.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# ---------------------------------------------------------------------------
# Same IDOR class of bug as VULN #1, but for write operations: no
# ownership check on update/delete. Added in Phase 2 to give the runner
# real PUT/PATCH/DELETE endpoints to exercise, not to introduce a new
# vulnerability category — that's still tracked as part of VULN #1/#6.
# ---------------------------------------------------------------------------
@app.put("/users/{user_id}")
def replace_user(user_id: int, payload: UserCreate, x_api_token: Optional[str] = Header(default=None)):
    caller_id = get_current_user_id(x_api_token)
    if caller_id is None:
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="User not found")

    USERS[user_id] = {
        "id": user_id,
        "username": payload.username,
        "email": payload.email,
        "age": payload.age,
        "is_admin": USERS[user_id].get("is_admin", False),
    }
    return USERS[user_id]


@app.patch("/users/{user_id}")
def update_user(user_id: int, payload: UserUpdate, x_api_token: Optional[str] = Header(default=None)):
    caller_id = get_current_user_id(x_api_token)
    if caller_id is None:
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="User not found")

    updates = payload.model_dump(exclude_unset=True)
    USERS[user_id].update(updates)
    return USERS[user_id]


@app.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: int, x_api_token: Optional[str] = Header(default=None)):
    caller_id = get_current_user_id(x_api_token)
    if caller_id is None:
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    if user_id not in USERS:
        raise HTTPException(status_code=404, detail="User not found")

    del USERS[user_id]
    return None


# ---------------------------------------------------------------------------
# VULN #2 — Weak input validation / no boundary checks
# `age` is accepted as any int, including negative numbers or absurd values.
# ---------------------------------------------------------------------------
@app.post("/users", status_code=201)
def create_user(payload: UserCreate):
    new_id = max(USERS.keys()) + 1
    # BUG: no validation on age range, no email format check, no username
    # length/charset check.
    USERS[new_id] = {
        "id": new_id,
        "username": payload.username,
        "email": payload.email,
        "age": payload.age,
        "is_admin": False,
    }
    return USERS[new_id]


# ---------------------------------------------------------------------------
# VULN #3 — Verbose error / information disclosure
# Login failures leak whether the *username* exists, which enables
# username enumeration.
# ---------------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(payload: LoginRequest):
    matching_user = next((u for u in USERS.values() if u["username"] == payload.username), None)
    if not matching_user:
        # BUG: distinct error message reveals the username doesn't exist
        raise HTTPException(status_code=404, detail="Username does not exist")
    # BUG: password isn't actually checked against anything real here —
    # any password "succeeds" if the username exists, and the error
    # messages differ between "bad username" and "bad password" cases,
    # which is itself an oracle even once password checking is added.
    return {"token": f"{matching_user['username']}-token", "user_id": matching_user["id"]}


# ---------------------------------------------------------------------------
# VULN #4 — Missing authorization on an admin-only-looking endpoint
# There is no check at all — anyone, authenticated or not, can hit this.
# ---------------------------------------------------------------------------
@app.get("/admin/stats")
def admin_stats():
    # BUG: no auth check whatsoever, despite the path implying admin-only.
    return {
        "total_users": len(USERS),
        "total_orders": len(ORDERS),
        "revenue": sum(o["amount"] for o in ORDERS.values()),
    }


# ---------------------------------------------------------------------------
# VULN #5 — Business-logic / boundary flaw
# `amount` accepts negative numbers, which is nonsensical for an order
# total and could be abused (e.g. negative-price refund logic elsewhere).
# ---------------------------------------------------------------------------
@app.post("/orders", status_code=201)
def create_order(payload: OrderCreate, x_api_token: Optional[str] = Header(default=None)):
    global _next_order_id
    caller_id = get_current_user_id(x_api_token)
    if caller_id is None:
        raise HTTPException(status_code=401, detail="Missing or invalid token")

    # BUG: no check that amount > 0.
    order = {"id": _next_order_id, "user_id": caller_id, "item": payload.item, "amount": payload.amount}
    ORDERS[_next_order_id] = order
    _next_order_id += 1
    return order


# ---------------------------------------------------------------------------
# VULN #6 — IDOR on a nested resource
# Same class of bug as VULN #1, but on orders: no ownership check.
# ---------------------------------------------------------------------------
@app.get("/orders/{order_id}")
def get_order(order_id: int, x_api_token: Optional[str] = Header(default=None)):
    caller_id = get_current_user_id(x_api_token)
    if caller_id is None:
        raise HTTPException(status_code=401, detail="Missing or invalid token")

    order = ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    # BUG: never checks order["user_id"] == caller_id
    return order
