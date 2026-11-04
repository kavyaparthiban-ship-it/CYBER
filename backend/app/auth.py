from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException, Request, Response

from backend.app import database


COOKIE_NAME = "hackgrid_session"
SESSION_HOURS = 12
PBKDF2_ITERATIONS = 310_000


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"{PBKDF2_ITERATIONS}${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        iterations_raw, salt_raw, digest_raw = stored_hash.split("$", 2)
        iterations = int(iterations_raw)
        salt = bytes.fromhex(salt_raw)
        expected = bytes.fromhex(digest_raw)
    except (ValueError, TypeError):
        return False
    if iterations < 100_000 or iterations > 1_000_000 or len(salt) != 16 or len(expected) != 32:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def start_session(response: Response, user: dict[str, Any]) -> dict[str, str]:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)
    database.create_auth_session(_token_hash(token), user["id"], expires_at.isoformat())
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=SESSION_HOURS * 60 * 60,
        httponly=True,
        secure=False,
        samesite="lax",
        path="/",
    )
    return {"email": user["email"]}


def current_user(request: Request) -> dict[str, Any]:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Please sign in to continue.")
    user = database.get_user_for_session(_token_hash(token))
    if user is None:
        raise HTTPException(status_code=401, detail="Your session expired. Please sign in again.")
    return user


def end_session(request: Request, response: Response) -> dict[str, bool]:
    token = request.cookies.get(COOKIE_NAME)
    if token:
        database.delete_auth_session(_token_hash(token))
    response.delete_cookie(key=COOKIE_NAME, path="/", httponly=True, samesite="lax")
    return {"signed_out": True}
