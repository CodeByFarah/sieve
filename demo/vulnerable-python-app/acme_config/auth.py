"""Bearer-token authentication for the config routes."""

import functools
import os

import jwt
from flask import abort, request


def _signing_key():
    return os.environ.get("ACME_JWT_KEY", "")


def require_token(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        token = header[len("Bearer "):] if header.startswith("Bearer ") else ""
        try:
            jwt.decode(token, _signing_key(), algorithms=["HS256"])
        except jwt.InvalidTokenError:
            abort(401)
        return view(*args, **kwargs)

    return wrapper
