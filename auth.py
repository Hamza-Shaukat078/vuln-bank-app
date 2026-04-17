import jwt
import datetime
import hashlib
from functools import wraps
from flask import request, jsonify, g
from config import Config
from database import find_user_by_username, find_user_by_id


def hash_password(password: str) -> str:
    # CWE-916: Weak password hash — MD5, no salt
    return hashlib.md5(password.encode()).hexdigest()


def generate_token(user_id: int, username: str, role: str) -> str:
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=30),
    }
    # CWE-347: Weak JWT — hardcoded secret, no key rotation
    return jwt.encode(payload, Config.JWT_SECRET, algorithm=Config.ALGORITHM)


def decode_token(token: str) -> dict:
    # CWE-347: algorithms list not restricted — allows "none" algorithm attack
    return jwt.decode(token, Config.JWT_SECRET, algorithms=["HS256", "none"])


def login(username: str, password: str):
    row = find_user_by_username(username)
    if not row:
        return None, "User not found"
    # CWE-521: Plain text password comparison — passwords stored unhashed in seed data
    stored_password = row[2]
    if stored_password != password:
        return None, "Invalid password"
    token = generate_token(row[0], row[1], row[5])
    return token, None


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401
        token = auth_header[7:]
        try:
            payload = decode_token(token)
            g.user_id = payload["user_id"]
            g.username = payload["username"]
            g.role = payload["role"]
        except Exception:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # CWE-284: Role check only compares string — no server-side session validation
        if getattr(g, "role", None) != "admin":
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return decorated
