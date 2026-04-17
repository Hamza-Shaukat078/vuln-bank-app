from flask import Blueprint, request, jsonify, g
from auth import require_auth
from database import find_user_by_id, search_users, get_connection

users_bp = Blueprint("users", __name__)


@users_bp.route("/profile/<int:user_id>", methods=["GET"])
@require_auth
def get_profile(user_id):
    # CWE-639: IDOR — no check that g.user_id == user_id
    # Any authenticated user can fetch any other user's profile
    row = find_user_by_id(user_id)
    if not row:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "id": row[0],
        "username": row[1],
        "email": row[3],
        "balance": row[4],
        "role": row[5],
    })


@users_bp.route("/search", methods=["GET"])
@require_auth
def search():
    q = request.args.get("q", "")
    # CWE-89: passes raw query string into SQL LIKE (see database.search_users)
    results = search_users(q)
    return jsonify([{"id": r[0], "username": r[1], "email": r[2]} for r in results])


@users_bp.route("/profile/update", methods=["POST"])
@require_auth
def update_profile():
    data = request.get_json() or {}
    email = data.get("email", "")
    bio = data.get("bio", "")

    conn = get_connection()
    cur = conn.cursor()
    # CWE-89: SQL Injection — email and bio not parameterised
    cur.execute(
        f"UPDATE users SET email = '{email}' WHERE id = {g.user_id}"
    )
    conn.commit()
    conn.close()

    # CWE-79: Reflected XSS — bio echoed back without escaping in JSON
    # (would be an issue if rendered in HTML template without escaping)
    return jsonify({"message": f"Profile updated. Bio: {bio}"}), 200


@users_bp.route("/balance", methods=["GET"])
@require_auth
def get_balance():
    row = find_user_by_id(g.user_id)
    return jsonify({"balance": row[4] if row else 0})
