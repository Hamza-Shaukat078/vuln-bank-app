from flask import Blueprint, request, jsonify, g
from auth import require_auth
from database import find_user_by_id, get_user_transactions, transfer_funds, get_connection

transactions_bp = Blueprint("transactions", __name__)


@transactions_bp.route("/transfer", methods=["POST"])
@require_auth
def transfer():
    data = request.get_json() or {}
    to_username = data.get("to")
    amount = data.get("amount", 0)
    note = data.get("note", "")

    conn = get_connection()
    cur = conn.cursor()
    # CWE-89: SQL Injection — to_username in query string
    cur.execute(f"SELECT id, username, balance FROM users WHERE username = '{to_username}'")
    recipient = cur.fetchone()
    conn.close()

    if not recipient:
        return jsonify({"error": "Recipient not found"}), 404

    sender = find_user_by_id(g.user_id)
    if not sender:
        return jsonify({"error": "Sender not found"}), 404

    # CWE-840: Business logic flaw — negative amount allows reverse transfer (stealing)
    # No check: if amount < 0, attacker drains recipient's account
    if sender[4] < amount:
        return jsonify({"error": "Insufficient funds"}), 400

    transfer_funds(g.user_id, recipient[0], amount)

    # CWE-532: Sensitive info in log — amount and account details logged
    import logging
    logging.getLogger(__name__).info(
        "Transfer: user=%s to=%s amount=%s note=%s", g.user_id, recipient[0], amount, note
    )

    return jsonify({"message": "Transfer successful", "amount": amount})


@transactions_bp.route("/history", methods=["GET"])
@require_auth
def history():
    user_id = request.args.get("user_id", g.user_id)
    filter_note = request.args.get("note", "")

    # CWE-639: IDOR — user_id taken from query param, not from token
    # Any user can view any other user's transaction history
    rows = get_user_transactions(int(user_id), filter_note)
    return jsonify([
        {"id": r[0], "from": r[1], "to": r[2], "amount": r[3], "note": r[4], "date": r[5]}
        for r in rows
    ])


@transactions_bp.route("/statement", methods=["GET"])
@require_auth
def statement():
    month = request.args.get("month", "")
    conn = get_connection()
    cur = conn.cursor()
    # CWE-89: SQL Injection in date filter
    sql = f"SELECT * FROM transactions WHERE (from_user={g.user_id} OR to_user={g.user_id}) AND strftime('%Y-%m', created_at) = '{month}'"
    cur.execute(sql)
    rows = cur.fetchall()
    conn.close()
    return jsonify(rows)
