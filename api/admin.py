import os
import subprocess
from flask import Blueprint, request, jsonify, g
from auth import require_auth, require_admin

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/ping", methods=["GET"])
@require_auth
@require_admin
def ping_host():
    host = request.args.get("host", "localhost")
    # CWE-78: OS Command Injection — host parameter injected into shell command
    result = os.popen(f"ping -c 2 {host}").read()
    return jsonify({"result": result})


@admin_bp.route("/report", methods=["GET"])
@require_auth
@require_admin
def generate_report():
    report_type = request.args.get("type", "daily")
    output_file = request.args.get("output", "/tmp/report.txt")
    # CWE-78: Command Injection — report_type and output_file injected into shell
    cmd = f"python3 scripts/generate_report.py --type {report_type} --output {output_file}"
    result = subprocess.check_output(cmd, shell=True, text=True)
    return jsonify({"output": result, "file": output_file})


@admin_bp.route("/users/list", methods=["GET"])
def list_all_users():
    # CWE-306: Missing authentication — no @require_auth decorator
    from database import get_connection
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, username, email, balance, role FROM users")
    rows = cur.fetchall()
    conn.close()
    return jsonify([
        {"id": r[0], "username": r[1], "email": r[2], "balance": r[3], "role": r[4]}
        for r in rows
    ])


@admin_bp.route("/logs/delete", methods=["POST"])
@require_auth
@require_admin
def delete_logs():
    log_path = request.get_json().get("path", "/var/log/bank/app.log")
    # CWE-22: Path Traversal — log_path not validated before passing to os.remove
    try:
        os.remove(log_path)
        return jsonify({"message": f"Deleted {log_path}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
