from flask import Flask, request, jsonify
from config import Config
from database import init_db
from auth import login
from api.users import users_bp
from api.transactions import transactions_bp
from api.admin import admin_bp
from api.files import files_bp
from utils.http_client import webhooks_bp
from utils.xml_parser import xml_bp

app = Flask(__name__)
app.config.from_object(Config)


# ── Register blueprints ───────────────────────────────────────────────────────
app.register_blueprint(users_bp, url_prefix="/api/users")
app.register_blueprint(transactions_bp, url_prefix="/api/transactions")
app.register_blueprint(admin_bp, url_prefix="/api/admin")
app.register_blueprint(files_bp, url_prefix="/api/files")
app.register_blueprint(webhooks_bp, url_prefix="/api")
app.register_blueprint(xml_bp, url_prefix="/api")


# ── Auth endpoints ────────────────────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # CWE-307: No rate limiting on login — brute force possible
    token, err = login(username, password)
    if err:
        # CWE-209: Verbose error reveals whether username exists
        return jsonify({"error": err}), 401

    return jsonify({"token": token})


@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json() or {}
    username = data.get("username", "")
    new_password = data.get("new_password", "")

    from database import get_connection
    conn = get_connection()
    cur = conn.cursor()
    # CWE-620: No old-password verification before resetting
    # CWE-89: SQL Injection in reset
    cur.execute(f"UPDATE users SET password = '{new_password}' WHERE username = '{username}'")
    conn.commit()
    conn.close()
    return jsonify({"message": "Password updated"})


@app.route("/api/health", methods=["GET"])
def health():
    # CWE-200: Exposes internal version, DB path, config in health endpoint
    return jsonify({
        "status": "ok",
        "version": "1.0.0",
        "db": Config.DATABASE_URL,
        "admin_email": "admin@bank.com",
        "debug": app.debug,
    })


if __name__ == "__main__":
    init_db()
    # CWE-94: Debug mode on in production exposes interactive debugger
    app.run(debug=True, host="0.0.0.0", port=5000)
