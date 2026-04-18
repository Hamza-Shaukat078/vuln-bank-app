"""
vuln_showcase.py — Deliberately Vulnerable Demo for Vulcan Scanner Testing

Each section targets a specific detection rule. Run the Vulcan scanner on this
file (or the whole vuln-bank-app repo) to test scanning, patching, and sandbox
attack execution end-to-end.

DO NOT deploy this file anywhere. It is intentionally insecure.
"""

import os
import sqlite3
import subprocess
import hashlib
import pickle
import base64
import logging
import tempfile
import hmac

import jwt
import requests
from flask import Flask, request, jsonify, send_file

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# 1. HARDCODED SECRETS  (CWE-798 / OWASP A02)
# ─────────────────────────────────────────────────────────────────────────────
SECRET_KEY       = "super_secret_jwt_key_12345"          # hardcoded JWT secret
DB_PASSWORD      = "admin123"                             # hardcoded DB password
AWS_ACCESS_KEY   = "AKIAIOSFODNN7EXAMPLE"                 # hardcoded AWS key
STRIPE_API_KEY   = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"    # hardcoded Stripe key
INTERNAL_TOKEN   = "Bearer eyJhbGciOiJub25lIn0.dGVzdA."  # hardcoded bearer


# ─────────────────────────────────────────────────────────────────────────────
# 2. DEBUG MODE ENABLED  (CWE-94 / OWASP A05)
# ─────────────────────────────────────────────────────────────────────────────
app.config["DEBUG"] = True          # exposes full stack traces in production
app.config["TESTING"] = True


# ─────────────────────────────────────────────────────────────────────────────
# 3. SQL INJECTION  (CWE-89 / OWASP A03)
# ─────────────────────────────────────────────────────────────────────────────
def get_user_by_id(user_id):
    """Classic string-format SQL injection — user_id flows directly into query."""
    conn = sqlite3.connect("bank.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + str(user_id)   # INJECTABLE
    cursor.execute(query)
    return cursor.fetchall()


def search_transactions(keyword):
    """f-string injection — keyword is unsanitised user input."""
    conn = sqlite3.connect("bank.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM transactions WHERE note LIKE '%{keyword}%'")  # INJECTABLE
    return cursor.fetchall()


def login_user(username, password):
    """Login bypass via SQL injection — both fields controlled by attacker."""
    conn = sqlite3.connect("bank.db")
    cursor = conn.cursor()
    query = (
        "SELECT id FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )
    cursor.execute(query)                                        # INJECTABLE
    return cursor.fetchone()


@app.route("/api/user")
def api_get_user():
    uid = request.args.get("id", "")
    return jsonify({"user": get_user_by_id(uid)})


@app.route("/api/search")
def api_search():
    kw = request.args.get("q", "")
    return jsonify({"results": search_transactions(kw)})


# ─────────────────────────────────────────────────────────────────────────────
# 4. COMMAND INJECTION  (CWE-78 / OWASP A03)
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/ping")
def ping():
    """User-controlled host injected into shell command."""
    host = request.args.get("host", "localhost")
    result = subprocess.check_output("ping -c 1 " + host, shell=True)   # INJECTABLE
    return result


@app.route("/api/convert")
def convert_file():
    """Filename injected into OS command — path traversal + command injection."""
    filename = request.args.get("file", "")
    output = os.popen(f"convert /uploads/{filename} /tmp/out.png")       # INJECTABLE
    return output.read()


# ─────────────────────────────────────────────────────────────────────────────
# 5. PATH TRAVERSAL  (CWE-22 / OWASP A01)
# ─────────────────────────────────────────────────────────────────────────────
UPLOAD_DIR = "/var/uploads"

@app.route("/api/files/download")
def download_file():
    """No path sanitisation — ../../etc/passwd traversal possible."""
    filename = request.args.get("name", "")
    path = os.path.join(UPLOAD_DIR, filename)    # TRAVERSAL: no realpath check
    return send_file(path)


@app.route("/api/files/read")
def read_file():
    """open() with raw user input."""
    name = request.args.get("name", "")
    with open("/reports/" + name) as f:          # TRAVERSAL
        return f.read()


# ─────────────────────────────────────────────────────────────────────────────
# 6. INSECURE DESERIALIZATION  (CWE-502 / OWASP A08)
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/session/restore", methods=["POST"])
def restore_session():
    """pickle.loads on untrusted cookie data — arbitrary code execution."""
    raw = request.cookies.get("session_data", "")
    obj = pickle.loads(base64.b64decode(raw))    # INSECURE DESERIALIZATION
    return jsonify({"restored": str(obj)})


@app.route("/api/prefs/load", methods=["POST"])
def load_preferences():
    """pickle from request body — RCE via crafted payload."""
    data = request.get_data()
    prefs = pickle.loads(data)                   # INSECURE DESERIALIZATION
    return jsonify(prefs)


# ─────────────────────────────────────────────────────────────────────────────
# 7. WEAK CRYPTOGRAPHY  (CWE-327 / OWASP A02)
# ─────────────────────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    """MD5 is broken — collision attacks, rainbow tables."""
    return hashlib.md5(password.encode()).hexdigest()    # WEAK CRYPTO


def sign_token(data: str) -> str:
    """SHA-1 HMAC is deprecated for security-sensitive signing."""
    return hmac.new(b"secret", data.encode(), hashlib.sha1).hexdigest()  # WEAK CRYPTO


def store_pin(pin: str) -> str:
    """SHA-1 with no salt for a PIN — trivially reversible."""
    return hashlib.sha1(pin.encode()).hexdigest()        # WEAK CRYPTO


# ─────────────────────────────────────────────────────────────────────────────
# 8. JWT NONE ALGORITHM  (CWE-347 / OWASP A02)
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/auth/verify", methods=["POST"])
def verify_token():
    """algorithms=["none"] accepts unsigned tokens — auth bypass."""
    token = request.json.get("token", "")
    payload = jwt.decode(
        token,
        options={"verify_signature": False},
        algorithms=["none", "HS256"],            # JWT NONE ALGORITHM
    )
    return jsonify(payload)


@app.route("/api/auth/decode")
def decode_token():
    """No algorithm restriction — attacker can switch to 'none'."""
    token = request.args.get("token", "")
    payload = jwt.decode(token, SECRET_KEY, algorithms=["none"])  # JWT NONE ALGORITHM
    return jsonify(payload)


# ─────────────────────────────────────────────────────────────────────────────
# 9. SSRF — SERVER-SIDE REQUEST FORGERY  (CWE-918 / OWASP A10)
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/webhook/test")
def test_webhook():
    """User-supplied URL fetched server-side — can hit internal services."""
    url = request.args.get("url", "")
    resp = requests.get(url, timeout=5)           # SSRF
    return resp.text


@app.route("/api/fetch")
def fetch_url():
    """Same pattern — attacker can target http://169.254.169.254/latest/meta-data"""
    target = request.args.get("target", "")
    data = requests.post(target, json={"key": "value"})   # SSRF
    return data.text


# ─────────────────────────────────────────────────────────────────────────────
# 10. DISABLED CERTIFICATE VALIDATION  (CWE-295 / OWASP A02)
# ─────────────────────────────────────────────────────────────────────────────
def call_payment_gateway(payload):
    """verify=False disables TLS — MITM attack possible."""
    return requests.post(
        "https://payments.internal/charge",
        json=payload,
        verify=False,                            # DISABLED CERT VALIDATION
    )


def fetch_exchange_rate(currency):
    """Same issue — HTTPS with cert validation off."""
    return requests.get(
        f"https://api.exchange.io/rate/{currency}",
        verify=False,                            # DISABLED CERT VALIDATION
    )


# ─────────────────────────────────────────────────────────────────────────────
# 11. LOG INJECTION  (CWE-117 / OWASP A09)
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.route("/api/transfer", methods=["POST"])
def transfer():
    """Unsanitised user input written to log — log injection / forging."""
    data     = request.get_json() or {}
    amount   = data.get("amount", 0)
    dest     = data.get("destination", "")
    # Attacker can inject newlines to forge log entries
    logger.info("Transfer initiated: amount=%s dest=%s", amount, dest)  # LOG INJECTION
    return jsonify({"status": "ok"})


# ─────────────────────────────────────────────────────────────────────────────
# 12. XML EXTERNAL ENTITY (XXE)  (CWE-611 / OWASP A05)
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/import/xml", methods=["POST"])
def import_xml():
    """lxml with no_network=False resolves external entities — XXE."""
    from lxml import etree
    xml_data = request.get_data()
    parser   = etree.XMLParser(resolve_entities=True)   # XXE
    tree     = etree.fromstring(xml_data, parser)
    return jsonify({"tag": tree.tag})


# ─────────────────────────────────────────────────────────────────────────────
# 13. HARDCODED IV (AES)  (CWE-329 / OWASP A02)
# ─────────────────────────────────────────────────────────────────────────────
def encrypt_card_number(card: str) -> bytes:
    """Hardcoded IV makes encryption deterministic — breaks confidentiality."""
    from Crypto.Cipher import AES
    key = os.urandom(32)
    iv  = b"\x00" * 16                          # HARDCODED IV — always the same
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = card.ljust(16).encode()
    return cipher.encrypt(padded)


# ─────────────────────────────────────────────────────────────────────────────
# 14. CODE INJECTION / eval()  (CWE-95 / OWASP A03)
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/calc")
def calculator():
    """eval() on user input — arbitrary Python execution."""
    expr = request.args.get("expr", "0")
    result = eval(expr)                          # CODE INJECTION
    return jsonify({"result": result})


@app.route("/api/filter")
def dynamic_filter():
    """exec() with user-supplied code string."""
    code = request.args.get("code", "")
    exec(code)                                   # CODE INJECTION
    return jsonify({"status": "executed"})


# ─────────────────────────────────────────────────────────────────────────────
# 15. AWS METADATA ACCESS  (OWASP A10)
# ─────────────────────────────────────────────────────────────────────────────
def get_instance_role():
    """Direct IMDS access — can expose IAM credentials from EC2 metadata."""
    resp = requests.get(
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        timeout=1,
    )                                            # AWS METADATA ACCESS
    return resp.text


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)   # DEBUG + binds all interfaces
