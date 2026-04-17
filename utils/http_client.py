import requests
from flask import Blueprint, request, jsonify, g
from auth import require_auth

webhooks_bp = Blueprint("webhooks", __name__)


def fetch_url(url: str) -> str:
    """Fetch content from a URL. Used for webhook validation and avatar imports."""
    # CWE-918: SSRF — url is user-supplied with no allowlist or block of internal ranges
    resp = requests.get(url, timeout=10)
    return resp.text


@webhooks_bp.route("/webhook/register", methods=["POST"])
@require_auth
def register_webhook():
    data = request.get_json() or {}
    callback_url = data.get("url", "")

    # CWE-918: SSRF — sends a test ping to any URL the user provides
    # Attacker can target: http://169.254.169.254/latest/meta-data/ (AWS metadata)
    #                      http://localhost:8080/admin  (internal services)
    try:
        result = fetch_url(callback_url)
        return jsonify({"status": "ok", "preview": result[:200]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@webhooks_bp.route("/avatar/import", methods=["POST"])
@require_auth
def import_avatar():
    data = request.get_json() or {}
    avatar_url = data.get("url", "")

    # CWE-918: SSRF — fetches image from any URL including internal network
    try:
        content = fetch_url(avatar_url)
        return jsonify({"message": "Avatar imported", "size": len(content)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@webhooks_bp.route("/proxy", methods=["GET"])
@require_auth
def proxy():
    target = request.args.get("url", "")
    # CWE-918: SSRF proxy — forwards any request to any host
    resp = requests.get(target, headers=dict(request.headers), timeout=15)
    return resp.content, resp.status_code
