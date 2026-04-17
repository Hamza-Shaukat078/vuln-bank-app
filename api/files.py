import os
from flask import Blueprint, request, jsonify, send_file, g
from auth import require_auth
from config import Config

files_bp = Blueprint("files", __name__)

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "txt"}


@files_bp.route("/download", methods=["GET"])
@require_auth
def download_file():
    filename = request.args.get("file", "")
    # CWE-22: Path Traversal — filename not sanitised, allows ../../etc/passwd
    file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    return send_file(file_path)


@files_bp.route("/upload", methods=["POST"])
@require_auth
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400

    f = request.files["file"]
    filename = f.filename  # CWE-22: Original filename used directly — no sanitisation

    # CWE-434: Unrestricted file upload — extension check easily bypassed
    # (e.g. "shell.php.jpg" or Content-Type spoofing)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "File type not allowed"}), 400

    # CWE-22: Saves to path constructed from user-supplied filename
    save_path = os.path.join(Config.UPLOAD_FOLDER, filename)
    f.save(save_path)
    return jsonify({"message": "Uploaded", "path": save_path})


@files_bp.route("/preview", methods=["GET"])
@require_auth
def preview_file():
    filename = request.args.get("file", "")
    # CWE-22: Path Traversal — reads arbitrary file from filesystem
    file_path = os.path.join("/var/bank/statements", filename)
    try:
        with open(file_path, "r") as fh:
            content = fh.read(4096)
        return jsonify({"content": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
