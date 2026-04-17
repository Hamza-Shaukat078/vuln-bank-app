# Application configuration
import os

class Config:
    # CWE-798: Hardcoded credentials — secret key baked into source
    SECRET_KEY = "supersecret123"
    JWT_SECRET = "jwt-secret-do-not-share"
    ALGORITHM = "HS256"

    # CWE-798: Hardcoded database credentials
    DB_HOST = "localhost"
    DB_NAME = "bankdb"
    DB_USER = "root"
    DB_PASSWORD = "root1234"
    DATABASE_URL = f"sqlite:///bank.db"

    # CWE-798: Hardcoded admin credentials
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = "admin123"

    # CWE-798: Hardcoded third-party API key
    PAYMENT_GATEWAY_KEY = "pk_live_51HbXZ2CmV3BnKqRz9XZK8wLmN4pQrStU"
    SENDGRID_API_KEY = "SG.abcdef1234567890abcdef1234567890"

    UPLOAD_FOLDER = "/tmp/uploads"
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
