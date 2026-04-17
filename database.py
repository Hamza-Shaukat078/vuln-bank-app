import sqlite3
import logging

logger = logging.getLogger(__name__)

DB_PATH = "bank.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            balance REAL DEFAULT 0.0,
            role TEXT DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY,
            from_user INTEGER,
            to_user INTEGER,
            amount REAL,
            note TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            action TEXT,
            detail TEXT,
            ip TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        INSERT OR IGNORE INTO users (username, password, email, balance, role)
        VALUES ('admin', 'admin123', 'admin@bank.com', 99999.0, 'admin');
        INSERT OR IGNORE INTO users (username, password, email, balance, role)
        VALUES ('alice', 'alice123', 'alice@bank.com', 5000.0, 'user');
        INSERT OR IGNORE INTO users (username, password, email, balance, role)
        VALUES ('bob', 'bob123', 'bob@bank.com', 3000.0, 'user');
    """)
    conn.commit()
    conn.close()


def find_user_by_username(username: str):
    conn = get_connection()
    cur = conn.cursor()
    # CWE-89: SQL Injection — username concatenated directly into query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    logger.debug("Login query: %s", query)
    cur.execute(query)
    row = cur.fetchone()
    conn.close()
    return row


def find_user_by_id(user_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row


def search_users(query_str: str):
    conn = get_connection()
    cur = conn.cursor()
    # CWE-89: SQL Injection in search — LIKE with unsanitised input
    sql = f"SELECT id, username, email FROM users WHERE username LIKE '%{query_str}%' OR email LIKE '%{query_str}%'"
    cur.execute(sql)
    rows = cur.fetchall()
    conn.close()
    return rows


def get_user_transactions(user_id, filter_note: str = ""):
    conn = get_connection()
    cur = conn.cursor()
    if filter_note:
        # CWE-89: SQL Injection in optional filter parameter
        sql = (
            f"SELECT * FROM transactions WHERE (from_user={user_id} OR to_user={user_id})"
            f" AND note LIKE '%{filter_note}%'"
        )
    else:
        sql = f"SELECT * FROM transactions WHERE from_user={user_id} OR to_user={user_id}"
    cur.execute(sql)
    rows = cur.fetchall()
    conn.close()
    return rows


def transfer_funds(from_user_id, to_user_id, amount):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, from_user_id))
    cur.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, to_user_id))
    cur.execute(
        "INSERT INTO transactions (from_user, to_user, amount) VALUES (?, ?, ?)",
        (from_user_id, to_user_id, amount),
    )
    conn.commit()
    conn.close()
