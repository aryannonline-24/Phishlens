# database.py
import sqlite3

DB_NAME = "phishlens.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_text TEXT,
            url TEXT,
            computed_score INTEGER,
            computed_risk TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS test_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_text TEXT,
            url TEXT,
            label TEXT,
            expected_risk TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_scan(message_text, url, score, risk):
    conn = get_connection()
    conn.execute(
        "INSERT INTO scan_history (message_text, url, computed_score, computed_risk) VALUES (?, ?, ?, ?)",
        (message_text, url, score, risk),
    )
    conn.commit()
    conn.close()