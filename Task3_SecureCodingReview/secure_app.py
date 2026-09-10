from flask import Flask, request, jsonify
import sqlite3
import subprocess
import os
import logging
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# SECURITY FIX 1: Load secret from environment variable
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "development-only-secret-change-me"
)

DATABASE = "users_secure.db"

logging.basicConfig(level=logging.INFO)


# SECURITY FIX 2: Secure password hashing
def hash_password(password):
    return generate_password_hash(password)


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)

    try:
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("admin", hash_password("admin123"))
        )
    except sqlite3.IntegrityError:
        pass

    conn.commit()
    conn.close()


@app.route("/")
def home():
    return jsonify({
        "application": "CodeAlpha Secure Coding Review Demo",
        "status": "running",
        "security": "secure version"
    })


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # SECURITY FIX 3: Input validation
    if not username or not password:
        return jsonify({
            "message": "Username and password are required"
        }), 400

    if len(username) > 50 or len(password) > 128:
        return jsonify({
            "message": "Invalid input"
        }), 400

    try:
        conn = get_db()

        # SECURITY FIX 4: Parameterized SQL query
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(user["password"], password):
            return jsonify({
                "message": "Login successful",
                "username": user["username"]
            })

        return jsonify({
            "message": "Invalid username or password"
        }), 401

    except sqlite3.Error:
        logging.exception("Database error during login")
        return jsonify({
            "message": "An internal error occurred"
        }), 500


@app.route("/ping", methods=["GET"])
def ping():
    host = request.args.get("host", "127.0.0.1").strip()

    # SECURITY FIX 5: Strict input validation
    if not host or len(host) > 253:
        return jsonify({
            "message": "Invalid host"
        }), 400

    allowed_characters = set(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789.-:"
    )

    if any(character not in allowed_characters for character in host):
        return jsonify({
            "message": "Invalid host"
        }), 400

    # SECURITY FIX 6: Avoid shell=True
    try:
        result = subprocess.run(
            ["ping", "-n", "1", host],
            shell=False,
            capture_output=True,
            text=True,
            timeout=5
        )

        return jsonify({
            "output": result.stdout,
            "error": result.stderr
        })

    except subprocess.TimeoutExpired:
        return jsonify({
            "message": "Ping request timed out"
        }), 504

    except (OSError, subprocess.SubprocessError):
        logging.exception("Ping operation failed")
        return jsonify({
            "message": "Unable to complete ping request"
        }), 500


@app.route("/search", methods=["GET"])
def search():
    username = request.args.get("username", "").strip()

    # SECURITY FIX 7: Input validation
    if len(username) > 50:
        return jsonify({
            "message": "Search input is too long"
        }), 400

    return jsonify({
        "search_query": username,
        "message": "Search completed"
    })


if __name__ == "__main__":
    initialize_database()

    # SECURITY FIX 8: Disable debug mode
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )