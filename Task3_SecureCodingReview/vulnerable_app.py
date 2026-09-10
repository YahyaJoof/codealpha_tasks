from flask import Flask, request, jsonify
import sqlite3
import subprocess

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded secret
app.config["SECRET_KEY"] = "CodeAlphaSuperSecret123"

DATABASE = "users.db"


# VULNERABILITY 2: Weak password storage
def hash_password(password):
    return password


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
        "status": "running"
    })


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # VULNERABILITY 3: SQL Injection
    query = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )

    try:
        conn = get_db()
        user = conn.execute(query).fetchone()
        conn.close()

        if user:
            return jsonify({
                "message": "Login successful",
                "username": user["username"]
            })

        return jsonify({
            "message": "Invalid username or password"
        }), 401

    except Exception as error:
        # VULNERABILITY 4: Excessive error disclosure
        return jsonify({
            "error": str(error)
        }), 500


@app.route("/ping", methods=["GET"])
def ping():
    host = request.args.get("host", "127.0.0.1")

    # VULNERABILITY 5: Command Injection
    command = "ping -n 1 " + host

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True
        )

        return jsonify({
            "output": result.stdout,
            "error": result.stderr
        })

    except Exception as error:
        return jsonify({
            "error": str(error)
        }), 500


@app.route("/search", methods=["GET"])
def search():
    username = request.args.get("username", "")

    # VULNERABILITY 6: Missing input validation
    return jsonify({
        "search_query": username,
        "message": "Search completed"
    })


if __name__ == "__main__":
    initialize_database()

    # Debug mode exposes additional information
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )