# test_server.py
from flask import Flask, request, send_from_directory, make_response
from markupsafe import escape
import traceback
import re

app = Flask(__name__, static_folder=".", template_folder=".")

@app.route("/test_page.html")
def test_page():
    return send_from_directory(".", "test_page.html")

def classify_payload(username: str) -> str:
    u = username.lower()
    if "<script" in u or "onerror=" in u or "onload=" in u:
        return "xss"
    if " or 1=1" in u or "union" in u or "select" in u:
        return "sqli"
    if any(op in u for op in [";", "&&", "|", "`", "$("]):
        return "cmd"
    if "traceback" in u or "typeerror" in u or "exception" in u:
        return "info"
    return "safe"

@app.route("/submit", methods=["POST"])
def submit():
    username = request.values.get("username", "")

    vuln = classify_payload(username)

    if vuln == "xss":
        return make_response(f"<h2>welcome, {username}</h2>", 200)

    if vuln == "sqli":
        return make_response(f"<h2>welcome, {escape(username)}</h2><pre>SQLSTATE[42000]: Syntax error</pre>", 200)

    if vuln == "cmd":
        return make_response(f"<h2>welcome, {escape(username)}</h2><pre>sh: 1: command not found\nroot@localhost:/#</pre>", 200)

    if vuln == "info":
        try:
            raise TypeError("simulated error")
        except Exception:
            tb = traceback.format_exc()
            return make_response(f"<h2>welcome, {escape(username)}</h2><pre>{escape(tb)}</pre>", 200)

    # fallback safe
    return make_response(f"<h2>welcome, {escape(username)}</h2><p>safe response</p>", 200)

@app.route("/")
def index():
    return send_from_directory(".", "test_page.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
