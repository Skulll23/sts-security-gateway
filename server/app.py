"""
STS Target Server — intentionally vulnerable Flask app
Provides multiple realistic attack surfaces for the proxy to intercept.
Port: 8000
"""

from flask import Flask, request, render_template, redirect, url_for

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html", page="home")

@app.route("/login", methods=["GET", "POST"])
def login():
    result = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # Intentionally echoes input — SQL injection surface
        result = f"Attempting login for: {username}"
    return render_template("index.html", page="login", result=result)

@app.route("/search")
def search():
    q = request.args.get("q", "")
    # Reflects query param — XSS + SQLi surface
    results = [f"Result for: {q}"] if q else []
    return render_template("index.html", page="search", query=q, results=results)

@app.route("/comment", methods=["GET", "POST"])
def comment():
    posted = None
    if request.method == "POST":
        author  = request.form.get("author", "")
        content = request.form.get("content", "")
        posted  = {"author": author, "content": content}
    return render_template("index.html", page="comment", posted=posted)

@app.route("/file")
def file_viewer():
    path = request.args.get("path", "")
    # Path traversal surface
    output = f"Reading file: {path}" if path else ""
    return render_template("index.html", page="file", path=path, output=output)

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # Command injection surface
    output = f"Pinging: {host}" if host else ""
    return render_template("index.html", page="ping", host=host, output=output)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
