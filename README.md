from __future__ import annotations

import json
from typing import Any, Dict

from flask import Flask, Response, jsonify, render_template, request

from scanner.owasp import auth_simulation, export_history, get_history, scan_target

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan() -> Response:
    payload = request.get_json(silent=True) or {}
    target = (payload.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Please provide a target URL."}), 400

    username = (payload.get("username") or "").strip()
    password = (payload.get("password") or "").strip()
    result = scan_target(target, username=username, password=password)
    return jsonify(result)


@app.route("/api/auth-test", methods=["POST"])
def auth_test() -> Response:
    payload = request.get_json(silent=True) or {}
    target = (payload.get("target") or "").strip()
    username = (payload.get("username") or "").strip()
    password = (payload.get("password") or "").strip()

    if not target:
        return jsonify({"error": "Please provide a target URL."}), 400

    result = auth_simulation(target, username=username, password=password)
    return jsonify(result)


@app.route("/api/history")
def history() -> Response:
    return jsonify({"history": get_history(limit=20)})


@app.route("/api/export")
def export() -> Response:
    fmt = (request.args.get("format") or "json").lower()
    content = export_history(fmt)

    if fmt == "csv":
        return Response(
            content,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=scan_history.csv"},
        )

    return Response(
        json.dumps({"history": json.loads(content)["history"]}, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=scan_history.json"},
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
