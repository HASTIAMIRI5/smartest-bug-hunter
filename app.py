from flask import Flask, render_template, request, jsonify
from scanner.owasp import scan_target

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    payload = request.get_json(silent=True) or {}
    target = (payload.get("target") or "").strip()

    if not target:
        return jsonify({"error": "Please provide a target URL."}), 400

    result = scan_target(target)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
