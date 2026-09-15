# app.py
from flask import Flask, render_template, request, jsonify
from rules import run_analysis
from database import init_db, log_scan

app = Flask(__name__)
init_db()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    text = data.get("message", "")
    url = data.get("url", "")

    result = run_analysis(text, url)
    log_scan(text, url, result["score"], result["risk"])

    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)