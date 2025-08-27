from flask import Flask, jsonify

app = Flask(__name__)

@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok", "message": "EthioScan API is running"})

if __name__ == "__main__":
    app.run(debug=True)
