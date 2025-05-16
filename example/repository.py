import json
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

organizations = {}

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/organization/list", methods=["GET"])
def org_list():
    return json.dumps(organizations), 200

@app.route("/organization/create", methods=["POST"])
def create_org():
    data = request.json
    org_name = data.get("organization")
    username = data.get("username")
    name = data.get("name")
    email = data.get("email")
    public_key = data.get("public_key")

    if org_name in organizations:
        return jsonify({"error": "Organization already exists"}), 400

    organizations[org_name] = {
        "name": org_name,
        "subjects": [{
            "username": username,
            "name": name,
            "email": email,
            "public_key": public_key,
            "roles": ["Manager"]
        }]
    }
    return jsonify({"message": "Organization created successfully"}), 201

if __name__ == "__main__":
    app.run(debug=True)
