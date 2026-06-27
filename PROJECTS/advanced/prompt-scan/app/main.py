"""
Prompt Scan — Flask Application Entry Point
Author: mohelobeid (https://github.com/mohelobeid)
WARNING: INTENTIONALLY VULNERABLE. NEVER deploy to production.
"""

from __future__ import annotations
import os, platform, sys
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app.config import config
from app.utils.database import db
from app.utils.openai_client import openai_client

app = Flask(__name__, static_folder="../frontend", template_folder="../frontend")
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["WTF_CSRF_ENABLED"] = False
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route("/")
def index(): return send_from_directory("../frontend", "index.html")

@app.route("/health")
def health(): return jsonify({"status": "running", "version": "1.0.0", "vulnerabilities_enabled": True})

@app.route("/api/chat", methods=["POST"])
def chat():
    try:
        data = request.get_json()
        if not data or "message" not in data: return jsonify({"error": "No message provided"}), 400
        return jsonify(openai_client.chat(data["message"]))
    except Exception as exc:
        return jsonify({"error": str(exc), "error_type": type(exc).__name__, "config": config.get_config_dict()}), 500

@app.route("/api/chat/history", methods=["GET"])
def get_chat_history(): return jsonify(db.get_chat_history(request.args.get("user_id")))

@app.route("/api/chat/save", methods=["POST"])
def save_chat():
    data = request.get_json()
    return jsonify(db.save_chat(data.get("user_id",1), data.get("message",""), data.get("response",""), data.get("tokens_used",0)))

@app.route("/api/config", methods=["GET"])
def get_config(): return jsonify(config.get_config_dict())

@app.route("/api/model/info", methods=["GET"])
def get_model_info(): return jsonify(openai_client.get_model_info())

@app.route("/api/prompt-injection", methods=["POST"])
def test_prompt_injection():
    data = request.get_json()
    return jsonify(openai_client.execute_prompt_injection(data.get("prompt", "")))

@app.route("/api/dos/long-response", methods=["POST"])
def test_dos():
    data = request.get_json()
    return jsonify(openai_client.generate_long_response(data.get("prompt", "Generate a very long response")))

@app.route("/api/users", methods=["GET"])
def get_users(): return jsonify(db.get_all_users())

@app.route("/api/users/<user_id>", methods=["GET"])
def get_user(user_id: str): return jsonify(db.get_user_by_id(user_id))

@app.route("/api/users/search", methods=["GET"])
def search_users(): return jsonify(db.search_users(request.args.get("q", "")))

@app.route("/api/users/<user_id>/update", methods=["POST"])
def update_user(user_id: str):
    data = request.get_json()
    return jsonify(db.update_user(user_id, data.get("field",""), data.get("value","")))

@app.route("/api/secrets", methods=["GET"])
def get_secrets(): return jsonify(db.get_secrets())

@app.route("/api/database/query", methods=["POST"])
def execute_database_query(): return jsonify(db.execute_raw_sql(request.get_json().get("query","")))

@app.route("/api/database/schema", methods=["GET"])
def get_database_schema(): return jsonify(db.get_database_schema())

@app.route("/api/database/info", methods=["GET"])
def get_database_info(): return jsonify(db.get_database_info())

@app.route("/api/plugin/execute", methods=["POST"])
def execute_plugin():
    data = request.get_json()
    plugin_name = data.get("plugin", "")
    params = data.get("params", {})
    try:
        if plugin_name == "file_reader":
            from app.plugins.file_reader import read_file as _rf
            result = _rf(params.get("path", ""))
        elif plugin_name == "command_executor":
            from app.plugins.command_executor import execute_command
            result = execute_command(params.get("command", ""))
        elif plugin_name == "database_query":
            result = db.execute_raw_sql(params.get("query", ""))
        else:
            result = {"error": "Unknown plugin"}
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc), "plugin": plugin_name, "params": params}), 500

@app.route("/api/plugin/load", methods=["POST"])
def load_external_plugin():
    data = request.get_json()
    return jsonify({"message": "Plugin loading from external sources", "url": data.get("plugin_url",""),
                    "warning": "This demonstrates LLM05 supply chain risk."})

@app.route("/api/admin/delete-user/<user_id>", methods=["DELETE"])
def delete_user(user_id: str): return jsonify(db.delete_user(user_id))

@app.route("/api/system/info", methods=["GET"])
def get_system_info():
    return jsonify({"platform": platform.system(), "python_version": platform.python_version(),
                    "cwd": os.getcwd(), "env_vars": dict(os.environ), "config": config.get_config_dict()})

@app.errorhandler(404)
def not_found(_e):
    return jsonify({"error": "Not found", "path": request.path,
                    "available_endpoints": ["/api/chat","/api/config","/api/users","/api/secrets","/api/database/query","/api/plugin/execute"]}), 404

@app.errorhandler(500)
def internal_error(exc):
    return jsonify({"error": str(exc), "type": type(exc).__name__, "config": config.get_config_dict()}), 500

if __name__ == "__main__":
    if not config.validate_config(): sys.exit(1)
    print("\n🔓 PROMPT SCAN — SECURITY TESTING\n⚠️  INTENTIONALLY VULNERABLE — DO NOT DEPLOY TO PRODUCTION\n")
    print(f"🚀 http://{config.HOST}:{config.PORT}")
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
