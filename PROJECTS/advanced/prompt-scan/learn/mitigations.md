# Mitigations Guide

## LLM01 — Prompt Injection

```python
# Separate instruction from data with delimiters
messages = [
    {"role": "system", "content": system_prompt},
    {"role": "user", "content": f"User query: ```{user_input}```"},
]
```
- Use XML tags or JSON to separate instruction from data
- Implement an allow-list of topics the model may discuss
- Add a secondary classifier to detect injection attempts

## LLM02 — Insecure Output Handling

```python
import html
safe_response = html.escape(llm_output)           # HTML
cursor.execute("SELECT * FROM users WHERE username = ?", (term,))  # SQL
result = subprocess.run(["ls", path], capture_output=True)          # Shell
```

## LLM04 — Model DoS

```python
from flask_limiter import Limiter
limiter = Limiter(app, key_func=get_remote_address, default_limits=["10 per minute"])

@app.route("/api/chat", methods=["POST"])
@limiter.limit("5 per minute")
def chat(): ...
```

## LLM05 — Supply Chain
- Pin exact dependency versions in `pyproject.toml`
- Never load plugins from untrusted URLs
- Run `pip-audit` or `snyk` in CI

## LLM06 — Sensitive Information Disclosure

```python
@app.errorhandler(500)
def internal_error(exc):
    return jsonify({"error": "Internal server error"}), 500  # no config leak
```
- Store secrets in a secrets manager (Vault, AWS Secrets Manager)
- Remove `/api/config` and `/api/model/info` from production

## LLM07 — Insecure Plugin Design

```python
ALLOWED = {"ls", "pwd", "date"}
def execute_command(cmd):
    parts = cmd.strip().split()
    if not parts or parts[0] not in ALLOWED:
        return {"error": "Not permitted"}
    return subprocess.run(parts, capture_output=True, text=True, timeout=5)
```

## LLM08 — Excessive Agency

```python
def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.headers.get("Authorization") != f"Bearer {os.getenv('ADMIN_TOKEN')}":
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated
```

## LLM10 — Model Theft
- Never return the system prompt or raw API key in responses
- Implement query-rate monitoring and alerts
- Use per-environment API keys with spend limits
