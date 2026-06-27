# Prompt Scan — Learning Path

Work through these documents in order:

| File | Topic |
|------|-------|
| [`owasp-llm-overview.md`](owasp-llm-overview.md) | Conceptual overview of all 10 OWASP LLM risks |
| [`attack-walkthrough.md`](attack-walkthrough.md) | Reproduce every vulnerability step-by-step with curl |
| [`mitigations.md`](mitigations.md) | Practical fixes and secure patterns for each risk |

## Prerequisites
- Running instance of Prompt Scan (`uv run python app/main.py` or `docker compose up -d`)
- `curl` or any HTTP client (Burp Suite, Postman, etc.)
- An OpenAI API key configured in `.env`

## Learning Objectives
1. Explain each OWASP Top 10 LLM vulnerability in plain language
2. Reproduce prompt injection, SQL injection, RCE, and info-disclosure attacks
3. Apply concrete mitigations to a Python Flask codebase
