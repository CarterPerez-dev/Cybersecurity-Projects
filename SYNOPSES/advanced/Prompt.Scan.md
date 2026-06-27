# Prompt Scan — LLM Vulnerability Testing Platform

## Overview

Build a deliberately vulnerable AI/LLM chatbot application that exposes all ten OWASP Top 10 for Large Language Model Applications vulnerabilities as live, exploitable HTTP endpoints. The platform provides a controlled target environment for security professionals, penetration testers, and students to practice LLM-specific attack techniques — prompt injection, insecure output handling, model DoS, plugin exploitation, and more — without risk to production systems.

## Step-by-Step Instructions

1. **Understand the OWASP Top 10 for LLM Applications** by studying each risk category: LLM01 (Prompt Injection) attacks manipulate model behaviour through crafted input; LLM02 (Insecure Output Handling) occurs when raw LLM output is rendered or executed without sanitisation; LLM03 (Training Data Poisoning) injects malicious content into the model's context; LLM04 (Model Denial of Service) exhausts API quotas; LLM05 (Supply Chain) arises from untrusted plugins; LLM06 (Sensitive Information Disclosure) leaks credentials and API keys; LLM07 (Insecure Plugin Design) enables arbitrary code execution; LLM08 (Excessive Agency) grants unrestricted system permissions; LLM09 (Overreliance) accepts unvalidated output as ground truth; LLM10 (Model Theft) exposes model architecture and prompts.

2. **Design the architecture** with a Flask backend that intentionally disables every security control. Create a `Config` class that stores and exposes the OpenAI API key, admin credentials, and system prompt through a public endpoint, implementing LLM06 at the infrastructure level.

3. **Implement the vulnerable OpenAI client** wrapping the SDK with deliberate flaws: pass user input directly without sanitisation (LLM01), return full metadata including system prompt (LLM06/LLM10), expose `generate_long_response` with `max_tokens=4000` and no rate limiting (LLM04), and track `request_count` for usage pattern disclosure (LLM10).

4. **Build the injectable SQLite database helper** with three SQL injection classes: string-interpolated `search_users` enabling `' OR 1=1--` attacks, `update_user` accepting arbitrary field/value parameters, and `execute_raw_sql` running any SQL statement. Seed with fake users and a secrets table containing plaintext credentials.

5. **Create the dangerous plugin system** with `command_executor.py` using `subprocess.run(shell=True)` with no whitelist (LLM07/LLM08), and `file_reader.py` reading any path without validation. Add a `load_external_plugin` endpoint accepting a `plugin_url` to demonstrate LLM05.

6. **Implement Flask route handlers** mapping each OWASP category to exploitable endpoints: `/api/chat` (LLM01/02/04/06), `/api/config` (LLM06 full dump), `/api/prompt-injection` (LLM01), `/api/dos/long-response` (LLM04), `/api/plugin/execute` (LLM07/08), `/api/admin/delete-user/<id>` unauthenticated (LLM08), `/api/system/info` dumping `os.environ` (LLM06).

7. **Build the web interface** as a single HTML page using Bootstrap. Render LLM responses with `innerHTML` so XSS payloads execute in the browser (LLM02). Add a vulnerability panel with all exploitable endpoints and a config viewer calling `/api/config`.

8. **Document every vulnerability** in the `learn/` directory: `owasp-llm-overview.md` explaining each risk, `attack-walkthrough.md` with curl commands, and `mitigations.md` with concrete fixes.

9. **Containerise** with Docker using `uv` for dependency management, binding only to `127.0.0.1:5000`, with `HEALTHCHECK` on `/health` and `data/` mounted as a volume.

10. **Validate** by running every payload in `tests/attack_payloads.json`, confirming all ten OWASP LLM categories are reproducible, and verifying Docker isolation.

## Key Concepts to Learn
- OWASP Top 10 for Large Language Model Applications
- Prompt injection — direct, indirect, and role manipulation
- LLM output handling and XSS/SQLi/RCE attack vectors
- Rate limiting, token budgets, and denial-of-service mitigation
- Plugin architecture security and principle of least privilege
- Secrets management and environment variable hygiene
- Supply chain risks in AI/ML applications
- Model metadata disclosure and model theft vectors

## Deliverables
- Flask backend with all ten OWASP LLM vulnerabilities as live endpoints
- Vulnerable OpenAI client, SQLite helper, and plugin system
- Docker Compose environment with `uv` and volume isolation
- `learn/` directory with OWASP overview, attack walkthrough, and mitigations
- `tests/attack_payloads.json` with documented payloads for all ten categories
- Complete README with architecture diagram, API reference, and safety warnings

---
[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Advanced-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/prompt-scan)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=flat&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OWASP LLM](https://img.shields.io/badge/OWASP-Top%2010%20LLM-orange?style=flat)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
