# OWASP Top 10 for Large Language Model Applications — Overview

Every vulnerability below is live and exploitable in Prompt Scan.

## LLM01 — Prompt Injection
An attacker crafts input that causes the LLM to ignore its original instructions, reveal its system prompt, or adopt a new persona. Unlike SQL injection, there is no unambiguous syntax boundary between instruction and data in natural language.

**In this lab:** `/api/chat` passes user input directly to OpenAI. `/api/prompt-injection` removes even the system prompt.

## LLM02 — Insecure Output Handling
Raw LLM output is used without sanitisation — rendered as HTML (XSS), passed to a shell (RCE), or interpolated into SQL.

**In this lab:** Frontend renders responses with `innerHTML`. Database helper uses string interpolation in SQL queries.

## LLM03 — Training Data Poisoning
Malicious content injected into the model's context or history causes incorrect behaviour.

**In this lab:** `chat_with_context` accepts chat history without validation.

## LLM04 — Model Denial of Service
Requests exhaust API quotas through unrestricted token generation.

**In this lab:** `/api/dos/long-response` calls OpenAI with `max_tokens=4000` and no rate limiting.

## LLM05 — Supply Chain Vulnerabilities
Untrusted plugins or outdated dependencies compromise the application.

**In this lab:** `/api/plugin/load` accepts an arbitrary `plugin_url`.

## LLM06 — Sensitive Information Disclosure
API keys, system prompts, PII, or internal configuration are leaked.

**In this lab:** `GET /api/config` returns `OPENAI_API_KEY` and `ADMIN_PASSWORD`. Every error response includes the full config dict.

## LLM07 — Insecure Plugin Design
Plugins are granted excessive permissions and execute arbitrary code.

**In this lab:** `command_executor` uses `subprocess.run(shell=True)` with no whitelist. `file_reader` reads any path.

## LLM08 — Excessive Agency
The application is granted permissions far beyond what is needed.

**In this lab:** `DELETE /api/admin/delete-user/<id>` requires no auth. `POST /api/database/query` executes any SQL.

## LLM09 — Overreliance
The application trusts LLM output as ground truth without validation.

**In this lab:** All LLM responses returned directly without fact-checking or validation.

## LLM10 — Model Theft
Adversarial queries extract model architecture, prompts, and usage patterns.

**In this lab:** `GET /api/model/info` exposes model name, temperature, system prompt, raw API key, and request count.
