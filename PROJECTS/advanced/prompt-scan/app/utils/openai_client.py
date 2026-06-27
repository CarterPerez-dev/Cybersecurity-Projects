"""
Prompt Scan — OpenAI Client Utility
Author: mohelobeid (https://github.com/mohelobeid)
WARNING: Intentionally vulnerable. LLM01/LLM04/LLM06/LLM10
"""

from __future__ import annotations

import openai
from app.config import config


class VulnerableOpenAIClient:
    def __init__(self) -> None:
        openai.api_key = config.OPENAI_API_KEY
        self.model = config.OPENAI_MODEL
        self.max_tokens = config.OPENAI_MAX_TOKENS
        self.temperature = config.OPENAI_TEMPERATURE
        self.system_prompt = config.SYSTEM_PROMPT
        self.request_count: int = 0

    def chat(self, user_message: str, include_system_prompt: bool = True) -> dict:
        """LLM01: no sanitisation. LLM04: no rate limit. LLM06/10: full metadata returned."""
        try:
            messages: list[dict] = []
            if include_system_prompt:
                messages.append({"role": "system", "content": self.system_prompt})
            messages.append({"role": "user", "content": user_message})
            self.request_count += 1
            response = openai.chat.completions.create(
                model=self.model, messages=messages,
                max_tokens=self.max_tokens, temperature=self.temperature)
            return {
                "success": True, "message": response.choices[0].message.content,
                "model": self.model, "tokens_used": response.usage.total_tokens,
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "request_count": self.request_count,
                "system_prompt": self.system_prompt if include_system_prompt else None,
                "finish_reason": response.choices[0].finish_reason,
            }
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return {"success": False, "error": str(exc), "error_type": type(exc).__name__,
                    "api_key": config.OPENAI_API_KEY[:10] + "...", "model": self.model,
                    "request_count": self.request_count}

    def chat_with_context(self, user_message: str, chat_history: list[dict]) -> dict:
        """LLM01/LLM03: history accepted without validation."""
        try:
            messages: list[dict] = [{"role": "system", "content": self.system_prompt}]
            for msg in chat_history:
                messages.append(msg)
            messages.append({"role": "user", "content": user_message})
            self.request_count += 1
            response = openai.chat.completions.create(
                model=self.model, messages=messages,
                max_tokens=self.max_tokens, temperature=self.temperature)
            return {"success": True, "message": response.choices[0].message.content,
                    "tokens_used": response.usage.total_tokens, "context_messages": len(messages)}
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return {"success": False, "error": str(exc)}

    def get_model_info(self) -> dict:
        """LLM06/LLM10: exposes raw API key and all model details."""
        return {"model": self.model, "max_tokens": self.max_tokens,
                "temperature": self.temperature, "system_prompt": self.system_prompt,
                "api_key": config.OPENAI_API_KEY, "request_count": self.request_count,
                "api_endpoint": "https://api.openai.com/v1/chat/completions"}

    def execute_prompt_injection(self, malicious_prompt: str) -> dict:
        """LLM01: no system prompt, no guardrails."""
        return self.chat(malicious_prompt, include_system_prompt=False)

    def generate_long_response(self, prompt: str) -> dict:
        """LLM04: max_tokens=4000, no rate limiting."""
        try:
            response = openai.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": "Generate extremely detailed and long responses."},
                           {"role": "user", "content": prompt}],
                max_tokens=4000, temperature=self.temperature)
            return {"success": True, "message": response.choices[0].message.content,
                    "tokens_used": response.usage.total_tokens}
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return {"success": False, "error": str(exc)}

    def reset_request_count(self) -> None:
        self.request_count = 0


openai_client = VulnerableOpenAIClient()
