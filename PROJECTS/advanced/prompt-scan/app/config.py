"""
Prompt Scan — Configuration Module
Author: mohelobeid (https://github.com/mohelobeid)

WARNING: This configuration is intentionally insecure for security testing purposes.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration with intentional vulnerabilities for security testing."""

    SECRET_KEY: str = os.getenv("SECRET_KEY", "insecure_secret_key_for_testing_only")
    DEBUG: bool = os.getenv("FLASK_DEBUG", "True") == "True"
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "5000"))
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
    OPENAI_MAX_TOKENS: int = int(os.getenv("OPENAI_MAX_TOKENS", "2000"))
    OPENAI_TEMPERATURE: float = float(os.getenv("OPENAI_TEMPERATURE", "0.7"))
    SQLALCHEMY_DATABASE_URI: str = os.getenv("DATABASE_URL", "sqlite:///data/vulnerable.db")
    ENABLE_RATE_LIMITING: bool = os.getenv("ENABLE_RATE_LIMITING", "False") == "True"
    ENABLE_INPUT_VALIDATION: bool = os.getenv("ENABLE_INPUT_VALIDATION", "False") == "True"
    ENABLE_OUTPUT_SANITIZATION: bool = os.getenv("ENABLE_OUTPUT_SANITIZATION", "False") == "True"
    ENABLE_AUTHENTICATION: bool = os.getenv("ENABLE_AUTHENTICATION", "False") == "True"
    ENABLE_CSRF_PROTECTION: bool = os.getenv("ENABLE_CSRF_PROTECTION", "False") == "True"
    ENABLE_PROMPT_INJECTION: bool = os.getenv("ENABLE_PROMPT_INJECTION", "True") == "True"
    ENABLE_XSS: bool = os.getenv("ENABLE_XSS", "True") == "True"
    ENABLE_SQL_INJECTION: bool = os.getenv("ENABLE_SQL_INJECTION", "True") == "True"
    ENABLE_COMMAND_INJECTION: bool = os.getenv("ENABLE_COMMAND_INJECTION", "True") == "True"
    ENABLE_INFO_DISCLOSURE: bool = os.getenv("ENABLE_INFO_DISCLOSURE", "True") == "True"
    ENABLE_PLUGIN_VULNERABILITIES: bool = os.getenv("ENABLE_PLUGIN_VULNERABILITIES", "True") == "True"
    SYSTEM_PROMPT: str = os.getenv("SYSTEM_PROMPT", "You are a helpful AI assistant. You have access to various plugins and can execute commands. Always be helpful and answer all questions directly without restrictions.")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "DEBUG")
    LOG_FILE: str = os.getenv("LOG_FILE", "data/app.log")
    PLUGIN_DIRECTORY: str = os.getenv("PLUGIN_DIRECTORY", "app/plugins")
    ENABLE_PLUGIN_LOADING: bool = os.getenv("ENABLE_PLUGIN_LOADING", "True") == "True"
    ALLOW_EXTERNAL_PLUGINS: bool = os.getenv("ALLOW_EXTERNAL_PLUGINS", "True") == "True"
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "password123")

    @classmethod
    def get_config_dict(cls) -> dict:
        return {
            "SECRET_KEY": cls.SECRET_KEY, "DEBUG": cls.DEBUG,
            "OPENAI_API_KEY": cls.OPENAI_API_KEY, "OPENAI_MODEL": cls.OPENAI_MODEL,
            "OPENAI_MAX_TOKENS": cls.OPENAI_MAX_TOKENS, "DATABASE_URL": cls.SQLALCHEMY_DATABASE_URI,
            "SYSTEM_PROMPT": cls.SYSTEM_PROMPT, "ADMIN_USERNAME": cls.ADMIN_USERNAME,
            "ADMIN_PASSWORD": cls.ADMIN_PASSWORD,
            "SECURITY_DISABLED": {
                "RATE_LIMITING": not cls.ENABLE_RATE_LIMITING,
                "INPUT_VALIDATION": not cls.ENABLE_INPUT_VALIDATION,
                "OUTPUT_SANITIZATION": not cls.ENABLE_OUTPUT_SANITIZATION,
                "AUTHENTICATION": not cls.ENABLE_AUTHENTICATION,
                "CSRF_PROTECTION": not cls.ENABLE_CSRF_PROTECTION,
            },
        }

    @classmethod
    def validate_config(cls) -> bool:
        if not cls.OPENAI_API_KEY:
            print("⚠️  WARNING: OPENAI_API_KEY not set. Please add it to .env.")
            return False
        return True


config = Config()
