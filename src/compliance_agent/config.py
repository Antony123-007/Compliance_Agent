from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


def load_environment() -> None:
    load_dotenv(dotenv_path=_repo_root() / ".env", override=False)
    _clear_blank_env_var("OPENAI_BASE_URL")
    _clear_blank_env_var("COMPLIANCE_AGENT_OUTPUT_DIR")


def default_model() -> str:
    return os.getenv("OPENAI_MODEL", "gpt-4.1-mini")


def default_base_url() -> str | None:
    value = os.getenv("OPENAI_BASE_URL", "").strip()
    return value or None


def default_api_key_env() -> str:
    return os.getenv("COMPLIANCE_AGENT_API_KEY_ENV", "OPENAI_API_KEY")


def configured_output_root() -> Path | None:
    value = os.getenv("COMPLIANCE_AGENT_OUTPUT_DIR", "").strip()
    if not value:
        return None
    return Path(value).expanduser()


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _clear_blank_env_var(name: str) -> None:
    value = os.getenv(name)
    if value is not None and not value.strip():
        os.environ.pop(name, None)
