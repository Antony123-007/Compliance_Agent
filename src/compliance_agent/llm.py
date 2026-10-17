from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from openai import APIConnectionError, APIStatusError, OpenAI, RateLimitError

from compliance_agent.frameworks import catalog_summary
from compliance_agent.prompts import (
    SYSTEM_PROMPT,
    build_baseline_prompt,
    build_correction_prompt,
    build_extraction_prompt,
)


class LLMResponseError(RuntimeError):
    pass


class LLMRequestError(RuntimeError):
    pass


@dataclass(slots=True)
class LLMSettings:
    model: str
    api_key_env: str = "OPENAI_API_KEY"
    base_url: str | None = None
    provider_name: str = "openai-compatible"

    def api_key(self) -> str:
        value = os.environ.get(self.api_key_env)
        if value:
            return value
        if self.base_url:
            return "local"
        raise RuntimeError(
            f"Missing API key. Set {self.api_key_env} in the environment or in the repo "
            ".env file, or use a local compatible runtime with --base-url."
        )


class LLMClient:
    def __init__(self, settings: LLMSettings) -> None:
        self.settings = settings
        self.client = OpenAI(api_key=settings.api_key(), base_url=settings.base_url)

    def extract(self, source_name: str, text: str) -> dict[str, Any]:
        prompt = build_extraction_prompt(source_name, text, catalog_summary())
        content = self._chat(prompt)
        return self._parse_json(content)

    def correct(self, validation_errors: list[str], raw_response: str) -> dict[str, Any]:
        prompt = build_correction_prompt(validation_errors, raw_response)
        content = self._chat(prompt)
        return self._parse_json(content)

    def baseline_extract(self, source_name: str, text: str) -> dict[str, Any]:
        content = self._chat(build_baseline_prompt(source_name, text))
        return self._parse_json(content)

    def _chat(self, prompt: str) -> str:
        try:
            try:
                completion = self.client.chat.completions.create(
                    model=self.settings.model,
                    temperature=0,
                    response_format={"type": "json_object"},
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                )
            except TypeError:
                completion = self.client.chat.completions.create(
                    model=self.settings.model,
                    temperature=0,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                )
        except (RateLimitError, APIConnectionError, APIStatusError) as exc:
            raise _translate_openai_error(exc) from exc

        content = completion.choices[0].message.content
        if not content:
            raise LLMResponseError("Model returned an empty response.")
        return content

    def _parse_json(self, content: str) -> dict[str, Any]:
        cleaned = content.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            cleaned = cleaned.replace("json\n", "", 1).strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            start = cleaned.find("{")
            end = cleaned.rfind("}")
            if start != -1 and end != -1 and end > start:
                return json.loads(cleaned[start : end + 1])
        raise LLMResponseError("Model returned invalid JSON.")


def _translate_openai_error(exc: Exception) -> LLMRequestError:
    if isinstance(exc, RateLimitError):
        return LLMRequestError(
            "The model request was rejected by the provider due to quota or rate limits. "
            "Add API credits, switch to a different funded model account, or configure a "
            "local OpenAI-compatible runtime with --base-url."
        )
    if isinstance(exc, APIConnectionError):
        return LLMRequestError(
            "The agent could not reach the model provider. Check Internet access, "
            "proxy settings, or the configured base URL."
        )
    if isinstance(exc, APIStatusError):
        return LLMRequestError(
            f"The model provider returned an API error: {exc.status_code}."
        )
    return LLMRequestError("The model request failed.")
