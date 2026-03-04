"""
Grok (xAI) provider – hardened for structured JSON output.

Uses the xAI API which is OpenAI-compatible.
"""

from __future__ import annotations

import json
from typing import Any

from trustlens.core import AIProvider, get_settings
from trustlens.core.logging import get_logger
from trustlens.services.ai import BaseAIProvider, register_provider

logger = get_logger(__name__)


@register_provider(AIProvider.GROK)
class GrokProvider(BaseAIProvider):
    """
    Grok (xAI) API provider with structured JSON output.

    Uses OpenAI-compatible SDK pointed at xAI's endpoint.
    Temperature set near-zero for deterministic output.
    """

    @property
    def name(self) -> str:
        return "grok"

    async def analyze(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        from openai import AsyncOpenAI

        settings = get_settings()
        if not settings.grok_api_key:
            raise ValueError("TRUSTLENS_GROK_API_KEY is not set")

        client = AsyncOpenAI(
            api_key=settings.grok_api_key,
            base_url="https://api.x.ai/v1",
        )

        logger.info("grok.sending_request", model=settings.grok_model)
        try:
            response = await client.chat.completions.create(
                model=settings.grok_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.05,
                max_tokens=4096,
            )
        except Exception as e:
            raise ConnectionError(f"Grok (xAI) API call failed: {e}") from e

        content = response.choices[0].message.content or ""

        if not content.strip():
            raise ValueError("Grok returned empty response")

        return json.loads(content)
