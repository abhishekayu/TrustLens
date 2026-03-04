"""
Google Gemini provider – hardened for structured JSON output.

Uses the Google Generative AI SDK (google-generativeai).
"""

from __future__ import annotations

import json
import re
from typing import Any

from trustlens.core import AIProvider, get_settings
from trustlens.core.logging import get_logger
from trustlens.services.ai import BaseAIProvider, register_provider

logger = get_logger(__name__)

_JSON_OBJECT_RE = re.compile(r"\{[\s\S]*\}", re.MULTILINE)


@register_provider(AIProvider.GEMINI)
class GeminiProvider(BaseAIProvider):
    """
    Google Gemini API provider with structured JSON output.

    Uses google-generativeai SDK.
    Multi-layer JSON extraction for robust parsing.
    """

    @property
    def name(self) -> str:
        return "gemini"

    async def analyze(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        import google.generativeai as genai

        settings = get_settings()
        if not settings.gemini_api_key:
            raise ValueError("TRUSTLENS_GEMINI_API_KEY is not set")

        genai.configure(api_key=settings.gemini_api_key)

        model = genai.GenerativeModel(
            model_name=settings.gemini_model,
            system_instruction=system_prompt,
            generation_config=genai.GenerationConfig(
                response_mime_type="application/json",
                temperature=0.05,
                max_output_tokens=4096,
            ),
        )

        logger.info("gemini.sending_request", model=settings.gemini_model)
        try:
            response = await model.generate_content_async(user_prompt)
        except Exception as e:
            raise ConnectionError(f"Gemini API call failed: {e}") from e

        content = response.text or ""

        if not content.strip():
            raise ValueError("Gemini returned empty response")

        # Multi-layer JSON extraction
        # Layer 1: direct parse
        try:
            return json.loads(content.strip())
        except json.JSONDecodeError:
            pass

        # Layer 2: markdown fences
        for fence in ("```json", "```"):
            if fence in content:
                parts = content.split(fence)
                if len(parts) >= 2:
                    candidate = parts[1].split("```")[0].strip()
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        continue

        # Layer 3: regex
        match = _JSON_OBJECT_RE.search(content)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass

        raise json.JSONDecodeError(
            f"No valid JSON in Gemini response ({len(content)} chars)", content, 0
        )
