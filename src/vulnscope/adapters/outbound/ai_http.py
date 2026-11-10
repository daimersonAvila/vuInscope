"""Public AI adapter (OpenAI-compatible chat endpoint). Default provider: Pollinations.AI — public, no API key.

The call is made server-side so no credentials or provider URLs ever reach the browser and the
site's Content-Security-Policy can stay `connect-src 'self'`.
"""
from __future__ import annotations

import re

import requests

from ...domain.errors import AIUnavailableError

_AD = re.compile(r"\n*---\n*\**(?:Support Pollinations|Sponsor)[\s\S]*$", re.I)


class OpenAICompatibleClient:
    def __init__(self, base_url: str, model: str, api_key: str = "", timeout: int = 45, name: str = "public-ai"):
        self.url, self.model, self.api_key, self.timeout, self.name = base_url, model, api_key, timeout, name

    def complete(self, system: str, user: str) -> str:
        headers = {"Content-Type": "application/json", "User-Agent": "vulnscope/1.0"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = {"model": self.model, "temperature": 0.2, "max_tokens": 900, "private": True,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        try:
            r = requests.post(self.url, json=body, headers=headers, timeout=self.timeout, allow_redirects=False)
            if r.status_code != 200:
                raise AIUnavailableError(f"AI provider returned HTTP {r.status_code}")
            text = r.json()["choices"][0]["message"]["content"]
        except AIUnavailableError:
            raise
        except (requests.RequestException, ValueError, KeyError, IndexError, TypeError) as exc:
            raise AIUnavailableError("AI provider unavailable") from exc
        if not isinstance(text, str):
            raise AIUnavailableError("Unexpected AI response")
        return _AD.sub("", text).strip()
