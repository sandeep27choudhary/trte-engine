import hashlib
import json
import os
from typing import Optional

import redis
from anthropic import Anthropic
from openai import OpenAI

REDIS_URL = os.environ["REDIS_URL"]
REDIS_LLM_TTL = int(os.getenv("REDIS_LLM_TTL_SECONDS", "86400"))
CACHE_PREFIX = "trte:llm:"

SYSTEM_PROMPT = (
    "You are a security triage assistant. Analyze the vulnerability findings below.\n"
    "Return a JSON array where each element corresponds to one finding (same order).\n"
    "Each element must have exactly these fields:\n"
    '- "id": the finding id (string)\n'
    '- "exploitability": 1-2 sentences on how this could be exploited (string)\n'
    '- "fix": 1-2 sentences on how to fix it (string)\n'
    '- "urgency": one of "now", "today", or "this-week" (string)\n'
    "Return ONLY valid JSON. No markdown, no explanation."
)


def _cache_key(finding: dict) -> str:
    canonical = json.dumps(finding, sort_keys=True)
    return CACHE_PREFIX + hashlib.sha256(canonical.encode()).hexdigest()


def _compress(f: dict) -> str:
    cve = f.get("cve") or "no-cve"
    desc = (f.get("description") or "")[:100]
    return (
        f"{f['id']} | {f['service']} | {f['severity']} | {f['type']} | "
        f"{f['environment']} | exposed={f.get('internet_exposed', False)} | "
        f"sensitive={f.get('sensitive_data', False)} | {cve} | \"{desc}\""
    )


class LLMProvider:
    def __init__(self):
        self._redis = redis.from_url(REDIS_URL)

    def _call_llm(self, findings: list[dict]) -> list[dict]:
        raise NotImplementedError

    def analyze(self, findings: list[dict]) -> dict[str, Optional[dict]]:
        results: dict[str, Optional[dict]] = {}
        uncached: list[dict] = []

        for f in findings:
            cached = self._redis.get(_cache_key(f))
            if cached:
                results[f["id"]] = json.loads(cached)
            else:
                uncached.append(f)

        if uncached:
            try:
                enrichments = self._call_llm(uncached)
                for f, enrichment in zip(uncached, enrichments):
                    self._redis.setex(_cache_key(f), REDIS_LLM_TTL, json.dumps(enrichment))
                    results[f["id"]] = enrichment
            except Exception as e:
                print(f"LLM call failed: {e}")
                for f in uncached:
                    results[f["id"]] = None

        return results


class OpenAIProvider(LLMProvider):
    def __init__(self):
        super().__init__()
        self._client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
        self._model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    def _call_llm(self, findings: list[dict]) -> list[dict]:
        lines = "\n".join(_compress(f) for f in findings)
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": lines},
            ],
            temperature=0.2,
        )
        return json.loads(resp.choices[0].message.content)


class AnthropicProvider(LLMProvider):
    def __init__(self):
        super().__init__()
        self._client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self._model = os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")

    def _call_llm(self, findings: list[dict]) -> list[dict]:
        lines = "\n".join(_compress(f) for f in findings)
        resp = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": lines}],
        )
        return json.loads(resp.content[0].text)


class OpenRouterProvider(LLMProvider):
    def __init__(self):
        super().__init__()
        self._client = OpenAI(
            api_key=os.environ["OPENROUTER_API_KEY"],
            base_url="https://openrouter.ai/api/v1",
        )
        self._model = os.environ["OPENROUTER_MODEL"]

    def _call_llm(self, findings: list[dict]) -> list[dict]:
        lines = "\n".join(_compress(f) for f in findings)
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": lines},
            ],
            temperature=0.2,
        )
        return json.loads(resp.choices[0].message.content)


_PROVIDERS = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "openrouter": OpenRouterProvider,
}


def get_llm_provider() -> LLMProvider:
    name = os.environ.get("LLM_PROVIDER", "openai")
    cls = _PROVIDERS.get(name)
    if cls is None:
        raise ValueError(
            f"Unknown LLM_PROVIDER '{name}'. Must be one of: {list(_PROVIDERS.keys())}"
        )
    return cls()
