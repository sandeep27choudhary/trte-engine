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
    "You are a security reasoning engine. You do NOT change base scores. "
    "You only analyze exploitability, detect simple correlations, and produce concise actionable insights.\n\n"
    "Rules:\n"
    "- Be deterministic and concise\n"
    "- No hallucinations\n"
    "- Do not invent missing data\n"
    "- Use only given inputs\n"
    "- Max 2-3 lines per explanation\n\n"
    "Tasks:\n"
    "1. For each finding:\n"
    "   - Determine if it is realistically exploitable\n"
    "   - Provide a short reason (max 2 lines)\n"
    "   - Provide a concrete fix\n"
    "   - Assign urgency: now | today | this-week\n"
    "   - Suggest adjusted_priority: high | medium | low based on real-world risk\n\n"
    "2. Correlation (IMPORTANT):\n"
    "   - Identify simple attack paths across findings\n"
    "   - Only use obvious combinations like:\n"
    "     - internet_exposed + weak auth\n"
    "     - sensitive_data + public access\n"
    "     - production + critical vuln\n"
    "   - If correlation exists, include a combined_risk note for the relevant finding\n\n"
    "Return a JSON object with a 'results' array. Each element must have exactly these fields:\n"
    '- "id": the finding id (string)\n'
    '- "exploitability": High | Medium | Low (string)\n'
    '- "reason": max 2 lines on why it is exploitable (string)\n'
    '- "fix": concrete remediation (string)\n'
    '- "urgency": one of "now", "today", "this-week" (string)\n'
    '- "adjusted_priority": one of "high", "medium", "low" (string)\n'
    '- "combined_risk": correlation note if applicable, else null\n\n'
    "Return ONLY valid JSON. No markdown, no explanation."
)


def _cache_key(finding: dict) -> str:
    canonical = json.dumps(finding, sort_keys=True, default=str)
    return CACHE_PREFIX + hashlib.sha256(canonical.encode()).hexdigest()


def _format_finding(f: dict) -> str:
    cve = f.get("cve") or "no-cve"
    desc = (f.get("description") or "")[:100]
    ctx = f.get("context") or {}
    context_str = ""
    if ctx:
        parts = []
        if ctx.get("criticality"):
            parts.append(f"criticality={ctx['criticality']}")
        if ctx.get("public_facing") is not None:
            parts.append(f"public_facing={ctx['public_facing']}")
        if ctx.get("owner"):
            parts.append(f"owner={ctx['owner']}")
        if parts:
            context_str = " | " + " | ".join(parts)
    return (
        f"{f['id']} | {f['service']} | {f['severity']} | {f['type']} | "
        f"{f['environment']} | exposed={f.get('internet_exposed', False)} | "
        f"sensitive={f.get('sensitive_data', False)} | score={f.get('base_score', 0)} | "
        f"{cve} | \"{desc}\"{context_str}"
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
                enrichment_by_id = {e["id"]: e for e in enrichments}
                for f in uncached:
                    enrichment = enrichment_by_id.get(f["id"])
                    if enrichment:
                        self._redis.setex(_cache_key(f), REDIS_LLM_TTL, json.dumps(enrichment))
                        results[f["id"]] = enrichment
                    else:
                        results[f["id"]] = None
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
        lines = "\n".join(_format_finding(f) for f in findings)
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": lines},
            ],
            temperature=0.2,
        )
        return json.loads(resp.choices[0].message.content)["results"]


class AnthropicProvider(LLMProvider):
    def __init__(self):
        super().__init__()
        self._client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self._model = os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")

    def _call_llm(self, findings: list[dict]) -> list[dict]:
        lines = "\n".join(_format_finding(f) for f in findings)
        resp = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": lines}],
        )
        return json.loads(resp.content[0].text)["results"]


class OpenRouterProvider(LLMProvider):
    def __init__(self):
        super().__init__()
        self._client = OpenAI(
            api_key=os.environ["OPENROUTER_API_KEY"],
            base_url="https://openrouter.ai/api/v1",
        )
        self._model = os.environ["OPENROUTER_MODEL"]

    def _call_llm(self, findings: list[dict]) -> list[dict]:
        lines = "\n".join(_format_finding(f) for f in findings)
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": lines},
            ],
            temperature=0.2,
        )
        return json.loads(resp.choices[0].message.content)["results"]


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
