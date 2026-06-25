"""Route alert triage stages to configured LLM providers."""
from __future__ import annotations

import json
import time
from typing import Any, Dict, Mapping, Optional

from .env import load_ai_env_into_process
from .providers import LLMProvider, provider_from_config


DEFAULT_ROUTES = {
    "batch_triage": "codex_direct",
    "source_review": "codex_direct",
    "agent_triage": "codex_direct",
    "critical_review": "codex_direct",
    "rule_parse": "codex_direct",
    "fallback": "codex_direct",
}


def provider_configs(config: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    llm = config.get("llm") or {}
    configured = llm.get("providers") or {}
    if configured:
        return {str(k): dict(v or {}) for k, v in configured.items()}
    # Backward-compatible provider built from existing llm keys.
    return {
        "codex_direct": {
            "type": "codex_direct",
            "model": llm.get("model", "gpt-5.5"),
            "url": llm.get("codex_responses_url"),
            "reasoning_effort": llm.get("reasoning_effort", "medium"),
            "timeout_seconds": llm.get("timeout_seconds", 180),
        }
    }


def routing_config(config: Mapping[str, Any]) -> Dict[str, str]:
    llm = config.get("llm") or {}
    routes = dict(DEFAULT_ROUTES)
    routes.update({str(k): str(v) for k, v in (llm.get("routing") or {}).items() if v})
    if llm.get("provider") and not llm.get("providers"):
        for key in list(routes):
            routes[key] = str(llm.get("provider"))
    return routes


class LLMRouter:
    def __init__(self, config: Mapping[str, Any]):
        self.config = config
        load_ai_env_into_process(config)
        self.providers = provider_configs(config)
        self.routes = routing_config(config)

    def provider_name_for(self, stage: str) -> str:
        return self.routes.get(stage) or self.routes.get("fallback") or "codex_direct"

    def provider_for(self, stage: str) -> LLMProvider:
        name = self.provider_name_for(stage)
        cfg = self.providers.get(name)
        if not cfg:
            raise RuntimeError(f"route {stage} points to missing provider {name}")
        return provider_from_config(name, cfg)

    def complete_json(self, stage: str, prompt: str, system: str = "", timeout: Optional[float] = None):
        provider = self.provider_for(stage)
        return provider.complete_json(prompt, system=system, timeout=timeout)

    def summary(self) -> Dict[str, Any]:
        return {
            "routes": self.routes,
            "providers": {
                name: {
                    "type": cfg.get("type"),
                    "model": cfg.get("model"),
                    "base_url": cfg.get("base_url") or cfg.get("url") or "",
                    "api_key_env": cfg.get("api_key_env") or "",
                }
                for name, cfg in self.providers.items()
            },
        }

    def health(self) -> Dict[str, Any]:
        out = {}
        for name, cfg in self.providers.items():
            try:
                out[name] = provider_from_config(name, cfg).healthcheck()
            except Exception as exc:
                out[name] = {"ok": False, "provider": name, "error": str(exc)}
        return out

    def test_provider(self, name: str, live: bool = False, timeout: float = 30.0) -> Dict[str, Any]:
        cfg = self.providers.get(name)
        if not cfg:
            return {"ok": False, "provider": name, "error": "provider_not_found"}
        provider = provider_from_config(name, cfg)
        health = provider.healthcheck(timeout=min(timeout, 6.0))
        result: Dict[str, Any] = {
            "provider": name,
            "model": provider.model,
            "type": cfg.get("type"),
            "live": bool(live),
            "config_ok": bool(health.get("ok")),
            "health": health,
        }
        if not health.get("ok") or not live:
            result["ok"] = bool(health.get("ok")) and not live
            return result

        started = time.time()
        try:
            response = provider.complete_json(
                '{"task":"smoke_test","instruction":"只输出 JSON 对象 {\\\"ok\\\":true,\\\"stage\\\":\\\"provider_smoke\\\"}"}',
                system="你是一个 JSON 连通性测试器。不要输出 Markdown,只输出一个 JSON 对象。",
                timeout=timeout,
            )
        except Exception as exc:
            return dict(result, ok=False, error=str(exc)[:800], elapsed_ms=int((time.time() - started) * 1000))
        parsed = _parse_jsonish(response.text)
        elapsed_ms = int((time.time() - started) * 1000)
        result.update({
            "ok": bool(parsed.get("ok") is True or parsed.get("stage") == "provider_smoke"),
            "elapsed_ms": elapsed_ms,
            "response_model": response.model,
            "usage": response.usage,
            "parsed": parsed,
            "text_preview": response.text[:300],
        })
        if not result["ok"]:
            result["error"] = "provider_did_not_return_expected_json"
        return result


def _parse_jsonish(text: str) -> Dict[str, Any]:
    value = str(text or "").strip()
    if not value:
        return {}
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    except json.JSONDecodeError:
        pass
    start = value.find("{")
    end = value.rfind("}")
    if 0 <= start < end:
        try:
            parsed = json.loads(value[start:end + 1])
            return parsed if isinstance(parsed, dict) else {"value": parsed}
        except json.JSONDecodeError:
            return {}
    return {}
