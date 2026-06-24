"""Pluggable LLM providers used by the agent triage flow.

Provider implementations are deliberately small and dependency-light. They use
plain HTTP or local CLIs so the existing project does not need a new SDK just to
switch between DeepSeek, GLM, Codex, and Claude.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional


CODEX_RESPONSES_URL = "https://chatgpt.com/backend-api/codex/responses"
ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"


@dataclass
class LLMResponse:
    text: str
    model: str = ""
    provider: str = ""
    usage: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)


class LLMProvider:
    def __init__(self, name: str, config: Mapping[str, Any]):
        self.name = name
        self.config = dict(config or {})

    @property
    def model(self) -> str:
        return str(self.config.get("model") or "")

    def complete_json(self, prompt: str, system: str = "", timeout: Optional[float] = None) -> LLMResponse:
        raise NotImplementedError

    def healthcheck(self, timeout: float = 6.0) -> Dict[str, Any]:
        try:
            # Avoid expensive checks: validate local config/env only by default.
            self._require_ready()
            return {"ok": True, "provider": self.name, "model": self.model, "mode": self.config.get("type")}
        except Exception as exc:
            return {"ok": False, "provider": self.name, "model": self.model, "error": str(exc)}

    def _require_ready(self) -> None:
        return None


class OpenAICompatibleProvider(LLMProvider):
    """OpenAI Chat Completions compatible provider.

    DeepSeek and GLM can both be configured through this class.
    """

    def _api_key(self) -> str:
        env = str(self.config.get("api_key_env") or "OPENAI_API_KEY")
        key = str(self.config.get("api_key") or os.getenv(env) or "")
        if not key:
            raise RuntimeError(f"missing api key env {env}")
        return key

    def _base_url(self) -> str:
        return str(self.config.get("base_url") or "https://api.openai.com/v1").rstrip("/")

    def _require_ready(self) -> None:
        self._api_key()
        if not self.model:
            raise RuntimeError("missing model")

    def complete_json(self, prompt: str, system: str = "", timeout: Optional[float] = None) -> LLMResponse:
        self._require_ready()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        body: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": float(self.config.get("temperature", 0)),
            "stream": False,
        }
        if self.config.get("json_mode", True):
            body["response_format"] = {"type": "json_object"}
        if self.config.get("reasoning_effort"):
            body["reasoning_effort"] = self.config.get("reasoning_effort")
        if self.config.get("thinking") is not None:
            body["thinking"] = self.config.get("thinking")

        response = self._post_chat(body, timeout or float(self.config.get("timeout_seconds", 180)))
        choice = (response.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        return LLMResponse(
            text=str(message.get("content") or ""),
            model=str(response.get("model") or self.model),
            provider=self.name,
            usage=response.get("usage") or {},
            raw=response,
        )

    def _post_chat(self, body: Dict[str, Any], timeout: float) -> Dict[str, Any]:
        headers = {
            "Authorization": "Bearer " + self._api_key(),
            "Content-Type": "application/json",
        }
        url = self._base_url() + "/chat/completions"
        optional_keys = ("response_format", "reasoning_effort", "thinking")
        current = dict(body)
        for _ in range(len(optional_keys) + 1):
            try:
                return _post_json(url, current, headers, timeout)
            except RuntimeError as exc:
                message = str(exc)
                removed = False
                # Some compatible APIs lag OpenAI's optional request fields.
                # Retry once per unsupported field while preserving the same
                # provider interface for DeepSeek/GLM/OpenAI-compatible APIs.
                for key in optional_keys:
                    if key in current and key in message:
                        current = dict(current)
                        current.pop(key, None)
                        removed = True
                        break
                if not removed:
                    raise
        return _post_json(url, current, headers, timeout)


class AnthropicProvider(LLMProvider):
    """Claude API provider using Anthropic Messages API."""

    def _api_key(self) -> str:
        env = str(self.config.get("api_key_env") or "ANTHROPIC_API_KEY")
        key = str(self.config.get("api_key") or os.getenv(env) or "")
        if not key:
            raise RuntimeError(f"missing api key env {env}")
        return key

    def _require_ready(self) -> None:
        self._api_key()
        if not self.model:
            raise RuntimeError("missing model")

    def complete_json(self, prompt: str, system: str = "", timeout: Optional[float] = None) -> LLMResponse:
        self._require_ready()
        body: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": int(self.config.get("max_tokens", 2048)),
            "temperature": float(self.config.get("temperature", 0)),
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            body["system"] = system
        response = _post_json(
            str(self.config.get("url") or ANTHROPIC_MESSAGES_URL),
            body,
            {
                "x-api-key": self._api_key(),
                "anthropic-version": str(self.config.get("anthropic_version") or "2023-06-01"),
                "Content-Type": "application/json",
            },
            timeout or float(self.config.get("timeout_seconds", 180)),
        )
        chunks = []
        for item in response.get("content") or []:
            if item.get("type") == "text":
                chunks.append(str(item.get("text") or ""))
        return LLMResponse(
            text="".join(chunks),
            model=str(response.get("model") or self.model),
            provider=self.name,
            usage=response.get("usage") or {},
            raw=response,
        )


class CodexDirectProvider(LLMProvider):
    """Codex subscription provider using local ~/.codex/auth.json."""

    def _auth_headers(self) -> Dict[str, str]:
        auth_path = Path(str(self.config.get("auth_path") or Path.home() / ".codex" / "auth.json"))
        if not auth_path.exists():
            raise RuntimeError(f"missing codex auth file {auth_path}")
        data = json.loads(auth_path.read_text(encoding="utf-8"))
        tokens = data.get("tokens") or {}
        if tokens.get("access_token") and tokens.get("account_id"):
            return {
                "Authorization": "Bearer " + str(tokens["access_token"]),
                "ChatGPT-Account-ID": str(tokens["account_id"]),
                "OAI-Product-Sku": "codex",
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
            }
        token = data.get("access_token") or data.get("id_token") or data.get("token")
        if not token:
            # Some Codex builds store token under nested account keys.
            for value in data.values():
                if isinstance(value, dict):
                    token = value.get("access_token") or value.get("id_token") or value.get("token")
                    if token:
                        break
        if not token:
            raise RuntimeError("missing codex auth token")
        return {
            "Authorization": "Bearer " + str(token),
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        }

    def _require_ready(self) -> None:
        self._auth_headers()
        if not self.model:
            raise RuntimeError("missing model")

    def complete_json(self, prompt: str, system: str = "", timeout: Optional[float] = None) -> LLMResponse:
        self._require_ready()
        instructions = system or "只输出一个有效 JSON 对象。"
        body = {
            "model": self.model,
            "instructions": instructions,
            "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": prompt}]}],
            "tools": [],
            "tool_choice": "none",
            "parallel_tool_calls": False,
            "reasoning": {"effort": self.config.get("reasoning_effort", "medium")},
            "store": False,
            "stream": True,
            "include": [],
        }
        req = urllib.request.Request(
            str(self.config.get("url") or CODEX_RESPONSES_URL),
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            method="POST",
            headers=self._auth_headers(),
        )
        chunks: List[str] = []
        usage: Dict[str, Any] = {}
        try:
            with urllib.request.urlopen(req, timeout=timeout or float(self.config.get("timeout_seconds", 180))) as resp:
                event_name = ""
                data_lines: List[str] = []
                for raw in resp:
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    if line:
                        if line.startswith("event:"):
                            event_name = line.split(":", 1)[1].strip()
                        elif line.startswith("data:"):
                            data_lines.append(line.split(":", 1)[1].lstrip())
                        continue
                    if not data_lines:
                        continue
                    payload = "\n".join(data_lines)
                    data_lines = []
                    if payload == "[DONE]":
                        break
                    try:
                        obj = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
                    typ = obj.get("type") or event_name
                    if typ == "response.output_text.delta":
                        chunks.append(str(obj.get("delta") or ""))
                    elif typ == "response.completed":
                        response = obj.get("response") or {}
                        usage = response.get("usage") or {}
                        if not chunks:
                            chunks.append(_extract_responses_output(response))
                        break
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"codex_direct HTTP {exc.code}: {body_text[:500]}") from exc
        return LLMResponse(text="".join(chunks), model=self.model, provider=self.name, usage=usage)


class LocalCliProvider(LLMProvider):
    """Subscription-backed local CLI provider, e.g. Claude Code or Codex CLI."""

    def _require_ready(self) -> None:
        if not self.config.get("command"):
            raise RuntimeError("missing command")
        cmd = list(self.config.get("command") or [])
        binary = str(cmd[0]) if cmd else ""
        if binary and "/" not in binary and "\\" not in binary and not shutil.which(binary):
            raise RuntimeError(f"command not found: {binary}")

    def complete_json(self, prompt: str, system: str = "", timeout: Optional[float] = None) -> LLMResponse:
        self._require_ready()
        cmd = list(self.config.get("command") or [])
        if not cmd:
            raise RuntimeError("empty command")
        full_prompt = (system.strip() + "\n\n" if system else "") + prompt
        env = os.environ.copy()
        env.setdefault("PYTHONIOENCODING", "utf-8")
        env.setdefault("PYTHONUTF8", "1")
        proc = subprocess.run(
            cmd,
            input=full_prompt,
            text=True,
            capture_output=True,
            timeout=timeout or float(self.config.get("timeout_seconds", 180)),
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout or f"cli exited {proc.returncode}")[:800])
        return LLMResponse(text=proc.stdout, model=self.model, provider=self.name, raw={"stderr": proc.stderr})


def provider_from_config(name: str, config: Mapping[str, Any]) -> LLMProvider:
    typ = str((config or {}).get("type") or "").lower()
    if typ in {"openai_compatible", "openai", "deepseek", "glm"}:
        return OpenAICompatibleProvider(name, config)
    if typ in {"anthropic", "claude_api"}:
        return AnthropicProvider(name, config)
    if typ in {"codex_direct", "codex_subscription"}:
        return CodexDirectProvider(name, config)
    if typ in {"local_cli", "claude_cli", "codex_cli", "claude_subscription"}:
        return LocalCliProvider(name, config)
    raise RuntimeError(f"unknown provider type {typ or '<empty>'}")


def _post_json(url: str, body: Mapping[str, Any], headers: Mapping[str, str], timeout: float) -> Dict[str, Any]:
    req = urllib.request.Request(
        url,
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        method="POST",
        headers=dict(headers),
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {body_text[:500]}") from exc


def _extract_responses_output(response: Mapping[str, Any]) -> str:
    chunks: List[str] = []
    for item in response.get("output") or []:
        for content in item.get("content") or []:
            if content.get("type") in {"output_text", "text"}:
                chunks.append(str(content.get("text") or ""))
    return "".join(chunks)
