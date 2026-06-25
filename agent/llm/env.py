"""Shared AI provider environment-file helpers."""
from __future__ import annotations

import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any, Mapping, Optional


def ai_env_path(config: Mapping[str, Any], root: Optional[Path] = None) -> Path:
    agent_cfg = config.get("agent") or {}
    path = str(os.environ.get("CFW_AI_ENV_FILE") or agent_cfg.get("ai_env_file") or "").strip()
    if not path:
        base = Path(root) if root else Path.cwd()
        path = "/etc/cfw-ai.env" if sys.platform.startswith("linux") else str(base / ".env.ai")
    return Path(path)


def load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for line in lines:
        text = line.strip()
        if not text or text.startswith("#") or "=" not in text:
            continue
        key, value = text.split("=", 1)
        key = key.strip()
        if valid_env_key(key):
            values[key] = unquote_env_value(value.strip())
    return values


def load_ai_env_into_process(config: Mapping[str, Any], root: Optional[Path] = None) -> None:
    for key, value in load_env_file(ai_env_path(config, root)).items():
        if value and key not in os.environ:
            os.environ[key] = value


def llm_env_status(config: Mapping[str, Any], root: Optional[Path] = None) -> dict[str, Any]:
    llm = config.get("llm") or {}
    providers = llm.get("providers") or {}
    env_path = ai_env_path(config, root)
    env_values = load_env_file(env_path)
    tracked: set[str] = set()
    for provider in providers.values():
        key = str((provider or {}).get("api_key_env") or "").strip()
        if key:
            tracked.add(key)
    tracked.update(
        k for k in env_values
        if k.endswith("_API_KEY") or k in {"OPENAI_API_KEY", "DEEPSEEK_API_KEY", "GLM_API_KEY", "ANTHROPIC_API_KEY"}
    )
    return {
        "file": str(env_path),
        "keys": {
            key: {
                "present": bool(os.environ.get(key) or env_values.get(key)),
                "process": bool(os.environ.get(key)),
                "file": bool(env_values.get(key)),
            }
            for key in sorted(tracked)
        },
    }


def save_ai_env_values(config: Mapping[str, Any], values: Mapping[str, Any], root: Optional[Path] = None) -> None:
    path = ai_env_path(config, root)
    current = load_env_file(path)
    changed = False
    for raw_key, raw_value in values.items():
        key = str(raw_key or "").strip()
        if not key:
            continue
        if not valid_env_key(key):
            raise ValueError(f"invalid_env_key:{key}")
        value = str(raw_value or "").strip()
        if not value:
            continue
        current[key] = value
        os.environ[key] = value
        changed = True
    if not changed:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    content = ["# Managed by CFW SOC console. Do not commit this file."]
    for key in sorted(current):
        content.append(f"{key}={quote_env_value(current[key])}")
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("\n".join(content) + "\n", encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(path)


def valid_env_key(key: str) -> bool:
    return bool(re.fullmatch(r"[A-Z_][A-Z0-9_]*", str(key or "")))


def quote_env_value(value: str) -> str:
    text = str(value or "")
    return "'" + text.replace("'", "'\"'\"'") + "'"


def unquote_env_value(value: str) -> str:
    text = str(value or "")
    if (text.startswith("'") and text.endswith("'")) or (text.startswith('"') and text.endswith('"')):
        try:
            return shlex.split(text)[0]
        except (ValueError, IndexError):
            return text[1:-1]
    return text
