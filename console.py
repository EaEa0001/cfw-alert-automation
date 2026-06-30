"""CFW 研判控制台 — 本地 Web 看板。

用法:
    python console.py            # 默认 127.0.0.1:8787
    python console.py --port 9000 --host 0.0.0.0

数据来自 triage_stats(读 data/ 与 reports/ 的 jsonl),无数据库,刷新即最新。
默认只绑定本机回环,数据不出本机。
"""
import argparse
import configparser
import hashlib
import ipaddress
import json
import os
import re
import shlex
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, jsonify, request

import triage_stats as stats
from agent.llm.env import ai_env_path, load_ai_env_into_process, load_env_file, llm_env_status, save_ai_env_values
from agent.llm.router import LLMRouter, _parse_jsonish
from agent.rules import CustomRuleStore, llm_rule_parse_prompt, propose_rule_from_llm_parse, propose_rule_from_text
from agent.schemas import AlertTask
from agent.triage_service import AgentTriageService

app = Flask(__name__)
ROOT = Path(__file__).resolve().parent
TENCENT_ENV_KEYS = ("TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY", "TENCENTCLOUD_TOKEN")
LEGACY_WHITELIST_CANDIDATES = [
    {
        "ip": "210.22.92.182",
        "target": "company_scan_ips",
        "label": "公司 / 受控扫描源",
        "reason": "历史规则候选: 初始版本将该 IP 标记为 company_scan",
    },
]
MANUAL_ACTIONS_PATH = ROOT / "data" / "manual-actions.jsonl"
BLOCK_IP_CONFIRM_TOKEN = "CONFIRM_TENCENT_CFW_BLOCK"


@app.route("/")
def index():
    from flask import redirect
    return redirect("/soc/")


@app.route("/api/overview")
def api_overview():
    return jsonify(stats.overview(_days()))


@app.route("/api/trend")
def api_trend():
    return jsonify(stats.trend(_days()))


@app.route("/api/health")
def api_health():
    return jsonify(stats.health(_days()))


@app.route("/api/profiles")
def api_profiles():
    return jsonify(stats.profiles(_days()))


@app.route("/api/alerts")
def api_alerts():
    return jsonify(stats.alerts(
        _days(),
        level=request.args.get("level") or None,
        result=request.args.get("result") or None,
        source=request.args.get("source") or None,
        limit=int(request.args.get("limit", 300)),
    ))


@app.route("/api/attacker_rank")
def api_attacker_rank():
    return jsonify(stats.attacker_rank(_days()))


@app.route("/api/asset_rank")
def api_asset_rank():
    return jsonify(stats.asset_rank(_days()))


@app.route("/api/realtime")
def api_realtime():
    return jsonify(stats.realtime_attention(_days()))


@app.route("/api/pipeline")
def api_pipeline():
    return jsonify(stats.pipeline_status(_days(), _load_local_config()))


@app.route("/api/reports/summary")
def api_reports_summary():
    days = _days()
    alerts = stats.alerts(days, limit=500)
    key_alerts = [
        row for row in alerts
        if stats.requires_manual_attention(row)
    ][:12]
    return jsonify({
        "days": days,
        "generated_at": _now_text(),
        "overview": stats.overview(days),
        "trend": stats.trend(days),
        "health": stats.health(days),
        "attackers": stats.attacker_rank(days, limit=8),
        "assets": stats.asset_rank(days, limit=8),
        "profiles": stats.profiles(days, limit=6),
        "key_alerts": key_alerts,
        "recent_alerts": alerts[:12],
        "pipeline": stats.pipeline_status(days, _load_local_config()),
    })


@app.route("/api/asset_cards")
def api_asset_cards():
    return jsonify(stats.asset_cards(
        _days(),
        only_notable=request.args.get("all", "0") != "1",
    ))


@app.route("/api/agent/config")
def api_agent_config():
    config = _load_local_config()
    router = LLMRouter(config)
    llm = config.get("llm") or {}
    return jsonify({
        "model_routing": router.summary(),
        "provider_health": router.health(),
        "llm_settings": {
            "enabled": bool(llm.get("enabled", True)),
            "rule_parse": dict(llm.get("rule_parse") or {}),
            "routing": dict(router.routes),
            "providers": _sanitize_llm_providers(config),
            "env": llm_env_status(config, ROOT),
        },
        "tencent_auth": _tencent_auth_status(config),
        "agent": config.get("agent") or {},
    })


@app.route("/api/tencent/auth/config", methods=["POST"])
def api_tencent_auth_config_update():
    body = request.get_json(silent=True) or {}
    config = _load_local_config()

    if "region" in body:
        config["region"] = str(body.get("region") or "ap-shanghai").strip() or "ap-shanghai"
    if "endpoint" in body:
        config["endpoint"] = str(body.get("endpoint") or "cfw.tencentcloudapi.com").strip() or "cfw.tencentcloudapi.com"
    if "credential_profiles" in body:
        profiles = _parse_profiles(body.get("credential_profiles"))
        if profiles:
            config["credential_profiles"] = profiles

    secrets_update = body.get("secrets") if isinstance(body.get("secrets"), dict) else {}
    tencent_secrets = {
        key: value for key, value in secrets_update.items()
        if str(key) in TENCENT_ENV_KEYS
    }
    if tencent_secrets:
        try:
            save_ai_env_values(config, tencent_secrets, ROOT)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    _save_local_config(config)
    return jsonify({"ok": True, "tencent_auth": _tencent_auth_status(config)})


@app.route("/api/agent/providers/<provider_name>/test", methods=["POST"])
def api_agent_provider_test(provider_name):
    body = request.get_json(silent=True) or {}
    live = bool(body.get("live", False))
    try:
        timeout = max(3.0, min(120.0, float(body.get("timeout", 30))))
    except (TypeError, ValueError):
        timeout = 30.0
    result = LLMRouter(_load_local_config()).test_provider(provider_name, live=live, timeout=timeout)
    status = 200 if result.get("ok") else 400
    return jsonify(result), status


@app.route("/api/agent/providers/models", methods=["POST"])
def api_agent_provider_models():
    body = request.get_json(silent=True) or {}
    provider = body.get("provider") if isinstance(body.get("provider"), dict) else {}
    secrets = body.get("secrets") if isinstance(body.get("secrets"), dict) else {}
    config = _load_local_config()
    result = _fetch_provider_models(config, provider, secrets)
    return jsonify(result)


@app.route("/api/agent/llm/config", methods=["POST"])
def api_agent_llm_config_update():
    body = request.get_json(silent=True) or {}
    config = _load_local_config()
    llm = config.setdefault("llm", {})
    llm.setdefault("routing", {})
    llm.setdefault("providers", {})

    if "enabled" in body:
        llm["enabled"] = bool(body.get("enabled"))

    rule_parse_update = body.get("rule_parse") if isinstance(body.get("rule_parse"), dict) else None
    if rule_parse_update:
        current_rule_parse = dict(llm.get("rule_parse") or {})
        if "enabled" in rule_parse_update:
            current_rule_parse["enabled"] = bool(rule_parse_update.get("enabled"))
        if "timeout_seconds" in rule_parse_update:
            try:
                current_rule_parse["timeout_seconds"] = max(5, min(300, int(rule_parse_update.get("timeout_seconds"))))
            except (TypeError, ValueError):
                pass
        llm["rule_parse"] = current_rule_parse

    provider_update = body.get("provider") if isinstance(body.get("provider"), dict) else None
    if provider_update:
        name = str(provider_update.get("name") or "").strip()
        if not name:
            return jsonify({"error": "missing_provider_name"}), 400
        providers = llm.setdefault("providers", {})
        current = dict(providers.get(name) or {})
        allowed = {
            "type", "model", "base_url", "url", "api_key_env",
            "reasoning_effort", "timeout_seconds", "json_mode", "max_tokens",
            "anthropic_version", "command", "auth_path", "temperature",
        }
        for key, value in provider_update.items():
            key = str(key)
            if key == "name" or key not in allowed:
                continue
            if value in (None, ""):
                current.pop(key, None)
            elif key in {"timeout_seconds", "max_tokens"}:
                try:
                    current[key] = int(value)
                except (TypeError, ValueError):
                    continue
            elif key == "json_mode":
                current[key] = bool(value)
            elif key == "command":
                parsed = _parse_command_value(value)
                if parsed:
                    current[key] = parsed
                else:
                    current.pop(key, None)
            elif key == "temperature":
                try:
                    current[key] = float(value)
                except (TypeError, ValueError):
                    continue
            else:
                current[key] = str(value)
        providers[name] = current

    secrets_update = body.get("secrets") if isinstance(body.get("secrets"), dict) else None
    if secrets_update:
        try:
            save_ai_env_values(config, secrets_update, ROOT)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    routing_update = body.get("routing") if isinstance(body.get("routing"), dict) else None
    if routing_update:
        allowed_stages = {"batch_triage", "source_review", "agent_triage", "critical_review", "rule_parse"}
        providers = llm.get("providers") or {}
        for stage, provider in routing_update.items():
            stage = str(stage)
            provider = str(provider or "")
            if stage in allowed_stages and provider and provider in providers:
                llm["routing"][stage] = provider

    _save_local_config(config)
    router = LLMRouter(config)
    return jsonify({
        "ok": True,
        "model_routing": router.summary(),
        "provider_health": router.health(),
        "llm_settings": {
            "enabled": bool((config.get("llm") or {}).get("enabled", True)),
            "rule_parse": dict((config.get("llm") or {}).get("rule_parse") or {}),
            "routing": dict(router.routes),
            "providers": _sanitize_llm_providers(config),
            "env": llm_env_status(config, ROOT),
        },
    })


@app.route("/api/agent/rules")
def api_agent_rules():
    rules = _default_whitelist_rules(_load_local_config())
    rules.extend(CustomRuleStore().list_rules(include_inactive=True))
    return jsonify(rules)


@app.route("/api/agent/whitelist", methods=["GET", "POST"])
def api_agent_whitelist():
    config = _load_local_config()
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        config["tencent_scan_ips"] = _sanitize_ip_list(body.get("tencent_scan_ips"))
        config["company_scan_ips"] = _sanitize_ip_list(body.get("company_scan_ips"))
        _save_local_config(config)
    return jsonify(_whitelist_config_view(config))


@app.route("/api/agent/alerts")
def api_agent_alerts():
    return jsonify(stats.alerts(
        _days(),
        level=request.args.get("level") or None,
        result=request.args.get("result") or None,
        source=request.args.get("source") or None,
        limit=int(request.args.get("limit", 80)),
    ))


@app.route("/api/agent/rules/draft", methods=["POST"])
def api_agent_rule_draft():
    body = request.get_json(silent=True) or {}
    text = str(body.get("text") or "")
    alert = _alert_task_from_body(body)
    config = _load_local_config()
    default_days = _custom_rule_default_days(config)
    if bool(body.get("use_llm", False)):
        return jsonify(_propose_rule_with_llm(text, alert, config=config))
    return jsonify(propose_rule_from_text(text, alert, default_days=default_days))


@app.route("/api/agent/rules", methods=["POST"])
def api_agent_rule_save():
    body = request.get_json(silent=True) or {}
    rule = body.get("rule") or body
    activate = bool(body.get("activate", False))
    saved = CustomRuleStore().save_rule(rule, activate=activate)
    block_result = _auto_tencent_block_if_requested(saved, body)
    response = dict(saved)
    if block_result is not None:
        response["_tencent_block_result"] = block_result
    return jsonify(response)


@app.route("/api/agent/tencent/block-ip", methods=["POST"])
def api_agent_tencent_block_ip():
    import cfw_alert_center_triage as center

    body = request.get_json(silent=True) or {}
    rule = body.get("rule") if isinstance(body.get("rule"), dict) else {}
    ips = body.get("ips")
    if not isinstance(ips, list):
        ips = rule.get("ips") or (rule.get("match") or {}).get("src_ips") or []
    if not ips and body.get("text"):
        draft = propose_rule_from_text(str(body.get("text") or ""))
        if draft.get("action") == "block_ip":
            ips = draft.get("ips") or []
            rule = draft
    comment = str(body.get("comment") or rule.get("source_text") or "natural language block ip")
    dry_run = body.get("dry_run", True)
    wants_execute = dry_run is False or str(dry_run).strip().lower() in {"0", "false", "no", "off"}
    if wants_execute:
        return jsonify({
            "error": "manual_block_required",
            "status": "blocked",
            "reason": "平台不自动调用腾讯云封禁，请人工在腾讯云控制台执行",
        }), 403
    result = center.create_block_ip_rules(
        _load_local_config(),
        ips,
        comment=comment,
        dry_run=bool(dry_run),
        confirm_token=str(body.get("confirm") or ""),
    )
    status = 200 if not result.get("error") else 400
    return jsonify(result), status


@app.route("/api/agent/rules/<rule_id>/activate", methods=["POST"])
def api_agent_rule_activate(rule_id):
    body = request.get_json(silent=True) or {}
    item = CustomRuleStore().activate_rule(rule_id)
    if item:
        block_result = _auto_tencent_block_if_requested(item, body)
        if block_result is not None:
            item = dict(item)
            item["_tencent_block_result"] = block_result
    return (jsonify(item), 200) if item else (jsonify({"error": "rule_not_found"}), 404)


@app.route("/api/agent/rules/<rule_id>/disable", methods=["POST"])
def api_agent_rule_disable(rule_id):
    item = CustomRuleStore().disable_rule(rule_id)
    return (jsonify(item), 200) if item else (jsonify({"error": "rule_not_found"}), 404)


@app.route("/api/agent/triage/preview", methods=["POST"])
def api_agent_triage_preview():
    body = request.get_json(silent=True) or {}
    service = AgentTriageService(_load_local_config())
    run_model = bool(body.get("run_model", False))
    days = _body_days(body)
    if isinstance(body.get("record"), dict):
        result = service.triage_alert_center_record(body["record"], run_model=run_model)
    elif isinstance(body.get("row"), dict):
        result = service.triage_judgement_row(body["row"], run_model=run_model)
    else:
        result = service.triage_by_alert_id(
            str(body.get("alert_id") or ""),
            days=days,
            live=bool(body.get("live", False)),
            run_model=run_model,
        )
    status = 404 if result.get("error") else 200
    return jsonify(result), status


@app.route("/api/agent/alerts/<path:alert_id>/handle", methods=["POST"])
def api_agent_alert_handle(alert_id):
    body = request.get_json(silent=True) or {}
    action = str(body.get("action") or "").strip()
    row = _find_alert_row(alert_id)
    if not row:
        return jsonify({"error": "alert_not_found", "alert_id": alert_id}), 404

    try:
        result = _handle_alert_action(row, action, body)
    except ValueError as exc:
        return jsonify({"error": str(exc), "alert_id": alert_id}), 400
    status = 400 if result.get("error") else 200
    return jsonify(result), status


@app.route("/api/attack_graph")
def api_attack_graph():
    try:
        md = int(request.args.get("min_danger", 2))
    except (TypeError, ValueError):
        md = 2
    return jsonify(stats.attack_graph(
        _days(),
        focus=request.args.get("focus", "key"),
        min_danger=md,
        collapse_solo=request.args.get("collapse", "1") != "0",
        target=request.args.get("target") or None,
    ))


# ---- cfw-soc 大屏(Claude Design 版,静态文件在 screen/ 目录) ----
import os as _os
from flask import send_from_directory as _send

_SCREEN_DIR = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "screen")


@app.route("/soc")
def soc_redirect():
    from flask import redirect
    return redirect("/soc/")


@app.route("/soc/")
def soc_index():
    return _soc_response("index.html")


@app.route("/soc/<path:filename>")
def soc_static(filename):
    return _soc_response(filename)


def _soc_response(filename):
    resp = _send(_SCREEN_DIR, filename)
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


def _days():
    try:
        return max(1, min(60, int(request.args.get("days", 7))))
    except (TypeError, ValueError):
        return 7


def _body_days(body):
    try:
        return max(1, min(60, int(body.get("days", 7))))
    except (TypeError, ValueError):
        return 7


def _now_text():
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _load_local_config():
    for name in ("config.json", "config.example.json"):
        path = ROOT / name
        if not path.exists():
            continue
        try:
            config = json.loads(path.read_text(encoding="utf-8"))
            load_ai_env_into_process(config, ROOT)
            return config
        except Exception:
            continue
    return {"llm": {}}


def _save_local_config(config):
    path = ROOT / "config.json"
    path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _tencent_auth_status(config):
    load_ai_env_into_process(config, ROOT)
    env_path = ai_env_path(config, ROOT)
    env_values = load_env_file(env_path)
    keys = {
        key: {
            "present": bool(os.environ.get(key) or env_values.get(key)),
            "process": bool(os.environ.get(key)),
            "file": bool(env_values.get(key)),
        }
        for key in TENCENT_ENV_KEYS
    }
    tccli_profiles = _tccli_profile_status(config)
    env_ready = bool(keys["TENCENTCLOUD_SECRET_ID"]["present"] and keys["TENCENTCLOUD_SECRET_KEY"]["present"])
    tccli_ready = any(item.get("ready") for item in tccli_profiles)
    source = "env" if env_ready else ("tccli" if tccli_ready else "missing")
    return {
        "region": config.get("region", "ap-shanghai"),
        "endpoint": config.get("endpoint", "cfw.tencentcloudapi.com"),
        "credential_profiles": list(config.get("credential_profiles") or ["akonly", "default"]),
        "source": source,
        "ready": bool(env_ready or tccli_ready),
        "env": {
            "file": str(env_path),
            "keys": keys,
        },
        "tccli_profiles": tccli_profiles,
    }


def _tccli_profile_status(config):
    out = []
    tccli_dir = Path.home() / ".tccli"
    for profile in config.get("credential_profiles", ["akonly", "default"]):
        name = str(profile or "").strip()
        if not name:
            continue
        path = tccli_dir / f"{name}.credential"
        out.append({
            "name": name,
            "file": str(path),
            "exists": path.exists(),
            "ready": _tccli_file_has_secret_pair(path, name),
        })
    return out


def _tccli_file_has_secret_pair(path, profile):
    if not path.exists():
        return False
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if _json_has_secret_pair(value):
            return True
    except Exception:
        pass
    parser = configparser.ConfigParser()
    try:
        parser.read(path, encoding="utf-8")
    except Exception:
        return False
    sections = [profile] if profile in parser else parser.sections()
    for section in sections:
        values = parser[section]
        sid = values.get("secretId") or values.get("secret_id") or values.get("SecretId")
        sk = values.get("secretKey") or values.get("secret_key") or values.get("SecretKey")
        if sid and sk:
            return True
    return False


def _json_has_secret_pair(value):
    if not isinstance(value, dict):
        return False
    sid = value.get("secretId") or value.get("SecretId") or value.get("secret_id") or value.get("SecretID")
    sk = value.get("secretKey") or value.get("SecretKey") or value.get("secret_key")
    if sid and sk:
        return True
    return any(_json_has_secret_pair(child) for child in value.values())


def _parse_profiles(value):
    if isinstance(value, str):
        raw = value.replace(";", ",").replace("\n", ",").split(",")
    elif isinstance(value, (list, tuple)):
        raw = value
    else:
        raw = []
    profiles = []
    seen = set()
    for item in raw:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        profiles.append(text)
    return profiles


def _fetch_provider_models(config, provider, secrets):
    provider = dict(provider or {})
    typ = str(provider.get("type") or "").lower()
    model = str(provider.get("model") or "").strip()
    if typ in {"codex_direct", "codex_subscription", "local_cli", "claude_cli", "codex_cli", "claude_subscription"}:
        return {"ok": True, "provider_type": typ, "models": [model] if model else [], "source": "local_config"}

    api_key = _provider_api_key_for_fetch(config, provider, secrets)
    if not api_key:
        return {"ok": False, "error": "missing_api_key", "models": []}

    timeout = 12
    try:
        timeout = max(3, min(30, int(provider.get("timeout_seconds") or timeout)))
    except (TypeError, ValueError):
        pass

    try:
        if typ in {"anthropic", "claude_api"}:
            return _fetch_anthropic_models(provider, api_key, timeout)
        return _fetch_openai_compatible_models(provider, api_key, timeout)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:300]
        return {"ok": False, "error": f"http_{exc.code}", "detail": body, "models": []}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:300], "models": []}


def _provider_api_key_for_fetch(config, provider, secrets):
    env_name = str((provider or {}).get("api_key_env") or "").strip()
    if env_name and isinstance(secrets, dict) and secrets.get(env_name):
        return str(secrets.get(env_name) or "").strip()
    if isinstance(secrets, dict) and secrets.get("api_key"):
        return str(secrets.get("api_key") or "").strip()
    env_values = load_env_file(ai_env_path(config, ROOT))
    if env_name:
        return str(os.environ.get(env_name) or env_values.get(env_name) or "").strip()
    return ""


def _fetch_openai_compatible_models(provider, api_key, timeout):
    base_url = str(provider.get("base_url") or "https://api.openai.com/v1").rstrip("/")
    url = base_url + "/models"
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"Authorization": "Bearer " + api_key, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    models = _extract_model_ids(payload)
    return {"ok": True, "models": models, "source": url}


def _fetch_anthropic_models(provider, api_key, timeout):
    url = str(provider.get("models_url") or "https://api.anthropic.com/v1/models")
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "x-api-key": api_key,
            "anthropic-version": str(provider.get("anthropic_version") or "2023-06-01"),
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    models = _extract_model_ids(payload)
    return {"ok": True, "models": models, "source": url}


def _extract_model_ids(payload):
    data = payload.get("data") if isinstance(payload, dict) else payload
    if not isinstance(data, list):
        return []
    models = []
    seen = set()
    for item in data:
        model_id = item if isinstance(item, str) else (item or {}).get("id")
        model_id = str(model_id or "").strip()
        if not model_id or model_id in seen:
            continue
        seen.add(model_id)
        models.append(model_id)
    return models[:200]


def _parse_command_value(value):
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    text = str(value or "").strip()
    if not text:
        return []
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def _custom_rule_default_days(config):
    try:
        rules_config = (((config.get("agent") or {}).get("custom_rules") or {}))
        return max(1, min(365, int(rules_config.get("default_expire_days", 30))))
    except (TypeError, ValueError):
        return 30


def _sanitize_ip_list(values):
    out = []
    seen = set()
    if isinstance(values, str):
        raw_values = values.replace(",", "\n").replace(";", "\n").splitlines()
    elif isinstance(values, (list, tuple, set)):
        raw_values = values
    else:
        raw_values = []
    for raw in raw_values:
        text = str(raw or "").strip()
        if not text or text.startswith("#"):
            continue
        ip = text.split("#", 1)[0].strip()
        if not ip:
            continue
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if parsed.version != 4:
            continue
        ip_text = str(parsed)
        if ip_text not in seen:
            seen.add(ip_text)
            out.append(ip_text)
    return out


def _whitelist_config_view(config):
    tencent_ips = _sanitize_ip_list(config.get("tencent_scan_ips"))
    company_ips = _sanitize_ip_list(config.get("company_scan_ips"))
    existing = set(tencent_ips) | set(company_ips)
    candidates = [
        item for item in LEGACY_WHITELIST_CANDIDATES
        if item.get("ip") and item.get("ip") not in existing
    ]
    return {
        "tencent_scan_ips": tencent_ips,
        "company_scan_ips": company_ips,
        "whitelist_ips": sorted(set(tencent_ips) | set(company_ips)),
        "candidates": candidates,
        "counts": {
            "tencent_scan_ips": len(tencent_ips),
            "company_scan_ips": len(company_ips),
            "total": len(set(tencent_ips) | set(company_ips)),
            "candidates": len(candidates),
        },
    }


def _default_whitelist_rules(config):
    view = _whitelist_config_view(config)
    groups = [
        ("system_tencent_scan_whitelist", "腾讯云扫描源默认白名单", "tencent_scan_ips", view["tencent_scan_ips"]),
        ("system_company_scan_whitelist", "公司扫描源默认白名单", "company_scan_ips", view["company_scan_ips"]),
    ]
    rules = []
    for rule_id, title, config_key, ips in groups:
        if not ips:
            continue
        rules.append({
            "rule_id": rule_id,
            "type": "scanner_whitelist",
            "source_text": title,
            "match": {"src_ips": ips},
            "ips": ips,
            "action": "allow_scanner_ip",
            "scope": "default_scan_whitelist",
            "status": "active",
            "trusted_source": True,
            "requires_human_confirm": False,
            "expires_at": "",
            "created_at": "",
            "updated_at": "",
            "system": True,
            "readonly": True,
            "config_key": config_key,
        })
    return rules


def _sanitize_llm_providers(config):
    llm = config.get("llm") or {}
    providers = llm.get("providers") or {}
    if not providers:
        providers = LLMRouter(config).providers
    allowed = {
        "type", "model", "base_url", "url", "api_key_env",
        "reasoning_effort", "timeout_seconds", "json_mode", "max_tokens",
        "anthropic_version", "command", "auth_path", "temperature",
    }
    out = {}
    for name, cfg in providers.items():
        item = {}
        for key, value in dict(cfg or {}).items():
            if key in {"api_key", "access_token", "secret_key", "secret_id"}:
                continue
            if key in allowed:
                item[key] = value
        out[str(name)] = item
    return out


def _auto_tencent_block_if_requested(rule, body):
    if not bool((body or {}).get("auto_tencent_block")):
        return None
    if str((rule or {}).get("action") or "") != "block_ip":
        return {"status": "skipped", "reason": "rule_action_not_block_ip"}
    return {
        "status": "skipped",
        "reason": "manual_block_required",
        "message": "平台不自动调用腾讯云封禁，请人工在腾讯云控制台执行",
    }


def _propose_rule_with_llm(text, alert, config=None):
    config = config or _load_local_config()
    default_days = _custom_rule_default_days(config)
    fallback = propose_rule_from_text(text, alert=alert, default_days=default_days)
    llm = config.get("llm") or {}
    rule_parse = llm.get("rule_parse") or {}
    if not bool(llm.get("enabled", True)) or rule_parse.get("enabled") is False:
        fallback["parser"] = "heuristic"
        fallback.setdefault("notes", []).append("LLM规则解析未启用,已使用本地解析")
        return fallback

    try:
        system, prompt = llm_rule_parse_prompt(text, alert)
        timeout = max(5.0, min(300.0, float(rule_parse.get("timeout_seconds", 90))))
        response = LLMRouter(config).complete_json("rule_parse", prompt, system=system, timeout=timeout)
        parsed = _parse_jsonish(response.text)
        if not parsed:
            raise RuntimeError("llm_rule_parse_empty_json")
        draft = propose_rule_from_llm_parse(parsed, text, alert=alert, default_days=default_days)
        draft["llm_provider"] = response.provider
        draft["llm_model"] = response.model
        draft["llm_usage"] = response.usage
        return draft
    except Exception as exc:
        fallback["parser"] = "heuristic"
        fallback["llm_error"] = str(exc)[:500]
        fallback.setdefault("notes", []).append("LLM解析失败,已回退本地规则解析")
        return fallback


def _find_alert_row(alert_id):
    alert_id = str(alert_id or "")
    if not alert_id:
        return None
    for row in stats.alerts(60, limit=10000):
        if str(row.get("告警ID") or "") == alert_id:
            return row
    return None


def _split_first(value):
    for item in re.split(r"[|,\s]+", str(value or "")):
        item = item.strip()
        if item:
            return item
    return ""


def _ips_from_row_values(*values):
    ips = []
    seen = set()
    for value in values:
        for item in re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", str(value or "")):
            if item in seen:
                continue
            seen.add(item)
            ips.append(item)
    return ips


def _is_global_ipv4(value):
    try:
        ip = ipaddress.ip_address(str(value or "").strip())
        return ip.version == 4 and ip.is_global
    except ValueError:
        return False


def _alert_match(row):
    rule_id = _split_first(row.get("规则ID"))
    src_ip = _split_first(row.get("攻击IP") or row.get("源IP"))
    dst_ip = _split_first(row.get("目标IP"))
    return {
        "event_name": row.get("事件名称", ""),
        "rule_id": rule_id,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "direction": str(row.get("方向") or ""),
    }


def _rule_expires(days=30):
    try:
        days = max(1, min(365, int(days)))
    except (TypeError, ValueError):
        days = 30
    return (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


def _manual_action_id(entry):
    raw = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "ma_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _append_manual_action(entry):
    entry = dict(entry)
    entry.setdefault("created_at", _now_text())
    entry.setdefault("operator", "console")
    entry.setdefault("status", "handled")
    entry.setdefault("status_label", "已处理")
    entry["action_id"] = _manual_action_id(entry)
    MANUAL_ACTIONS_PATH.parent.mkdir(exist_ok=True)
    with MANUAL_ACTIONS_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
    return entry


def _action_response(row, entry, rule=None, tencent_block=None):
    alert_id = row.get("告警ID", "")
    refreshed = _find_alert_row(alert_id) or row
    response = {
        "ok": not bool(entry.get("error")),
        "alert_id": alert_id,
        "action": entry,
        "alert": refreshed,
    }
    if rule is not None:
        response["rule"] = rule
    if tencent_block is not None:
        response["tencent_block"] = tencent_block
    if entry.get("error"):
        response["error"] = entry["error"]
    return response


def _handle_alert_action(row, action, body):
    alert_id = str(row.get("告警ID") or "")
    note = str(body.get("note") or "").strip()
    days = body.get("days", 30)
    snapshot = {
        "time": row.get("告警时间", ""),
        "level": row.get("告警等级", ""),
        "event": row.get("事件名称", ""),
        "result": row.get("模型研判", ""),
        "reason": row.get("研判理由", ""),
        "key_evidence": row.get("关键证据", ""),
        "source": row.get("攻击IP", ""),
        "target": row.get("目标IP", ""),
        "asset": row.get("目标资产", ""),
    }

    if action == "reopen":
        entry = _append_manual_action({
            "alert_id": alert_id,
            "action": action,
            "action_label": "撤销处理",
            "status": "reopened",
            "status_label": "已撤销",
            "note": note,
            "alert_snapshot": snapshot,
        })
        return _action_response(row, entry)

    if action == "mark_handled":
        entry = _append_manual_action({
            "alert_id": alert_id,
            "action": action,
            "action_label": "人工确认已处理",
            "status": "handled",
            "status_label": "已处理",
            "note": note or "人工确认已完成线下处置",
            "alert_snapshot": snapshot,
        })
        return _action_response(row, entry)

    if action == "block_source":
        candidates = _ips_from_row_values(
            body.get("target_ip"),
            row.get("处置对象"),
            row.get("真实攻击源"),
            row.get("攻击IP"),
        )
        target_ip = next((ip for ip in candidates if _is_global_ipv4(ip)), "")
        if not target_ip:
            raise ValueError("no_public_disposition_ip")
        comment = f"CFW待人工封禁 {alert_id} {row.get('事件名称', '')}"[:120]
        rule = {
            "type": "ip_blocklist",
            "source_text": comment,
            "match": {"src_ips": [target_ip]},
            "ips": [target_ip],
            "action": "block_ip",
            "scope": "ip_list",
            "status": "draft",
            "trusted_source": False,
            "requires_human_confirm": True,
            "expires_at": _rule_expires(days),
            "created_at": _now_text(),
            "notes": ["由告警研判台登记封禁建议；平台不自动调用腾讯云，请人工到腾讯云执行"],
        }
        saved = CustomRuleStore().save_rule(rule, activate=False)
        entry = _append_manual_action({
            "alert_id": alert_id,
            "action": action,
            "action_label": "待人工封禁",
            "status": "pending",
            "status_label": "待人工",
            "target_ip": target_ip,
            "rule_id": saved.get("rule_id", ""),
            "note": note or "已登记封禁对象，需人工到腾讯云执行；完成后点标记已处理",
            "alert_snapshot": snapshot,
        })
        return _action_response(row, entry, rule=saved)

    if action == "false_positive":
        match = {k: v for k, v in _alert_match(row).items() if v}
        rule = {
            "type": "trusted_false_positive",
            "source_text": f"告警 {alert_id} 人工确认业务误报",
            "match": match,
            "action": "skip_llm_and_omit",
            "scope": "same_src_same_dst_same_rule",
            "status": "active",
            "trusted_source": True,
            "requires_human_confirm": False,
            "expires_at": _rule_expires(days),
            "created_at": _now_text(),
            "notes": ["由告警研判台一键标记误报创建，按源IP+目标IP+规则ID+事件名窄匹配"],
        }
        saved = CustomRuleStore().save_rule(rule, activate=True)
        entry = _append_manual_action({
            "alert_id": alert_id,
            "action": action,
            "action_label": "业务误报加白",
            "status": "handled",
            "status_label": "已处理",
            "rule_id": saved.get("rule_id", ""),
            "note": note or "已创建业务误报白名单规则",
            "alert_snapshot": snapshot,
        })
        return _action_response(row, entry, rule=saved)

    if action == "scanner_whitelist":
        candidates = _ips_from_row_values(body.get("target_ip"), row.get("真实攻击源"), row.get("攻击IP"))
        src_ip = candidates[0] if candidates else ""
        if not src_ip:
            raise ValueError("missing_scanner_ip")
        rule = {
            "type": "scanner_whitelist",
            "source_text": f"告警 {alert_id} 人工确认受控扫描源",
            "match": {"src_ip": src_ip},
            "ips": [src_ip],
            "action": "allow_scanner_ip",
            "scope": "same_src_ip",
            "status": "active",
            "trusted_source": True,
            "requires_human_confirm": False,
            "expires_at": _rule_expires(days),
            "created_at": _now_text(),
            "notes": ["由告警研判台一键扫描源白名单创建"],
        }
        saved = CustomRuleStore().save_rule(rule, activate=True)
        entry = _append_manual_action({
            "alert_id": alert_id,
            "action": action,
            "action_label": "扫描源白名单",
            "status": "handled",
            "status_label": "已处理",
            "target_ip": src_ip,
            "rule_id": saved.get("rule_id", ""),
            "note": note or "已创建扫描源白名单规则",
            "alert_snapshot": snapshot,
        })
        return _action_response(row, entry, rule=saved)

    raise ValueError("unknown_action")


def _find_alert_task(alert_id):
    if not alert_id:
        return None
    for row in stats.alerts(60, limit=2000):
        if str(row.get("告警ID") or "") == str(alert_id):
            return AlertTask.from_judgement_row(row)
    return None


def _alert_task_from_body(body):
    alert = body.get("alert")
    if isinstance(alert, dict):
        return AlertTask.from_judgement_row(alert)
    row = body.get("row")
    if isinstance(row, dict):
        return AlertTask.from_judgement_row(row)
    record = body.get("record")
    if isinstance(record, dict):
        return AlertTask.from_alert_center_record(record)
    alert_id = str(body.get("alert_id") or "")
    return _find_alert_task(alert_id) if alert_id else None



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CFW 研判控制台 Web 服务")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    print(f"CFW 研判控制台: http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)
