"""Custom safety rules and natural-language rule drafts."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .schemas import AlertTask


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
RULES_PATH = DATA_DIR / "custom-rules.jsonl"

EVENT_ID_RE = re.compile(
    r"(?:事件|告警)\s*(?:编号|ID|id)?\s*[:：#]?\s*([A-Za-z0-9_.:-]{6,})"
    r"|(?:编号|ID|id)\s*[:：#]\s*([A-Za-z0-9_.:-]{6,})"
)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
BLOCK_WORDS = ("封禁", "拉黑", "黑名单", "阻断", "禁止访问", "block", "ban", "deny")
SCANNER_WORDS = ("漏扫", "扫描器", "扫描源", "腾讯云扫描", "公司扫描")
TRUSTED_SCANNER_WORDS = ("公司", "腾讯云", "漏扫", "受控")
FUTURE_WORDS = ("以后", "同类", "不研判", "直接加白", "一直", "下次")
ONCE_WORDS = ("只忽略本次", "本次", "这条")
ALLOWED_MATCH_FIELDS = {"alert_id", "source_alert_id", "event_name", "direction", "rule_id", "src_ip", "dst_ip", "src_ips", "dst_ips"}


def _now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _expires(days: int) -> str:
    return (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


def _rule_id(seed: Mapping[str, Any]) -> str:
    raw = json.dumps(seed, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "cr_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def _valid_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(str(value or "")).version == 4
    except ValueError:
        return False


def _ip_list_from_text(text: str) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in IPV4_RE.findall(str(text or "")):
        if item in seen or not _valid_ipv4(item):
            continue
        seen.add(item)
        out.append(item)
    return out


def _event_id_from_text(text: str) -> str:
    for m in EVENT_ID_RE.finditer(str(text or "")):
        for value in m.groups():
            if value and not _valid_ipv4(value):
                return value
    return ""


def _contains_any(text: str, words: Iterable[str]) -> bool:
    value = str(text or "").lower()
    return any(w.lower() in value for w in words)


def _match_from_alert(alert: Optional[AlertTask], event_id: str = "") -> Dict[str, Any]:
    if not alert:
        return {"alert_id": event_id} if event_id else {}
    return {
        "event_name": alert.event_name,
        "rule_id": alert.rule_ids[0] if alert.rule_ids else "",
        "src_ip": alert.src_ips[0] if alert.src_ips else "",
        "dst_ip": alert.dst_ips[0] if alert.dst_ips else "",
        "direction": alert.direction,
    }


def _block_draft(text: str, ips: List[str], default_days: int) -> Dict[str, Any]:
    draft = {
        "type": "ip_blocklist",
        "source_text": text,
        "match": {"src_ips": ips},
        "ips": ips,
        "action": "block_ip",
        "scope": "ip_list",
        "status": "draft",
        "trusted_source": False,
        "requires_human_confirm": True,
        "expires_at": _expires(default_days),
        "created_at": _now_text(),
        "notes": [
            "已解析为封禁草案,保存草案不会下发防火墙策略",
            "确认生效前需要确认封禁位置、方向、优先级和回滚策略",
        ],
    }
    draft["rule_id"] = _rule_id(draft)
    return draft


def llm_rule_parse_prompt(text: str, alert: Optional[AlertTask] = None) -> tuple[str, str]:
    """Build a strict JSON prompt for LLM-assisted rule parsing."""

    context = alert.compact_identity() if alert else {}
    system = (
        "你是云防火墙 SOC 的自然语言规则解析器。"
        "你只把操作员输入解析成 JSON 意图,绝不声称已经执行动作。"
        "只允许以下 intent: skip_llm_and_omit, omit_once, allow_scanner_ip, block_ip, unknown。"
        "不要输出 Markdown,只输出一个 JSON 对象。"
    )
    payload = {
        "operator_text": str(text or ""),
        "selected_alert": context,
        "allowed_schema": {
            "intent": "skip_llm_and_omit|omit_once|allow_scanner_ip|block_ip|unknown",
            "scope": "single_alert|same_src_ip|same_src_same_dst_same_rule|ip_list",
            "event_id": "optional selected EventId/告警ID",
            "ips": ["optional IPv4 list for scanner/block rules"],
            "trusted_source": "boolean, only true for explicit company/tencent/controlled scanner wording",
            "match": {
                "alert_id": "optional",
                "event_name": "optional",
                "rule_id": "optional",
                "src_ip": "optional",
                "dst_ip": "optional",
                "direction": "optional",
            },
            "confidence": "high|medium|low",
            "reason": "short Chinese reason",
        },
        "intent_guidance": [
            "封禁、拉黑、加入黑名单、阻断来源 => block_ip。",
            "公司漏扫、受控扫描源、腾讯云扫描源 => allow_scanner_ip。",
            "正常业务、误报、以后同类不研判、直接加白 => skip_llm_and_omit。",
            "只处理本次、只忽略这条 => omit_once。",
            "缺少关键对象且无法从 selected_alert 补齐时 => unknown。",
        ],
    }
    return system, json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "是", "受控", "可信"}


def _normalize_intent(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"block_ip", "ip_blocklist", "blacklist", "blacklist_ip", "ban_ip", "deny_ip"}:
        return "block_ip"
    if any(word in text for word in ("封禁", "拉黑", "黑名单", "阻断", "block", "ban", "deny")):
        return "block_ip"
    if text in {"allow_scanner_ip", "scanner_whitelist", "scanner", "whitelist_scanner"}:
        return "allow_scanner_ip"
    if any(word in text for word in ("扫描源", "扫描器", "漏扫", "scanner")):
        return "allow_scanner_ip"
    if text in {"skip_llm_and_omit", "trusted_false_positive", "false_positive", "normal_business"}:
        return "skip_llm_and_omit"
    if any(word in text for word in ("不研判", "正常业务", "误报", "同类", "加白")):
        return "skip_llm_and_omit"
    if text in {"omit_once", "single_alert", "ignore_once"}:
        return "omit_once"
    if any(word in text for word in ("本次", "这条", "once")):
        return "omit_once"
    return "unknown"


def _ips_from_values(*values: Any) -> List[str]:
    out: List[str] = []
    seen = set()
    for value in values:
        for item in _as_list(value):
            candidates = _ip_list_from_text(str(item or ""))
            if not candidates and _valid_ipv4(str(item or "")):
                candidates = [str(item).strip()]
            for ip in candidates:
                if ip in seen:
                    continue
                seen.add(ip)
                out.append(ip)
    return out


def _ips_from_llm_parse(parsed: Mapping[str, Any], text: str, alert: Optional[AlertTask], allow_alert_context: bool = False) -> List[str]:
    match = parsed.get("match") if isinstance(parsed.get("match"), Mapping) else {}
    ips = _ips_from_values(
        parsed.get("ips"),
        parsed.get("ip_list"),
        parsed.get("src_ips"),
        parsed.get("src_ip"),
        match.get("src_ips"),
        match.get("src_ip"),
        text,
    )
    if not ips and allow_alert_context and alert and alert.src_ips:
        ips = [ip for ip in alert.src_ips if _valid_ipv4(ip)]
    return list(dict.fromkeys(ips))


def _clean_match(match: Any) -> Dict[str, Any]:
    if not isinstance(match, Mapping):
        return {}
    out: Dict[str, Any] = {}
    for key, value in match.items():
        key = str(key or "")
        if key not in ALLOWED_MATCH_FIELDS or value in (None, "", [], {}):
            continue
        if key in {"src_ips", "dst_ips"}:
            ips = _ips_from_values(value)
            if ips:
                out[key] = ips
        elif key in {"src_ip", "dst_ip"}:
            ips = _ips_from_values(value)
            if ips:
                out[key] = ips[0]
        elif key in {"alert_id", "source_alert_id"} and _valid_ipv4(str(value)):
            continue
        else:
            out[key] = str(value)
    return out


def _safe_llm_parse(parsed: Mapping[str, Any]) -> Dict[str, Any]:
    allowed = {"intent", "action", "type", "scope", "event_id", "ips", "ip_list", "trusted_source", "confidence", "reason", "match"}
    out = {str(k): v for k, v in dict(parsed or {}).items() if str(k) in allowed}
    if "match" in out:
        out["match"] = _clean_match(out["match"])
    if "ips" in out:
        out["ips"] = _ips_from_values(out["ips"])[:200]
    if "ip_list" in out:
        out["ip_list"] = _ips_from_values(out["ip_list"])[:200]
    return out


def _annotate_llm_draft(draft: Dict[str, Any], parsed: Mapping[str, Any], intent: str) -> Dict[str, Any]:
    draft = dict(draft)
    notes = list(draft.get("notes") or [])
    notes.append("LLM解析结果已由本地允许动作和匹配字段白名单收敛")
    draft["notes"] = notes
    draft["parser"] = "llm"
    draft["llm_intent"] = intent
    draft["llm_confidence"] = str(parsed.get("confidence") or "")
    draft["parse_reason"] = str(parsed.get("reason") or "")[:240]
    draft["llm_parse"] = _safe_llm_parse(parsed)
    return draft


def propose_rule_from_llm_parse(
    parsed: Mapping[str, Any],
    text: str,
    alert: Optional[AlertTask] = None,
    default_days: int = 30,
) -> Dict[str, Any]:
    """Normalize LLM parser output into the same conservative rule draft shape."""

    parsed = dict(parsed or {})
    text = str(text or "").strip()
    intent = _normalize_intent(parsed.get("intent") or parsed.get("action") or parsed.get("type"))
    if intent == "unknown":
        draft = propose_rule_from_text(text, alert=alert, default_days=default_days)
        draft["parser"] = "heuristic"
        draft["llm_intent"] = "unknown"
        draft["llm_parse"] = _safe_llm_parse(parsed)
        draft.setdefault("notes", []).append("LLM未能确认意图,已回退本地保守解析")
        return draft

    if intent == "block_ip":
        ips = _ips_from_llm_parse(parsed, text, alert, allow_alert_context=True)
        if ips:
            return _annotate_llm_draft(_block_draft(text, ips, default_days), parsed, intent)

    event_id = str(parsed.get("event_id") or _event_id_from_text(text) or "")
    if _valid_ipv4(event_id):
        event_id = ""
    llm_match = _clean_match(parsed.get("match"))

    if intent == "allow_scanner_ip":
        ips = _ips_from_llm_parse(parsed, text, alert, allow_alert_context=True)
        match = {"src_ip": ips[0]} if ips else {}
        trusted_source = _truthy(parsed.get("trusted_source")) or _contains_any(text, TRUSTED_SCANNER_WORDS)
        draft = {
            "type": "scanner_whitelist",
            "source_text": text,
            "match": match,
            "action": "allow_scanner_ip",
            "scope": "same_src_ip",
            "status": "draft",
            "trusted_source": trusted_source,
            "requires_human_confirm": True,
            "expires_at": _expires(default_days),
            "created_at": _now_text(),
            "notes": [],
        }
        if not draft["match"]:
            draft["notes"].append("未解析到扫描源IP,需要先选择一条告警或补充IP")
        if not trusted_source:
            draft["notes"].append("扫描源加白需要明确这是受控扫描源")
        draft["rule_id"] = _rule_id(draft)
        return _annotate_llm_draft(draft, parsed, intent)

    match = llm_match or _match_from_alert(alert, event_id=event_id)
    if event_id and "alert_id" not in match and "source_alert_id" not in match:
        match["source_alert_id"] = event_id
    action = "skip_llm_and_omit" if intent == "skip_llm_and_omit" else "omit_once"
    scope = str(parsed.get("scope") or "")
    if action == "skip_llm_and_omit":
        if scope not in {"same_src_same_dst_same_rule", "same_src_ip", "single_alert"}:
            scope = "same_src_same_dst_same_rule"
    else:
        scope = "single_alert"
    draft = {
        "type": "trusted_false_positive",
        "source_text": text,
        "match": {k: v for k, v in match.items() if v},
        "action": action,
        "scope": scope,
        "status": "draft",
        "trusted_source": False,
        "requires_human_confirm": True,
        "expires_at": _expires(default_days),
        "created_at": _now_text(),
        "notes": [],
    }
    if not draft["match"]:
        draft["notes"].append("未解析到事件编号或告警字段,需要先选择一条告警")
    if action == "skip_llm_and_omit":
        draft["notes"].append("未来规则默认按源IP+目标IP+规则ID+事件名窄匹配")
    draft["rule_id"] = _rule_id(draft)
    return _annotate_llm_draft(draft, parsed, intent)


def propose_rule_from_text(text: str, alert: Optional[AlertTask] = None, default_days: int = 30) -> Dict[str, Any]:
    """Convert an operator sentence into a conservative rule draft.

    This parser is intentionally narrow. A later LLM parser can enrich drafts,
    but persisted rules must still use the same structured fields.
    """

    text = str(text or "").strip()
    ips = _ip_list_from_text(text)
    if _contains_any(text, BLOCK_WORDS):
        if not ips and alert and alert.src_ips:
            ips = list(dict.fromkeys([ip for ip in alert.src_ips if _valid_ipv4(ip)]))
        if ips:
            return _block_draft(text, ips, default_days)

    event_id = _event_id_from_text(text)
    future = _contains_any(text, FUTURE_WORDS)
    scanner = _contains_any(text, SCANNER_WORDS)
    once_only = _contains_any(text, ONCE_WORDS) or not future

    action = "mark_false_positive"
    rule_type = "trusted_false_positive"
    scope = "single_alert"
    trusted_source = False
    requires_human_confirm = True

    if scanner:
        action = "allow_scanner_ip"
        rule_type = "scanner_whitelist"
        scope = "same_src_ip"
        trusted_source = _contains_any(text, TRUSTED_SCANNER_WORDS)
    elif future and not once_only:
        action = "skip_llm_and_omit"
        scope = "same_src_same_dst_same_rule"
    elif once_only:
        action = "omit_once"
        scope = "single_alert"

    match = _match_from_alert(alert, event_id=event_id)
    if scanner and not alert and ips and "src_ip" not in match:
        match["src_ip"] = ips[0]
    if event_id and "alert_id" not in match:
        match["source_alert_id"] = event_id

    draft = {
        "type": rule_type,
        "source_text": text,
        "match": {k: v for k, v in match.items() if v},
        "action": action,
        "scope": scope,
        "status": "draft",
        "trusted_source": trusted_source,
        "requires_human_confirm": requires_human_confirm,
        "expires_at": _expires(default_days),
        "created_at": _now_text(),
        "notes": [],
    }
    if not draft["match"]:
        draft["notes"].append("未解析到事件编号或告警字段,需要先选择一条告警")
    if action == "skip_llm_and_omit":
        draft["notes"].append("未来规则默认按源IP+目标IP+规则ID+事件名窄匹配")
    if action == "allow_scanner_ip" and not trusted_source:
        draft["notes"].append("扫描源加白需要明确这是受控扫描源")
    draft["rule_id"] = _rule_id(draft)
    return draft


def rule_active(rule: Mapping[str, Any], now: Optional[str] = None) -> bool:
    if rule.get("status") != "active":
        return False
    expires_at = str(rule.get("expires_at") or "")
    if not expires_at:
        return True
    return expires_at >= (now or _now_text())


def _matches_value(rule_value: Any, actual_values: Iterable[str]) -> bool:
    if not rule_value:
        return True
    actual = {str(v) for v in actual_values if str(v)}
    if isinstance(rule_value, (list, tuple, set)):
        return bool({str(v) for v in rule_value if str(v)} & actual)
    return str(rule_value) in actual


def rule_matches(rule: Mapping[str, Any], alert: AlertTask) -> bool:
    match = rule.get("match") or {}
    if not match:
        return False
    known_fields = {"alert_id", "source_alert_id", "event_name", "direction", "rule_id", "src_ip", "dst_ip", "src_ips", "dst_ips"}
    if not any(match.get(k) for k in known_fields):
        return False
    if match.get("alert_id") and match.get("alert_id") != alert.alert_id:
        return False
    if match.get("source_alert_id") and match.get("source_alert_id") != alert.alert_id:
        return False
    if match.get("event_name") and match.get("event_name") != alert.event_name:
        return False
    if match.get("direction") and str(match.get("direction")) != str(alert.direction):
        return False
    if not _matches_value(match.get("rule_id"), alert.rule_ids):
        return False
    if not _matches_value(match.get("src_ip"), alert.src_ips):
        return False
    if not _matches_value(match.get("src_ips"), alert.src_ips):
        return False
    if not _matches_value(match.get("dst_ip"), alert.dst_ips):
        return False
    if not _matches_value(match.get("dst_ips"), alert.dst_ips):
        return False
    return True


class CustomRuleStore:
    def __init__(self, path: Path = RULES_PATH):
        self.path = path

    def list_rules(self, include_inactive: bool = True) -> List[Dict[str, Any]]:
        rows = _read_jsonl(self.path)
        if include_inactive:
            return rows
        return [r for r in rows if rule_active(r)]

    def save_rule(self, rule: Mapping[str, Any], activate: bool = False) -> Dict[str, Any]:
        obj = dict(rule)
        obj.setdefault("rule_id", _rule_id(obj))
        obj.setdefault("created_at", _now_text())
        obj["updated_at"] = _now_text()
        if activate:
            obj["status"] = "active"
        rows = [r for r in self.list_rules(include_inactive=True) if r.get("rule_id") != obj["rule_id"]]
        rows.append(obj)
        _write_jsonl(self.path, rows)
        return obj

    def activate_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        rows = self.list_rules(include_inactive=True)
        out = None
        for row in rows:
            if row.get("rule_id") == rule_id:
                row["status"] = "active"
                row["updated_at"] = _now_text()
                out = row
        if out:
            _write_jsonl(self.path, rows)
        return out

    def disable_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        rows = self.list_rules(include_inactive=True)
        out = None
        for row in rows:
            if row.get("rule_id") == rule_id:
                row["status"] = "disabled"
                row["updated_at"] = _now_text()
                out = row
        if out:
            _write_jsonl(self.path, rows)
        return out

    def matching_rules(self, alert: AlertTask) -> List[Dict[str, Any]]:
        return [r for r in self.list_rules(include_inactive=False) if rule_matches(r, alert)]
