"""Shared data contracts for agentized CFW triage."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional


TRIAGE_RESULTS = {
    "确认成功",
    "确认未成功",
    "未见成功证据",
    "扫描探测",
    "业务误报",
    "需人工复核",
}

IGNORE_RESULTS = {"确认未成功", "未见成功证据", "扫描探测", "业务误报"}


def _compact_join(values: Iterable[Any], limit: int = 12) -> str:
    items = [str(v) for v in values or [] if str(v)]
    if len(items) <= limit:
        return "|".join(items)
    return "|".join(items[:limit]) + f"|...+{len(items) - limit}"


def _first_present(record: Mapping[str, Any], *keys: str, default: str = "") -> str:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return str(value)
    return default


def normalize_level(value: Any) -> str:
    mapping = {"High": "高危", "Middle": "中危", "Low": "低危"}
    return mapping.get(value, mapping.get(str(value), str(value or "")))


def normalize_attack_result(value: Any) -> str:
    mapping = {
        0: "未知",
        1: "攻击成功",
        2: "攻击失败",
        3: "尝试/探测",
        "0": "未知",
        "1": "攻击成功",
        "2": "攻击失败",
        "3": "尝试/探测",
    }
    return mapping.get(value, str(value or ""))


@dataclass
class AlertTask:
    """Normalized alert unit consumed by the agent flow."""

    alert_id: str
    event_name: str
    level: str
    attack_result: str = ""
    src_ips: List[str] = field(default_factory=list)
    dst_ips: List[str] = field(default_factory=list)
    rule_ids: List[str] = field(default_factory=list)
    direction: str = ""
    start_time: str = ""
    end_time: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_alert_center_record(cls, record: Mapping[str, Any]) -> "AlertTask":
        """Build an AlertTask from Tencent CFW Alert Center API fields."""

        src_ips = [str(x) for x in (record.get("SrcIpList") or []) if str(x)]
        dst_ips = [str(x) for x in (record.get("DstIpList") or []) if str(x)]
        rule_ids = [str(x) for x in (record.get("RuleIdList") or []) if str(x)]
        return cls(
            alert_id=_first_present(record, "EventId", "AlertClusterId", "告警ID"),
            event_name=_first_present(record, "EventName", "事件名称"),
            level=normalize_level(_first_present(record, "Level", "告警等级")),
            attack_result=normalize_attack_result(record.get("AttackResult", record.get("攻击结果", ""))),
            src_ips=src_ips,
            dst_ips=dst_ips,
            rule_ids=rule_ids,
            direction=_first_present(record, "Direction", "方向"),
            start_time=_first_present(record, "StartTime", "开始时间"),
            end_time=_first_present(record, "EndTime", "告警时间", "结束时间"),
            raw=dict(record),
        )

    @classmethod
    def from_judgement_row(cls, row: Mapping[str, Any]) -> "AlertTask":
        """Build an AlertTask from the local judgement row shape."""

        return cls(
            alert_id=_first_present(row, "告警ID"),
            event_name=_first_present(row, "事件名称"),
            level=normalize_level(_first_present(row, "告警等级")),
            attack_result=_first_present(row, "攻击结果"),
            src_ips=[x for x in str(row.get("攻击IP") or row.get("源IP") or "").split("|") if x],
            dst_ips=[x for x in str(row.get("目标IP") or "").split("|") if x],
            rule_ids=[x for x in str(row.get("规则ID") or "").split("|") if x],
            direction=_first_present(row, "方向"),
            end_time=_first_present(row, "告警时间"),
            raw=dict(row),
        )

    def compact_identity(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "event": self.event_name,
            "level": self.level,
            "attack_result": self.attack_result,
            "src": _compact_join(self.src_ips),
            "dst": _compact_join(self.dst_ips),
            "rules": _compact_join(self.rule_ids),
            "direction": self.direction,
            "time": self.end_time or self.start_time,
        }


@dataclass
class EvidenceBundle:
    """Evidence assembled before model or agent judgement."""

    source_packet: Dict[str, Any] = field(default_factory=dict)
    netflow: List[Dict[str, Any]] = field(default_factory=list)
    assets: Dict[str, Any] = field(default_factory=dict)
    related_alerts: List[Dict[str, Any]] = field(default_factory=list)
    memory: List[Dict[str, Any]] = field(default_factory=list)
    custom_rules: List[Dict[str, Any]] = field(default_factory=list)

    def has_source_packet(self) -> bool:
        ev = self.source_packet or {}
        return bool(ev.get("req") or ev.get("resp") or ev.get("resp_body") or ev.get("cmd") or ev.get("flow"))

    def to_model_payload(self) -> Dict[str, Any]:
        return {
            "source_packet": self.source_packet,
            "netflow": self.netflow[:20],
            "assets": self.assets,
            "related_alerts": self.related_alerts[:20],
            "memory": self.memory[:10],
            "custom_rules": self.custom_rules[:10],
        }


@dataclass
class TriageVerdict:
    result: str
    confidence: str = "中"
    reason: str = ""
    key_evidence: str = ""
    next_step: str = ""
    source: str = ""
    model: str = ""
    tool_trace: List[Dict[str, Any]] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_judgement(cls, item: Mapping[str, Any]) -> "TriageVerdict":
        return cls(
            result=str(item.get("模型研判") or item.get("result") or "需人工复核"),
            confidence=str(item.get("模型置信度") or item.get("confidence") or "中"),
            reason=str(item.get("研判理由") or item.get("evidence") or ""),
            key_evidence=str(item.get("关键证据") or item.get("key_evidence") or ""),
            next_step=str(item.get("下一步") or item.get("next") or ""),
            source=str(item.get("研判来源") or item.get("source") or ""),
            model=str(item.get("研判模型") or item.get("model") or ""),
            raw=dict(item),
        )

    def to_judgement(self) -> Dict[str, Any]:
        return {
            "模型研判": self.result,
            "模型置信度": self.confidence,
            "研判理由": self.reason,
            "关键证据": self.key_evidence,
            "下一步": self.next_step,
            "研判来源": self.source,
            "研判模型": self.model,
            "工具轨迹": ";".join(t.get("tool", "") for t in self.tool_trace if t.get("tool")),
        }


@dataclass
class ActionPlan:
    """Actions proposed by model/rules. PolicyGuard decides what may execute."""

    actions: List[Dict[str, Any]] = field(default_factory=list)
    requires_human: bool = False
    reason: str = ""

    @classmethod
    def omit(cls, alert_id: str, reason: str) -> "ActionPlan":
        return cls(actions=[{"type": "omit_alert", "alert_id": alert_id, "reason": reason}], reason=reason)


@dataclass
class PolicyDecision:
    allowed_actions: List[Dict[str, Any]] = field(default_factory=list)
    blocked_actions: List[Dict[str, Any]] = field(default_factory=list)
    requires_human: bool = False
    reason: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def allows(self, action_type: str) -> bool:
        return any(action.get("type") == action_type for action in self.allowed_actions)

