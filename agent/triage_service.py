"""Dry-run service that wires the agent flow to existing CFW data sources."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from .policy import PolicyGuard
from .rules import CustomRuleStore
from .schemas import ActionPlan, AlertTask, EvidenceBundle, IGNORE_RESULTS, TriageVerdict
from .triage_flow import AgentTriageFlow


def _parse_source_packet(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {"raw": value[:2000]}
    return {}


def _row_without_private(row: Mapping[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in dict(row).items() if not str(k).startswith("_")}


def _evidence_from_row(row: Mapping[str, Any]) -> EvidenceBundle:
    return EvidenceBundle(source_packet=_parse_source_packet(row.get("源包证据")))


def _verdict_from_model_item(item: Mapping[str, Any], fallback_source: str) -> TriageVerdict:
    verdict = TriageVerdict.from_judgement(item)
    if not verdict.source:
        verdict.source = fallback_source
    return verdict


def _plan_for_verdict(alert: AlertTask, verdict: TriageVerdict) -> ActionPlan:
    if verdict.result in IGNORE_RESULTS:
        return ActionPlan.omit(alert.alert_id, verdict.result)
    return ActionPlan(
        actions=[{"type": "retain_for_review", "alert_id": alert.alert_id, "reason": verdict.result}],
        requires_human=True,
        reason=verdict.result,
    )


@dataclass
class AgentTriageService:
    """Preview one alert through rules, model/agent routing, and PolicyGuard.

    The service deliberately has no method that executes Tencent Cloud write
    APIs. Callers get a policy-scoped action preview and can decide whether an
    existing batch job should execute allowed actions later.
    """

    config: Mapping[str, Any]
    rules: Optional[CustomRuleStore] = None
    policy: Optional[PolicyGuard] = None

    def __post_init__(self) -> None:
        self.rules = self.rules or CustomRuleStore()
        self.policy = self.policy or PolicyGuard()

    def triage_alert_center_record(self, record: Mapping[str, Any], run_model: bool = True) -> Dict[str, Any]:
        import cfw_alert_center_triage as center

        labels = center.whitelist_labels(dict(self.config))
        row = center.record_to_judge_row(dict(record), labels, dict(self.config) if run_model else None)
        alert = AlertTask.from_alert_center_record(record)
        result = self._triage(alert, row, run_model=run_model)
        result["input_source"] = "alert_center_record"
        result["row"] = _row_without_private(row)
        return result

    def triage_judgement_row(self, row: Mapping[str, Any], run_model: bool = True) -> Dict[str, Any]:
        local_row = dict(row)
        alert = AlertTask.from_judgement_row(local_row)
        result = self._triage(alert, local_row, run_model=run_model)
        result["input_source"] = "judgement_row"
        result["row"] = _row_without_private(local_row)
        return result

    def triage_by_alert_id(self, alert_id: str, days: int = 7, live: bool = True, run_model: bool = True) -> Dict[str, Any]:
        alert_id = str(alert_id or "")
        if not alert_id:
            return {"error": "missing_alert_id"}
        if live:
            record = self._find_live_record(alert_id, days=days)
            if record:
                return self.triage_alert_center_record(record, run_model=run_model)
        row = self._find_report_row(alert_id, days=max(days, 60))
        if row:
            return self.triage_judgement_row(row, run_model=run_model)
        return {"error": "alert_not_found", "alert_id": alert_id}

    def _triage(self, alert: AlertTask, row: Mapping[str, Any], run_model: bool) -> Dict[str, Any]:
        evidence = _evidence_from_row(row)

        def evidence_loader(_: AlertTask) -> EvidenceBundle:
            return evidence

        def model_triage(_: AlertTask, __: EvidenceBundle) -> TriageVerdict:
            if not run_model:
                return TriageVerdict("需人工复核", "低", "预览未启用模型研判", source="dry_run_no_model")
            return self._model_triage_row(row)

        flow = AgentTriageFlow(
            policy=self.policy,
            rules=self.rules,
            evidence_loader=evidence_loader,
            model_triage=model_triage,
            agent_triage=None,
        )
        result = flow.triage(alert)
        result["dry_run"] = True
        result["would_execute"] = result.get("policy", {}).get("allowed_actions", [])
        result["blocked"] = result.get("policy", {}).get("blocked_actions", [])
        result["operator_message"] = self._operator_message(result)
        return result

    def _model_triage_row(self, row: Mapping[str, Any]) -> TriageVerdict:
        import cfw_alert_monitor as monitor

        local_row = dict(row)
        judgements = monitor.llm_judge_rows(dict(self.config), [local_row])
        key = monitor.judgement_key(local_row)
        item = judgements.get(key) or {}
        if not item:
            return TriageVerdict("需人工复核", "低", "模型未返回结构化结论", source="model_empty")
        return _verdict_from_model_item(item, "model_preview")

    def _find_live_record(self, alert_id: str, days: int) -> Optional[Dict[str, Any]]:
        try:
            import cfw_alert_center_triage as center

            records, _ = center.fetch_unhandled_alert_center(dict(self.config), days)
        except Exception:
            return None
        for record in records:
            rid = str(record.get("EventId") or record.get("AlertClusterId") or "")
            if rid == alert_id:
                return dict(record)
        return None

    def _find_report_row(self, alert_id: str, days: int) -> Optional[Dict[str, Any]]:
        try:
            import triage_stats

            rows = triage_stats.alerts(days, limit=5000)
        except Exception:
            return None
        for row in rows:
            if str(row.get("告警ID") or "") == alert_id:
                return dict(row)
        return None

    def _operator_message(self, result: Mapping[str, Any]) -> str:
        verdict = result.get("verdict") or {}
        policy = result.get("policy") or {}
        allowed = policy.get("allowed_actions") or []
        blocked = policy.get("blocked_actions") or []
        if blocked:
            return "策略闸拒绝自动处置,需要人工复核"
        if allowed:
            return "策略闸允许这些动作,当前接口仅做 dry-run 预览"
        if verdict.get("模型研判") == "需人工复核":
            return "没有可执行动作,保留人工研判"
        return "没有可执行动作"


def apply_policy_preview(alert: AlertTask, evidence: EvidenceBundle, verdict: TriageVerdict) -> Dict[str, Any]:
    """Small helper for tests and future APIs that only need PolicyGuard output."""

    plan = _plan_for_verdict(alert, verdict)
    decision = PolicyGuard().evaluate(alert, evidence, verdict, plan)
    return {
        "allowed_actions": decision.allowed_actions,
        "blocked_actions": decision.blocked_actions,
        "requires_human": decision.requires_human,
        "reason": decision.reason,
    }
