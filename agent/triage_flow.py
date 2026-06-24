"""Agent triage orchestration primitives.

This module describes the new flow without forcing the legacy hourly task to
switch all at once. Callers can wrap one alert at a time and gradually replace
legacy branches.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, Mapping, Optional

from .policy import PolicyGuard
from .rules import CustomRuleStore
from .schemas import ActionPlan, AlertTask, EvidenceBundle, PolicyDecision, TriageVerdict


class AgentTriageFlow:
    """Conservative alert flow: rules/evidence/model/agent/policy."""

    def __init__(
        self,
        policy: Optional[PolicyGuard] = None,
        rules: Optional[CustomRuleStore] = None,
        evidence_loader: Optional[Callable[[AlertTask], EvidenceBundle]] = None,
        model_triage: Optional[Callable[[AlertTask, EvidenceBundle], TriageVerdict]] = None,
        agent_triage: Optional[Callable[[AlertTask, EvidenceBundle, TriageVerdict], TriageVerdict]] = None,
    ):
        self.policy = policy or PolicyGuard()
        self.rules = rules or CustomRuleStore()
        self.evidence_loader = evidence_loader
        self.model_triage = model_triage
        self.agent_triage = agent_triage

    def triage(self, alert: AlertTask) -> Dict[str, Any]:
        evidence = self._load_evidence(alert)
        matched_rule = self._match_custom_rule(alert)
        if matched_rule:
            verdict = self._verdict_from_rule(matched_rule)
            plan = self._plan_from_rule(alert, matched_rule)
            decision = self.policy.evaluate(alert, evidence, verdict, plan, matched_rule)
            return self._result(alert, evidence, verdict, plan, decision, matched_rule)

        verdict = self._model_triage(alert, evidence)
        if self._should_escalate(alert, evidence, verdict):
            verdict = self._agent_triage(alert, evidence, verdict)
        plan = self._plan_from_verdict(alert, verdict)
        decision = self.policy.evaluate(alert, evidence, verdict, plan)
        return self._result(alert, evidence, verdict, plan, decision, None)

    def _load_evidence(self, alert: AlertTask) -> EvidenceBundle:
        if self.evidence_loader:
            return self.evidence_loader(alert)
        return EvidenceBundle()

    def _match_custom_rule(self, alert: AlertTask) -> Optional[Dict[str, Any]]:
        matches = self.rules.matching_rules(alert)
        return matches[0] if matches else None

    def _verdict_from_rule(self, rule: Mapping[str, Any]) -> TriageVerdict:
        if rule.get("type") == "scanner_whitelist":
            return TriageVerdict("扫描探测", "高", "命中受控扫描源规则", source="custom_rule")
        if rule.get("action") == "block_ip" or rule.get("type") == "ip_blocklist":
            return TriageVerdict("需人工复核", "高", "命中待封禁 IP 规则", source="custom_rule")
        return TriageVerdict("业务误报", "高", "命中自定义业务误报规则", source="custom_rule")

    def _plan_from_rule(self, alert: AlertTask, rule: Mapping[str, Any]) -> ActionPlan:
        action = rule.get("action")
        if action == "skip_llm_and_omit":
            return ActionPlan.omit(alert.alert_id, "自定义规则命中,跳过模型并忽略")
        if action == "allow_scanner_ip":
            src_ip = alert.src_ips[0] if alert.src_ips else ""
            return ActionPlan(actions=[{
                "type": "allow_scanner_ip",
                "ip": src_ip,
                "trusted_source": bool(rule.get("trusted_source")),
                "reason": "自定义扫描源规则",
            }])
        if action == "omit_once":
            return ActionPlan.omit(alert.alert_id, "自定义规则仅忽略本次")
        if action == "block_ip":
            src_ip = alert.src_ips[0] if alert.src_ips else ""
            return ActionPlan(
                actions=[{
                    "type": "retain_for_review",
                    "ip": src_ip,
                    "reason": "命中待封禁 IP 规则,等待人工确认执行",
                }],
                requires_human=True,
                reason="封禁规则当前只做人工复核标记",
            )
        return ActionPlan(requires_human=True, reason="自定义规则只标注不自动处置")

    def _model_triage(self, alert: AlertTask, evidence: EvidenceBundle) -> TriageVerdict:
        if self.model_triage:
            return self.model_triage(alert, evidence)
        return TriageVerdict("需人工复核", "低", "未配置模型研判器", source="agent_flow_stub")

    def _agent_triage(self, alert: AlertTask, evidence: EvidenceBundle, verdict: TriageVerdict) -> TriageVerdict:
        if self.agent_triage:
            return self.agent_triage(alert, evidence, verdict)
        return verdict

    def _should_escalate(self, alert: AlertTask, evidence: EvidenceBundle, verdict: TriageVerdict) -> bool:
        if alert.level in {"高危", "严重", "High", "Critical"}:
            return True
        if verdict.result == "需人工复核":
            return True
        if not evidence.has_source_packet() and verdict.confidence in {"低", "low"}:
            return True
        return False

    def _plan_from_verdict(self, alert: AlertTask, verdict: TriageVerdict) -> ActionPlan:
        if verdict.result in {"确认未成功", "未见成功证据", "扫描探测", "业务误报"}:
            return ActionPlan.omit(alert.alert_id, verdict.result)
        return ActionPlan(requires_human=True, reason=verdict.result)

    def _result(
        self,
        alert: AlertTask,
        evidence: EvidenceBundle,
        verdict: TriageVerdict,
        plan: ActionPlan,
        decision: PolicyDecision,
        matched_rule: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        return {
            "alert": alert.compact_identity(),
            "verdict": verdict.to_judgement(),
            "plan": {"actions": plan.actions, "requires_human": plan.requires_human, "reason": plan.reason},
            "policy": {
                "allowed_actions": decision.allowed_actions,
                "blocked_actions": decision.blocked_actions,
                "requires_human": decision.requires_human,
                "reason": decision.reason,
            },
            "matched_rule": dict(matched_rule or {}),
            "evidence_summary": {
                "has_source_packet": evidence.has_source_packet(),
                "netflow_count": len(evidence.netflow),
                "related_alert_count": len(evidence.related_alerts),
                "memory_count": len(evidence.memory),
            },
        }
