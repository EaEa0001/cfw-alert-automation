"""Local safety gate for all agent-proposed CFW actions."""
from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping, Optional

from .schemas import ActionPlan, AlertTask, EvidenceBundle, IGNORE_RESULTS, PolicyDecision, TriageVerdict


SUCCESS_RESULTS = {"确认成功"}
HIGH_LEVELS = {"高危", "严重", "High", "Critical"}
HIGH_SAFE_RESULTS = {"确认未成功", "扫描探测", "业务误报"}
SUCCESS_MARKS = {"git_ref", "passwd", "phpinfo", "cmd_uid", "index_of", "webshell"}
WRITE_ACTIONS = {"omit_alert", "allow_scanner_ip", "create_custom_rule", "skip_llm_and_omit", "block_ip"}


def _norm_conf(value: str) -> str:
    return {"high": "高", "medium": "中", "low": "低"}.get(str(value or "").lower(), str(value or ""))


def _mark_set(value: Any) -> set[str]:
    return {x.strip() for x in str(value or "").replace(";", ",").split(",") if x.strip()}


def has_success_evidence(evidence: EvidenceBundle | Mapping[str, Any]) -> bool:
    """Detect hard landing evidence from a standardized or raw evidence bundle."""

    if isinstance(evidence, EvidenceBundle):
        ev = evidence.source_packet or {}
    else:
        ev = dict(evidence or {})

    attack_result = str(ev.get("ar") or ev.get("attack_result") or "").lower()
    if any(word in attack_result for word in ("success", "succeed", "成功", "命中成功")):
        return True
    if ev.get("cmd"):
        return True
    if _mark_set(ev.get("resp_mark")) & SUCCESS_MARKS:
        return True
    body = str(ev.get("resp_body") or ev.get("resp") or "")
    body_lower = body.lower()
    return any(mark in body_lower for mark in ("uid=0", "phpinfo()", "index of /", "webshell", "/etc/passwd"))


def has_any_evidence(evidence: EvidenceBundle, verdict: Optional[TriageVerdict] = None) -> bool:
    if evidence.has_source_packet() or evidence.netflow or evidence.assets or evidence.related_alerts:
        return True
    return bool(verdict and verdict.key_evidence)


def is_high_risk(alert: AlertTask) -> bool:
    if alert.level in HIGH_LEVELS:
        return True
    attack_result = str(alert.attack_result or "")
    return attack_result in {"1", "攻击成功"} or "成功" in attack_result


class PolicyGuard:
    """Hard-coded action policy. Models can propose; this class decides."""

    def evaluate(
        self,
        alert: AlertTask,
        evidence: EvidenceBundle,
        verdict: TriageVerdict,
        plan: ActionPlan,
        matched_rule: Optional[Mapping[str, Any]] = None,
    ) -> PolicyDecision:
        decision = PolicyDecision(reason=plan.reason or verdict.reason)

        for action in plan.actions:
            checked = self._evaluate_action(alert, evidence, verdict, action, matched_rule)
            if checked.get("allowed"):
                allowed = dict(action)
                allowed["policy_reason"] = checked.get("reason", "")
                decision.allowed_actions.append(allowed)
            else:
                blocked = dict(action)
                blocked["policy_reason"] = checked.get("reason", "blocked_by_policy")
                decision.blocked_actions.append(blocked)

        decision.requires_human = (
            plan.requires_human
            or not decision.allowed_actions
            or bool(decision.blocked_actions)
            or self.must_retain(alert, evidence, verdict)
        )
        if decision.requires_human and not decision.reason:
            decision.reason = "需人工复核或策略拒绝自动处置"
        return decision

    def must_retain(self, alert: AlertTask, evidence: EvidenceBundle, verdict: TriageVerdict) -> bool:
        if verdict.result in SUCCESS_RESULTS:
            return True
        if str(alert.attack_result) in {"1", "攻击成功"}:
            return True
        if has_success_evidence(evidence):
            return True
        if alert.level in HIGH_LEVELS and verdict.result not in HIGH_SAFE_RESULTS:
            return True
        return False

    def _evaluate_action(
        self,
        alert: AlertTask,
        evidence: EvidenceBundle,
        verdict: TriageVerdict,
        action: Mapping[str, Any],
        matched_rule: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        action_type = str(action.get("type") or "")
        if action_type in {"notify", "write_memory", "retain_for_review"}:
            return {"allowed": True, "reason": "read_or_review_action"}
        if action_type == "omit_alert" or action_type == "skip_llm_and_omit":
            return self._can_omit(alert, evidence, verdict, matched_rule)
        if action_type == "allow_scanner_ip":
            return self._can_allow_scanner_ip(alert, verdict, action, matched_rule)
        if action_type == "create_custom_rule":
            return self._can_create_rule(alert, verdict, action)
        if action_type in WRITE_ACTIONS:
            return {"allowed": False, "reason": f"unsupported_write_action:{action_type}"}
        return {"allowed": False, "reason": f"unknown_action:{action_type}"}

    def _can_omit(
        self,
        alert: AlertTask,
        evidence: EvidenceBundle,
        verdict: TriageVerdict,
        matched_rule: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        if not alert.alert_id:
            return {"allowed": False, "reason": "missing_alert_id"}
        if verdict.result in SUCCESS_RESULTS:
            return {"allowed": False, "reason": "confirmed_success_never_omit"}
        if str(alert.attack_result) in {"1", "攻击成功"}:
            return {"allowed": False, "reason": "cloud_success_never_omit"}
        if has_success_evidence(evidence):
            return {"allowed": False, "reason": "landing_evidence_never_omit"}
        if verdict.result not in IGNORE_RESULTS:
            return {"allowed": False, "reason": f"result_not_auto_ignorable:{verdict.result}"}

        confidence = _norm_conf(verdict.confidence)
        if alert.level in HIGH_LEVELS:
            if verdict.result not in HIGH_SAFE_RESULTS:
                return {"allowed": False, "reason": "high_alert_unknown_outcome_retained"}
            if confidence == "低":
                return {"allowed": False, "reason": "high_alert_low_confidence_retained"}
            if not has_any_evidence(evidence, verdict):
                return {"allowed": False, "reason": "high_alert_requires_real_evidence"}

        if matched_rule and matched_rule.get("action") == "skip_llm_and_omit":
            if matched_rule.get("status") != "active":
                return {"allowed": False, "reason": "custom_rule_not_active"}
        return {"allowed": True, "reason": "safe_to_omit"}

    def _can_allow_scanner_ip(
        self,
        alert: AlertTask,
        verdict: TriageVerdict,
        action: Mapping[str, Any],
        matched_rule: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        trusted_source = bool(action.get("trusted_source")) or bool((matched_rule or {}).get("trusted_source"))
        if not trusted_source:
            return {"allowed": False, "reason": "scanner_whitelist_requires_trusted_source"}
        if verdict.result not in {"扫描探测", "业务误报"}:
            return {"allowed": False, "reason": "scanner_whitelist_requires_scan_or_fp"}
        if alert.level in HIGH_LEVELS:
            return {"allowed": False, "reason": "high_alert_scanner_whitelist_requires_manual"}
        return {"allowed": True, "reason": "trusted_scanner_whitelist"}

    def _can_create_rule(self, alert: AlertTask, verdict: TriageVerdict, action: Mapping[str, Any]) -> Dict[str, Any]:
        if verdict.result in SUCCESS_RESULTS or str(alert.attack_result) in {"1", "攻击成功"}:
            return {"allowed": False, "reason": "success_alert_cannot_seed_auto_rule"}
        if alert.level in HIGH_LEVELS and not action.get("requires_human_confirm", True):
            return {"allowed": False, "reason": "high_alert_rule_requires_human_confirm"}
        return {"allowed": True, "reason": "rule_draft_allowed"}
