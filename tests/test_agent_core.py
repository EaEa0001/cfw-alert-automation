import unittest
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from agent.llm.router import LLMRouter
from agent.policy import PolicyGuard
from agent.rules import CustomRuleStore, propose_rule_from_llm_parse, propose_rule_from_text, rule_matches
from agent.schemas import ActionPlan, AlertTask, EvidenceBundle, TriageVerdict
from agent.triage_service import AgentTriageService, apply_policy_preview
from cfw_alert_monitor import call_router_batch, has_success_source_evidence, run_router_agent_triage
import triage_stats
from cfw_alert_center_triage import (
    apply_custom_rules_to_rows,
    build_block_ip_payloads,
    create_block_ip_rules,
    custom_rule_decision,
    manual_review_candidates,
    realtime_triage_once,
    record_to_judge_row,
)


class AgentPolicyTests(unittest.TestCase):
    def guard(self, alert, evidence, verdict):
        return PolicyGuard().evaluate(alert, evidence, verdict, ActionPlan.omit(alert.alert_id, verdict.result))

    def test_cloud_success_never_omitted(self):
        alert = AlertTask(alert_id="a1", event_name="RCE", level="中危", attack_result="攻击成功")
        verdict = TriageVerdict("未见成功证据", "高", "模型误判")
        decision = self.guard(alert, EvidenceBundle(), verdict)
        self.assertFalse(decision.allows("omit_alert"))
        self.assertTrue(decision.requires_human)

    def test_high_unknown_outcome_retained(self):
        alert = AlertTask(alert_id="a2", event_name="Log4j", level="高危")
        verdict = TriageVerdict("未见成功证据", "高", "无回显")
        decision = self.guard(alert, EvidenceBundle(source_packet={"req": "GET /"}), verdict)
        self.assertFalse(decision.allows("omit_alert"))

    def test_high_business_fp_with_evidence_can_omit(self):
        alert = AlertTask(alert_id="a3", event_name="SQL注入", level="高危")
        verdict = TriageVerdict("业务误报", "高", "正常业务接口", key_evidence="POST /v1/order/query")
        evidence = EvidenceBundle(source_packet={"req": "POST /v1/order/query HTTP/1.1", "resp": "200 OK"})
        decision = self.guard(alert, evidence, verdict)
        self.assertTrue(decision.allows("omit_alert"))

    def test_landing_evidence_blocks_omit(self):
        alert = AlertTask(alert_id="a4", event_name="命令执行", level="中危")
        verdict = TriageVerdict("确认未成功", "高", "错误分类")
        evidence = EvidenceBundle(source_packet={"resp_body": "uid=0(root) gid=0(root)"})
        decision = self.guard(alert, evidence, verdict)
        self.assertFalse(decision.allows("omit_alert"))

    def test_missing_alert_identity_is_not_enough_for_high_policy(self):
        alert = AlertTask(alert_id="", event_name="", level="")
        verdict = TriageVerdict("业务误报", "高", "无原始记录")
        decision = self.guard(alert, EvidenceBundle(), verdict)
        self.assertFalse(decision.allows("omit_alert"))


class SourceEvidenceTests(unittest.TestCase):
    def test_es_bulk_created_is_success_evidence(self):
        row = {
            "源包证据": {
                "req": "POST /sup8-code-log-101366039588-2026/_doc/_bulk HTTP/1.1",
                "resp": "HTTP/1.1 201 Created",
                "resp_body": '{"items":[{"index":{"status":201,"result":"created"}}]}',
            }
        }
        self.assertTrue(has_success_source_evidence(row))

    def test_plain_http_200_is_not_success_evidence(self):
        row = {
            "源包证据": {
                "req": "POST /login HTTP/1.1",
                "resp": "HTTP/1.1 200 OK",
                "resp_body": "<html>ok</html>",
            }
        }
        self.assertFalse(has_success_source_evidence(row))


class CustomRuleDraftTests(unittest.TestCase):
    def test_future_normal_business_rule_is_narrow(self):
        alert = AlertTask(
            alert_id="123456",
            event_name="SQL注入",
            level="中危",
            src_ips=["10.0.1.5"],
            dst_ips=["10.0.2.8"],
            rule_ids=["r-1"],
        )
        draft = propose_rule_from_text("事件编号 123456 是正常业务,以后同类不研判", alert)
        self.assertEqual(draft["action"], "skip_llm_and_omit")
        self.assertEqual(draft["scope"], "same_src_same_dst_same_rule")
        self.assertEqual(draft["match"]["src_ip"], "10.0.1.5")
        self.assertEqual(draft["match"]["dst_ip"], "10.0.2.8")
        self.assertEqual(draft["match"]["rule_id"], "r-1")

    def test_scanner_rule_requires_trusted_source_wording(self):
        draft = propose_rule_from_text("这个源 IP 是扫描器,以后加白")
        self.assertEqual(draft["type"], "scanner_whitelist")
        self.assertFalse(draft["trusted_source"])
        self.assertTrue(draft["requires_human_confirm"])

    def test_scanner_ip_is_not_parsed_as_alert_id(self):
        draft = propose_rule_from_text("45.79.8.221 是公司漏扫扫描源,以后直接加白")
        self.assertEqual(draft["action"], "allow_scanner_ip")
        self.assertEqual(draft["match"]["src_ip"], "45.79.8.221")
        self.assertNotIn("alert_id", draft["match"])

    def test_event_id_with_label_still_parsed(self):
        draft = propose_rule_from_text("事件编号 c4928e6220312b9c073fb260c816dd10 是正常业务,以后不研判")
        self.assertEqual(draft["action"], "skip_llm_and_omit")
        self.assertEqual(draft["match"]["alert_id"], "c4928e6220312b9c073fb260c816dd10")

    def test_block_sentence_extracts_multiple_ips(self):
        draft = propose_rule_from_text("请封禁 1.2.3.4 5.6.7.8,原因: 恶意扫描")
        self.assertEqual(draft["type"], "ip_blocklist")
        self.assertEqual(draft["action"], "block_ip")
        self.assertEqual(draft["scope"], "ip_list")
        self.assertEqual(draft["ips"], ["1.2.3.4", "5.6.7.8"])
        self.assertEqual(draft["match"], {"src_ips": ["1.2.3.4", "5.6.7.8"]})
        self.assertTrue(draft["requires_human_confirm"])
        self.assertEqual(draft["status"], "draft")

    def test_block_txt_draft_extracts_ip_list(self):
        draft = propose_rule_from_text("封禁以下IP\n1.1.1.1\n2.2.2.2\n# comment\n3.3.3.3")
        self.assertEqual(draft["action"], "block_ip")
        self.assertEqual(draft["ips"], ["1.1.1.1", "2.2.2.2", "3.3.3.3"])
        self.assertNotIn("alert_id", draft["match"])
        self.assertTrue(any("保存草案不会下发防火墙策略" in note for note in draft["notes"]))

    def test_ip_list_match_does_not_match_everything(self):
        rule = {"status": "active", "action": "block_ip", "match": {"src_ips": ["1.1.1.1"]}}
        self.assertTrue(rule_matches(rule, AlertTask(alert_id="a", event_name="x", level="中危", src_ips=["1.1.1.1"])))
        self.assertFalse(rule_matches(rule, AlertTask(alert_id="b", event_name="x", level="中危", src_ips=["2.2.2.2"])))
        self.assertFalse(rule_matches({"status": "active", "action": "block_ip", "match": {}}, AlertTask(alert_id="c", event_name="x", level="中危")))

    def test_llm_parse_block_is_sanitized_to_block_rule(self):
        draft = propose_rule_from_llm_parse({
            "intent": "block_ip",
            "ips": ["8.8.8.8", "127.0.0.1", "bad"],
            "match": {"unexpected": "drop-me", "src_ip": "8.8.8.8"},
            "confidence": "high",
            "reason": "恶意扫描",
        }, "把 8.8.8.8 加入黑名单")
        self.assertEqual(draft["action"], "block_ip")
        self.assertEqual(draft["ips"], ["8.8.8.8", "127.0.0.1"])
        self.assertEqual(draft["match"], {"src_ips": ["8.8.8.8", "127.0.0.1"]})
        self.assertEqual(draft["parser"], "llm")
        self.assertNotIn("unexpected", draft["llm_parse"]["match"])

    def test_llm_parse_scanner_uses_src_ip_and_trusted_source(self):
        draft = propose_rule_from_llm_parse({
            "intent": "allow_scanner_ip",
            "ips": ["45.79.8.221"],
            "trusted_source": True,
            "confidence": "high",
        }, "45.79.8.221 是公司漏扫扫描源,以后直接加白")
        self.assertEqual(draft["action"], "allow_scanner_ip")
        self.assertEqual(draft["match"]["src_ip"], "45.79.8.221")
        self.assertTrue(draft["trusted_source"])
        self.assertEqual(draft["parser"], "llm")

    def test_llm_parse_unknown_falls_back_to_heuristic(self):
        draft = propose_rule_from_llm_parse({"intent": "unknown"}, "请封禁 1.2.3.4")
        self.assertEqual(draft["action"], "block_ip")
        self.assertEqual(draft["parser"], "heuristic")
        self.assertEqual(draft["llm_intent"], "unknown")

    def test_active_rule_skips_model_for_matching_alert(self):
        record = {
            "EventId": "event-123456",
            "EventName": "SQL注入",
            "Level": "Middle",
            "AttackResult": "2",
            "SrcIpList": ["10.0.1.5"],
            "DstIpList": ["10.0.2.8"],
            "RuleIdList": ["r-1"],
            "Direction": "1",
            "EndTime": "2026-06-23 10:00:00",
        }
        rule = {
            "rule_id": "cr-test",
            "status": "active",
            "type": "trusted_false_positive",
            "action": "skip_llm_and_omit",
            "match": {
                "event_name": "SQL注入",
                "rule_id": "r-1",
                "src_ip": "10.0.1.5",
                "dst_ip": "10.0.2.8",
            },
            "expires_at": "2099-01-01 00:00:00",
        }
        with tempfile.TemporaryDirectory() as td:
            store = CustomRuleStore(Path(td) / "rules.jsonl")
            store.save_rule(rule)
            decision = custom_rule_decision(record, store=store)
            self.assertIsNotNone(decision)
            self.assertTrue(decision["ignore"])
            row = record_to_judge_row(record, {}, None)
            judgements = apply_custom_rules_to_rows([row], store=store)
            self.assertIn("event-123456", judgements)
            self.assertEqual(judgements["event-123456"]["研判来源"], "custom_rule")

    def test_custom_rule_cannot_override_cloud_success(self):
        record = {
            "EventId": "event-success",
            "EventName": "命令执行",
            "Level": "Middle",
            "AttackResult": "1",
            "SrcIpList": ["10.0.1.5"],
            "DstIpList": ["10.0.2.8"],
            "RuleIdList": ["r-1"],
        }
        rule = {
            "rule_id": "cr-success",
            "status": "active",
            "type": "trusted_false_positive",
            "action": "skip_llm_and_omit",
            "match": {"event_name": "命令执行", "rule_id": "r-1", "src_ip": "10.0.1.5", "dst_ip": "10.0.2.8"},
            "expires_at": "2099-01-01 00:00:00",
        }
        with tempfile.TemporaryDirectory() as td:
            store = CustomRuleStore(Path(td) / "rules.jsonl")
            store.save_rule(rule)
            self.assertIsNone(custom_rule_decision(record, store=store))


class AgentTriageServiceTests(unittest.TestCase):
    def test_service_custom_rule_preview_returns_policy_allowed_action(self):
        row = {
            "告警ID": "svc-alert-1",
            "事件名称": "SQL注入",
            "告警等级": "中危",
            "攻击IP": "10.0.1.5",
            "目标IP": "10.0.2.8",
            "规则ID": "r-1",
        }
        rule = {
            "rule_id": "svc-rule",
            "status": "active",
            "type": "trusted_false_positive",
            "action": "skip_llm_and_omit",
            "match": {"event_name": "SQL注入", "rule_id": "r-1", "src_ip": "10.0.1.5", "dst_ip": "10.0.2.8"},
            "expires_at": "2099-01-01 00:00:00",
        }
        with tempfile.TemporaryDirectory() as td:
            store = CustomRuleStore(Path(td) / "rules.jsonl")
            store.save_rule(rule)
            service = AgentTriageService({"llm": {"enabled": False}}, rules=store)
            result = service.triage_judgement_row(row, run_model=False)
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["matched_rule"]["rule_id"], "svc-rule")
        self.assertEqual(result["verdict"]["研判来源"], "custom_rule")
        self.assertEqual(result["policy"]["allowed_actions"][0]["type"], "omit_alert")

    def test_service_no_model_preview_retains_for_review(self):
        with tempfile.TemporaryDirectory() as td:
            service = AgentTriageService({"llm": {"enabled": False}}, rules=CustomRuleStore(Path(td) / "rules.jsonl"))
            result = service.triage_judgement_row({
                "告警ID": "svc-alert-2",
                "事件名称": "命令执行",
                "告警等级": "高危",
                "攻击IP": "1.2.3.4",
                "目标IP": "10.0.2.8",
            }, run_model=False)
        self.assertEqual(result["verdict"]["模型研判"], "需人工复核")
        self.assertTrue(result["policy"]["requires_human"])
        self.assertEqual(result["would_execute"], [])

    def test_policy_preview_blocks_success_evidence(self):
        alert = AlertTask(alert_id="svc-alert-3", event_name="RCE", level="中危")
        evidence = EvidenceBundle(source_packet={"resp_body": "uid=0(root)"})
        verdict = TriageVerdict("确认未成功", "高", "错误结论")
        policy = apply_policy_preview(alert, evidence, verdict)
        self.assertEqual(policy["blocked_actions"][0]["policy_reason"], "landing_evidence_never_omit")


class ConsoleAgentApiTests(unittest.TestCase):
    def test_triage_preview_api_accepts_row_without_model(self):
        from console import app

        client = app.test_client()
        response = client.post("/api/agent/triage/preview", json={
            "run_model": False,
            "row": {
                "告警ID": "api-alert-1",
                "事件名称": "目录遍历",
                "告警等级": "中危",
                "攻击IP": "1.2.3.4",
                "目标IP": "10.0.0.2",
            },
        })
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["dry_run"])
        self.assertEqual(payload["input_source"], "judgement_row")

    def test_rule_draft_api_can_use_llm_parser_route(self):
        from console import app

        code = (
            "import json, sys; sys.stdin.read(); "
            "print(json.dumps({'intent':'block_ip','ips':['8.8.8.8'],"
            "'confidence':'high','reason':'bad source'}, ensure_ascii=False))"
        )
        config = {
            "llm": {
                "enabled": True,
                "rule_parse": {"enabled": True, "timeout_seconds": 10},
                "providers": {
                    "fake_rule": {
                        "type": "local_cli",
                        "command": [sys.executable, "-c", code],
                        "model": "fake-rule",
                    }
                },
                "routing": {"rule_parse": "fake_rule"},
            },
            "agent": {"custom_rules": {"default_expire_days": 12}},
        }
        with patch("console._load_local_config", return_value=config):
            response = app.test_client().post("/api/agent/rules/draft", json={
                "text": "把 8.8.8.8 加入黑名单",
                "use_llm": True,
            })
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["action"], "block_ip")
        self.assertEqual(payload["parser"], "llm")
        self.assertEqual(payload["llm_provider"], "fake_rule")

    def test_rule_draft_api_falls_back_when_llm_parser_fails(self):
        from console import app

        config = {
            "llm": {
                "enabled": True,
                "rule_parse": {"enabled": True, "timeout_seconds": 1},
                "providers": {"missing": {"type": "local_cli", "command": ["definitely-not-found"]}},
                "routing": {"rule_parse": "missing"},
            }
        }
        with patch("console._load_local_config", return_value=config):
            response = app.test_client().post("/api/agent/rules/draft", json={
                "text": "封禁 9.9.9.9",
                "use_llm": True,
            })
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["action"], "block_ip")
        self.assertEqual(payload["parser"], "heuristic")
        self.assertIn("llm_error", payload)


class ConsoleReportsApiTests(unittest.TestCase):
    def test_reports_summary_api_returns_daily_shape(self):
        from console import app

        response = app.test_client().get("/api/reports/summary?days=1")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["days"], 1)
        self.assertIn("overview", payload)
        self.assertIn("trend", payload)
        self.assertIn("health", payload)
        self.assertIn("key_alerts", payload)
        self.assertIn("pipeline", payload)


class TriageStatsProfileTests(unittest.TestCase):
    def test_no_success_exploit_attempts_do_not_become_high_risk_profile(self):
        events = [
            "PHPUnit远程代码执行漏洞利用(CVE-2017-9841)",
            "phpcgi 代码执行漏洞攻击(CVE-2012-1823)",
            "通用检测 PHP代码执行漏洞攻击",
            "通用检测 文件包含攻击",
            "在URI中发现PHP配置选项",
            "phpcgi Windows平台代码执行漏洞攻击(CVE-2024-4577)",
            "PHP系统伪协议构造请求攻击",
            "疑似Shell命令执行攻击",
            "通用检测 PHP代码执行漏洞攻击",
        ]
        rows = [{
            "告警ID": f"no-success-{idx}",
            "告警时间": "2026-06-23 16:57:00",
            "告警等级": "中危",
            "事件名称": event,
            "攻击IP": "176.193.141.80",
            "目标IP": "172.19.0.14",
            "模型研判": "未见成功证据",
            "研判来源": "codex_direct",
        } for idx, event in enumerate(events)]

        with patch("triage_stats.load_judgements", return_value=rows):
            profiles = triage_stats._fallback_profiles_from_judgements(days=1)

        profile = profiles[0]
        self.assertEqual(profile["ip"], "176.193.141.80")
        self.assertLess(profile["score"], 70)
        self.assertEqual(profile["band"], "关注")
        self.assertEqual(profile["stage"], "尝试利用")
        self.assertEqual(profile["killchain_max"], "尝试利用")
        self.assertEqual(profile["cloud_success"], 0)
        self.assertEqual(profile["high"], 0)

    def test_confirmed_success_still_becomes_high_risk_profile(self):
        rows = [{
            "告警ID": "success-1",
            "告警时间": "2026-06-23 16:57:00",
            "告警等级": "中危",
            "事件名称": "疑似Shell命令执行攻击",
            "攻击IP": "8.8.8.8",
            "目标IP": "172.19.0.14",
            "模型研判": "确认成功",
            "研判来源": "codex_direct",
        }]

        with patch("triage_stats.load_judgements", return_value=rows):
            profiles = triage_stats._fallback_profiles_from_judgements(days=1)

        profile = profiles[0]
        self.assertEqual(profile["band"], "高危")
        self.assertGreaterEqual(profile["score"], 70)
        self.assertEqual(profile["stage"], "成功利用")
        self.assertEqual(profile["killchain_max"], "成功利用")


class RouterTests(unittest.TestCase):
    def test_legacy_config_routes_to_codex_direct(self):
        router = LLMRouter({"llm": {"provider": "codex_direct", "model": "gpt-5.5"}})
        summary = router.summary()
        self.assertEqual(summary["routes"]["batch_triage"], "codex_direct")
        self.assertEqual(summary["providers"]["codex_direct"]["type"], "codex_direct")
        self.assertEqual(summary["providers"]["codex_direct"]["model"], "gpt-5.5")

    def test_router_batch_triage_uses_configured_provider(self):
        code = (
            "import sys; sys.stdin.read(); "
            "print('[{\"id\":1,\"result\":\"扫描探测\",\"confidence\":\"high\","
            "\"evidence\":\"扫描器探测\",\"next\":\"自动忽略\",\"key_evidence\":\"ua=zgrab\"}]')"
        )
        config = {
            "llm": {
                "providers": {
                    "fake_local": {
                        "type": "local_cli",
                        "command": [sys.executable, "-c", code],
                        "model": "fake-model",
                    }
                },
                "routing": {"batch_triage": "fake_local"},
            }
        }
        by_key, usage = call_router_batch(config, "batch_triage", [{
            "告警ID": "alert-1",
            "告警时间": "2026-06-23 10:00:00",
            "攻击IP": "1.2.3.4",
            "目标IP": "10.0.0.2",
            "告警等级": "低危",
            "事件名称": "zgrab扫描",
        }])
        self.assertIn("alert-1", by_key)
        self.assertEqual(by_key["alert-1"]["模型研判"], "扫描探测")
        self.assertEqual(by_key["alert-1"]["模型置信度"], "高")
        self.assertEqual(by_key["alert-1"]["_provider"], "fake_local")
        self.assertEqual(usage["provider"], "fake_local")

    def test_router_agent_triage_can_call_json_tool(self):
        code = (
            "import sys; data=sys.stdin.read(); "
            "print('{\"result\":\"确认未成功\",\"confidence\":\"high\","
            "\"evidence\":\"hex已解码无成功证据\",\"next\":\"自动忽略\","
            "\"key_evidence\":\"hello\"}' if 'hello' in data else "
            "'{\"tool_call\":{\"name\":\"decode_hex\",\"args\":{\"hex\":\"68656c6c6f\"},"
            "\"reason\":\"解码载荷\"}}')"
        )
        config = {
            "llm": {
                "agent_triage": {"enabled": True, "max_rounds": 3},
                "providers": {
                    "fake_agent": {
                        "type": "local_cli",
                        "command": [sys.executable, "-c", code],
                        "model": "fake-agent-model",
                    }
                },
                "routing": {"agent_triage": "fake_agent"},
            }
        }
        result = run_router_agent_triage(config, {}, {
            "告警ID": "a-json-agent",
            "事件名称": "hex载荷",
            "告警等级": "中危",
            "攻击IP": "1.2.3.4",
            "目标IP": "10.0.0.8",
        }, max_rounds=3)
        self.assertIsNotNone(result)
        self.assertEqual(result["模型研判"], "确认未成功")
        self.assertEqual(result["模型置信度"], "高")
        self.assertEqual(result["研判来源"], "fake_agent_agent")
        self.assertEqual(result["工具轨迹"], "decode_hex")

    def test_router_provider_live_smoke_test_uses_configured_provider(self):
        code = "import sys; sys.stdin.read(); print('{\"ok\":true,\"stage\":\"provider_smoke\"}')"
        router = LLMRouter({
            "llm": {
                "providers": {
                    "fake_smoke": {
                        "type": "local_cli",
                        "command": [sys.executable, "-c", code],
                        "model": "fake-smoke",
                    }
                },
                "routing": {"batch_triage": "fake_smoke"},
            }
        })
        result = router.test_provider("fake_smoke", live=True, timeout=5)
        self.assertTrue(result["ok"])
        self.assertTrue(result["config_ok"])
        self.assertEqual(result["parsed"]["stage"], "provider_smoke")


class ConsoleProviderApiTests(unittest.TestCase):
    def test_provider_test_api_reports_missing_provider(self):
        from console import app

        client = app.test_client()
        response = client.post("/api/agent/providers/not-exist/test", json={"live": False})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "provider_not_found")


class ConsoleWhitelistApiTests(unittest.TestCase):
    def test_default_whitelist_rules_are_included_from_config(self):
        from console import app

        config = {
            "tencent_scan_ips": ["1.1.1.1"],
            "company_scan_ips": ["2.2.2.2"],
        }
        with tempfile.TemporaryDirectory() as td:
            store = CustomRuleStore(Path(td) / "rules.jsonl")
            with patch("console._load_local_config", lambda: config), \
                    patch("console.CustomRuleStore", lambda: store):
                response = app.test_client().get("/api/agent/rules")
        self.assertEqual(response.status_code, 200)
        rules = response.get_json()
        system_rules = [rule for rule in rules if rule.get("system")]
        self.assertEqual(len(system_rules), 2)
        self.assertEqual(system_rules[0]["status"], "active")
        self.assertTrue(system_rules[0]["readonly"])
        self.assertIn("1.1.1.1", system_rules[0]["ips"])

    def test_whitelist_config_api_sanitizes_and_saves_ip_lists(self):
        from console import app

        saved = {}
        config = {"tencent_scan_ips": [], "company_scan_ips": []}

        def save_config(value):
            saved.update(value)

        with patch("console._load_local_config", lambda: dict(config)), \
                patch("console._save_local_config", save_config):
            response = app.test_client().post("/api/agent/whitelist", json={
                "tencent_scan_ips": "1.1.1.1\nbad\n1.1.1.1\n# comment",
                "company_scan_ips": ["2.2.2.2", "127.0.0.1", "2.2.2.2"],
            })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["tencent_scan_ips"], ["1.1.1.1"])
        self.assertEqual(data["company_scan_ips"], ["2.2.2.2", "127.0.0.1"])
        self.assertEqual(data["counts"]["total"], 3)
        self.assertEqual(saved["tencent_scan_ips"], ["1.1.1.1"])

    def test_whitelist_config_exposes_legacy_candidate_until_configured(self):
        from console import app

        with patch("console._load_local_config", lambda: {"tencent_scan_ips": [], "company_scan_ips": []}):
            response = app.test_client().get("/api/agent/whitelist")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["candidates"][0]["ip"], "210.22.92.182")
        self.assertEqual(data["candidates"][0]["target"], "company_scan_ips")

        with patch("console._load_local_config", lambda: {"tencent_scan_ips": [], "company_scan_ips": ["210.22.92.182"]}):
            response = app.test_client().get("/api/agent/whitelist")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["candidates"], [])


class TencentBlockIpTests(unittest.TestCase):
    def test_block_ip_payload_uses_tencent_blacklist_api_shape(self):
        payload = build_block_ip_payloads(
            {"block_ip": {"direction_list": "0,1", "fw_type": 1, "end_time": "2099-01-01 00:00:00"}},
            ["1.1.1.1", "1.1.1.1", "127.0.0.1", "bad"],
            comment="恶意扫描",
        )
        self.assertEqual(payload["api_action"], "CreateBlockIgnoreRuleNew")
        self.assertEqual(payload["ips"], ["1.1.1.1"])
        self.assertEqual(payload["invalid_ips"], ["127.0.0.1", "bad"])
        self.assertEqual(payload["payloads"][0]["RuleType"], 1)
        self.assertEqual(payload["payloads"][0]["CoverDuplicate"], 1)
        self.assertEqual(payload["payloads"][0]["Rules"][0]["Ioc"], "1.1.1.1")
        self.assertEqual(payload["payloads"][0]["Rules"][0]["DirectionList"], "0,1")
        self.assertEqual(payload["payloads"][0]["Rules"][0]["FwType"], 1)

    def test_block_ip_execute_requires_confirm_token(self):
        result = create_block_ip_rules({}, ["1.1.1.1"], dry_run=False)
        self.assertEqual(result["error"], "missing_confirm_token")
        self.assertNotIn("results", result)

    def test_block_ip_console_api_dry_run_from_rule(self):
        from console import app

        client = app.test_client()
        rule = propose_rule_from_text("封禁以下IP\n1.1.1.1\n2.2.2.2")
        response = client.post("/api/agent/tencent/block-ip", json={"rule": rule, "dry_run": True})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "preview")
        self.assertEqual(data["api_action"], "CreateBlockIgnoreRuleNew")
        self.assertEqual(data["ips"], ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(data["payloads"][0]["RuleType"], 1)

    def test_block_ip_rule_activation_can_auto_call_tencent(self):
        from console import app

        rule = propose_rule_from_text("封禁以下IP\n1.1.1.1\n2.2.2.2")
        with tempfile.TemporaryDirectory() as td:
            store = CustomRuleStore(Path(td) / "rules.jsonl")
            with patch("console.CustomRuleStore", lambda: store), \
                    patch("cfw_alert_center_triage.create_block_ip_rules") as block:
                block.return_value = {"status": "executed", "ips": ["1.1.1.1", "2.2.2.2"]}
                response = app.test_client().post("/api/agent/rules", json={
                    "rule": rule,
                    "activate": True,
                    "auto_tencent_block": True,
                    "confirm": "CONFIRM_TENCENT_CFW_BLOCK",
                })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "active")
        self.assertEqual(data["_tencent_block_result"]["status"], "executed")
        block.assert_called_once()


class RealtimePollingTests(unittest.TestCase):
    def test_manual_candidates_are_retained_rows_not_ignored_rows(self):
        rows = [
            {"告警ID": "ignored-1", "模型研判": "未见成功证据", "研判来源": "codex_direct"},
            {"告警ID": "manual-1", "模型研判": "需人工复核", "研判来源": "codex_direct"},
            {"告警ID": "manual-high", "模型研判": "未见成功证据", "告警等级": "高危", "研判来源": "codex_direct"},
        ]
        candidates = manual_review_candidates(rows, {"ignored-1"})
        self.assertEqual([row["告警ID"] for row in candidates], ["manual-1", "manual-high"])

    def test_realtime_once_no_new_records_is_noop(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = {
                "realtime_triage": {
                    "state_file": str(Path(td) / "state.json"),
                    "lookback_minutes": 5,
                },
                "llm": {"enabled": False},
            }
            with patch("cfw_alert_center_triage.fetch_unhandled_alert_center_range") as fetch:
                fetch.return_value = ([], {"start": "2026-06-23 10:00:00", "end": "2026-06-23 10:05:00", "total": 0})
                result = realtime_triage_once(cfg, dry_run=True)
        self.assertEqual(result["new_records"], 0)
        self.assertNotIn("judgement_jsonl", result)


if __name__ == "__main__":
    unittest.main()
