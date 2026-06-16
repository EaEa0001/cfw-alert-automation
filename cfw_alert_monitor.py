#!/usr/bin/env python3
import argparse
import configparser
import csv
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import http.client
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path

from tencentcloud.common import credential
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.cfw.v20190904 import cfw_client, models


ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.json"
DATA_DIR = ROOT / "data"
REPORT_DIR = ROOT / "reports"
LOG_DIR = ROOT / "logs"
THREAT_INDEX = "rule_threatinfo"
MAX_LIMIT = 1000
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CODEX_RESPONSES_URL = "https://chatgpt.com/backend-api/codex/responses"
CODEX_AUTH_PATH = Path.home() / ".codex" / "auth.json"
DIRECT_RESULTS = {"确认成功", "确认未成功", "未见成功证据", "扫描探测", "需人工复核"}
DEFAULT_AUTO_IGNORE_RESULTS = {"确认未成功", "未见成功证据", "扫描探测"}
CONFIDENCE_MAP = {
    "high": "高",
    "medium": "中",
    "low": "低",
    "高": "高",
    "中": "中",
    "低": "低",
}


def now_local():
    return datetime.now().replace(microsecond=0)


def dt_text(value):
    return value.strftime("%Y-%m-%d %H:%M:%S")


def load_config():
    with CONFIG_PATH.open("r", encoding="utf-8") as fh:
        config = json.load(fh)
    config["whitelist_ips"] = sorted(
        set(config.get("tencent_scan_ips", [])) | set(config.get("company_scan_ips", []))
    )
    return config


def wecom_config(config):
    value = config.get("wecom") or {}
    if "enabled" not in value:
        value["enabled"] = False
    return value


def truncate_utf8(value, max_bytes=3800):
    raw = str(value).encode("utf-8")
    if len(raw) <= max_bytes:
        return str(value)
    suffix = "\n> 消息已截断，完整结果请查看本地报告。"
    limit = max(0, max_bytes - len(suffix.encode("utf-8")))
    return raw[:limit].decode("utf-8", errors="ignore") + suffix


def send_wecom_markdown(config, content, notification_type, webhook_override=None):
    notify_cfg = wecom_config(config)
    result = {
        "enabled": bool(notify_cfg.get("enabled", False)),
        "type": notification_type,
        "sent": False,
    }
    # 可传独立 webhook(如"需人工研判"专用群);不传则用默认企微机器人
    webhook_url = str(webhook_override or notify_cfg.get("webhook_url") or "").strip()
    if not result["enabled"]:
        result["reason"] = "disabled"
        return result
    if not webhook_url:
        result["reason"] = "missing_webhook_url"
        return result

    payload = {
        "msgtype": "markdown",
        "markdown": {"content": truncate_utf8(content, int(notify_cfg.get("max_bytes", 3800)))},
    }
    request = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=int(notify_cfg.get("timeout_seconds", 15))) as response:
            response_payload = json.loads(response.read().decode("utf-8"))
        result["response"] = response_payload
        result["sent"] = int(response_payload.get("errcode", -1)) == 0
        if not result["sent"]:
            result["reason"] = response_payload.get("errmsg") or "wecom_api_error"
    except Exception as exc:
        result["reason"] = str(exc)

    DATA_DIR.mkdir(exist_ok=True)
    append_jsonl(
        DATA_DIR / f"wecom-notify-{now_local().strftime('%Y-%m-%d')}.jsonl",
        [dict(result, recorded_at=dt_text(now_local()))],
    )
    return result


def send_wecom_text(config, content, notification_type, webhook_override=None, mentioned_list=None):
    """发企微 text 消息。text 类型支持 @(markdown 不支持),用于需人工研判 @所有人。"""
    notify_cfg = wecom_config(config)
    result = {"enabled": bool(notify_cfg.get("enabled", False)), "type": notification_type, "sent": False}
    webhook_url = str(webhook_override or notify_cfg.get("webhook_url") or "").strip()
    if not result["enabled"]:
        result["reason"] = "disabled"
        return result
    if not webhook_url:
        result["reason"] = "missing_webhook_url"
        return result
    text = {"content": truncate_utf8(content, int(notify_cfg.get("max_bytes", 3800)))}
    if mentioned_list:
        text["mentioned_list"] = mentioned_list
    request = urllib.request.Request(
        webhook_url,
        data=json.dumps({"msgtype": "text", "text": text}, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=int(notify_cfg.get("timeout_seconds", 15))) as response:
            response_payload = json.loads(response.read().decode("utf-8"))
        result["response"] = response_payload
        result["sent"] = int(response_payload.get("errcode", -1)) == 0
        if not result["sent"]:
            result["reason"] = response_payload.get("errmsg") or "wecom_api_error"
    except Exception as exc:
        result["reason"] = str(exc)
    return result


def push_manual_review_wecom(config, items, title="需人工研判告警"):
    """企微 bot 专推"需人工复核"+"确认成功"的告警卡片。

    与小时/日报汇总用同一个企微机器人;也可在 wecom.manual_webhook_url 配独立群。
    """
    notify_cfg = wecom_config(config)
    if not notify_cfg.get("enabled", False) or not notify_cfg.get("manual_enabled", True):
        return {"sent": False, "reason": "disabled"}
    if not items:
        return {"sent": False, "reason": "no_items"}
    limit = int(notify_cfg.get("manual_max_items", 10))
    lines = [f"## 🔔 {title}（{len(items)} 条需处理）", ""]
    for it in items[:limit]:
        t = str(it.get("告警时间", ""))[5:16]
        lines.append(f"**[{it.get('告警等级','')}] {it.get('事件名称','')}**")
        lines.append(f"> 攻击IP：{it.get('攻击IP','')}　目标：{it.get('目标IP','')}")
        lines.append(f"> 研判：**{it.get('模型研判','')}**　{it.get('研判理由','')}")
        if it.get("关键证据"):
            lines.append(f"> 证据：{str(it.get('关键证据'))[:80]}")
        lines.append(f"> 时间：{t}")
        lines.append("")
    if len(items) > limit:
        lines.append(f"> ……另有 {len(items) - limit} 条，见控制台")
    webhook = notify_cfg.get("manual_webhook_url") or None
    # markdown 卡片(带格式)+ text @所有人(markdown 不支持 @,故补一条 text)
    card = send_wecom_markdown(config, "\n".join(lines).strip(), "manual_review", webhook_override=webhook)
    at_result = {"sent": False, "reason": "disabled"}
    if notify_cfg.get("manual_at_all", True):
        high = sum(1 for it in items if it.get("告警等级") == "高危")
        at_text = f"⚠️ 有 {len(items)} 条告警需人工研判（高危 {high}），请及时处理。详情见上方卡片。"
        at_result = send_wecom_text(config, at_text, "manual_review_at",
                                    webhook_override=webhook, mentioned_list=["@all"])
    return {"sent": card.get("sent"), "card": card, "at_all": at_result}


def counter_text(counter, order=None, limit=6):
    if order:
        items = [(key, counter.get(key, 0)) for key in order if counter.get(key, 0)]
    else:
        items = counter.most_common(limit)
    return "、".join(f"{key} {value}" for key, value in items[:limit]) or "无"


def disposition_failures(disposition):
    failures = 0
    for action in disposition.get("actions", []):
        if action.get("error") or action.get("return_code") not in (None, 0, "0"):
            failures += 1
    return failures


# 把内部研判状态翻译成运维能行动的人话 + 优先级
_REASON_PLAIN = [
    ("Shodan", ("背景探测(Shodan)", 9)),
    ("白名单", ("白名单扫描源", 9)),
    ("扫描器特征", ("扫描器探测,未成功", 8)),
    ("响应为失败码", ("攻击已失败(响应失败码)", 8)),
    ("云端判失败", ("攻击疑似失败,低优先级", 7)),
    ("攻击结果未知", ("利用尝试,未确认是否得手,建议查日志", 4)),
    ("高危告警保留", ("高危事件,需人工确认", 2)),
    ("云端标记攻击成功", ("⚠️云端标记成功,立即核查", 0)),
]
# 扫描/探测类事件名关键词(归入"背景噪声"汇总,不逐条刷屏)
_NOISE_KEYWORDS = ("扫描", "探测", "Censys", "masscan", "nmap", "zgrab", "Shodan", "信息泄露")


def _plain_reason(reason):
    for key, (plain, prio) in _REASON_PLAIN:
        if key in str(reason or ""):
            return plain, prio
    return str(reason or "需复核"), 5


def _is_noise_event(name):
    return any(k in str(name or "") for k in _NOISE_KEYWORDS)


def build_hourly_wecom_message(start_text, end_text, total, rows, judged_rows, disposition, alert_center):
    ac = alert_center or {}
    window = f"{start_text[11:16]}-{end_text[11:16]}"
    retained_items = ac.get("retained_items") or []

    # 原始流量需关注(确认成功/需人工/高危)
    flow_review = [
        row for row in judged_rows
        if row.get("模型研判") in ("确认成功", "需人工复核") or row.get("告警等级") in ("严重", "高危")
    ]

    # 告警中心保留项:分流为「真威胁(需关注)」和「背景噪声(只计数)」
    threats, noise = [], []
    for item in retained_items:
        if _is_noise_event(item.get("event_name")):
            noise.append(item)
        else:
            threats.append(item)
    # 真威胁按优先级排序(理由翻译里带优先级)
    for it in threats:
        it["_plain"], it["_prio"] = _plain_reason(it.get("reason"))
    threats.sort(key=lambda it: (it["_prio"], not it.get("src_public", False)))

    fallback_count = sum(1 for row in judged_rows if str(row.get("研判来源", "")).startswith("rule_fallback"))
    has_critical = ac.get("retained_success", 0) or any(it["_prio"] <= 2 for it in threats) or flow_review

    lines = [f"## 🛡️ 云防火墙告警简报  {window}"]

    # 一行总览(口语化,一眼懂:产生多少、忽略多少噪声、剩多少要管)
    _total = ac.get("active_before", 0)
    _ignored = ac.get("ignored_confirmed", 0)
    _left = ac.get("retained", 0)
    lines.append(
        f"> 本时段共产生 **{_total}** 条告警,自动忽略 **{_ignored}** 条噪声,**剩 {_left} 条需关注**"
        + (f"(另原始流量 {len(rows)} 条)" if rows else "")
    )
    # 模型连接异常时本轮深判被短路降级,这些不是"没研判",是已入队待网络恢复自动补判。
    _degraded = ac.get("deep_degraded", 0)
    _enqueued = ac.get("retry_queue_enqueued", 0)
    if _degraded or _enqueued:
        lines.append(
            f"> ⚠️ <font color=\"warning\">本轮模型连接异常,**{max(_degraded, _enqueued)}** 条暂未深判"
            f"(下方研判为规则初判),已入队,网络恢复后自动用 Agent 补判</font>"
        )

    # 按攻击者(源IP集合)聚合,同一组源IP的多手法合并成一条,避免刷屏
    by_attacker = {}
    for it in threats:
        key = "|".join(sorted(it.get("src_ips") or []) or ["未知"])
        g = by_attacker.setdefault(key, {
            "src": key, "events": set(), "assets": set(), "dsts": set(),
            "direction": it.get("direction") or "", "prio": it["_prio"], "plain": it["_plain"],
        })
        g["events"].add(it.get("event_name") or "未知事件")
        g["assets"].update(it.get("asset_names") or [])
        g["dsts"].update(it.get("dst_ips") or [])
        g["prio"] = min(g["prio"], it["_prio"])
    attackers = sorted(by_attacker.values(), key=lambda g: (g["prio"], len(g["events"]) * -1))

    if attackers or flow_review:
        lines.append(f"\n**🔴 需重点关注（{len(attackers)} 个来源 / {len(flow_review)} 原始流量）**")
        for g in attackers[:8]:
            evs = sorted(g["events"])
            ev_show = evs[0] if len(evs) == 1 else f"{evs[0]} 等 {len(evs)} 种手法"
            dst = "|".join(sorted(g["dsts"])[:3]) or "未知"
            asset = "、".join(sorted(g["assets"])[:3])
            dst_show = f"{dst}（{asset}）" if asset else dst
            lines.append(
                f"> [{g['direction']}] **{ev_show}**\n"
                f"> 　{g['src']} → {dst_show}\n"
                f"> 　{g['plain']}"
            )
        for row in flow_review[:3]:
            target = row.get("目标资产") or row.get("目标IP") or "未知"
            lines.append(
                f"> [原始流量] **{row.get('事件名称') or '未知事件'}**\n"
                f"> 　{row.get('攻击IP') or '未知'} → {target}　{row.get('模型研判') or row.get('告警等级')}"
            )

    # 🟡 自动已处理 / 背景噪声(只汇总计数,不刷屏)
    auto_handled = int(ac.get("ignored_confirmed", 0) or 0)
    if auto_handled or noise:
        parts = []
        if auto_handled:
            parts.append(f"自动忽略 **{auto_handled}**")
        if noise:
            noise_src = len({"|".join(n.get("src_ips") or []) for n in noise})
            parts.append(f"背景扫描噪声 **{len(noise)}** 条（{noise_src} 个源,已留存待日报清理）")
        lines.append(f"\n**🟡 已处理 / 噪声**：" + "　".join(parts))

    # 异常提示
    fails = disposition_failures(disposition) + disposition_failures(
        {"actions": (ac.get("omit_actions") or []) + (ac.get("white_actions") or [])})
    if fails:
        lines.append(f"\n<font color=\"warning\">⚠️ 处置失败 **{fails}** 条,需检查</font>")
    if fallback_count:
        lines.append(f"<font color=\"warning\">⚠️ 模型降级 **{fallback_count}** 条(连接异常,用规则兜底)</font>")
    if not (threats or flow_review):
        lines.append("\n<font color=\"info\">✅ 本小时无需重点关注的告警</font>")

    return "\n".join(lines)


def run_alert_center_hourly(config, end_text):
    alert_cfg = (config.get("llm") or {}).get("alert_center_auto_dispose") or {}
    if not alert_cfg.get("enabled", True):
        return {"enabled": False, "reason": "disabled", "retained_events": {}, "retained_items": []}
    lookback = max(1, int(alert_cfg.get("lookback_hours", 2)))
    end = datetime.strptime(end_text, "%Y-%m-%d %H:%M:%S")
    start_text = dt_text(end - timedelta(hours=lookback))
    command = [
        sys.executable,
        str(ROOT / "cfw_alert_center_triage.py"),
        "--safe-hourly",
        "--start",
        start_text,
        "--end",
        end_text,
    ]
    child_env = dict(os.environ)
    child_env["PYTHONIOENCODING"] = "utf-8"
    completed = subprocess.run(
        command,
        cwd=str(ROOT),
        env=child_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=int(alert_cfg.get("timeout_seconds", 180)),
    )
    if completed.returncode != 0:
        return {
            "enabled": True,
            "error": compact_text(completed.stderr or completed.stdout, 500),
            "retained_events": {},
            "retained_items": [],
        }
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    try:
        return json.loads(lines[-1])
    except (IndexError, json.JSONDecodeError):
        return {
            "enabled": True,
            "error": "invalid alert center hourly output",
            "retained_events": {},
            "retained_items": [],
        }


def latest_unique_hourly_judgements(day):
    latest = {}
    triage_path = DATA_DIR / f"hourly-triage-{day}.jsonl"
    if not triage_path.exists():
        return []
    with triage_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            payload = json.loads(line)
            for row in payload.get("rows", []):
                key = judgement_key(row)
                if key:
                    latest[key] = row
    return list(latest.values())


def build_daily_wecom_message(day, events, ip_rows, alert_rows=None):
    levels = Counter(event.get("level", "") for event in events if event.get("level"))
    event_names = Counter(event.get("event_name", "") for event in events if event.get("event_name"))
    ip_counts = Counter(event.get("attack_ip", "") for event in events if event.get("attack_ip"))
    final_rows = alert_rows if alert_rows is not None else latest_unique_hourly_judgements(day)
    judgement_counts = Counter(row.get("模型研判", "") for row in final_rows if row.get("模型研判"))
    source_counts = Counter(row.get("研判来源", "") for row in final_rows if row.get("研判来源"))
    fallback_count = sum(
        count for source, count in source_counts.items() if source.startswith("rule_fallback")
    )
    attention_rows = [
        row
        for row in final_rows
        if row.get("模型研判") in {"确认成功", "需人工复核"}
    ]
    attention_rows.sort(
        key=lambda row: (
            row.get("模型研判") != "确认成功",
            row.get("告警等级") not in {"严重", "高危"},
            row.get("告警时间", ""),
        )
    )
    attention_text = "；".join(
        f"{row.get('攻击IP', '-')}/{row.get('事件名称', '-')}/{row.get('研判理由', '-')}"
        for row in attention_rows[:5]
    ) or "无"

    ignored_alerts = 0
    white_candidates = 0
    action_failures = 0
    dispose_path = DATA_DIR / f"auto-dispose-{day}.jsonl"
    if dispose_path.exists():
        with dispose_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                payload = json.loads(line)
                ignored_alerts += int(payload.get("ignored_alerts", 0) or 0)
                white_candidates += int(payload.get("white_rule_candidates", 0) or 0)
                action_failures += disposition_failures(payload)

    alert_center_ignored = 0
    alert_center_failures = 0
    alert_center_latest = {}
    alert_center_path = DATA_DIR / f"alert-center-hourly-{day}.jsonl"
    if alert_center_path.exists():
        with alert_center_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                payload = json.loads(line)
                if payload.get("dry_run"):
                    continue
                alert_center_latest = payload
                alert_center_ignored += int(payload.get("ignored_confirmed", 0) or 0)
                alert_center_failures += disposition_failures(
                    {"actions": payload.get("omit_actions", []) + payload.get("white_actions", [])}
                )

    # 结论式日报:先给一句话结论,再给关键数字,噪声收起来。
    total = len(events)
    confirmed = judgement_counts.get("确认成功", 0)
    manual = judgement_counts.get("需人工复核", 0)
    auto_done = total - confirmed - manual  # 自动处理掉的(各类无害结论)
    total_failures = action_failures + alert_center_failures

    # 一句话结论
    if confirmed:
        verdict = f"⚠️ **发现 {confirmed} 条确认成功,需立即处置**"
    elif total_failures:
        verdict = f"⚠️ 处置有 **{total_failures}** 条失败,需检查"
    elif fallback_count >= total * 0.5 and total:
        verdict = f"⚠️ 模型连接异常,**{fallback_count}** 条降级未深判(已入队,网络恢复自动补判)"
    elif manual:
        verdict = f"✅ 无确认得手;**{manual}** 条待人工复核,其余已自动处理"
    else:
        verdict = "✅ 全部自动研判处理,无需人工"

    top_ip = counter_text(ip_counts, limit=5)
    top_ev = counter_text(event_names, limit=5)
    lines = [
        f"## 云防火墙日报 {day}",
        f"> {verdict}",
        f"- 全天告警 **{total}** 条(高危 {levels.get('高危', 0)})| 攻击IP **{len(ip_rows)}** 个",
        f"- 处理:自动 **{auto_done + ignored_alerts + alert_center_ignored}** | 待人工 **{manual}** | 确认成功 **{confirmed}**",
        f"- 主要攻击源:{top_ip}",
        f"- 主要手法:{top_ev}",
    ]
    if fallback_count:
        lines.append(f"- <font color=\"warning\">模型降级 {fallback_count} 条(已入队待补判)</font>")
    lines.append("> 扫描IP/漏扫IP已排除不封禁;明细见控制台")
    return "\n".join(lines)


def _find_credential_pair(value):
    if not isinstance(value, dict):
        return None

    sid = (
        value.get("secretId")
        or value.get("SecretId")
        or value.get("secret_id")
        or value.get("SecretID")
    )
    sk = (
        value.get("secretKey")
        or value.get("SecretKey")
        or value.get("secret_key")
        or value.get("SecretKey")
    )
    token = value.get("token") or value.get("Token")
    if sid and sk:
        return sid, sk, token

    for child in value.values():
        found = _find_credential_pair(child)
        if found:
            return found
    return None


def _read_json_credential(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return _find_credential_pair(value)


def _read_ini_credential(path, profile):
    parser = configparser.ConfigParser()
    try:
        parser.read(path, encoding="utf-8")
    except Exception:
        return None

    sections = [profile] if profile in parser else parser.sections()
    for section in sections:
        values = parser[section]
        sid = values.get("secretId") or values.get("secret_id") or values.get("SecretId")
        sk = values.get("secretKey") or values.get("secret_key") or values.get("SecretKey")
        token = values.get("token") or values.get("Token")
        if sid and sk:
            return sid, sk, token
    return None


def load_credentials(config):
    env_sid = os.getenv("TENCENTCLOUD_SECRET_ID")
    env_sk = os.getenv("TENCENTCLOUD_SECRET_KEY")
    env_token = os.getenv("TENCENTCLOUD_TOKEN")
    if env_sid and env_sk:
        return env_sid, env_sk, env_token

    tccli_dir = Path.home() / ".tccli"
    for profile in config.get("credential_profiles", ["akonly", "default"]):
        path = tccli_dir / f"{profile}.credential"
        if not path.exists():
            continue
        found = _read_json_credential(path) or _read_ini_credential(path, profile)
        if found:
            return found

    raise RuntimeError("No Tencent Cloud credential found in env or ~/.tccli profiles.")


def build_client(config):
    sid, sk, token = load_credentials(config)
    cred = credential.Credential(sid, sk, token) if token else credential.Credential(sid, sk)
    http_profile = HttpProfile()
    http_profile.endpoint = config.get("endpoint", "cfw.tencentcloudapi.com")
    client_profile = ClientProfile()
    client_profile.httpProfile = http_profile
    return cfw_client.CfwClient(cred, config.get("region", "ap-shanghai"), client_profile)


def parse_data(data):
    if not data:
        return []
    value = json.loads(data) if isinstance(data, str) else data
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("Data", "List", "Rows", "Records"):
            if isinstance(value.get(key), list):
                return value[key]
    return []


def describe_unhandled(client, start_text, end_text):
    req = models.DescribeUnHandleEventTabListRequest()
    req.StartTime = start_text
    req.EndTime = end_text
    resp = client.DescribeUnHandleEventTabList(req)
    payload = json.loads(resp.to_json_string())
    return {
        "start_time": start_text,
        "end_time": end_text,
        "return_code": payload.get("ReturnCode"),
        "return_msg": payload.get("ReturnMsg"),
        "request_id": payload.get("RequestId"),
        "data": payload.get("Data") or {},
    }


def fetch_threat_logs(client, start_text, end_text):
    records = []
    total = None
    offset = 0
    while True:
        req = models.DescribeLogsRequest()
        req.Index = THREAT_INDEX
        req.Limit = MAX_LIMIT
        req.Offset = offset
        req.StartTime = start_text
        req.EndTime = end_text
        resp = client.DescribeLogs(req)
        if resp.ReturnCode != 0:
            raise RuntimeError(f"DescribeLogs failed: {resp.ReturnCode} {resp.ReturnMsg}")

        page = parse_data(resp.Data)
        if total is None:
            total = resp.Total or len(page)
        records.extend(page)
        offset += MAX_LIMIT
        if not page or offset >= total:
            break
    return records, total or 0


def valid_public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global


def split_ips(value):
    if not value:
        return []
    candidates = []
    if isinstance(value, list):
        raw_values = value
    else:
        raw_values = IP_RE.findall(str(value))
    for item in raw_values:
        item = str(item).strip()
        if valid_public_ip(item):
            candidates.append(item)
    return candidates


def choose_attack_ips(record):
    direction = str(record.get("Direction") or "")
    fields = ["SourceIp", "XForwardFor", "XffAll", "XffSpecific"]
    if direction == "0":
        fields = ["TargetIp", "SourceIp", "XForwardFor", "XffAll", "XffSpecific"]

    ips = []
    for field in fields:
        for ip in split_ips(record.get(field)):
            if ip not in ips:
                ips.append(ip)
    return ips


def event_time(record):
    for key in ("BeginTime", "EndTime", "Time", "Timestamp"):
        value = record.get(key)
        if value:
            return str(value)
    return ""


def first_match(pattern, text, flags=re.I):
    match = re.search(pattern, text or "", flags)
    return match.group(1).strip() if match else ""


def compact_text(value, limit=220):
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:limit]


def evidence_marker(text):
    text = text or ""
    markers = []
    checks = [
        ("404", r"\b404\b|Not Found|找不到"),
        ("403", r"\b403\b|Forbidden"),
        ("401", r"\b401\b|Unauthorized"),
        ("500", r"\b50[0-9]\b"),
        ("200", r"\b200\b|HTTP/1\.[01] 200"),
        ("git_ref", r"ref:\s*refs/heads|refs/heads/"),
        ("passwd", r"root:.*:0:0:|/bin/bash"),
        ("phpinfo", r"PHP Version|phpinfo\("),
        ("cmd_uid", r"\buid=\d+|gid=\d+|groups=\d+"),
        ("md5_echo", r"[a-f0-9]{32}"),
        ("index_of", r"Index of /"),
        ("webshell", r"eval\(|assert\(|base64_decode|cmd=|shell"),
    ]
    for name, pattern in checks:
        if re.search(pattern, text, re.I):
            markers.append(name)
    return ",".join(markers[:8])


def decode_hex_section(payload, label, max_bytes=2048):
    match = re.search(label + r":\s*([0-9A-Fa-f\s]{20,})", payload or "", re.I)
    if not match:
        return ""
    hex_text = re.sub(r"[^0-9A-Fa-f]", "", match.group(1))
    if len(hex_text) % 2:
        hex_text = hex_text[:-1]
    if not hex_text:
        return ""
    try:
        raw = bytes.fromhex(hex_text[: max_bytes * 2])
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""


def payload_sections(payload):
    payload = str(payload or "")
    original = payload
    hex_idx = original.find("Hex Message:")
    if hex_idx >= 0:
        original = original[:hex_idx]
    response = decode_hex_section(payload, "Hex Response Message")
    return original, response


def source_evidence_from_record(record):
    payload = str(record.get("Payload") or "")
    original, response_text = payload_sections(payload)
    req_line = first_match(r"Original Message:\s*([^\r\n]+)", original)
    if not req_line:
        req_line = first_match(r"\b((?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+[^\r\n]{1,260})", original)
    host = first_match(r"\bHost:\s*([^\r\n]+)", original)
    ua = first_match(r"\bUser-Agent:\s*([^\r\n]+)", original)
    response_status = first_match(r"(HTTP/1\.[01]\s+\d{3}[^\r\n]*)", response_text)
    if not response_status:
        response_status = first_match(r"(HTTP/1\.[01]\s+\d{3}[^\r\n]*)", payload)
    if not response_status:
        response_status = first_match(r"\b(\d{3}\s+(?:Not Found|Forbidden|Unauthorized|OK|Internal Server Error))", payload)

    evidence = {
        "ar": compact_text(record.get("attack_result"), 80),
        "req": compact_text(req_line, 260),
        "host": compact_text(host, 80),
        "ua": compact_text(ua, 100),
        "resp": compact_text(response_status, 120),
        "req_mark": evidence_marker(original),
        "resp_mark": evidence_marker(response_text),
        "cmd": compact_text(record.get("Cmdline"), 120),
        "flow": compact_text(record.get("flow_id"), 80),
        "log": compact_text(record.get("log_id"), 80),
        "decrypt": str(record.get("decrypt_flow") or ""),
    }
    for key in list(evidence):
        if evidence[key] in ("", "0.0.0.0", "None"):
            evidence.pop(key, None)
    if response_text and "resp" not in evidence:
        evidence["resp_hint"] = compact_text(response_text, 120)
    return evidence


def normalized_event(record, attack_ip, whitelist_label):
    return {
        "event_time": event_time(record),
        "attack_ip": attack_ip,
        "direction": str(record.get("Direction") or ""),
        "level": str(record.get("Level") or ""),
        "event_name": str(record.get("EventName") or ""),
        "threat_type": str(record.get("ThreatType") or ""),
        "source_country": str(record.get("Country") or ""),
        "source_ip": str(record.get("SourceIp") or ""),
        "target_ip": str(record.get("TargetIp") or record.get("PublicIp") or ""),
        "target_port": str(record.get("TargetPort") or record.get("PublicPort") or ""),
        "asset_name": str(record.get("AssetName") or record.get("DstInstanceName") or ""),
        "asset_id": str(record.get("AssetId") or record.get("DstInstanceId") or ""),
        "rule_id": str(record.get("RuleId") or ""),
        "strategy": str(record.get("Strategy") or ""),
        "threat_desc": str(record.get("ThreatDesc") or ""),
        "threat_suggestion": str(record.get("ThreatSuggestion") or ""),
        "source_evidence": source_evidence_from_record(record),
        "whitelist_label": whitelist_label,
    }


def event_key(event):
    parts = [
        event.get("event_time", ""),
        event.get("attack_ip", ""),
        event.get("source_ip", ""),
        event.get("target_ip", ""),
        event.get("target_port", ""),
        event.get("event_name", ""),
        event.get("rule_id", ""),
        event.get("level", ""),
        event.get("direction", ""),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def read_seen(path):
    if not path.exists():
        return set()
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


def append_jsonl(path, rows):
    if not rows:
        return
    with path.open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_lines(path, lines):
    path.write_text("\n".join(sorted(lines)) + ("\n" if lines else ""), encoding="utf-8")


def whitelist_map(config):
    labels = {}
    for ip in config.get("tencent_scan_ips", []):
        labels[ip] = "tencent_scan"
    for ip in config.get("company_scan_ips", []):
        labels[ip] = "company_scan"
    return labels


def collect(args):
    config = load_config()
    client = build_client(config)
    end = now_local()
    if args.start and args.end:
        start_text = args.start
        end_text = args.end
        day = start_text[:10]
    else:
        lookback = args.lookback_hours or int(config.get("lookback_hours", 2))
        start = end - timedelta(hours=lookback)
        start_text = dt_text(start)
        end_text = dt_text(end)
        day = end.strftime("%Y-%m-%d")

    DATA_DIR.mkdir(exist_ok=True)
    LOG_DIR.mkdir(exist_ok=True)

    unhandled = describe_unhandled(client, start_text, end_text)
    append_jsonl(DATA_DIR / f"unhandled-summary-{day}.jsonl", [unhandled])

    records, total = fetch_threat_logs(client, start_text, end_text)
    labels = whitelist_map(config)
    seen_path = DATA_DIR / f"seen-{day}.txt"
    events_path = DATA_DIR / f"events-{day}.jsonl"
    seen = read_seen(seen_path)

    new_events = []
    ignored = Counter()
    for record in records:
        ips = choose_attack_ips(record)
        if not ips:
            ignored["no_public_attack_ip"] += 1
            continue
        for ip in ips:
            label = labels.get(ip, "")
            if label:
                ignored[label] += 1
                continue
            event = normalized_event(record, ip, label)
            key = event_key(event)
            if key in seen:
                ignored["duplicate"] += 1
                continue
            event["recorded_at"] = dt_text(now_local())
            event["event_key"] = key
            new_events.append(event)
            seen.add(key)

    append_jsonl(events_path, new_events)
    write_lines(seen_path, seen)

    window_events = []
    for record in records:
        for ip in choose_attack_ips(record):
            if labels.get(ip):
                continue
            window_events.append(normalized_event(record, ip, ""))
    hourly_rows = build_alert_rows(day, window_events, config)
    if not getattr(args, "skip_triage", False):
        hourly_judgements = llm_judge_rows(config, hourly_rows)
        write_hourly_triage(day, start_text, end_text, hourly_rows, hourly_judgements)
        disposed_rows = apply_judgements([dict(row) for row in hourly_rows], hourly_judgements)
        disposition = auto_dispose_rows(client, config, disposed_rows, records)
        append_jsonl(DATA_DIR / f"auto-dispose-{day}.jsonl", [dict(disposition, recorded_at=dt_text(now_local()))])
        alert_center_disposition = run_alert_center_hourly(config, end_text)
    else:
        hourly_judgements = {}
        disposed_rows = []
        disposition = {"enabled": False, "reason": "skip_triage"}
        alert_center_disposition = {"enabled": False, "reason": "skip_triage", "retained_events": {}, "retained_items": []}

    result = {
        "mode": "collect",
        "start_time": start_text,
        "end_time": end_text,
        "cloud_log_total": total,
        "new_attack_events": len(new_events),
        "hourly_alert_count": len(hourly_rows),
        "hourly_triage_enabled": not getattr(args, "skip_triage", False),
        "ignored": dict(ignored),
        "events_file": str(events_path),
        "unhandled_summary_file": str(DATA_DIR / f"unhandled-summary-{day}.jsonl"),
        "hourly_triage_file": str(DATA_DIR / f"hourly-triage-{day}.jsonl"),
        "auto_dispose": {
            "enabled": disposition.get("enabled", False),
            "ignored_alerts": disposition.get("ignored_alerts", 0),
            "white_rule_candidates": disposition.get("white_rule_candidates", 0),
            "skipped_missing_log_id": disposition.get("skipped_missing_log_id", 0),
        },
        "alert_center_auto_dispose": alert_center_disposition,
    }
    notify_cfg = wecom_config(config)
    if notify_cfg.get("hourly_enabled", True) and (
        hourly_rows or notify_cfg.get("notify_on_empty", True)
    ) and not getattr(args, "skip_triage", False):
        hourly_msg = build_hourly_wecom_message(
            start_text, end_text, total, hourly_rows, disposed_rows,
            disposition, alert_center_disposition,
        )
        result["wecom_notify"] = send_wecom_markdown(config, hourly_msg, "hourly")
        # 仅当本小时有真高危(确认成功 / 高危留存 / 原始流量需关注)才 @所有人,
        # 普通噪声小时静默播报,不打扰。
        ac = alert_center_disposition or {}
        flow_critical = any(
            r.get("模型研判") in ("确认成功", "需人工复核") or r.get("告警等级") in ("严重", "高危")
            for r in disposed_rows
        )
        if notify_cfg.get("hourly_at_all_on_critical", True) and (
            ac.get("retained_success", 0) or ac.get("retained_high", 0) or flow_critical
        ):
            send_wecom_text(
                config,
                f"⚠️ 本小时有需重点关注的告警(高危留存 {ac.get('retained_high', 0)}),详见上方简报,请及时处理。",
                "hourly_at", mentioned_list=["@all"],
            )
    print(json.dumps(result, ensure_ascii=False))


def load_events_for_day(day):
    path = DATA_DIR / f"events-{day}.jsonl"
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def hydrate_events_with_source_evidence(config, day, events):
    llm = config.get("llm") or {}
    source_cfg = llm.get("source_review") or {}
    if not source_cfg.get("hydrate_missing_evidence", True):
        return events
    if not events or all((event.get("source_evidence") or {}) for event in events):
        return events

    labels = whitelist_map(config)
    client = build_client(config)
    today = now_local().strftime("%Y-%m-%d")
    start_text = f"{day} 00:00:00"
    end_text = dt_text(now_local()) if day == today else f"{day} 23:59:59"
    try:
        records, _ = fetch_threat_logs(client, start_text, end_text)
    except Exception:
        return events

    evidence_by_key = {}
    for record in records:
        for ip in choose_attack_ips(record):
            if labels.get(ip):
                continue
            event = normalized_event(record, ip, "")
            evidence = event.get("source_evidence") or {}
            if evidence:
                evidence_by_key[event_key(event)] = evidence

    if not evidence_by_key:
        return events

    hydrated = []
    for event in events:
        if not event.get("source_evidence"):
            key = event.get("event_key") or event_key(event)
            evidence = evidence_by_key.get(key)
            if evidence:
                event = dict(event)
                event["source_evidence"] = evidence
        hydrated.append(event)
    return hydrated


# --- Active source-packet retrieval for alert-center triage ---------------
# Alert-center events are aggregated and carry no raw packet. Instead of only
# hoping a matching event happens to sit in the local day cache, we actively
# pull the threat-log index (rule_threatinfo, which carries the raw Payload)
# for the event's own time window, parse it with source_evidence_from_record,
# and return real request/response/command evidence to the model.

_THREAT_WINDOW_CACHE = {}


def _threat_logs_for_window(config, start_text, end_text):
    """Fetch (and cache) parsed threat logs for a time window string."""
    cache_key = f"{start_text}|{end_text}"
    if cache_key in _THREAT_WINDOW_CACHE:
        return _THREAT_WINDOW_CACHE[cache_key]
    client = build_client(config)
    try:
        records, _ = fetch_threat_logs(client, start_text, end_text)
    except Exception as exc:
        append_llm_error("source_fetch", "threat_logs", [], exc)
        records = []
    index = []
    for record in records:
        evidence = source_evidence_from_record(record)
        if not evidence:
            continue
        src = {str(record.get("SourceIp") or "")}
        for ip in choose_attack_ips(record):
            src.add(str(ip))
        index.append(
            {
                "src_ips": {ip for ip in src if ip},
                "dst_ip": str(record.get("TargetIp") or record.get("PublicIp") or ""),
                "event_name": str(record.get("EventName") or ""),
                "time": event_time(record),
                "evidence": evidence,
            }
        )
    _THREAT_WINDOW_CACHE[cache_key] = index
    return index


def _decode_hex_blob(value, max_bytes=4096):
    """Decode a hex-encoded blob (netflow_nta http_* fields) to text."""
    hex_text = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))
    if len(hex_text) % 2:
        hex_text = hex_text[:-1]
    if not hex_text:
        return ""
    try:
        return bytes.fromhex(hex_text[: max_bytes * 2]).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _netflow_evidence_from_record(record):
    """Build a source_evidence dict from a netflow_nta (NTA) flow record.

    netflow_nta carries full intra-VPC HTTP traffic that the threat index does
    not — request/response headers and the response body, hex-encoded. This is
    the only place internal (10.x/172.x → 10.x) lateral attacks leave a packet.
    """
    # 不看 event_type(可能被标成 TCP),只要能解出 HTTP 请求/响应内容就用。
    req_head = _decode_hex_blob(record.get("http_request_header"))
    req_body = _decode_hex_blob(record.get("http_request_body"), 1024)
    resp_head = _decode_hex_blob(record.get("http_response_header"))
    resp_body = _decode_hex_blob(record.get("http_response_body"))
    if not (req_head or resp_head or resp_body):
        return {}

    req_line = first_match(r"\b((?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+[^\r\n]{1,300})", req_head)
    if not req_line:
        req_line = str(record.get("http_url") or "")
    host = first_match(r"\bHost:\s*([^\r\n]+)", req_head)
    ua = first_match(r"\bUser-Agent:\s*([^\r\n]+)", req_head)
    resp_status = first_match(r"(HTTP/1\.[01]\s+\d{3}[^\r\n]*)", resp_head)

    req_text = req_head + "\n" + req_body
    resp_text = resp_head + "\n" + resp_body
    evidence = {
        "req": compact_text(req_line, 300),
        "host": compact_text(host, 80),
        "ua": compact_text(ua, 100),
        "resp": compact_text(resp_status, 120),
        "req_mark": evidence_marker(req_text),
        # 成功证据主要在响应体里(命令回显/etc passwd/敏感数据),给响应打标记
        "resp_mark": evidence_marker(resp_text),
        "resp_body": compact_text(resp_body, 600),
        "flow": "netflow_nta",
    }
    for key in list(evidence):
        if evidence[key] in ("", "0.0.0.0", "None"):
            evidence.pop(key, None)
    return evidence


def _netflow_logs_for_record(config, record, start_text, end_text, limit=None):
    """Fetch netflow_nta flows for this record's src IPs within the window.

    Filtered by src_ip to keep the query bounded (the raw index has tens of
    millions of rows). Cached per (src_ip|window)."""
    src_ips = [str(ip) for ip in (record.get("SrcIpList") or []) if str(ip)]
    if not src_ips:
        return []
    if limit is None:
        source_cfg = (config.get("llm") or {}).get("source_review") or {}
        limit = int(source_cfg.get("netflow_fetch_limit", 100))

    # netflow_nta 的 DescribeLogs 只对整点对齐的时间窗返回数据,带分秒的边界
    # (如 08:48:50)会返回 Total=0。把窗口 start 下取整、end 上取整到整点。
    def _align(text, ceil):
        try:
            dt = datetime.strptime(str(text), "%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError):
            return text
        if dt.minute or dt.second:
            dt = dt.replace(minute=0, second=0)
            if ceil:
                dt += timedelta(hours=1)
        return dt_text(dt)

    start_text = _align(start_text, ceil=False)
    end_text = _align(end_text, ceil=True)

    client = build_client(config)
    out = []
    for src_ip in src_ips[:4]:
        cache_key = f"netflow|{src_ip}|{start_text}|{end_text}"
        if cache_key in _THREAT_WINDOW_CACHE:
            out.extend(_THREAT_WINDOW_CACHE[cache_key])
            continue
        rows = []
        try:
            req = models.DescribeLogsRequest()
            req.Index = "netflow_nta"
            req.Limit = limit
            req.Offset = 0
            req.StartTime = start_text
            req.EndTime = end_text
            # 按 app_protocol=HTTP 过滤(不是 event_type):NTA 会把一部分本质是
            # HTTP 的流标成 event_type=TCP,但 app_protocol 仍是 HTTP 且带响应体。
            # 用 app_protocol 能把这批“伪装成 TCP 的 HTTP”一起捞回,提高命中率;
            # 同时跳过纯 TCP 元数据噪声(无 payload)。TLS 是密文、UNKNOWN 无结构,
            # 都解不出明文,不取。
            flt_ip = models.CommonFilter()
            flt_ip.Name = "src_ip"
            flt_ip.OperatorType = 1
            flt_ip.Values = [src_ip]
            flt_http = models.CommonFilter()
            flt_http.Name = "app_protocol"
            flt_http.OperatorType = 1
            flt_http.Values = ["HTTP"]
            req.Filters = [flt_ip, flt_http]
            resp = client.DescribeLogs(req)
            for rec in parse_data(resp.Data):
                evidence = _netflow_evidence_from_record(rec)
                if not evidence:
                    continue
                rows.append(
                    {
                        "src_ips": {str(rec.get("src_ip") or src_ip)},
                        "dst_ip": str(rec.get("dst_ip") or ""),
                        "event_name": "",
                        "time": str(rec.get("EndTime") or ""),
                        "evidence": evidence,
                    }
                )
        except Exception as exc:
            append_llm_error("source_fetch", "netflow_nta", [], exc)
        _THREAT_WINDOW_CACHE[cache_key] = rows
        out.extend(rows)
    return out


def _evidence_quality(evidence):
    score = 0
    if evidence.get("cmd"):
        score += 8
    if evidence.get("resp_mark"):
        score += 6
    if evidence.get("resp") or evidence.get("resp_hint"):
        score += 4
    if evidence.get("req_mark"):
        score += 2
    if evidence.get("req"):
        score += 1
    return score


def fetch_source_evidence_for_record(config, record, pad_minutes=10, limit=6):
    """Actively pull raw source packets matching an alert-center record.

    Lenient match: source IP overlap (preferred) and event name, within the
    record's time window padded by pad_minutes. Returns the combined evidence
    of the strongest matches, or {} when nothing relevant is found.
    """
    def _parse(value):
        try:
            return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError):
            return None

    start = _parse(record.get("StartTime"))
    end = _parse(record.get("EndTime"))
    if not start or not end:
        return {}
    src_ips = {str(ip) for ip in (record.get("SrcIpList") or [])}
    dst_ips = {str(ip) for ip in (record.get("DstIpList") or [])}
    event_name = str(record.get("EventName") or "")

    window_start = dt_text(start - timedelta(minutes=pad_minutes))
    window_end = dt_text(end + timedelta(minutes=pad_minutes))

    def _match(candidates, require_event=True, enforce_dst=True):
        out = []
        for item in candidates:
            if src_ips and not (item["src_ips"] & src_ips):
                continue
            if not src_ips and require_event and event_name and item["event_name"] != event_name:
                continue
            if enforce_dst and dst_ips and item["dst_ip"] and item["dst_ip"] not in dst_ips:
                continue
            if require_event and event_name and item["event_name"] and item["event_name"] != event_name:
                out.append((0, item["evidence"]))
                continue
            # dst 匹配上的额外加权,匹配不上的也保留(XFF/代理会改写 dst)。
            dst_bonus = 50 if (dst_ips and item["dst_ip"] in dst_ips) else 0
            out.append((_evidence_quality(item["evidence"]) + 100 + dst_bonus, item["evidence"]))
        return out

    # 第一来源:威胁日志(rule_threatinfo),覆盖公网攻击。
    matched = _match(_threat_logs_for_window(config, window_start, window_end))
    source_tag = "threat_logs"

    # 回退来源:NTA 全流量(netflow_nta),覆盖内网横向(10.x/172.x)攻击 ——
    # 威胁日志查不到内网包,但 NTA 记录了完整内网 HTTP 请求/响应体。
    if not matched:
        netflow = _netflow_logs_for_record(config, record, window_start, window_end)
        # 内网流量按 src_ip 匹配为主,dst 仅加权不强制(XFF/代理改写 dst)。
        matched = _match(netflow, require_event=False, enforce_dst=False)
        source_tag = "netflow_nta"

    if not matched:
        return {}
    matched.sort(key=lambda pair: pair[0], reverse=True)
    selected = [ev for _, ev in matched[:limit]]

    combined = {}
    for key in ("ar", "req", "host", "ua", "resp", "resp_hint", "req_mark", "resp_mark", "resp_body", "cmd"):
        values = []
        for evidence in selected:
            value = str(evidence.get(key) or "").strip()
            if value and value not in values:
                values.append(value)
        if values:
            combined[key] = " || ".join(values)
    combined["flow"] = f"fetched_{source_tag}={len(matched)}"
    combined["_fetched"] = True
    return combined


def action_for(levels, event_names):
    level_set = set(levels)
    names = " ".join(event_names)
    if "严重" in level_set or "高危" in level_set:
        return "建议复核后封禁攻击源；排查目标资产漏洞与补丁"
    if "RCE" in names.upper() or "远程代码" in names or "漏洞利用" in names:
        return "建议优先复核攻击源；检查目标资产漏洞面"
    if "中危" in level_set:
        return "建议复核来源与目标资产；必要时加入封禁"
    return "持续观察；低危/提示类先不自动封禁"


def classify_for(levels, event_names):
    action = action_for(levels, event_names)
    if "封禁" in action:
        return "封禁候选"
    if "优先" in action:
        return "优先排查"
    if "复核" in action:
        return "复核"
    return "观察"


def alert_action_for(level, event_name):
    text = f"{level} {event_name}".upper()
    if level in ("严重", "高危"):
        return "复核后封禁攻击源；排查目标资产漏洞与补丁"
    if any(keyword in text for keyword in ("RCE", "CVE", "命令注入", "代码执行", "SQL注入", "漏洞攻击", "目录遍历")):
        return "优先复核攻击载荷与目标资产；必要时封禁攻击源"
    if any(keyword in text for keyword in ("扫描", "探测", "ZGRAB", "MASSCAN")):
        return "按扫描探测处理；确认非业务来源后加入封禁候选"
    if level == "中危":
        return "复核来源和目标资产访问日志"
    return "观察；低危/提示类不自动封禁"


def alert_classify_for(level, event_name):
    text = f"{level} {event_name}".upper()
    if any(keyword in text for keyword in ("扫描", "探测", "ZGRAB", "MASSCAN")):
        return "扫描探测"
    if level in ("严重", "高危"):
        return "需人工复核"
    if any(keyword in text for keyword in ("RCE", "CVE", "命令注入", "代码执行", "SQL注入", "漏洞攻击", "目录遍历")):
        return "需人工复核"
    return "未见成功证据"


def build_alert_rows(day, events, config):
    labels = whitelist_map(config)
    rows = []
    for event in sorted(events, key=lambda item: item.get("event_time", "")):
        ip = event.get("attack_ip", "")
        if not ip or ip in labels:
            continue
        level = event.get("level", "")
        event_name = event.get("event_name", "")
        alert_id = event.get("event_key") or event_key(event)
        rows.append(
            {
                "日期": day,
                "告警ID": alert_id,
                "告警时间": event.get("event_time", ""),
                "攻击IP": ip,
                "源IP": event.get("source_ip", ""),
                "目标IP": event.get("target_ip", ""),
                "目标端口": event.get("target_port", ""),
                "目标资产": event.get("asset_name", ""),
                "方向": event.get("direction", ""),
                "告警等级": level,
                "事件名称": event_name,
                "威胁类型": event.get("threat_type", ""),
                "来源国家": event.get("source_country", ""),
                "规则ID": event.get("rule_id", ""),
                "策略": event.get("strategy", ""),
                "威胁描述": event.get("threat_desc", ""),
                "云防火墙建议": event.get("threat_suggestion", ""),
                "源包证据": event.get("source_evidence", {}),
                "本地建议": alert_action_for(level, event_name),
                "白名单状态": "非白名单",
            }
        )
    return rows


def build_ip_rows(day, events, config):
    by_ip = defaultdict(list)
    labels = whitelist_map(config)
    for event in events:
        ip = event.get("attack_ip", "")
        if not ip or ip in labels:
            continue
        by_ip[ip].append(event)

    rows = []
    for ip, items in sorted(by_ip.items(), key=lambda item: (-len(item[1]), item[0])):
        levels = [item.get("level", "") for item in items]
        names = [item.get("event_name", "") for item in items if item.get("event_name")]
        targets = [
            (item.get("asset_name") or item.get("target_ip") or "").strip()
            for item in items
            if (item.get("asset_name") or item.get("target_ip"))
        ]
        countries = [item.get("source_country", "") for item in items if item.get("source_country")]
        times = sorted([item.get("event_time", "") for item in items if item.get("event_time")])
        level_counter = Counter(levels)
        rows.append(
            {
                "日期": day,
                "攻击IP": ip,
                "告警数": len(items),
                "严重": level_counter.get("严重", 0),
                "高危": level_counter.get("高危", 0),
                "中危": level_counter.get("中危", 0),
                "低危": level_counter.get("低危", 0),
                "提示": level_counter.get("提示", 0),
                "首次发现": times[0] if times else "",
                "最后发现": times[-1] if times else "",
                "主要事件": "; ".join(name for name, _ in Counter(names).most_common(5)),
                "目标资产": "; ".join(name for name, _ in Counter(targets).most_common(5)),
                "来源国家": "; ".join(name for name, _ in Counter(countries).most_common(3)),
                "建议处置": action_for(levels, names),
                "白名单状态": "非白名单",
            }
        )
    return rows


def judgement_key(row):
    return row.get("告警ID") or row.get("攻击IP", "")


def fallback_judgement(row, source, model):
    key = judgement_key(row)
    if row.get("告警ID"):
        level = row.get("告警等级", "")
        event_name = row.get("事件名称", "")
        return {
            "告警ID": key,
            "攻击IP": row.get("攻击IP", ""),
            "模型研判": alert_classify_for(level, event_name),
            "模型置信度": "低" if source.startswith("rule_fallback") else "中",
            "研判理由": "模型不可用，已按告警等级和事件类型使用本地规则降级",
            "下一步": row.get("本地建议", ""),
            "研判来源": source,
            "研判模型": model,
        }

    levels = []
    for name in ("严重", "高危", "中危", "低危", "提示"):
        try:
            if int(row.get(name) or 0) > 0:
                levels.append(name)
        except ValueError:
            pass
    event_names = [part.strip() for part in str(row.get("主要事件") or "").split(";") if part.strip()]
    return {
        "攻击IP": row.get("攻击IP", ""),
        "模型研判": classify_for(levels, event_names),
        "模型置信度": "低" if source.startswith("rule_fallback") else "中",
        "研判理由": "模型不可用，已按等级、事件类型和频次使用本地规则降级",
        "下一步": row.get("建议处置", ""),
        "研判来源": source,
        "研判模型": model,
    }


def salvage_json_objects(text):
    """从被截断的 JSON 数组里抢救出所有完整的 {...} 对象。

    大批次研判时模型输出可能超长被截断,导致整段 json.loads 失败、整批降级。
    这里逐字符扫描配平花括号,把已经完整的对象一个个抠出来,避免整批丢失。
    """
    objs = []
    depth = 0
    start = -1
    in_str = False
    esc = False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    chunk = text[start:i + 1]
                    try:
                        objs.append(json.loads(chunk))
                    except json.JSONDecodeError:
                        pass
                    start = -1
    return objs


def parse_llm_json(text):
    text = (text or "").strip()
    if not text:
        raise ValueError("empty model response")
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"(\[.*\]|\{.*\})", text, re.S)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
        # 截断抢救:抠出所有完整对象,至少保住一部分研判而非整批降级
        salvaged = salvage_json_objects(text)
        if salvaged:
            return salvaged
        raise


def extract_llm_results(parsed):
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        results = parsed.get("results")
        if isinstance(results, list):
            return results
    raise ValueError("model response results is not a list")


def normalize_direct_result(value):
    value = str(value or "").strip()
    if value in DIRECT_RESULTS:
        return value
    if value in ("成功", "攻击成功", "已成功"):
        return "确认成功"
    if value in ("失败", "未成功", "阻断", "已阻断"):
        return "确认未成功"
    if value in ("扫描", "探测", "扫描探测"):
        return "扫描探测"
    if value in ("复核", "疑似攻击", "封禁候选", "优先排查"):
        return "需人工复核"
    return "未见成功证据" if value in ("观察", "疑似误报", "误报") else "需人工复核"


def normalize_confidence(value):
    return CONFIDENCE_MAP.get(str(value or "").strip().lower(), CONFIDENCE_MAP.get(str(value or "").strip(), "中"))


def call_llm_batch(client, model, batch):
    system = (
        "你是企业云防火墙告警研判助手。只根据输入的汇总字段输出处置建议，"
        "不要执行封禁动作。腾讯云扫描 IP 和公司漏扫 IP 已经在调用前过滤。"
        "输出必须是 JSON，格式为 {\"results\":[...]}; 每个 results 元素必须包含："
        "攻击IP、模型研判、模型置信度、研判理由、下一步。"
        "模型研判只能从 封禁候选、优先排查、复核、观察 中选择。"
        "模型置信度只能从 高、中、低 中选择。理由控制在 60 个中文以内。"
    )
    payload = {
        "alerts": [
            {
                "攻击IP": row.get("攻击IP"),
                "告警数": row.get("告警数"),
                "严重": row.get("严重"),
                "高危": row.get("高危"),
                "中危": row.get("中危"),
                "低危": row.get("低危"),
                "提示": row.get("提示"),
                "主要事件": row.get("主要事件"),
                "目标资产": row.get("目标资产"),
                "来源国家": row.get("来源国家"),
                "首次发现": row.get("首次发现"),
                "最后发现": row.get("最后发现"),
                "本地规则建议": row.get("建议处置"),
            }
            for row in batch
        ]
    }
    response = client.responses.create(
        model=model,
        instructions=system,
        input=json.dumps(payload, ensure_ascii=False),
    )
    parsed = parse_llm_json(getattr(response, "output_text", ""))
    results = extract_llm_results(parsed)
    by_key = {}
    for item in results:
        if not isinstance(item, dict):
            continue
        key = item.get("告警ID") or item.get("攻击IP")
        if key:
            by_key[str(key)] = item
    return by_key


def compact_row(row):
    if row.get("告警ID"):
        return {
            "告警ID": row.get("告警ID"),
            "告警时间": row.get("告警时间"),
            "攻击IP": row.get("攻击IP"),
            "目标资产": row.get("目标资产"),
            "目标IP": row.get("目标IP"),
            "目标端口": row.get("目标端口"),
            "方向": row.get("方向"),
            "告警等级": row.get("告警等级"),
            "事件名称": row.get("事件名称"),
            "威胁类型": row.get("威胁类型"),
            "来源国家": row.get("来源国家"),
            "威胁描述": row.get("威胁描述"),
            "云防火墙建议": row.get("云防火墙建议"),
            "本地建议": row.get("本地建议"),
        }
    return {
        "攻击IP": row.get("攻击IP"),
        "告警数": row.get("告警数"),
        "严重": row.get("严重"),
        "高危": row.get("高危"),
        "中危": row.get("中危"),
        "低危": row.get("低危"),
        "提示": row.get("提示"),
        "主要事件": row.get("主要事件"),
        "目标资产": row.get("目标资产"),
        "来源国家": row.get("来源国家"),
        "本地建议": row.get("建议处置"),
    }


def compact_direct_row(row, index):
    if row.get("告警ID"):
        compact = {
            "id": index,
            "t": row.get("告警时间", ""),
            "ip": row.get("攻击IP", ""),
            "src": row.get("源IP", ""),
            "dst": row.get("目标IP", ""),
            "port": row.get("目标端口", ""),
            "asset": row.get("目标资产", ""),
            "lv": row.get("告警等级", ""),
            "ev": row.get("事件名称", ""),
            "typ": row.get("威胁类型", ""),
            "dir": row.get("方向", ""),
            "country": row.get("来源国家", ""),
            "rule": row.get("规则ID", ""),
            "strategy": row.get("策略", ""),
        }
        if row.get("威胁描述"):
            compact["desc"] = str(row.get("威胁描述"))[:160]
        if row.get("云防火墙建议"):
            compact["suggest"] = str(row.get("云防火墙建议"))[:120]
        # 把已抓到的源包证据(含主动拉取的 HTTP 请求/响应)带进首轮研判,
        # 否则模型看不到包,只能按聚合字段判“无源包”。
        evidence = row.get("源包证据")
        if isinstance(evidence, dict) and evidence:
            trimmed = {}
            for key in ("ar", "req", "resp", "req_mark", "resp_mark", "resp_body", "cmd"):
                value = str(evidence.get(key) or "").strip()
                if value:
                    trimmed[key] = compact_text(value, 300 if key in ("resp_body", "req") else 140)
            if trimmed:
                compact["e"] = trimmed
        return compact

    return {
        "id": index,
        "ip": row.get("攻击IP", ""),
        "cnt": row.get("告警数", ""),
        "sev": {
            "严重": row.get("严重", 0),
            "高危": row.get("高危", 0),
            "中危": row.get("中危", 0),
            "低危": row.get("低危", 0),
            "提示": row.get("提示", 0),
        },
        "events": row.get("主要事件", ""),
        "asset": row.get("目标资产", ""),
        "country": row.get("来源国家", ""),
    }


def parse_codex_jsonl(stdout):
    usage = None
    agent_text = ""
    for line in stdout.splitlines():
        try:
            evt = json.loads(line)
        except Exception:
            continue
        if evt.get("type") == "item.completed" and evt.get("item", {}).get("type") == "agent_message":
            agent_text = evt.get("item", {}).get("text", "")
        if evt.get("type") == "turn.completed":
            usage = evt.get("usage")
    return agent_text, usage


def call_codex_batch(config, model, batch):
    llm = config.get("llm") or {}
    codex_path = llm.get("codex_path") or "codex.cmd"
    direct_alert = bool(batch and batch[0].get("告警ID"))
    if direct_alert:
        task_text = (
            "对输入云防火墙单条告警逐条研判，给出results数组。"
            "字段: 告警ID,攻击IP,模型研判,模型置信度,研判理由,下一步。"
            "模型研判取值:确认成功/确认未成功/未见成功证据/扫描探测/需人工复核。"
            "确认成功必须有明确成功证据。置信度:高/中/低。理由30字内。"
        )
    else:
        task_text = (
            "对输入攻击IP汇总告警给出results数组，字段: 攻击IP,模型研判,模型置信度,研判理由,下一步。"
            "模型研判取值:封禁候选/优先排查/复核/观察。置信度:高/中/低。理由30字内。"
        )
    prompt = (
        "只输出紧凑JSON，不要解释。你是云防火墙告警研判助手。"
        + task_text
        + "腾讯云扫描IP和公司漏扫IP已过滤。不能声称已经执行封禁。"
        "\n"
        + json.dumps(
            {"alerts": [compact_row(row) for row in batch]},
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )
    cmd = [
        codex_path,
        "exec",
        "-m",
        model,
        "--skip-git-repo-check",
        "--ephemeral",
        "--ignore-rules",
        "-s",
        "read-only",
        "--json",
        "-",
    ]
    if llm.get("ignore_user_config", True):
        cmd.insert(6, "--ignore-user-config")
    proc = subprocess.run(
        cmd,
        input=prompt.encode("utf-8"),
        capture_output=True,
        timeout=float(llm.get("timeout_seconds", 240)),
    )
    stdout = proc.stdout.decode("utf-8", errors="replace")
    stderr = proc.stderr.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        raise RuntimeError((stderr or stdout or f"codex exited {proc.returncode}")[:1000])
    text, usage = parse_codex_jsonl(stdout)
    parsed = parse_llm_json(text)
    results = extract_llm_results(parsed)
    by_key = {}
    for item in results:
        if isinstance(item, dict) and (item.get("告警ID") or item.get("攻击IP")):
            item["_usage"] = usage or {}
            key = item.get("告警ID") or item.get("攻击IP")
            by_key[str(key)] = item
    return by_key, usage or {}


def load_codex_auth_headers():
    try:
        auth = json.loads(CODEX_AUTH_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"cannot read Codex auth file: {CODEX_AUTH_PATH}") from exc
    tokens = auth.get("tokens") or {}
    access_token = tokens.get("access_token")
    account_id = tokens.get("account_id")
    if not access_token or not account_id:
        raise RuntimeError(f"missing access_token/account_id in {CODEX_AUTH_PATH}")
    return {
        "Accept": "text/event-stream",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
        "ChatGPT-Account-ID": account_id,
        "OAI-Product-Sku": "codex",
    }


_CODEX_OPENER = None
_CODEX_OPENER_KEY = None


def _codex_opener(config):
    """构建走代理的 urllib opener(本机直连 chatgpt.com 不稳,需经本地代理)。

    读 llm.proxy(如 http://127.0.0.1:10808);留空则直连。opener 按 proxy 缓存。
    """
    global _CODEX_OPENER, _CODEX_OPENER_KEY
    proxy = str((config.get("llm") or {}).get("proxy") or "").strip()
    if _CODEX_OPENER is not None and _CODEX_OPENER_KEY == proxy:
        return _CODEX_OPENER
    if proxy:
        handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        _CODEX_OPENER = urllib.request.build_opener(handler)
    else:
        _CODEX_OPENER = urllib.request.build_opener()  # 无代理=直连
    _CODEX_OPENER_KEY = proxy
    return _CODEX_OPENER


def _codex_urlopen(config, req, timeout):
    """对 Codex 接口发请求,自动走配置的代理。"""
    return _codex_opener(config).open(req, timeout=timeout)


def codex_direct_prompt(batch, id_map):
    direct_alert = bool(batch and batch[0].get("告警ID"))
    compact_rows = []
    for index, row in enumerate(batch, start=1):
        id_map[index] = judgement_key(row)
        compact_rows.append(compact_direct_row(row, index))

    if direct_alert:
        task = (
            "逐条复核云防火墙告警是否攻击成功。结果只能取:"
            "确认成功,确认未成功,未见成功证据,扫描探测,需人工复核。"
            "字段e是已抓取的真实源数据包(ar=攻击结果,req=请求行,resp=响应状态,"
            "resp_mark/req_mark=特征标记,resp_body=响应体,cmd=命令回显);有e时必须"
            "基于真实包给出有依据的初步结论,不要再判“无源包”。"
            "确认成功必须有明确证据: ar成功、命令执行回显、文件写入、webshell、"
            "敏感数据返回(如响应体含/etc/passwd内容、uid=、phpinfo)、回连。"
            "请求里带../etc/passwd等利用串且resp为200并在resp_body看到敏感内容→确认成功;"
            "resp为404/403/401或WAF阻断→确认未成功;有利用请求但响应非成功且无回显→未见成功证据;"
            "纯扫描器特征→扫描探测;有真实包但证据矛盾或确实高危且无法定论→需人工复核。"
            "单独HTTP 200、普通页面、ETag、哈希样字符串不算成功证据。"
        )
    else:
        task = (
            "逐条复核攻击IP汇总风险。结果只能取:需人工复核,扫描探测,未见成功证据。"
            "根据等级、频次和事件类型给出下一步。"
        )
    return (
        task
        + "只输出JSON数组，每项字段:id,result,confidence,evidence,next,key_evidence。"
        "confidence取high/medium/low。evidence(判定依据)不超过40个汉字,next不超过20个汉字。"
        "key_evidence摘抄源包中最支撑结论的原文片段(≤120字符),无源包则空串。"
        "腾讯云扫描IP和公司漏扫IP已过滤，不能声称已经执行封禁。告警="
        + json.dumps(compact_rows, ensure_ascii=False, separators=(",", ":"))
    )


def codex_direct_request_body(model, prompt, reasoning_effort="low"):
    return {
        "model": model,
        "instructions": "你是安全告警复核助手。只输出符合用户要求的紧凑JSON，不输出解释。",
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": prompt}],
            }
        ],
        "tools": [],
        "tool_choice": "none",
        "parallel_tool_calls": False,
        "reasoning": {"effort": reasoning_effort},
        "store": False,
        "stream": True,
        "include": [],
        "text": {"verbosity": "low"},
    }


def parse_codex_direct_usage(usage):
    usage = usage or {}
    input_details = usage.get("input_tokens_details") or {}
    output_details = usage.get("output_tokens_details") or {}
    return {
        "input_tokens": usage.get("input_tokens", ""),
        "cached_input_tokens": input_details.get("cached_tokens", ""),
        "output_tokens": usage.get("output_tokens", ""),
        "reasoning_output_tokens": output_details.get("reasoning_tokens", ""),
        "total_tokens": usage.get("total_tokens", ""),
    }


def extract_completed_output(response):
    parts = []
    for item in response.get("output") or []:
        if item.get("type") != "message":
            continue
        for content in item.get("content") or []:
            if content.get("type") == "output_text" and content.get("text"):
                parts.append(content["text"])
    return "".join(parts)


def handle_codex_direct_sse(event_name, data):
    if data == "[DONE]":
        return event_name, "", None, None
    payload = json.loads(data)
    event_type = payload.get("type") or event_name
    if event_type == "response.output_text.delta":
        return event_type, payload.get("delta", ""), None, None
    if event_type == "response.completed":
        response = payload.get("response") or {}
        return event_type, extract_completed_output(response), response.get("usage"), response.get("id")
    if event_type in {"response.failed", "response.incomplete"}:
        response = payload.get("response") or {}
        error = response.get("error") or payload.get("error") or {}
        raise RuntimeError(f"{event_type}: {json.dumps(error, ensure_ascii=False)[:800]}")
    return event_type, "", None, None


def _retry_cfg(config):
    llm = config.get("llm") or {}
    retry = llm.get("retry") or {}
    return (
        max(0, int(retry.get("max_retries", 2))),
        float(retry.get("backoff_seconds", 2.0)),
        float(retry.get("backoff_factor", 2.0)),
    )


def with_codex_retry(config, attempt_fn, label):
    """对一次完整的请求+流式消费做重试。

    只在连接类错误(URLError/超时/不完整读取)上重试——这些是抖动,重试有意义;
    HTTPError(4xx/5xx 业务错误)和已解析的 RuntimeError 立即抛出,重试无益。
    指数退避。重试事件记入 llm-errors.jsonl 便于在控制台看降级前的抖动。
    """
    max_retries, backoff, factor = _retry_cfg(config)
    delay = backoff
    last_exc = None
    for attempt in range(max_retries + 1):
        try:
            return attempt_fn()
        except urllib.error.HTTPError:
            raise  # 业务错误,重试无意义
        except (urllib.error.URLError, TimeoutError, ConnectionError,
                http.client.IncompleteRead, http.client.RemoteDisconnected) as exc:
            last_exc = exc
            if attempt >= max_retries:
                break
            append_jsonl(LOG_DIR / "llm-errors.jsonl", [{
                "time": dt_text(now_local()),
                "provider": label,
                "model": (config.get("llm") or {}).get("model", ""),
                "error_type": "retry_" + type(exc).__name__,
                "error": f"attempt {attempt + 1}/{max_retries + 1} failed: {str(exc)[:300]}",
            }])
            time.sleep(delay)
            delay *= factor
    raise last_exc


def call_codex_direct_batch(config, model, batch):
    llm = config.get("llm") or {}
    id_map = {}
    prompt = codex_direct_prompt(batch, id_map)
    body = json.dumps(
        codex_direct_request_body(model, prompt, llm.get("reasoning_effort", "medium")),
        ensure_ascii=False,
    ).encode("utf-8")
    req = urllib.request.Request(
        llm.get("codex_responses_url") or CODEX_RESPONSES_URL,
        data=body,
        method="POST",
        headers=load_codex_auth_headers(),
    )

    started = time.perf_counter()

    def _attempt():
        output_chunks = []
        usage = {}
        response_id = ""
        try:
            with _codex_urlopen(config, req, float(llm.get("timeout_seconds", 180))) as resp:
                event_name = None
                data_lines = []
                for raw_line in resp:
                    line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                    if not line:
                        if data_lines:
                            event_type, text, event_usage, event_response_id = handle_codex_direct_sse(
                                event_name, "\n".join(data_lines)
                            )
                            if text and (event_type != "response.completed" or not output_chunks):
                                output_chunks.append(text)
                            if event_usage is not None:
                                usage = parse_codex_direct_usage(event_usage)
                            if event_response_id:
                                response_id = event_response_id
                            if event_type == "response.completed":
                                break
                        event_name = None
                        data_lines = []
                        continue
                    if line.startswith("event:"):
                        event_name = line.split(":", 1)[1].strip()
                    elif line.startswith("data:"):
                        data_lines.append(line.split(":", 1)[1].lstrip())
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"codex direct HTTP {exc.code}: {body_text[:800]}") from exc
        return output_chunks, usage, response_id

    output_chunks, usage, response_id = with_codex_retry(config, _attempt, "codex_direct")

    parsed = parse_llm_json("".join(output_chunks))
    results = extract_llm_results(parsed)
    by_key = {}
    for item in results:
        if not isinstance(item, dict):
            continue
        try:
            key = id_map.get(int(item.get("id")))
        except Exception:
            key = None
        if not key:
            key = item.get("告警ID") or item.get("攻击IP")
        if key:
            item["模型研判"] = normalize_direct_result(item.get("result") or item.get("模型研判"))
            item["模型置信度"] = normalize_confidence(item.get("confidence") or item.get("模型置信度"))
            item["研判理由"] = str(item.get("evidence") or item.get("研判理由") or "")[:120]
            item["下一步"] = str(item.get("next") or item.get("下一步") or "")[:80]
            item["关键证据"] = str(item.get("key_evidence") or item.get("关键证据") or "")[:160]
            by_key[str(key)] = item
    usage["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    usage["response_id"] = response_id
    return by_key, usage


# =========================================================================
# Agent 工具循环研判(复用 Codex 订阅,无需 API key)
#
# 与单轮研判的区别:给模型一组“只读取证”工具,模型自己决定取哪些证、取几轮,
# 最后基于真实证据给出带证据链的结论。所有工具只读取证,绝不处置 —— 忽略/加白
# 仍由本地规则代码执行,模型不碰云资源,保住安全边界。
# =========================================================================

TRIAGE_TOOLS = [
    {
        "type": "function",
        "name": "pull_packets",
        "description": (
            "拉取指定攻击源IP在该告警时间窗内的真实源数据包(HTTP请求行、响应状态、"
            "响应体片段、命令回显标记)。判断攻击是否成功前应优先调用。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "攻击源IP,取告警的源IP之一"},
            },
            "required": ["ip"],
        },
    },
    {
        "type": "function",
        "name": "decode_hex",
        "description": "把源包里的hex编码片段解码成明文文本,用于看清响应体或载荷内容。",
        "parameters": {
            "type": "object",
            "properties": {
                "hex": {"type": "string", "description": "hex字符串"},
            },
            "required": ["hex"],
        },
    },
    {
        "type": "function",
        "name": "get_related_alerts",
        "description": "查同一攻击源IP在近几天的其他未处理告警,判断是否在持续攻击或多点尝试。",
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "攻击源IP"},
                "days": {"type": "integer", "description": "回溯天数,默认2"},
            },
            "required": ["ip"],
        },
    },
    {
        "type": "function",
        "name": "query_flow",
        "description": (
            "查询该源IP的真实流量元数据(netflow,即使非HTTP也能查)。返回访问的URL、"
            "目标端口、源/目标实例名、协议、字节数。当 pull_packets 拉不到HTTP源包时,"
            "用这个换个角度看流量:URL是业务路径还是攻击路径、源/目标是不是业务服务,"
            "据此判断是真实攻击还是内网业务被误报。"
        ),
        "parameters": {
            "type": "object",
            "properties": {"ip": {"type": "string", "description": "要查的源IP"}},
            "required": ["ip"],
        },
    },
    {
        "type": "function",
        "name": "identify_asset",
        "description": (
            "查询一个IP是什么资产(CVM/容器POD名、是否为 ingress入口/oss存储/网关等"
            "基础设施)。用于判断:内网源打内网基础设施(ingress/oss)多为业务调用误报;"
            "打数据库/敏感服务才更可疑。"
        ),
        "parameters": {
            "type": "object",
            "properties": {"ip": {"type": "string", "description": "要查的IP(源或目标)"}},
            "required": ["ip"],
        },
    },
    {
        "type": "function",
        "name": "check_ip_history",
        "description": (
            "查询一个IP近期的行为画像:历史告警类型/次数、是否内网、是否曾被人工确认过。"
            "用于判断这是反复误报的业务IP,还是新出现的可疑源。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "要查的IP"},
                "days": {"type": "integer", "description": "回溯天数,默认5"},
            },
            "required": ["ip"],
        },
    },
]


def _tool_pull_packets(config, record, args):
    ip = str(args.get("ip") or "")
    # 用告警自身的时间窗;若指定了某个 IP,临时收窄到该 IP 提高相关性
    sub = dict(record)
    if ip:
        sub["SrcIpList"] = [ip]
    evidence = fetch_source_evidence_for_record(config, sub)
    if not evidence:
        return {"found": False, "note": "该IP在时间窗内无可解析HTTP源包(可能为非HTTP流量)"}
    # 精简返回,避免塞爆上下文
    out = {k: v for k, v in evidence.items() if k in (
        "req", "resp", "resp_mark", "resp_body", "req_mark", "cmd", "host", "ua", "ar", "flow")}
    out["found"] = True
    return out


def _tool_decode_hex(config, record, args):
    text = _decode_hex_blob(args.get("hex"), max_bytes=2048)
    return {"text": text[:1000]} if text else {"text": "", "note": "无法解码"}


def _tool_get_related_alerts(config, record, args):
    ip = str(args.get("ip") or "")
    days = int(args.get("days") or 2)
    try:
        import cfw_alert_center_triage as triage
        records, _ = triage.fetch_unhandled_alert_center(config, days)
    except Exception as exc:
        return {"error": str(exc)[:200]}
    related = []
    for r in records:
        if ip in [str(x) for x in (r.get("SrcIpList") or [])]:
            related.append({
                "event": str(r.get("EventName") or ""),
                "level": str(r.get("Level") or ""),
                "time": str(r.get("EndTime") or ""),
                "ar": str(r.get("AttackResult") or ""),
            })
    return {"ip": ip, "count": len(related), "alerts": related[:15]}


def _query_netflow_raw(config, ip, record=None, limit=15):
    """查 netflow_nta 该源IP的流量(任意协议),返回精简元数据列表。"""
    # 时间窗:优先用告警自身窗口,否则用近6小时
    def _parse(v):
        try:
            return datetime.strptime(str(v), "%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError):
            return None
    end = _parse((record or {}).get("EndTime")) or now_local()
    start = _parse((record or {}).get("StartTime")) or (end - timedelta(hours=6))
    # netflow 只认整点对齐窗口
    s = start.replace(minute=0, second=0)
    e = (end.replace(minute=0, second=0) + timedelta(hours=1))
    try:
        req = models.DescribeLogsRequest()
        req.Index = "netflow_nta"
        req.Limit = limit
        req.Offset = 0
        req.StartTime = dt_text(s)
        req.EndTime = dt_text(e)
        flt = models.CommonFilter()
        flt.Name = "src_ip"
        flt.OperatorType = 1
        flt.Values = [str(ip)]
        req.Filters = [flt]
        resp = build_client(config).DescribeLogs(req)
        rows = []
        for r in parse_data(resp.Data):
            rows.append({k: r.get(k) for k in (
                "dst_ip", "dst_port", "event_type", "app_protocol",
                "src_ins_name", "dst_ins_name", "http_url") if r.get(k)})
        return rows
    except Exception as exc:
        return [{"error": str(exc)[:150]}]


# 基础设施资产名特征(打这些多为业务调用,误报概率高)
_INFRA_HINTS = ("ingress", "oss", "gateway", "网关", "nginx", "proxy", "lb-", "slb", "redis", "mq", "kafka")


def _tool_query_flow(config, record, args):
    ip = str(args.get("ip") or "")
    flows = _query_netflow_raw(config, ip, record, limit=20)
    if not flows or (len(flows) == 1 and flows[0].get("error")):
        return {"found": False, "note": "无流量记录", "raw": flows}
    # 汇总:目标实例、URL、端口
    urls = sorted({f.get("http_url") for f in flows if f.get("http_url")})[:8]
    dst_assets = sorted({f.get("dst_ins_name") for f in flows if f.get("dst_ins_name")})[:5]
    ports = sorted({str(f.get("dst_port")) for f in flows if f.get("dst_port")})
    src_asset = next((f.get("src_ins_name") for f in flows if f.get("src_ins_name")), "")
    return {
        "found": True, "src_asset": src_asset, "dst_assets": dst_assets,
        "dst_ports": ports[:8], "urls": urls, "flow_count": len(flows),
    }


def _tool_identify_asset(config, record, args):
    ip = str(args.get("ip") or "")
    # 先从告警记录里的实例列表找,再从 netflow 找
    name, atype = "", ""
    for inst in (record.get("DstInstanceList") or []) + (record.get("SrcInstanceList") or []):
        if isinstance(inst, dict) and str(inst.get("InstanceIp")) == ip:
            name, atype = str(inst.get("InstanceName") or ""), str(inst.get("InstanceType") or "")
            break
    if not name:
        flows = _query_netflow_raw(config, ip, record, limit=5)
        name = next((f.get("src_ins_name") or f.get("dst_ins_name") for f in flows
                     if f.get("src_ins_name") or f.get("dst_ins_name")), "")
    is_infra = any(h in str(name).lower() for h in _INFRA_HINTS)
    try:
        internal = not __import__("ipaddress").ip_address(ip).is_global
    except ValueError:
        internal = False
    return {"ip": ip, "asset_name": name, "asset_type": atype,
            "is_infrastructure": is_infra, "internal": internal,
            "note": "基础设施(ingress/oss/网关等),内网调用多为业务" if is_infra else ""}


def _tool_check_ip_history(config, record, args):
    ip = str(args.get("ip") or "")
    days = int(args.get("days") or 5)
    try:
        internal = not __import__("ipaddress").ip_address(ip).is_global
    except ValueError:
        internal = False
    # 历史告警
    try:
        import cfw_alert_center_triage as triage
        recs, _ = triage.fetch_unhandled_alert_center(config, days)
    except Exception as exc:
        return {"error": str(exc)[:150]}
    from collections import Counter
    evs = Counter()
    for r in recs:
        if ip in [str(x) for x in (r.get("SrcIpList") or [])]:
            evs[str(r.get("EventName") or "")] += 1
    # 是否曾人工放弃/确认(retry-giveup 留痕)
    confirmed = False
    try:
        gp = ROOT / "data" / "retry-giveup.jsonl"
        if gp.exists():
            confirmed = ip in gp.read_text(encoding="utf-8")
    except Exception:
        pass
    return {"ip": ip, "internal": internal, "alert_types": dict(evs.most_common(8)),
            "total_alerts": sum(evs.values()), "seen_before": confirmed}


TOOL_DISPATCH = {
    "pull_packets": _tool_pull_packets,
    "decode_hex": _tool_decode_hex,
    "get_related_alerts": _tool_get_related_alerts,
    "query_flow": _tool_query_flow,
    "identify_asset": _tool_identify_asset,
    "check_ip_history": _tool_check_ip_history,
}


def dispatch_tool(name, args, config, record):
    fn = TOOL_DISPATCH.get(name)
    if not fn:
        return {"error": f"unknown tool {name}"}
    try:
        return fn(config, record, args or {})
    except Exception as exc:
        return {"error": str(exc)[:300]}


def _agent_request_body(model, input_items, reasoning_effort):
    return {
        "model": model,
        "instructions": (
            "你是资深安全告警研判员。判断云防火墙告警攻击是否成功,必须基于工具取到的"
            "真实证据,不能凭聚合字段或请求特征臆断。可多次调用工具取证,要查深查透。"
            "取证策略(重要):先 pull_packets 拉源包;若拉不到(常见于内网流量),"
            "不要就此判'未见证据',必须换招继续查:用 query_flow 看该IP真实流量的URL/端口/"
            "目标实例,用 identify_asset 看源和目标是什么资产,用 check_ip_history 看这IP历史行为。"
            "综合判断:内网业务节点访问内网基础设施(ingress/oss/网关)、URL是业务路径(如"
            "/v1/.../geo/conver 这类接口)、无敏感操作 → 是'内网业务被IDS误报',判确认未成功或"
            "未见成功证据(高置信),不要判需人工。只有出现命令回显/webshell/敏感数据外泄/异常端口"
            "回连/打数据库等敏感服务,才判确认成功或保留人工。"
            "得到足够证据后,只输出一个紧凑JSON对象(不要解释、不要数组),字段:"
            "result(确认成功/确认未成功/未见成功证据/扫描探测/需人工复核),"
            "confidence(high/medium/low),evidence(判定依据,≤40汉字),"
            "next(下一步,≤20汉字),key_evidence(支撑结论的源包原文片段/流量URL/资产名,≤120字符,无则空串)。"
            "确认成功必须有命令回显/文件写入/webshell/敏感数据返回/回连等明确落地证据;"
            "单独HTTP200、普通页面、内网业务接口调用不算成功。"
            "尽量给出确定结论,只有证据确实矛盾或确实高危无法定论时才用需人工复核。"
        ),
        "input": input_items,
        "tools": TRIAGE_TOOLS,
        "tool_choice": "auto",
        "parallel_tool_calls": False,
        "reasoning": {"effort": reasoning_effort},
        "store": False,
        "stream": True,
        "include": [],
    }


def _agent_stream_once(config, body):
    """发一轮请求,流式收集:最终文本、本轮发起的 function_call 列表、usage。"""
    llm = config.get("llm") or {}
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        llm.get("codex_responses_url") or CODEX_RESPONSES_URL,
        data=data, method="POST", headers=load_codex_auth_headers(),
    )

    def _attempt():
        text_parts = []
        calls = {}  # item_id -> {call_id,name,arguments}
        usage = {}
        try:
            with _codex_urlopen(config, req, float(llm.get("timeout_seconds", 180))) as resp:
                event_name = None
                data_lines = []
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
                    blob = "\n".join(data_lines)
                    data_lines = []
                    event_name = None
                    if blob == "[DONE]":
                        continue
                    try:
                        payload = json.loads(blob)
                    except Exception:
                        continue
                    et = payload.get("type") or ""
                    if et == "response.output_text.delta":
                        text_parts.append(payload.get("delta", ""))
                    elif et == "response.output_item.added":
                        item = payload.get("item") or {}
                        if item.get("type") == "function_call":
                            calls[item.get("id")] = {
                                "call_id": item.get("call_id"),
                                "name": item.get("name"),
                                "arguments": item.get("arguments") or "",
                            }
                    elif et == "response.function_call_arguments.delta":
                        cid = payload.get("item_id")
                        if cid in calls:
                            calls[cid]["arguments"] += payload.get("delta", "")
                    elif et == "response.function_call_arguments.done":
                        cid = payload.get("item_id")
                        if cid in calls and payload.get("arguments"):
                            calls[cid]["arguments"] = payload.get("arguments")
                    elif et == "response.completed":
                        response = payload.get("response") or {}
                        if not text_parts:
                            text_parts.append(extract_completed_output(response))
                        usage = parse_codex_direct_usage(response.get("usage"))
                    elif et in {"response.failed", "response.incomplete"}:
                        response = payload.get("response") or {}
                        err = response.get("error") or payload.get("error") or {}
                        raise RuntimeError(f"{et}: {json.dumps(err, ensure_ascii=False)[:400]}")
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"codex agent HTTP {exc.code}: {body_text[:400]}") from exc
        return "".join(text_parts), list(calls.values()), usage

    return with_codex_retry(config, _attempt, "codex_agent")


def run_codex_agent_triage(config, record, row, model, max_rounds=6):
    """对单条告警跑工具循环研判,返回研判 dict(含证据链),失败返回 None。"""
    llm = config.get("llm") or {}
    agent_cfg = llm.get("agent_triage") or {}
    effort = agent_cfg.get("reasoning_effort", "high")
    max_rounds = int(agent_cfg.get("max_rounds", max_rounds))

    seed = {
        "告警ID": row.get("告警ID"),
        "事件名称": row.get("事件名称"),
        "告警等级": row.get("告警等级"),
        "攻击IP": row.get("攻击IP"),
        "目标IP": row.get("目标IP"),
        "威胁描述": row.get("威胁描述"),
    }
    input_items = [{
        "type": "message", "role": "user",
        "content": [{"type": "input_text",
                     "text": "研判这条告警,先用工具取证再下结论。告警=" +
                             json.dumps(seed, ensure_ascii=False, separators=(",", ":"))}],
    }]
    agg_usage = {"input_tokens": 0, "output_tokens": 0, "reasoning_output_tokens": 0}
    tool_trace = []
    for round_idx in range(max_rounds):
        # 最后一轮强制收尾:tool_choice=none,模型必须给结论而不能再调工具,
        # 避免一直调工具撞轮数上限后返回 None。
        last_round = round_idx == max_rounds - 1
        body = _agent_request_body(model, input_items, effort)
        if last_round:
            body["tool_choice"] = "none"
        text, calls, usage = _agent_stream_once(config, body)
        for k in agg_usage:
            try:
                agg_usage[k] += int(usage.get(k) or 0)
            except (TypeError, ValueError):
                pass
        if calls and not last_round:
            for call in calls:
                try:
                    args = json.loads(call["arguments"]) if call["arguments"] else {}
                except Exception:
                    args = {}
                result = dispatch_tool(call["name"], args, config, record)
                tool_trace.append({"tool": call["name"], "args": args})
                # 把模型的 function_call 与我们的执行结果都回填,模型才能续推
                input_items.append({
                    "type": "function_call",
                    "call_id": call["call_id"],
                    "name": call["name"],
                    "arguments": call["arguments"],
                })
                input_items.append({
                    "type": "function_call_output",
                    "call_id": call["call_id"],
                    "output": json.dumps(result, ensure_ascii=False)[:4000],
                })
            continue  # 有工具调用,进入下一轮让模型看结果
        # 无工具调用 = 最终结论
        parsed = _parse_agent_final(text)
        if not parsed:
            return None
        parsed["研判来源"] = "codex_agent"
        parsed["研判模型"] = model
        parsed["工具轨迹"] = ";".join(t["tool"] for t in tool_trace)
        parsed["输入Token"] = str(agg_usage["input_tokens"])
        parsed["输出Token"] = str(agg_usage["output_tokens"])
        parsed["推理Token"] = str(agg_usage["reasoning_output_tokens"])
        return parsed
    return None  # 超过轮数上限仍未收敛


def _parse_agent_final(text):
    try:
        parsed = parse_llm_json(text)
    except Exception:
        return None
    if isinstance(parsed, list):
        parsed = parsed[0] if parsed else {}
    if not isinstance(parsed, dict):
        return None
    result = normalize_direct_result(parsed.get("result") or parsed.get("模型研判"))
    return {
        "模型研判": result,
        "模型置信度": normalize_confidence(parsed.get("confidence") or parsed.get("模型置信度")),
        "研判理由": str(parsed.get("evidence") or parsed.get("研判理由") or "")[:120],
        "下一步": str(parsed.get("next") or parsed.get("下一步") or "")[:80],
        "关键证据": str(parsed.get("key_evidence") or parsed.get("关键证据") or "")[:160],
    }


def source_review_enabled(config):
    llm = config.get("llm") or {}
    source_cfg = llm.get("source_review") or {}
    return llm.get("provider") == "codex_direct" and bool(source_cfg.get("enabled", True))


def source_evidence(row):
    evidence = row.get("源包证据") or {}
    return evidence if isinstance(evidence, dict) else {}


def source_group_key(row):
    evidence = source_evidence(row)
    req = evidence.get("req") or ""
    req_fingerprint = hashlib.sha1(req.encode("utf-8", errors="ignore")).hexdigest()[:10] if req else ""
    return "|".join(
        [
            row.get("攻击IP", ""),
            row.get("目标IP", ""),
            row.get("目标端口", ""),
            row.get("事件名称", ""),
            row.get("规则ID", ""),
            req_fingerprint,
        ]
    )


def has_source_evidence(row):
    evidence = source_evidence(row)
    return bool(
        evidence.get("req")
        or evidence.get("resp")
        or evidence.get("ar")
        or evidence.get("req_mark")
        or evidence.get("resp_mark")
        or evidence.get("resp_body")
    )


def has_success_source_evidence(row):
    evidence = source_evidence(row)
    attack_result = str(evidence.get("ar") or "").lower()
    if any(word in attack_result for word in ("success", "succeed", "成功", "命中成功")):
        return True
    if evidence.get("cmd"):
        return True
    resp_mark = set(str(evidence.get("resp_mark") or "").split(","))
    success_marks = {"git_ref", "passwd", "phpinfo", "cmd_uid", "index_of", "webshell"}
    if resp_mark & success_marks:
        return True
    # 内网 NTA 抓到的响应体里若出现命令回显/敏感文件标记,也算成功证据
    body_marks = set(evidence_marker(str(evidence.get("resp_body") or "")).split(","))
    return bool(body_marks & success_marks)


def compact_source_review_row(row, index, max_chars):
    evidence = dict(source_evidence(row))
    trimmed = {}
    # 成功证据主要藏在响应体和命令回显里,给这些字段更宽的预算,避免回显被截断
    # 导致“看不出成功”。请求侧只是攻击特征,保持较短。
    wide_keys = {"resp", "resp_hint", "resp_mark", "resp_body", "cmd", "decrypt"}
    for key in ("ar", "req", "host", "ua", "resp", "resp_hint", "req_mark", "resp_mark", "resp_body", "cmd", "flow", "log", "decrypt"):
        value = evidence.get(key)
        if not value:
            continue
        if key == "req":
            limit = max_chars
        elif key in wide_keys:
            limit = max(max_chars, 600)
        else:
            limit = 120
        trimmed[key] = compact_text(value, limit)
    return {
        "id": index,
        "prev": row.get("模型研判", ""),
        "conf": row.get("模型置信度", ""),
        "ip": row.get("攻击IP", ""),
        "dst": row.get("目标IP", ""),
        "port": row.get("目标端口", ""),
        "asset": row.get("目标资产", ""),
        "lv": row.get("告警等级", ""),
        "ev": row.get("事件名称", ""),
        "typ": row.get("威胁类型", ""),
        "e": trimmed,
    }


def source_review_prompt(batch, id_map, max_chars):
    rows = []
    for index, row in enumerate(batch, start=1):
        id_map[index] = source_group_key(row)
        rows.append(compact_source_review_row(row, index, max_chars))
    return (
        "根据源包摘要复核云防火墙告警是否攻击成功，重点减少不必要人工复核。"
        "结果只能取:确认成功,确认未成功,未见成功证据,扫描探测,需人工复核。"
        "判定规则: 有命令执行/文件写入/webshell/敏感数据返回/有效回显/回连才确认成功；"
        "注意:req和req_mark只是攻击请求特征，不能单独作为成功证据；"
        "只有ar成功、cmd、resp_mark或响应内容体现成功时才能确认成功；"
        "单独HTTP 200、普通页面、ETag或哈希样字符串不是成功证据；"
        "响应为404/403/401、WAF阻断、无有效回显且只有利用尝试时确认未成功或未见成功证据；"
        "目录扫描、敏感文件探测、zgrab/masscan/censys特征判扫描探测；"
        "只有缺关键源包证据且确实高危才保留需人工复核。"
        "对高危(lv=高危)告警必须逐条审视响应体/命令回显,给出可复核的证据链,不要只给标签。"
        "只输出JSON数组，每项字段:id,result,confidence,evidence,next,key_evidence。"
        "evidence用不超过40个汉字说明判定依据;next不超过20个汉字;"
        "key_evidence直接摘抄源包中最能支撑结论的原文片段(命令回显/响应状态/敏感数据,≤120字符),无则空串。"
        "confidence取high/medium/low。样本="
        + json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    )


def call_codex_direct_source_batch(config, model, batch):
    llm = config.get("llm") or {}
    source_cfg = llm.get("source_review") or {}
    max_chars = int(source_cfg.get("max_evidence_chars", 420))
    id_map = {}
    prompt = source_review_prompt(batch, id_map, max_chars)
    # 高危深度研判通道:批次含高危告警时,把推理强度升到 high,让模型真正
    # 沿证据链推断而不是浅层归类。普通批次维持配置的较低强度以控成本。
    base_effort = source_cfg.get("reasoning_effort", llm.get("reasoning_effort", "medium"))
    has_high = any(row.get("告警等级") == "高危" for row in batch)
    effort = source_cfg.get("high_reasoning_effort", "high") if has_high else base_effort
    body = json.dumps(
        codex_direct_request_body(model, prompt, effort),
        ensure_ascii=False,
    ).encode("utf-8")
    req = urllib.request.Request(
        llm.get("codex_responses_url") or CODEX_RESPONSES_URL,
        data=body,
        method="POST",
        headers=load_codex_auth_headers(),
    )

    started = time.perf_counter()

    def _attempt():
        output_chunks = []
        usage = {}
        try:
            with _codex_urlopen(config, req, float(llm.get("timeout_seconds", 180))) as resp:
                event_name = None
                data_lines = []
                for raw_line in resp:
                    line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                    if not line:
                        if data_lines:
                            event_type, text, event_usage, _ = handle_codex_direct_sse(event_name, "\n".join(data_lines))
                            if text and (event_type != "response.completed" or not output_chunks):
                                output_chunks.append(text)
                            if event_usage is not None:
                                usage = parse_codex_direct_usage(event_usage)
                            if event_type == "response.completed":
                                break
                        event_name = None
                        data_lines = []
                        continue
                    if line.startswith("event:"):
                        event_name = line.split(":", 1)[1].strip()
                    elif line.startswith("data:"):
                        data_lines.append(line.split(":", 1)[1].lstrip())
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"codex source review HTTP {exc.code}: {body_text[:800]}") from exc
        return output_chunks, usage

    output_chunks, usage = with_codex_retry(config, _attempt, "source_review")

    parsed = parse_llm_json("".join(output_chunks))
    results = extract_llm_results(parsed)
    by_group = {}
    for item in results:
        if not isinstance(item, dict):
            continue
        try:
            key = id_map.get(int(item.get("id")))
        except Exception:
            key = None
        if key:
            by_group[key] = {
                "模型研判": normalize_direct_result(item.get("result") or item.get("模型研判")),
                "模型置信度": normalize_confidence(item.get("confidence") or item.get("模型置信度")),
                "研判理由": str(item.get("evidence") or item.get("研判理由") or "")[:120],
                "下一步": str(item.get("next") or item.get("下一步") or "")[:80],
                "关键证据": str(item.get("key_evidence") or item.get("关键证据") or "")[:160],
            }
    usage["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    return by_group, usage


def refine_judgements_with_source(config, rows, judgements, model):
    if not source_review_enabled(config):
        return judgements
    llm = config.get("llm") or {}
    source_cfg = llm.get("source_review") or {}
    max_groups = int(source_cfg.get("max_groups_per_run", 200))
    batch_size = max(1, int(source_cfg.get("batch_size", 60)))

    # 只要抓到了真实源包就做源包深度研判,不再因为首轮贴了浅标签而跳过 ——
    # 这是“拉到 HTTP 源包必须基于包给结论”的关键。可用 review_all_with_evidence
    # 关掉,退回只复核“需人工复核”。
    review_all = bool(source_cfg.get("review_all_with_evidence", True))
    groups = {}
    for row in rows:
        key = judgement_key(row)
        judgement = judgements.get(key) or {}
        result = judgement.get("模型研判")
        if not has_source_evidence(row):
            continue
        if not review_all and result != "需人工复核":
            continue
        # 首轮已高置信判定为纯扫描的,无需再花一轮(扫描器特征足够明确)。
        if result == "扫描探测" and judgement.get("模型置信度") == "高":
            continue
        group_key = source_group_key(row)
        groups.setdefault(group_key, row)
        if len(groups) >= max_groups:
            break

    if not groups:
        return judgements

    group_rows = list(groups.values())
    batches = [group_rows[i : i + batch_size] for i in range(0, len(group_rows), batch_size)]
    group_results = {}
    with ThreadPoolExecutor(max_workers=max(1, int(llm.get("max_workers", 3)))) as executor:
        future_map = {executor.submit(call_codex_direct_source_batch, config, model, batch): batch for batch in batches}
        for future in as_completed(future_map):
            batch = future_map[future]
            try:
                by_group, usage = future.result()
            except Exception as exc:
                append_llm_error("source_review", model, batch, exc)
                continue
            for group_key, item in by_group.items():
                item["_usage"] = usage
                group_results[group_key] = item

    for row in rows:
        key = judgement_key(row)
        group_key = source_group_key(row)
        item = group_results.get(group_key)
        if not item:
            continue
        current = judgements.get(key) or {}
        model_result = item.get("模型研判", current.get("模型研判", ""))
        model_reason = item.get("研判理由", current.get("研判理由", ""))
        if model_result == "确认成功" and not has_success_source_evidence(row):
            model_result = "未见成功证据"
            model_reason = "仅请求侧特征"
        merged = dict(current)
        merged.update(
            {
                "模型研判": model_result,
                "模型置信度": item.get("模型置信度", current.get("模型置信度", "")),
                "研判理由": model_reason,
                "下一步": item.get("下一步", current.get("下一步", "")),
                "关键证据": item.get("关键证据", current.get("关键证据", "")),
                "研判来源": "codex_direct_source",
                "研判模型": model,
                "输入Token": str((item.get("_usage") or {}).get("input_tokens", current.get("输入Token", ""))),
                "输出Token": str((item.get("_usage") or {}).get("output_tokens", current.get("输出Token", ""))),
                "推理Token": str((item.get("_usage") or {}).get("reasoning_output_tokens", current.get("推理Token", ""))),
            }
        )
        judgements[key] = merged
    return judgements


def codex_reachable(config, timeout=6):
    """轻量探测 Codex 接口可达性(只建连+读少量字节)。不可达返回 False。"""
    llm = config.get("llm") or {}
    url = llm.get("codex_responses_url") or CODEX_RESPONSES_URL
    try:
        body = json.dumps(codex_direct_request_body(llm.get("model", "gpt-5.5"), "ping", "low"),
                          ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST", headers=load_codex_auth_headers())
        with _codex_urlopen(config, req, timeout) as resp:
            resp.read(64)
        return True
    except urllib.error.HTTPError:
        return True  # 服务器有响应(哪怕业务错误),说明网络通
    except Exception:
        return False


def llm_judge_rows(config, rows):
    llm = config.get("llm") or {}
    model = llm.get("model", "gpt-5.5")
    if not rows:
        return {}
    if not llm.get("enabled", False):
        return {judgement_key(row): fallback_judgement(row, "rule_fallback_llm_disabled", model) for row in rows}

    provider = llm.get("provider", "codex_cli")
    # 连接预检:provider 为 codex_direct 且接口不可达时,整轮短路,全部降级
    # (避免每条干等超时;这些会被上层重试队列接住,网络恢复时补判)。
    if provider == "codex_direct" and llm.get("precheck", True):
        if not codex_reachable(config, timeout=int(llm.get("precheck_timeout", 6))):
            append_llm_error("precheck", model, [], RuntimeError("codex unreachable, skip LLM this run"))
            return {judgement_key(row): fallback_judgement(row, "rule_fallback_codex_unreachable", model) for row in rows}
    batch_size = max(1, int(llm.get("batch_size", 8)))
    max_workers = max(1, int(llm.get("max_workers", 6)))
    batches = [rows[i : i + batch_size] for i in range(0, len(rows), batch_size)]
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        if provider == "codex_direct":
            future_map = {executor.submit(call_codex_direct_batch, config, model, batch): batch for batch in batches}
        elif provider == "codex_cli":
            future_map = {executor.submit(call_codex_batch, config, model, batch): batch for batch in batches}
        else:
            if not os.getenv("OPENAI_API_KEY"):
                return {
                    judgement_key(row): fallback_judgement(row, "rule_fallback_missing_openai_api_key", model)
                    for row in rows
                }
            try:
                from openai import OpenAI
            except Exception:
                return {
                    judgement_key(row): fallback_judgement(row, "rule_fallback_openai_sdk_missing", model)
                    for row in rows
                }
            client = OpenAI(timeout=float(llm.get("timeout_seconds", 45)))
            future_map = {executor.submit(call_llm_batch, client, model, batch): batch for batch in batches}
        for future in as_completed(future_map):
            batch = future_map[future]
            try:
                future_result = future.result()
                if provider in ("codex_cli", "codex_direct"):
                    by_key, usage = future_result
                else:
                    by_key, usage = future_result, {}
            except Exception as exc:
                append_llm_error(provider, model, batch, exc)
                by_key = {}
                usage = {}
            for row in batch:
                key = judgement_key(row)
                item = by_key.get(key)
                if item:
                    judgement = str(item.get("模型研判") or item.get("result") or "需人工复核")
                    confidence = str(item.get("模型置信度") or item.get("confidence") or "中")
                    reason = str(item.get("研判理由") or item.get("evidence") or "")
                    next_step = str(item.get("下一步") or item.get("next") or row.get("本地建议") or row.get("建议处置") or "")
                    if provider == "codex_direct":
                        judgement = normalize_direct_result(judgement)
                        confidence = normalize_confidence(confidence)
                    results[key] = {
                        "告警ID": key if row.get("告警ID") else "",
                        "攻击IP": row.get("攻击IP", ""),
                        "模型研判": judgement,
                        "模型置信度": confidence,
                        "研判理由": reason,
                        "关键证据": str(item.get("关键证据") or ""),
                        "下一步": next_step,
                        "研判来源": provider,
                        "研判模型": model,
                        "输入Token": str((usage or {}).get("input_tokens", "")),
                        "输出Token": str((usage or {}).get("output_tokens", "")),
                        "推理Token": str((usage or {}).get("reasoning_output_tokens", "")),
                    }
                else:
                    results[key] = fallback_judgement(row, "rule_fallback_model_parse_error", model)
            # 整批 miss 说明该批次解析失败/返回空,记日志使其在控制台可见,
            # 否则大批降级会静默发生(eval 已暴露过日报批次 90% 降级)。
            miss = sum(1 for row in batch if not by_key.get(judgement_key(row)))
            if miss and miss == len(batch):
                append_jsonl(LOG_DIR / "llm-errors.jsonl", [{
                    "time": dt_text(now_local()),
                    "provider": provider + "_parse_miss",
                    "model": model,
                    "batch_size": len(batch),
                    "error_type": "batch_all_fallback",
                    "error": f"批次 {len(batch)} 条全部降级(解析失败或空响应)",
                }])
    results = refine_judgements_with_source(config, rows, results, model)
    return escalate_with_agent(config, rows, results, model)


def escalate_with_agent(config, rows, judgements, model):
    """对高危/需人工复核的告警升级为 Agent 工具循环研判(模型自主取证)。

    只对值得的子集开(贵+慢),Agent 失败保留原判。可用 agent_triage.enabled 关闭。
    """
    llm = config.get("llm") or {}
    agent_cfg = llm.get("agent_triage") or {}
    if not (llm.get("provider") == "codex_direct" and agent_cfg.get("enabled", False)):
        return judgements

    # 小时任务有超时限制,Agent 多轮很慢,只升级最该查的少量;日报无紧超时可多。
    # HOURLY_MODE 由 safe_hourly 入口设置。
    if globals().get("_HOURLY_AGENT_MODE"):
        max_alerts = int(agent_cfg.get("max_alerts_hourly", 15))
    else:
        max_alerts = int(agent_cfg.get("max_alerts_per_run", 40))
    max_workers = max(1, int(agent_cfg.get("max_workers", 2)))

    targets = []
    for row in rows:
        key = judgement_key(row)
        cur = judgements.get(key) or {}
        result = cur.get("模型研判")
        level = row.get("告警等级")
        # 升级条件:高危,或仍需人工复核(单轮+源包都没定论的),才值得多轮深挖
        if level == "高危" or result == "需人工复核":
            targets.append((key, row))
        if len(targets) >= max_alerts:
            break
    if not targets:
        return judgements

    record_by_key = {judgement_key(row): row.get("_record") for row in rows}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(run_codex_agent_triage, config, record_by_key.get(key) or {}, row, model): key
            for key, row in targets
        }
        for future in as_completed(future_map):
            key = future_map[future]
            try:
                agent_result = future.result()
            except Exception as exc:
                append_llm_error("codex_agent", model, [], exc)
                continue
            if not agent_result:
                continue
            merged = dict(judgements.get(key) or {})
            merged.update(agent_result)
            # 安全闸:Agent 判“确认成功”但行内无成功源包证据时,降回未见成功证据
            row = next((r for k, r in targets if k == key), None)
            if row is not None and agent_result.get("模型研判") == "确认成功" and not has_success_source_evidence(row):
                merged["模型研判"] = "未见成功证据"
                merged["研判理由"] = "Agent判成功但无落地源包证据"
            judgements[key] = merged
    return judgements


def append_llm_error(provider, model, batch, exc):
    LOG_DIR.mkdir(exist_ok=True)
    payload = {
        "time": dt_text(now_local()),
        "provider": provider,
        "model": model,
        "batch_size": len(batch),
        "error_type": type(exc).__name__,
        "error": str(exc)[:2000],
    }
    append_jsonl(LOG_DIR / "llm-errors.jsonl", [payload])


def apply_judgements(rows, judgements):
    for row in rows:
        judgement = judgements.get(judgement_key(row)) or {}
        row["模型研判"] = judgement.get("模型研判", "")
        row["模型置信度"] = judgement.get("模型置信度", "")
        row["研判理由"] = judgement.get("研判理由", "")
        row["下一步"] = judgement.get("下一步", "")
        row["研判来源"] = judgement.get("研判来源", "")
        row["研判模型"] = judgement.get("研判模型", "")
        row["输入Token"] = judgement.get("输入Token", "")
        row["输出Token"] = judgement.get("输出Token", "")
        row["推理Token"] = judgement.get("推理Token", "")
    return rows


def write_hourly_triage(day, start_text, end_text, rows, judgements):
    payload = {
        "recorded_at": dt_text(now_local()),
        "start_time": start_text,
        "end_time": end_text,
        "alert_count": len(rows),
        "rows": apply_judgements([dict(row) for row in rows], judgements),
    }
    append_jsonl(DATA_DIR / f"hourly-triage-{day}.jsonl", [payload])


def write_csv(path, fieldnames, rows):
    target = path
    try:
        fh = target.open("w", newline="", encoding="utf-8-sig")
    except PermissionError:
        stamp = now_local().strftime("%H%M%S")
        target = path.with_name(f"{path.stem}-{stamp}{path.suffix}")
        fh = target.open("w", newline="", encoding="utf-8-sig")
    with fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return target


def chunks(items, size):
    for index in range(0, len(items), size):
        yield items[index : index + size]


def response_snapshot(resp):
    payload = json.loads(resp.to_json_string())
    payload.pop("RequestId", None)
    return payload


def auto_dispose_config(config):
    llm = config.get("llm") or {}
    auto_cfg = llm.get("auto_dispose") or {}
    if "enabled" not in auto_cfg:
        auto_cfg["enabled"] = False
    return auto_cfg


def alert_log_id(row):
    evidence = source_evidence(row)
    return evidence.get("log") or row.get("日志ID") or row.get("log_id") or ""


def ignore_candidate_result(config):
    auto_cfg = auto_dispose_config(config)
    values = auto_cfg.get("ignore_results")
    if not values:
        return DEFAULT_AUTO_IGNORE_RESULTS
    return {str(value) for value in values}


def omit_alerts(client, log_ids, config):
    auto_cfg = auto_dispose_config(config)
    batch_size = max(1, int(auto_cfg.get("batch_size", 50)))
    table_type = auto_cfg.get("omit_table_type", "AlertTable")
    unique_ids = sorted({str(item).strip() for item in log_ids if str(item).strip()})
    results = []
    for batch in chunks(unique_ids, batch_size):
        req = models.CreateAlertCenterOmitRequest()
        req.HandleIdList = batch
        req.TableType = table_type
        try:
            resp = client.CreateAlertCenterOmit(req)
            results.append(
                {
                    "action": "omit",
                    "count": len(batch),
                    "return_code": resp.ReturnCode,
                    "return_msg": resp.ReturnMsg,
                    "status": resp.Status,
                    "request_id": resp.RequestId,
                }
            )
        except Exception as exc:
            results.append({"action": "omit", "count": len(batch), "error": str(exc)})
    return results


def ids_white_candidates_from_records(records, config):
    labels = whitelist_map(config)
    candidates = {}
    for record in records:
        rule_id = str(record.get("RuleId") or "").strip()
        if not rule_id:
            continue
        dst_ip = str(record.get("TargetIp") or record.get("PublicIp") or "").strip()
        for ip in choose_attack_ips(record):
            label = labels.get(ip)
            if not label:
                continue
            key = (rule_id, ip, dst_ip)
            candidates[key] = {
                "rule_id": rule_id,
                "src_ip": ip,
                "dst_ip": dst_ip,
                "label": label,
                "event_name": str(record.get("EventName") or ""),
            }
    return list(candidates.values())


def create_ids_white_rules(client, candidates, config):
    auto_cfg = auto_dispose_config(config)
    if not auto_cfg.get("ids_white_enabled", True):
        return []
    white_rule_type = auto_cfg.get("ids_white_rule_type", "srcdst")
    fw_type = int(auto_cfg.get("ids_white_fw_type", 7))
    results = []
    for item in candidates:
        req = models.CreateIdsWhiteRuleRequest()
        req.IdsRuleId = item["rule_id"]
        req.WhiteRuleType = white_rule_type
        req.FwType = fw_type
        req.SrcIp = item["src_ip"]
        if white_rule_type in ("dst", "srcdst"):
            req.DstIp = item.get("dst_ip") or ""
        try:
            resp = client.CreateIdsWhiteRule(req)
            results.append(
                {
                    "action": "ids_white",
                    "rule_id": item["rule_id"],
                    "src_ip": item["src_ip"],
                    "dst_ip": item.get("dst_ip", ""),
                    "label": item.get("label", ""),
                    "event_name": item.get("event_name", ""),
                    "return_code": resp.ReturnCode,
                    "return_msg": resp.ReturnMsg,
                    "status": resp.Status,
                    "request_id": resp.RequestId,
                }
            )
        except Exception as exc:
            results.append(
                {
                    "action": "ids_white",
                    "rule_id": item["rule_id"],
                    "src_ip": item["src_ip"],
                    "dst_ip": item.get("dst_ip", ""),
                    "label": item.get("label", ""),
                    "event_name": item.get("event_name", ""),
                    "error": str(exc),
                }
            )
    return results


def load_alert_report_judgements(day):
    path = REPORT_DIR / f"cfw_alert_judgement_{day}.csv"
    if not path.exists():
        return {}
    rows = []
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            key = row.get("告警ID") or ""
            if key:
                rows.append((key, row))
    return {key: row for key, row in rows}


def auto_dispose_rows(client, config, rows, records=None):
    auto_cfg = auto_dispose_config(config)
    if not auto_cfg.get("enabled", False):
        return {"enabled": False, "ignored_alerts": 0, "white_rule_candidates": 0, "actions": []}

    ignore_results = ignore_candidate_result(config)
    log_ids = []
    skipped_missing_log_id = 0
    for row in rows:
        if row.get("模型研判") not in ignore_results:
            continue
        log_id = alert_log_id(row)
        if log_id:
            log_ids.append(log_id)
        else:
            skipped_missing_log_id += 1

    actions = []
    actions.extend(omit_alerts(client, log_ids, config))

    white_candidates = ids_white_candidates_from_records(records or [], config)
    actions.extend(create_ids_white_rules(client, white_candidates, config))

    return {
        "enabled": True,
        "ignored_alerts": len(set(log_ids)),
        "skipped_missing_log_id": skipped_missing_log_id,
        "white_rule_candidates": len(white_candidates),
        "actions": actions,
    }


def add_alert_judgement_counts(ip_rows, alert_rows):
    counters = defaultdict(Counter)
    for row in alert_rows:
        ip = row.get("攻击IP", "")
        judgement = row.get("模型研判", "")
        if ip and judgement:
            counters[ip][judgement] += 1

    for row in ip_rows:
        counter = counters.get(row.get("攻击IP", ""), Counter())
        row["确认成功告警数"] = counter.get("确认成功", 0)
        row["确认未成功告警数"] = counter.get("确认未成功", 0)
        row["未见成功证据告警数"] = counter.get("未见成功证据", 0)
        row["扫描探测告警数"] = counter.get("扫描探测", 0)
        row["需人工复核告警数"] = counter.get("需人工复核", 0)
    return ip_rows


def ip_summary_fieldnames():
    return [
        "日期",
        "攻击IP",
        "告警数",
        "严重",
        "高危",
        "中危",
        "低危",
        "提示",
        "首次发现",
        "最后发现",
        "主要事件",
        "目标资产",
        "来源国家",
        "建议处置",
        "确认成功告警数",
        "确认未成功告警数",
        "未见成功证据告警数",
        "扫描探测告警数",
        "需人工复核告警数",
        "白名单状态",
    ]


def report(args):
    config = load_config()
    day = args.date or now_local().strftime("%Y-%m-%d")

    if args.refresh:
        client = build_client(config)
        start_text = f"{day} 00:00:00"
        end_text = dt_text(now_local()) if day == now_local().strftime("%Y-%m-%d") else f"{day} 23:59:59"
        tmp_args = argparse.Namespace(start=start_text, end=end_text, lookback_hours=None, skip_triage=True)
        collect(tmp_args)

    if getattr(args, "ip_only", False):
        events = load_events_for_day(day)
    else:
        events = hydrate_events_with_source_evidence(config, day, load_events_for_day(day))
    REPORT_DIR.mkdir(exist_ok=True)

    alert_out = REPORT_DIR / f"cfw_alert_judgement_{day}.csv"
    ip_out = REPORT_DIR / f"cfw_attack_ip_summary_{day}.csv"

    if getattr(args, "ip_only", False):
        ip_rows = build_ip_rows(day, events, config)
        ip_rows = add_alert_judgement_counts(ip_rows, [])
        ip_out = write_csv(ip_out, ip_summary_fieldnames(), ip_rows)
        result = {
            "mode": "report_ip_only",
            "date": day,
            "attack_ip_count": len(ip_rows),
            "event_count": len(events),
            "ip_summary_file": str(ip_out),
        }
        if wecom_config(config).get("daily_enabled", True):
            result["wecom_notify"] = send_wecom_markdown(
                config,
                build_daily_wecom_message(day, events, ip_rows),
                "daily",
            )
        print(json.dumps(result, ensure_ascii=False))
        return

    alert_rows = build_alert_rows(day, events, config)
    if getattr(args, "limit", None):
        alert_rows = alert_rows[: args.limit]
    alert_judgements = llm_judge_rows(config, alert_rows)
    alert_rows = apply_judgements(alert_rows, alert_judgements)

    alert_fieldnames = [
        "日期",
        "告警ID",
        "告警时间",
        "攻击IP",
        "源IP",
        "目标IP",
        "目标端口",
        "目标资产",
        "方向",
        "告警等级",
        "事件名称",
        "威胁类型",
        "来源国家",
        "规则ID",
        "策略",
        "威胁描述",
        "云防火墙建议",
        "源包证据",
        "本地建议",
        "模型研判",
        "模型置信度",
        "研判理由",
        "下一步",
        "研判来源",
        "研判模型",
        "输入Token",
        "输出Token",
        "推理Token",
        "白名单状态",
    ]
    alert_out = write_csv(alert_out, alert_fieldnames, alert_rows)

    ip_rows = build_ip_rows(day, events, config)
    ip_rows = add_alert_judgement_counts(ip_rows, alert_rows)
    ip_out = write_csv(ip_out, ip_summary_fieldnames(), ip_rows)

    result = {
        "mode": "report",
        "date": day,
        "alert_count": len(alert_rows),
        "attack_ip_count": len(ip_rows),
        "event_count": len(events),
        "alert_report_file": str(alert_out),
        "ip_summary_file": str(ip_out),
    }
    if wecom_config(config).get("daily_enabled", True):
        result["wecom_notify"] = send_wecom_markdown(
            config,
            build_daily_wecom_message(day, events, ip_rows, alert_rows),
            "daily",
        )
    print(json.dumps(result, ensure_ascii=False))


def fetch_records_for_day(config, day):
    today = now_local().strftime("%Y-%m-%d")
    start_text = f"{day} 00:00:00"
    end_text = dt_text(now_local()) if day == today else f"{day} 23:59:59"
    client = build_client(config)
    records, total = fetch_threat_logs(client, start_text, end_text)
    return client, records, total, start_text, end_text


def alert_rows_from_records(day, records, config):
    labels = whitelist_map(config)
    events = []
    for record in records:
        for ip in choose_attack_ips(record):
            if labels.get(ip):
                continue
            event = normalized_event(record, ip, "")
            event["event_key"] = event_key(event)
            events.append(event)
    return build_alert_rows(day, events, config)


def apply_report_judgements(rows, report_judgements):
    applied = []
    missing = 0
    for row in rows:
        key = judgement_key(row)
        report_row = report_judgements.get(key)
        if not report_row:
            missing += 1
            continue
        merged = dict(row)
        for name in ("模型研判", "模型置信度", "研判理由", "下一步", "研判来源", "研判模型", "输入Token", "输出Token", "推理Token"):
            merged[name] = report_row.get(name, "")
        applied.append(merged)
    return applied, missing


def dispose(args):
    config = load_config()
    day = args.date or now_local().strftime("%Y-%m-%d")
    report_judgements = load_alert_report_judgements(day)
    if not report_judgements:
        raise RuntimeError(f"missing alert judgement CSV for {day}; run report first")

    client, records, total, start_text, end_text = fetch_records_for_day(config, day)
    rows = alert_rows_from_records(day, records, config)
    applied_rows, missing_judgement = apply_report_judgements(rows, report_judgements)
    disposition = auto_dispose_rows(client, config, applied_rows, records)

    out = {
        "mode": "dispose",
        "date": day,
        "start_time": start_text,
        "end_time": end_text,
        "cloud_log_total": total,
        "alert_rows": len(rows),
        "judged_rows": len(applied_rows),
        "missing_judgement": missing_judgement,
        "ignored_alerts": disposition.get("ignored_alerts", 0),
        "skipped_missing_log_id": disposition.get("skipped_missing_log_id", 0),
        "white_rule_candidates": disposition.get("white_rule_candidates", 0),
        "actions": disposition.get("actions", []),
    }
    REPORT_DIR.mkdir(exist_ok=True)
    out_path = REPORT_DIR / f"cfw_disposition_{day}.json"
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    append_jsonl(DATA_DIR / f"auto-dispose-{day}.jsonl", [dict(out, recorded_at=dt_text(now_local()))])
    out["disposition_file"] = str(out_path)
    print(json.dumps(out, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description="Tencent Cloud Firewall alert monitor.")
    sub = parser.add_subparsers(dest="command", required=True)

    collect_parser = sub.add_parser("collect")
    collect_parser.add_argument("--lookback-hours", type=int, default=None)
    collect_parser.add_argument("--start")
    collect_parser.add_argument("--end")
    collect_parser.add_argument("--skip-triage", action="store_true")
    collect_parser.set_defaults(func=collect)

    report_parser = sub.add_parser("report")
    report_parser.add_argument("--date")
    report_parser.add_argument("--refresh", action="store_true")
    report_parser.add_argument("--limit", type=int)
    report_parser.add_argument("--ip-only", action="store_true")
    report_parser.set_defaults(func=report)

    dispose_parser = sub.add_parser("dispose")
    dispose_parser.add_argument("--date")
    dispose_parser.set_defaults(func=dispose)

    args = parser.parse_args()
    try:
        args.func(args)
    except (TencentCloudSDKException, RuntimeError, OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
