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


def send_wecom_markdown(config, content, notification_type):
    notify_cfg = wecom_config(config)
    result = {
        "enabled": bool(notify_cfg.get("enabled", False)),
        "type": notification_type,
        "sent": False,
    }
    webhook_url = str(notify_cfg.get("webhook_url") or "").strip()
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


def build_hourly_wecom_message(start_text, end_text, total, rows, judged_rows, disposition, alert_center):
    levels = Counter(row.get("告警等级", "") for row in rows if row.get("告警等级"))
    judgements = Counter(row.get("模型研判", "") for row in judged_rows if row.get("模型研判"))
    event_names = Counter(row.get("事件名称", "") for row in rows if row.get("事件名称"))
    review_rows = [
        row
        for row in judged_rows
        if row.get("模型研判") in ("确认成功", "需人工复核")
        or row.get("告警等级") in ("严重", "高危")
    ]
    review_names = Counter(row.get("事件名称", "") for row in review_rows if row.get("事件名称"))
    fallback_count = sum(
        1 for row in judged_rows if str(row.get("研判来源", "")).startswith("rule_fallback")
    )
    retained_events = Counter(alert_center.get("retained_events") or {})
    lines = [
        "## 云防火墙每小时告警处理",
        f"> 时间窗：{start_text} 至 {end_text}",
        f"- 原始流量：日志 **{total}**，研判 **{len(rows)}**，忽略 **{disposition.get('ignored_alerts', 0)}**",
        f"- 原始流量等级：{counter_text(levels, ['严重', '高危', '中危', '低危', '提示'])}",
        f"- 原始流量研判：{counter_text(judgements, ['确认成功', '需人工复核', '确认未成功', '未见成功证据', '扫描探测'])}",
        f"- 告警中心：检查 **{alert_center.get('active_before', 0)}**，忽略 **{alert_center.get('ignored_confirmed', 0)}**，保留 **{alert_center.get('retained', 0)}**",
        f"- 告警中心保留：高危 **{alert_center.get('retained_high', 0)}**，攻击成功 **{alert_center.get('retained_success', 0)}**",
        f"- 告警中心主要保留事件：{counter_text(retained_events, limit=5)}",
        f"- 处置失败：原始流量 **{disposition_failures(disposition)}**，告警中心 **{disposition_failures({'actions': alert_center.get('omit_actions', []) + alert_center.get('white_actions', [])})}**",
    ]
    retained_items = alert_center.get("retained_items") or []
    retained_count = int(alert_center.get("retained", len(retained_items)) or 0)
    total_review = len(review_rows) + retained_count
    if total_review:
        lines.append(f"- <font color=\"warning\">需要关注：原始流量 **{len(review_rows)}** 条，告警中心 **{retained_count}** 条</font>")
        priority = {"确认成功": 0, "严重": 1, "高危": 2, "需人工复核": 3}
        review_rows.sort(
            key=lambda row: (
                priority.get(row.get("模型研判"), priority.get(row.get("告警等级"), 9)),
                row.get("告警时间", ""),
            )
        )
        for row in review_rows[:5]:
            target = row.get("目标资产") or row.get("目标IP") or "未知目标"
            lines.append(
                f"> {row.get('模型研判') or row.get('告警等级')} | "
                f"{row.get('事件名称') or '未知事件'} | "
                f"{row.get('攻击IP') or '未知来源'} -> {target}"
            )
        for item in retained_items[:5]:
            src = "|".join(item.get("src_ips") or []) or "未知来源"
            dst = "|".join(item.get("dst_ips") or []) or "未知目标"
            lines.append(
                f"> 告警中心保留 | {item.get('event_name') or '未知事件'} | "
                f"{src} -> {dst} | {item.get('reason') or '需复核'}"
            )
    else:
        lines.append("- <font color=\"info\">本小时两个数据源均无需要关注的告警</font>")
    if fallback_count:
        lines.append(f"- <font color=\"warning\">模型降级：**{fallback_count}** 条使用本地规则，结果需注意</font>")
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

    return "\n".join(
        [
            "## 云防火墙每日告警日报",
            f"> 日期：{day}，统计截至 {dt_text(now_local())}",
            f"- 唯一告警：**{len(events)}**，攻击 IP：**{len(ip_rows)}**",
            f"- 告警等级：{counter_text(levels, ['严重', '高危', '中危', '低危', '提示'])}",
            f"- 唯一告警最终研判：{counter_text(judgement_counts, ['确认成功', '需人工复核', '确认未成功', '未见成功证据', '扫描探测'])}",
            f"- 研判来源：{counter_text(source_counts, ['codex_direct_source', 'codex_direct'])}",
            f"- 模型降级：**{fallback_count}**",
            f"- 需要关注：{attention_text}",
            f"- 原始流量处置累计：忽略 **{ignored_alerts}**，加白候选 **{white_candidates}**，失败 **{action_failures}**",
            f"- 告警中心处置累计：忽略 **{alert_center_ignored}**，最近窗口保留 **{alert_center_latest.get('retained', 0)}**，失败 **{alert_center_failures}**",
            f"- 主要攻击 IP：{counter_text(ip_counts, limit=8)}",
            f"- 主要事件：{counter_text(event_names, limit=8)}",
            "- <font color=\"info\">腾讯云扫描 IP 和公司漏扫 IP 已排除，不执行封禁</font>",
        ]
    )


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
        result["wecom_notify"] = send_wecom_markdown(
            config,
            build_hourly_wecom_message(
                start_text,
                end_text,
                total,
                hourly_rows,
                disposed_rows,
                disposition,
                alert_center_disposition,
            ),
            "hourly",
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
        if not match:
            raise
        return json.loads(match.group(0))


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
            "确认成功必须有明确证据: attack_result成功、命令执行、文件写入、webshell、敏感数据返回、回连。"
            "有明确失败/阻断证据才判确认未成功。只有探测特征且无成功证据判扫描探测。"
            "证据不足但风险高判需人工复核；普通缺少成功证据判未见成功证据。"
        )
    else:
        task = (
            "逐条复核攻击IP汇总风险。结果只能取:需人工复核,扫描探测,未见成功证据。"
            "根据等级、频次和事件类型给出下一步。"
        )
    return (
        task
        + "只输出JSON数组，每项字段:id,result,confidence,evidence,next。"
        "confidence取high/medium/low。evidence和next均不超过18个汉字。"
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

    output_chunks = []
    usage = {}
    response_id = ""
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=float(llm.get("timeout_seconds", 180))) as resp:
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
            item["研判理由"] = str(item.get("evidence") or item.get("研判理由") or "")[:80]
            item["下一步"] = str(item.get("next") or item.get("下一步") or "")[:80]
            by_key[str(key)] = item
    usage["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    usage["response_id"] = response_id
    return by_key, usage


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
    return bool(resp_mark & success_marks)


def compact_source_review_row(row, index, max_chars):
    evidence = dict(source_evidence(row))
    trimmed = {}
    for key in ("ar", "req", "host", "ua", "resp", "req_mark", "resp_mark", "cmd", "flow", "log", "decrypt"):
        value = evidence.get(key)
        if value:
            trimmed[key] = compact_text(value, max_chars if key == "req" else 120)
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
        "只输出JSON数组，每项字段:id,result,confidence,evidence,next。"
        "confidence取high/medium/low，evidence和next不超过16个汉字。样本="
        + json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    )


def call_codex_direct_source_batch(config, model, batch):
    llm = config.get("llm") or {}
    source_cfg = llm.get("source_review") or {}
    max_chars = int(source_cfg.get("max_evidence_chars", 420))
    id_map = {}
    prompt = source_review_prompt(batch, id_map, max_chars)
    body = json.dumps(
        codex_direct_request_body(model, prompt, source_cfg.get("reasoning_effort", llm.get("reasoning_effort", "medium"))),
        ensure_ascii=False,
    ).encode("utf-8")
    req = urllib.request.Request(
        llm.get("codex_responses_url") or CODEX_RESPONSES_URL,
        data=body,
        method="POST",
        headers=load_codex_auth_headers(),
    )

    output_chunks = []
    usage = {}
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=float(llm.get("timeout_seconds", 180))) as resp:
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
                "研判理由": str(item.get("evidence") or item.get("研判理由") or "")[:80],
                "下一步": str(item.get("next") or item.get("下一步") or "")[:80],
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

    groups = {}
    for row in rows:
        key = judgement_key(row)
        judgement = judgements.get(key) or {}
        if judgement.get("模型研判") != "需人工复核":
            continue
        if not has_source_evidence(row):
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
                "研判来源": "codex_direct_source",
                "研判模型": model,
                "输入Token": str((item.get("_usage") or {}).get("input_tokens", current.get("输入Token", ""))),
                "输出Token": str((item.get("_usage") or {}).get("output_tokens", current.get("输出Token", ""))),
                "推理Token": str((item.get("_usage") or {}).get("reasoning_output_tokens", current.get("推理Token", ""))),
            }
        )
        judgements[key] = merged
    return judgements


def llm_judge_rows(config, rows):
    llm = config.get("llm") or {}
    model = llm.get("model", "gpt-5.5")
    if not rows:
        return {}
    if not llm.get("enabled", False):
        return {judgement_key(row): fallback_judgement(row, "rule_fallback_llm_disabled", model) for row in rows}

    provider = llm.get("provider", "codex_cli")
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
                        "下一步": next_step,
                        "研判来源": provider,
                        "研判模型": model,
                        "输入Token": str((usage or {}).get("input_tokens", "")),
                        "输出Token": str((usage or {}).get("output_tokens", "")),
                        "推理Token": str((usage or {}).get("reasoning_output_tokens", "")),
                    }
                else:
                    results[key] = fallback_judgement(row, "rule_fallback_model_parse_error", model)
    return refine_judgements_with_source(config, rows, results, model)


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
