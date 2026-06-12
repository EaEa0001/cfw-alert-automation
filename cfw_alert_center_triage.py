import argparse
import csv
import hashlib
import hmac
import json
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

import cfw_alert_monitor as monitor


ROOT = Path(__file__).resolve().parent
REPORT_DIR = ROOT / "reports"
DATA_DIR = ROOT / "data"

LEVEL_MAP = {"High": "高危", "Middle": "中危", "Low": "低危"}
DIR_MAP = {0: "出向", 1: "入向", "0": "出向", "1": "入向"}
ATTACK_RESULT_MAP = {
    0: "未知",
    1: "攻击成功",
    2: "攻击失败",
    3: "尝试/探测",
    "0": "未知",
    "1": "攻击成功",
    "2": "攻击失败",
    "3": "尝试/探测",
}
IGNORE_RESULTS = {"确认未成功", "未见成功证据", "扫描探测"}
SAFE_SCAN_KEYWORDS = (
    "扫描",
    "探测",
    "爬虫",
    "zgrab",
    "masscan",
    "nmap",
    "censys",
    "paloalto",
)
SAFE_FAILURE_HTTP_CODES = {
    "301",
    "302",
    "303",
    "307",
    "308",
    "400",
    "401",
    "403",
    "404",
    "405",
    "406",
    "410",
    "429",
    "500",
    "501",
    "502",
    "503",
    "504",
}
_LOCAL_EVENT_CACHE = {}


def compact_join(values, limit=8):
    values = [str(v) for v in (values or []) if str(v)]
    if len(values) <= limit:
        return "|".join(values)
    return "|".join(values[:limit]) + f"|...+{len(values) - limit}"


def compact_geo(items, limit=6):
    output = []
    for item in (items or [])[:limit]:
        if not isinstance(item, dict):
            continue
        ip = item.get("IP", "")
        address = item.get("Address", "")
        output.append(f"{ip}:{address}" if address else str(ip))
    return "|".join(output)


def compact_assets(items, limit=6):
    output = []
    for item in (items or [])[:limit]:
        if not isinstance(item, dict):
            continue
        parts = [str(item.get(k, "")) for k in ("InstanceId", "InstanceName", "InstanceType", "InstanceIp") if item.get(k)]
        if parts:
            output.append("/".join(parts))
    if items and len(items) > limit:
        output.append(f"...+{len(items) - limit}")
    return "|".join(output)


def tc3_api(config, action, payload):
    sid, sk, token = monitor.load_credentials(config)
    service = "cfw"
    host = config.get("endpoint", "cfw.tencentcloudapi.com")
    version = "2019-09-04"
    region = config.get("region", "ap-shanghai")
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    timestamp = int(time.time())
    date = datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d")
    canonical_request = (
        "POST\n/\n\n"
        f"content-type:application/json; charset=utf-8\nhost:{host}\n\n"
        f"content-type;host\n{hashlib.sha256(body.encode('utf-8')).hexdigest()}"
    )
    credential_scope = f"{date}/{service}/tc3_request"
    string_to_sign = (
        "TC3-HMAC-SHA256\n"
        f"{timestamp}\n{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )

    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    secret_date = sign(("TC3" + sk).encode("utf-8"), date)
    secret_service = sign(secret_date, service)
    secret_signing = sign(secret_service, "tc3_request")
    signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    authorization = (
        f"TC3-HMAC-SHA256 Credential={sid}/{credential_scope}, "
        f"SignedHeaders=content-type;host, Signature={signature}"
    )
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Host": host,
        "X-TC-Action": action,
        "X-TC-Timestamp": str(timestamp),
        "X-TC-Version": version,
        "X-TC-Region": region,
        "Authorization": authorization,
    }
    if token:
        headers["X-TC-Token"] = token
    response = requests.post(f"https://{host}", data=body.encode("utf-8"), headers=headers, timeout=90)
    response.raise_for_status()
    data = response.json()
    payload = data.get("Response", {})
    if payload.get("Error"):
        raise RuntimeError(json.dumps(payload["Error"], ensure_ascii=False))
    return payload


def fetch_unhandled_alert_center_range(config, start, end):
    base = {
        "StartTime": monitor.dt_text(start) if isinstance(start, datetime) else str(start),
        "EndTime": monitor.dt_text(end) if isinstance(end, datetime) else str(end),
        "Offset": 0,
        "Limit": 200,
    }
    rows = []
    total = None
    offset = 0
    while True:
        payload = dict(base)
        payload["Offset"] = offset
        response = tc3_api(config, "DescribeAlertCenterList", payload)
        page = response.get("Data") or []
        if total is None:
            total = int(response.get("Total") or 0)
        rows.extend(page)
        if not page or len(rows) >= total:
            break
        offset += len(page)
    unhandled = [
        row
        for row in rows
        if str(row.get("ProcessingStatus", "0")) == "0" and str(row.get("HideStatus", "0")) == "0"
    ]
    return unhandled, {"start": base["StartTime"], "end": base["EndTime"], "total": total or len(rows)}


def fetch_unhandled_alert_center(config, days):
    end = monitor.now_local()
    return fetch_unhandled_alert_center_range(config, end - timedelta(days=days), end)


def parse_local_time(value):
    try:
        return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None


def local_events_for_record(record):
    start = parse_local_time(record.get("StartTime"))
    end = parse_local_time(record.get("EndTime"))
    if not start or not end:
        return []
    events = []
    day = start.date()
    while day <= end.date():
        day_text = day.isoformat()
        if day_text not in _LOCAL_EVENT_CACHE:
            _LOCAL_EVENT_CACHE[day_text] = monitor.load_events_for_day(day_text)
        events.extend(_LOCAL_EVENT_CACHE[day_text])
        day += timedelta(days=1)
    return events


def matching_local_events(record):
    start = parse_local_time(record.get("StartTime"))
    end = parse_local_time(record.get("EndTime"))
    if not start or not end:
        return []

    source_ips = {str(ip) for ip in (record.get("SrcIpList") or [])}
    target_ips = {str(ip) for ip in (record.get("DstIpList") or [])}
    event_name = str(record.get("EventName") or "")
    matched = []
    for event in local_events_for_record(record):
        if str(event.get("event_name") or "") != event_name:
            continue
        event_at = parse_local_time(event.get("event_time"))
        if not event_at or event_at < start - timedelta(minutes=5) or event_at > end + timedelta(minutes=5):
            continue
        if source_ips and not ({str(event.get("attack_ip") or ""), str(event.get("source_ip") or "")} & source_ips):
            continue
        if target_ips and str(event.get("target_ip") or "") not in target_ips:
            continue
        matched.append(event)
    return matched


def record_source_review_evidence(record):
    evidences = [event.get("source_evidence") or {} for event in matching_local_events(record)]
    evidences = [evidence for evidence in evidences if evidence]
    if not evidences:
        return {}

    def evidence_score(evidence):
        score = 0
        if evidence.get("cmd"):
            score += 8
        if evidence.get("resp_mark"):
            score += 6
        if evidence.get("resp"):
            score += 4
        if evidence.get("req_mark"):
            score += 2
        if evidence.get("req"):
            score += 1
        return score

    selected = sorted(evidences, key=evidence_score, reverse=True)[:4]
    combined = {}
    for key in ("ar", "req", "host", "ua", "resp", "req_mark", "resp_mark", "cmd"):
        values = []
        for evidence in selected:
            value = str(evidence.get(key) or "").strip()
            if value and value not in values:
                values.append(value)
        if values:
            combined[key] = " || ".join(values)
    combined["flow"] = f"matched_local_events={len(evidences)}"
    return combined


def record_source_failure_evidence(record):
    matched = []
    for event in matching_local_events(record):
        evidence = event.get("source_evidence") or {}
        response = str(evidence.get("resp_mark") or evidence.get("resp_hint") or evidence.get("resp") or "")
        code_match = monitor.re.search(r"\b([1-5]\d\d)\b", response)
        if code_match:
            matched.append((event.get("event_key") or monitor.event_key(event), code_match.group(1)))

    unique_matches = {str(key): code for key, code in matched}
    codes = sorted(set(unique_matches.values()))
    required = max(1, int(record.get("Count") or 1))
    return {
        "matched": len(unique_matches),
        "required": required,
        "codes": codes,
        "safe": len(unique_matches) >= required and bool(codes) and set(codes) <= SAFE_FAILURE_HTTP_CODES,
    }


def safe_hourly_decision(record, labels):
    event_id = str(record.get("EventId") or record.get("AlertClusterId") or "")
    name = str(record.get("EventName") or "")
    level = str(record.get("Level") or "")
    attack_result = str(record.get("AttackResult", ""))
    hits = white_hits(record, labels)
    decision = {
        "event_id": event_id,
        "event_name": name,
        "level": level,
        "attack_result": attack_result,
        "src_ips": [str(ip) for ip in (record.get("SrcIpList") or [])],
        "dst_ips": [str(ip) for ip in (record.get("DstIpList") or [])],
        "end_time": str(record.get("EndTime") or ""),
        "ignore": False,
        "reason": "",
        "white_hits": hits,
    }

    if attack_result == "1":
        decision["reason"] = "云端标记攻击成功"
        return decision
    if level == "High":
        decision["reason"] = "高危告警保留复核"
        return decision
    if hits:
        decision["ignore"] = True
        decision["reason"] = "白名单扫描源"
        return decision
    if attack_result in ("2", "3"):
        decision["ignore"] = True
        decision["reason"] = "云端明确标记攻击失败或尝试探测"
        return decision
    if any(keyword.lower() in name.lower() for keyword in SAFE_SCAN_KEYWORDS):
        decision["ignore"] = True
        decision["reason"] = "明确扫描探测类型"
        return decision

    evidence = record_source_failure_evidence(record)
    decision["source_evidence"] = evidence
    if evidence["safe"]:
        decision["ignore"] = True
        decision["reason"] = f"源包完整关联且响应为失败码: {'/'.join(evidence['codes'])}"
    else:
        decision["reason"] = "攻击结果未知且无完整失败证据"
    return decision


def safe_hourly_dispose(config, start, end, dry_run=False):
    records, query = fetch_unhandled_alert_center_range(config, start, end)
    labels = whitelist_labels(config)
    decisions = [safe_hourly_decision(record, labels) for record in records]
    ignore_ids = [item["event_id"] for item in decisions if item["ignore"] and item["event_id"]]
    white_records = [record_to_judge_row(record, labels) for record in records if white_hits(record, labels)]
    omit_actions = []
    white_actions = []
    if not dry_run:
        white_actions = allow_scanner_ips(config, white_records)
        omit_actions = omit_alert_center_events(
            config,
            ignore_ids,
            int((config.get("llm") or {}).get("auto_dispose", {}).get("batch_size", 50)),
        )

    if dry_run:
        remaining = [record for record, item in zip(records, decisions) if not item["ignore"]]
        retained = [item for item in decisions if not item["ignore"]]
        remaining_ids = {item["event_id"] for item in retained}
    else:
        remaining, _ = fetch_unhandled_alert_center_range(config, start, end)
        remaining_ids = {
            str(record.get("EventId") or record.get("AlertClusterId") or "") for record in remaining
        }
        retained = [item for item in decisions if item["event_id"] in remaining_ids]
    result = {
        "mode": "alert_center_hourly_safe",
        "dry_run": dry_run,
        "query_start": query["start"],
        "query_end": query["end"],
        "query_total": query["total"],
        "active_before": len(records),
        "selected_ignore": len(set(ignore_ids)),
        "ignored_confirmed": 0 if dry_run else len({event_id for event_id in ignore_ids if event_id not in remaining_ids}),
        "retained": len(remaining),
        "retained_high": sum(item.get("level") == "High" for item in retained),
        "retained_success": sum(item.get("attack_result") == "1" for item in retained),
        "ignore_reasons": dict(Counter(item["reason"] for item in decisions if item["ignore"])),
        "retained_reasons": dict(Counter(item["reason"] for item in retained)),
        "retained_events": dict(Counter(item["event_name"] for item in retained)),
        "retained_items": retained[:20],
        "omit_actions": omit_actions,
        "white_actions": white_actions,
    }
    DATA_DIR.mkdir(exist_ok=True)
    monitor.append_jsonl(
        DATA_DIR / f"alert-center-hourly-{monitor.now_local().strftime('%Y-%m-%d')}.jsonl",
        [dict(result, recorded_at=monitor.dt_text(monitor.now_local()))],
    )
    return result


def whitelist_labels(config):
    labels = {}
    for ip in config.get("tencent_scan_ips", []):
        labels[str(ip)] = "tencent_scan"
    for ip in config.get("company_scan_ips", []):
        labels[str(ip)] = "company_scan"
    return labels


def white_hits(record, labels):
    return sorted({str(ip) for ip in (record.get("SrcIpList") or []) if labels.get(str(ip))})


def record_to_judge_row(record, labels):
    hits = white_hits(record, labels)
    src_ips = [str(ip) for ip in (record.get("SrcIpList") or [])]
    dst_ips = [str(ip) for ip in (record.get("DstIpList") or [])]
    attack_result = ATTACK_RESULT_MAP.get(record.get("AttackResult"), str(record.get("AttackResult", "")))
    level = LEVEL_MAP.get(record.get("Level"), str(record.get("Level", "")))
    direction = DIR_MAP.get(record.get("Direction"), str(record.get("Direction", "")))
    desc = (
        f"count={record.get('Count','')}; ar={attack_result}; src_num={record.get('SrcIpNum','')}; "
        f"dst_num={record.get('DstIpNum','')}; action={record.get('ActionStatus','')}; "
        f"block={record.get('BlockStatus','')}; ignore={record.get('IgnoreStatus','')}; "
        f"white={compact_join(hits, 6)}"
    )
    return {
        "日期": record.get("EndTime", "")[:10],
        "告警ID": str(record.get("EventId") or record.get("AlertClusterId") or ""),
        "告警时间": record.get("EndTime", ""),
        "攻击IP": compact_join(src_ips, 10),
        "源IP": compact_join(src_ips, 10),
        "目标IP": compact_join(dst_ips, 10),
        "目标端口": "",
        "目标资产": compact_assets(record.get("DstInstanceList") or [], 4),
        "方向": direction,
        "告警等级": level,
        "事件名称": record.get("EventName", ""),
        "威胁类型": f"{record.get('KillChain','')}/{record.get('Source','')}",
        "来源国家": compact_geo(record.get("SrcIpInfo") or [], 4),
        "规则ID": compact_join(record.get("RuleIdList") or [], 6),
        "策略": str(record.get("Strategy", "")),
        "威胁描述": desc,
        "云防火墙建议": "告警中心聚合事件，无单条源包；需结合攻击结果和事件类型复核",
        "源包证据": record_source_review_evidence(record),
        "本地建议": "白名单扫描源加白并忽略" if hits else "按模型研判处理",
        "白名单状态": compact_join(hits, 6) if hits else "非白名单",
        "_record": record,
        "_white_hits": hits,
    }


def deterministic_white_judgement(row, model):
    return {
        "告警ID": row["告警ID"],
        "攻击IP": row.get("攻击IP", ""),
        "模型研判": "扫描探测",
        "模型置信度": "高",
        "研判理由": "白名单扫描源",
        "下一步": "创建IDS白名单并忽略",
        "研判来源": "rule_whitelist",
        "研判模型": model,
        "输入Token": "0",
        "输出Token": "0",
        "推理Token": "0",
    }


def apply_judgements(rows, judgements):
    out = []
    for row in rows:
        item = judgements.get(row["告警ID"]) or {}
        merged = {k: v for k, v in row.items() if not k.startswith("_")}
        for key in ("模型研判", "模型置信度", "研判理由", "下一步", "研判来源", "研判模型", "输入Token", "输出Token", "推理Token"):
            merged[key] = item.get(key, "")
        out.append(merged)
    return out


def white_rule_candidates(rows):
    candidates = {}
    for row in rows:
        record = row["_record"]
        hits = row["_white_hits"]
        if not hits:
            continue
        for src_ip in hits:
            label = "company_scan" if src_ip == "210.22.92.182" else "tencent_scan"
            for rule_id in record.get("RuleIdList") or []:
                for dst_ip in record.get("DstIpList") or []:
                    key = (str(rule_id), str(src_ip), str(dst_ip))
                    candidates[key] = {
                        "rule_id": str(rule_id),
                        "src_ip": str(src_ip),
                        "dst_ip": str(dst_ip),
                        "label": label,
                    }
    return list(candidates.values())


def omit_alert_center_events(config, event_ids, batch_size=50):
    event_ids = sorted({str(event_id) for event_id in event_ids if str(event_id)})
    actions = []
    for batch in monitor.chunks(event_ids, batch_size):
        payload = {
            "HandleIdList": batch,
            "HandleEventIdList": batch,
            "TableType": "AlertTable",
        }
        try:
            response = tc3_api(config, "CreateAlertCenterOmit", payload)
            actions.append(
                {
                    "action": "alert_center_omit",
                    "count": len(batch),
                    "return_code": response.get("ReturnCode"),
                    "return_msg": response.get("ReturnMsg"),
                    "status": response.get("Status"),
                    "request_id": response.get("RequestId"),
                }
            )
        except Exception as exc:
            actions.append({"action": "alert_center_omit", "count": len(batch), "error": str(exc)[:500]})
    return actions


def allow_scanner_ips(config, rows):
    by_direction = {}
    for row in rows:
        record = row["_record"]
        for ip in row["_white_hits"]:
            direction = str(record.get("Direction", "1"))
            by_direction.setdefault(direction, set()).add(str(ip))

    actions = []
    for direction, ips in sorted(by_direction.items()):
        handle_direction = "0" if direction == "0" else "1"
        payload = {
            "HandleTime": -2,
            "HandleType": 3,
            "AlertDirection": int(direction) if direction in ("0", "1") else 1,
            "HandleDirection": handle_direction,
            "HandleIpList": sorted(ips),
            "HandleComment": "scanner whitelist: tencent/company scan ip",
        }
        try:
            response = tc3_api(config, "CreateAlertCenterRule", payload)
            actions.append(
                {
                    "action": "alert_center_allow_ip",
                    "direction": direction,
                    "ips": sorted(ips),
                    "count": len(ips),
                    "return_code": response.get("ReturnCode"),
                    "return_msg": response.get("ReturnMsg"),
                    "status": response.get("Status"),
                    "request_id": response.get("RequestId"),
                }
            )
        except Exception as exc:
            actions.append(
                {
                    "action": "alert_center_allow_ip",
                    "direction": direction,
                    "ips": sorted(ips),
                    "count": len(ips),
                    "error": str(exc)[:500],
                }
            )
    return actions


def write_jsonl(path, rows):
    with path.open("w", encoding="utf-8", newline="") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Triage and dispose Tencent CFW alert center events.")
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--start")
    parser.add_argument("--end")
    parser.add_argument("--safe-hourly", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()

    config = monitor.load_config()
    if args.safe_hourly:
        end = args.end or monitor.dt_text(monitor.now_local())
        start = args.start or monitor.dt_text(monitor.now_local() - timedelta(hours=2))
        print(json.dumps(safe_hourly_dispose(config, start, end, args.dry_run), ensure_ascii=False))
        return

    model = (config.get("llm") or {}).get("model", "gpt-5.5")
    labels = whitelist_labels(config)
    if args.start and args.end:
        records, query = fetch_unhandled_alert_center_range(config, args.start, args.end)
    else:
        records, query = fetch_unhandled_alert_center(config, args.days)
    if args.limit:
        records = records[: args.limit]

    rows = [record_to_judge_row(record, labels) for record in records]
    white_rows = [row for row in rows if row["_white_hits"]]
    llm_rows = [row for row in rows if not row["_white_hits"]]
    judgements = {row["告警ID"]: deterministic_white_judgement(row, model) for row in white_rows}
    judgements.update(monitor.llm_judge_rows(config, llm_rows))

    judged_rows = apply_judgements(rows, judgements)
    ignore_ids = [
        row["告警ID"]
        for row in judged_rows
        if row.get("模型研判") in IGNORE_RESULTS and row.get("告警ID")
    ]
    candidates = white_rule_candidates(rows)

    REPORT_DIR.mkdir(exist_ok=True)
    DATA_DIR.mkdir(exist_ok=True)
    stamp = monitor.now_local().strftime("%Y%m%d_%H%M%S")
    csv_path = REPORT_DIR / f"cfw_alert_center_judgement_{stamp}.csv"
    jsonl_path = REPORT_DIR / f"cfw_alert_center_judgement_{stamp}.jsonl"
    dispose_path = REPORT_DIR / f"cfw_alert_center_disposition_{stamp}.json"

    fieldnames = [
        "日期",
        "告警ID",
        "告警时间",
        "攻击IP",
        "源IP",
        "目标IP",
        "目标资产",
        "方向",
        "告警等级",
        "事件名称",
        "威胁类型",
        "来源国家",
        "规则ID",
        "策略",
        "威胁描述",
        "本地建议",
        "白名单状态",
        "模型研判",
        "模型置信度",
        "研判理由",
        "下一步",
        "研判来源",
        "研判模型",
        "输入Token",
        "输出Token",
        "推理Token",
    ]
    monitor.write_csv(csv_path, fieldnames, judged_rows)
    write_jsonl(jsonl_path, judged_rows)

    white_actions = []
    omit_actions = []
    if not args.dry_run:
        white_actions = allow_scanner_ips(config, rows)
        omit_actions = omit_alert_center_events(config, ignore_ids, int((config.get("llm") or {}).get("auto_dispose", {}).get("batch_size", 50)))

    summary = {
        "mode": "alert_center_triage",
        "dry_run": args.dry_run,
        "query_start": query["start"],
        "query_end": query["end"],
        "query_total": query["total"],
        "alert_count": len(rows),
        "judgement_counts": dict(Counter(row.get("模型研判", "") for row in judged_rows)),
        "whitelist_hit_events": len(white_rows),
        "white_rule_candidates": len(candidates),
        "ignore_event_ids": len(set(ignore_ids)),
        "white_actions": white_actions,
        "omit_actions": omit_actions,
        "judgement_csv": str(csv_path),
        "judgement_jsonl": str(jsonl_path),
    }
    dispose_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    monitor.append_jsonl(DATA_DIR / f"alert-center-dispose-{monitor.now_local().strftime('%Y-%m-%d')}.jsonl", [summary])
    summary["disposition_file"] = str(dispose_path)
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
