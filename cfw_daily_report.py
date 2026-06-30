#!/usr/bin/env python3
import argparse
import json
from collections import Counter
from datetime import datetime, timedelta

import triage_stats as stats
from cfw_alert_monitor import DATA_DIR, dt_text, load_config, now_local, send_wecom_markdown


IGNORE_RESULTS = {"确认未成功", "未见成功证据", "扫描探测", "业务误报"}
KEY_RESULTS = {"确认成功", "需人工复核"}
DEFAULT_REPORT_TIME = "17:50:00"


def _parse_time(value):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(str(value), fmt)
        except ValueError:
            continue
    raise ValueError(f"invalid time: {value}")


def _row_time(row):
    value = str(row.get("告警时间") or "")[:19]
    if not value:
        return None
    try:
        return _parse_time(value)
    except ValueError:
        return None


def report_window(day, report_time=DEFAULT_REPORT_TIME):
    end = _parse_time(f"{day} {report_time}")
    return end - timedelta(days=1), end


def _split_values(value):
    return [part.strip() for part in str(value or "").split("|") if part.strip()]


def _counter_text(counter, limit=5):
    return "、".join(f"{key} {value}" for key, value in counter.most_common(limit)) or "无"


def _is_retry_pending(row):
    return row.get("模型研判") == "待模型重试" or stats.is_retry_pending_source(row.get("研判来源", ""))


def daily_rows(start, end, lookback_days=2):
    rows = []
    for row in stats.load_judgements(lookback_days):
        at = _row_time(row)
        if at and start <= at <= end:
            rows.append(row)
    rows.sort(key=lambda item: str(item.get("告警时间") or ""))
    return rows


def build_summary(day, rows, start, end):
    results = Counter(row.get("模型研判", "") for row in rows if row.get("模型研判"))
    levels = Counter(row.get("告警等级", "") for row in rows if row.get("告警等级"))
    retry_pending = sum(1 for row in rows if _is_retry_pending(row))
    confirmed = results.get("确认成功", 0)
    manual = results.get("需人工复核", 0)
    auto_done = max(0, len(rows) - confirmed - manual - retry_pending)

    ip_counts = Counter()
    attackers = set()
    event_counts = Counter()
    for row in rows:
        for ip in _split_values(row.get("攻击IP")):
            attackers.add(ip)
            ip_counts[ip] += 1
        event = row.get("事件名称")
        if event:
            event_counts[event] += 1

    attention = [
        row for row in rows
        if row.get("模型研判") in KEY_RESULTS or row.get("告警等级") in {"严重", "高危"}
    ]
    attention.sort(
        key=lambda row: (
            row.get("模型研判") == "确认成功",
            row.get("模型研判") == "需人工复核",
            row.get("告警等级") in {"严重", "高危"},
            row.get("告警时间", ""),
        ),
        reverse=True,
    )

    return {
        "date": day,
        "window_start": dt_text(start),
        "window_end": dt_text(end),
        "total": len(rows),
        "high": levels.get("严重", 0) + levels.get("高危", 0),
        "attack_ip_count": len(attackers),
        "auto_done": auto_done,
        "manual": manual,
        "retry_pending": retry_pending,
        "confirmed": confirmed,
        "results": dict(results),
        "levels": dict(levels),
        "top_ip": ip_counts.most_common(5),
        "top_event": event_counts.most_common(5),
        "attention": attention[:5],
    }


def build_message(summary):
    confirmed = summary["confirmed"]
    manual = summary["manual"]
    retry_pending = summary["retry_pending"]
    if confirmed:
        verdict = f"⚠️ **发现 {confirmed} 条确认成功,需立即处置**"
    elif retry_pending:
        verdict = f"⚠️ 模型连接异常,**{retry_pending}** 条待模型重试"
    elif manual:
        verdict = f"✅ 无确认得手;**{manual}** 条待人工复核,其余已自动处理"
    else:
        verdict = "✅ 全部自动研判处理,无需人工"

    lines = [
        f"## 云防火墙日报 {summary['date']}",
        f"> {verdict}",
        f"- 统计窗口:{summary['window_start']} ~ {summary['window_end']}",
        f"- 窗口研判告警 **{summary['total']}** 条(高危 {summary['high']})| 攻击IP **{summary['attack_ip_count']}** 个",
        f"- 处理:自动 **{summary['auto_done']}** | 待人工 **{manual}** | 待重试 **{retry_pending}** | 确认成功 **{confirmed}**",
        f"- 主要攻击源:{_counter_text(Counter(dict(summary['top_ip'])))}",
        f"- 主要手法:{_counter_text(Counter(dict(summary['top_event'])))}",
        "> 统计口径:告警中心实时研判结果,与控制台一致;不再按 raw threat 日志全量重算。",
    ]
    if summary["attention"]:
        items = []
        for row in summary["attention"]:
            items.append(
                f"{row.get('攻击IP', '-')}/{row.get('事件名称', '-')}/{row.get('模型研判', '-')}"
            )
        lines.append(f"- 关注项:{'；'.join(items)}")
    return "\n".join(lines)


def write_summary(summary, message, notify_result=None):
    DATA_DIR.mkdir(exist_ok=True)
    path = DATA_DIR / f"daily-summary-{summary['date']}.jsonl"
    record = {
        "recorded_at": dt_text(now_local()),
        "summary": {key: value for key, value in summary.items() if key != "attention"},
        "message": message,
        "wecom_notify": notify_result or {},
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return str(path)


def main():
    parser = argparse.ArgumentParser(description="Send CFW daily report from console-aligned triage data.")
    parser.add_argument("--date", default=now_local().strftime("%Y-%m-%d"))
    parser.add_argument("--start", help="Report window start, default is previous day 17:50:00.")
    parser.add_argument("--end", help="Report window end, default is report date 17:50:00.")
    parser.add_argument("--report-time", default=DEFAULT_REPORT_TIME)
    parser.add_argument("--lookback-days", type=int, default=2)
    parser.add_argument("--no-send", action="store_true", help="Build and print the report without sending WeCom.")
    args = parser.parse_args()

    default_start, default_end = report_window(args.date, args.report_time)
    start = _parse_time(args.start) if args.start else default_start
    end = _parse_time(args.end) if args.end else default_end
    lookback_days = max(args.lookback_days, (now_local() - start).days + 2, 1)
    rows = daily_rows(start, end, lookback_days)
    summary = build_summary(args.date, rows, start, end)
    message = build_message(summary)
    notify = {"sent": False, "reason": "no_send"} if args.no_send else send_wecom_markdown(load_config(), message, "daily")
    summary_file = "" if args.no_send else write_summary(summary, message, notify)
    print(json.dumps({
        "mode": "daily_report",
        "date": args.date,
        "summary_file": summary_file,
        "alert_count": summary["total"],
        "attack_ip_count": summary["attack_ip_count"],
        "judgement_counts": summary["results"],
        "wecom_notify": notify,
    }, ensure_ascii=False))
    if args.no_send:
        print(message)


if __name__ == "__main__":
    main()
