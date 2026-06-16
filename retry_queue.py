"""研判失败重试队列。

模型连接抖动(WinError 10060 等)会导致部分告警降级为 rule_fallback,
这些条目判不出真结果就一直挂"未处理",和网络正常的研判方(codex)口径不一致。

本模块把降级的告警记录落盘成队列,下次运行(网络恢复时)优先补判,
判出真模型结果(非 rule_fallback)后才出队。不依赖数据库,纯 jsonl。

队列项保存最小可重判信息(原始告警记录),因为告警中心记录是聚合事件,
EventId 稳定,可据此去重和重判。
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
QUEUE_PATH = ROOT / "data" / "retry-queue.jsonl"


def _key(record):
    return str(record.get("EventId") or record.get("AlertClusterId") or "")


def load_queue():
    """读取队列,按 EventId 去重(保留最新一条)。"""
    if not QUEUE_PATH.exists():
        return {}
    items = {}
    with QUEUE_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            rec = obj.get("record") or {}
            k = _key(rec)
            if k:
                items[k] = obj
    return items


def save_queue(items):
    QUEUE_PATH.parent.mkdir(exist_ok=True)
    with QUEUE_PATH.open("w", encoding="utf-8", newline="") as fh:
        for obj in items.values():
            fh.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")


def enqueue(records, recorded_at, reason="model_degraded", max_size=2000):
    """把降级的告警记录入队(已在队列的更新时间戳/计数)。"""
    if not records:
        return 0
    items = load_queue()
    added = 0
    for rec in records:
        k = _key(rec)
        if not k:
            continue
        prev = items.get(k)
        attempts = (prev.get("attempts", 0) + 1) if prev else 1
        items[k] = {
            "record": rec,
            "first_seen": (prev or {}).get("first_seen", recorded_at),
            "last_attempt": recorded_at,
            "attempts": attempts,
            "reason": reason,
        }
        if not prev:
            added += 1
    # 防止无界增长:超限时丢弃尝试次数最多(最老最难判)的
    if len(items) > max_size:
        ordered = sorted(items.items(), key=lambda kv: kv[1].get("attempts", 0), reverse=True)
        items = dict(ordered[len(ordered) - max_size:])
    save_queue(items)
    return added


def dequeue(event_ids):
    """把已判出真结果的 EventId 出队。"""
    if not event_ids:
        return 0
    items = load_queue()
    removed = 0
    for eid in event_ids:
        if str(eid) in items:
            del items[str(eid)]
            removed += 1
    if removed:
        save_queue(items)
    return removed


GIVEUP_PATH = ROOT / "data" / "retry-giveup.jsonl"


def queued_records(max_records=200, max_attempts=20):
    """取出待补判的告警记录。

    超过 max_attempts 仍判不出的不再无限补判,但**不静默丢弃** —— 落到
    retry-giveup.jsonl 留痕(这些是反复自动判不了的,本就该人工看),避免变盲区。
    """
    items = load_queue()
    stale = [k for k, v in items.items() if v.get("attempts", 0) > max_attempts]
    if stale:
        GIVEUP_PATH.parent.mkdir(exist_ok=True)
        with GIVEUP_PATH.open("a", encoding="utf-8") as fh:
            for k in stale:
                obj = dict(items[k], gave_up=True)
                fh.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n")
                del items[k]
        save_queue(items)
    records = [v["record"] for v in items.values()]
    return records[:max_records]


def stats():
    items = load_queue()
    return {"size": len(items), "max_attempts": max((v.get("attempts", 0) for v in items.values()), default=0)}
