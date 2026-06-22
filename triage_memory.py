# -*- coding: utf-8 -*-
"""研判记忆库 —— 让研判越用越省、越用越准,并沉淀金标准。

三件事:
  1) 写入:每次研判后,把 (指纹, 结论, 置信, 来源, 时间) 落库
  2) 检索:研判前按指纹/源IP查历史结论,作为"先验"喂给模型(模型仍可推翻)
  3) 金标准:凡是被人工处置过的(忽略/确认),沉淀成带标注的金标准样本,供 eval 回测

指纹设计(host/时间/告警ID 无关,这些会变):
    src_ip(归一) + 事件名 + 规则ID + 方向
  —— 与 merge_forward_duplicates 的去重指纹同源思想,但这里是跨时间的"长期记忆"。

存储:JSONL,无数据库。
  data/triage-memory.jsonl   每条研判记忆
  data/golden-set.jsonl      人工确认过结论的金标准样本
"""
import hashlib
import json
import os
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT, "data")
MEMORY_PATH = os.path.join(DATA_DIR, "triage-memory.jsonl")
GOLDEN_PATH = os.path.join(DATA_DIR, "golden-set.jsonl")

# 可忽略类(自动处置)与需保留类,用于判断"人工最终怎么处置"
IGNORE_RESULTS = {"确认未成功", "扫描探测", "未见成功证据", "业务误报"}
ESCALATE_RESULTS = {"确认成功", "需人工复核"}


def _norm_ip(ip):
    """归一源IP:取第一个(多IP用|分隔),公网保留,内网保留网段以容忍同段漂移。"""
    first = str(ip or "").split("|")[0].strip()
    return first


def fingerprint(src_ip, event_name, rule_id, direction=""):
    """跨时间的研判记忆指纹(host/时间/告警ID/方向 无关 —— 源IP+事件+规则已隐含方向,
    且方向字段写入与检索时未必一致,纳入会导致命不中,故不参与指纹)。"""
    raw = "|".join([
        _norm_ip(src_ip), str(event_name or ""), str(rule_id or ""),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _read_jsonl(path):
    if not os.path.exists(path):
        return
    with open(path, "rb") as f:
        for line in f:
            try:
                yield json.loads(line.decode("utf-8", errors="replace"))
            except Exception:
                continue


def _append_jsonl(path, obj):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


# ---------- 写入研判记忆 ----------
def remember(record_or_fields, judgement, recorded_at=None):
    """落一条研判记忆。record_or_fields 可传 dict(含 SrcIpList/EventName/RuleIdList/Direction)
    或已抽好的 (src_ip, event, rule_id, direction) 元组。judgement 为研判结果 dict。"""
    if isinstance(record_or_fields, (list, tuple)):
        src_ip, event, rule_id, direction = (list(record_or_fields) + ["", "", "", ""])[:4]
    else:
        r = record_or_fields
        src_ip = "|".join(str(x) for x in (r.get("SrcIpList") or [])) or r.get("攻击IP") or ""
        event = r.get("EventName") or r.get("事件名称") or ""
        rule_id = "|".join(str(x) for x in (r.get("RuleIdList") or [])) or r.get("规则ID") or ""
        direction = r.get("Direction") or r.get("方向") or ""
    fp = fingerprint(src_ip, event, rule_id, direction)
    result = judgement.get("模型研判") or judgement.get("result") or ""
    conf = judgement.get("模型置信度") or judgement.get("conf") or ""
    source = judgement.get("研判来源") or judgement.get("source") or ""
    _append_jsonl(MEMORY_PATH, {
        "fp": fp,
        "src_ip": _norm_ip(src_ip),
        "event": event,
        "rule_id": rule_id,
        "result": result,
        "conf": conf,
        "source": source,
        "reason": (judgement.get("研判理由") or judgement.get("why") or "")[:200],
        "at": recorded_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    return fp


# ---------- 检索先验 ----------
def lookup(src_ip, event_name, rule_id, direction="", days=30, max_hits=5):
    """按指纹查历史研判结论(同源同事件同规则)。返回最近 max_hits 条,新→旧。
    rule_fallback / 降级 的不算可信先验,过滤掉。"""
    fp = fingerprint(src_ip, event_name, rule_id, direction)
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    hits = []
    for rec in _read_jsonl(MEMORY_PATH):
        if rec.get("fp") != fp:
            continue
        if rec.get("at", "") < cutoff:
            continue
        if str(rec.get("source", "")).startswith("rule_fallback"):
            continue
        hits.append(rec)
    hits.sort(key=lambda x: x.get("at", ""), reverse=True)
    return hits[:max_hits]


def prior_hint(src_ip, event_name, rule_id, direction="", days=30):
    """把历史结论压成一句可塞进研判 prompt 的先验提示(命中才返回,否则空串)。"""
    hits = lookup(src_ip, event_name, rule_id, direction, days=days)
    if not hits:
        return ""
    # 统计历史结论分布
    from collections import Counter
    dist = Counter(h["result"] for h in hits if h.get("result"))
    if not dist:
        return ""
    top, n = dist.most_common(1)[0]
    return ("【历史先验】该源IP+事件+规则在近%d天有 %d 次研判记录,"
            "最常见结论:%s(%d/%d)。仅供参考,请仍基于本次证据独立判断,"
            "若本次证据与历史不符以本次为准。" % (days, len(hits), top, n, len(hits)))


# ---------- 金标准沉淀 ----------
def record_golden(record_fields, final_result, label_source="human_disposition",
                  recorded_at=None):
    """沉淀一条金标准样本(人工最终处置/确认的结论)。
    final_result: 人工最终认定的类别。label_source: 标注来源(human_disposition / manual_tag)。"""
    src_ip, event, rule_id, direction = (list(record_fields) + ["", "", "", ""])[:4]
    _append_jsonl(GOLDEN_PATH, {
        "fp": fingerprint(src_ip, event, rule_id, direction),
        "src_ip": _norm_ip(src_ip),
        "event": event,
        "rule_id": rule_id,
        "label": final_result,           # 金标准答案
        "label_source": label_source,
        "at": recorded_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })


def golden_set(days=90):
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    return [g for g in _read_jsonl(GOLDEN_PATH) if g.get("at", "") >= cutoff]


def stats():
    mem = list(_read_jsonl(MEMORY_PATH))
    gold = list(_read_jsonl(GOLDEN_PATH))
    fps = {m.get("fp") for m in mem}
    return {
        "memory_records": len(mem),
        "distinct_fingerprints": len(fps),
        "golden_samples": len(gold),
    }


if __name__ == "__main__":
    import sys, io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    print(json.dumps(stats(), ensure_ascii=False, indent=2))
