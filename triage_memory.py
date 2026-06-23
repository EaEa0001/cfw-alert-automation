# -*- coding: utf-8 -*-
"""研判记忆库 —— 让研判越用越省、越用越准。

两件事:
  1) 写入:每次研判后,把 (指纹, 结论, 置信, 来源, 时间) 落库
  2) 检索:研判前按指纹/源IP查历史结论,作为"先验"喂给模型(模型仍可推翻)

指纹设计(host/时间/告警ID 无关,这些会变):
    src_ip(归一) + 事件名 + 规则ID + 方向
  —— 与 merge_forward_duplicates 的去重指纹同源思想,但这里是跨时间的"长期记忆"。

存储:JSONL,无数据库。
  data/triage-memory.jsonl   每条研判记忆
"""
import hashlib
import json
import os
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ROOT, "data")
MEMORY_PATH = os.path.join(DATA_DIR, "triage-memory.jsonl")

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


# ================= 业务误报专用记忆 =================
# 业务误报 = 自己人的正常业务流量被规则误命中,高度稳定、几乎不会变恶意,
# 所以适合"记住→同类自动定误报"。指纹用"被误命中的业务特征",不含源IP
# (误报可能来自任意客户端/扫描器,绑源IP会漏;绑业务接口才稳)。
#   指纹 = 规则ID + 请求方法+URI路径(剥 host 和 query 参数)
# 同一接口同一规则的误命中跨资产都能复用;接口路径比资产名稳定。

BIZ_FP_PATH = os.path.join(DATA_DIR, "biz-fp-memory.jsonl")
# 自动定误报的门槛:同指纹历史被判业务误报这么多次、且占比这么高,才允许命中即定
BIZ_MIN_TIMES = 3
BIZ_MIN_RATIO = 0.9


def _req_path(req_line):
    """从请求行 'POST /a/b?x=1 HTTP/1.1' 提取 '方法 /a/b'(去 query、去协议版本)。"""
    parts = str(req_line or "").split()
    if len(parts) < 2:
        return ""
    method, uri = parts[0], parts[1]
    path = uri.split("?")[0].split("#")[0]
    return "%s %s" % (method.upper(), path)


def biz_fingerprint(rule_id, req_line):
    """业务误报内容指纹 = 规则ID + 方法+路径(去host/去query)。"""
    raw = "|".join([str(rule_id or ""), _req_path(req_line)])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _extract_req(record_or_row):
    """从记录/研判行里取请求行(源包证据.req)。兼容 dict 与 CSV 字符串。"""
    ev = (record_or_row.get("source_evidence") or record_or_row.get("源包证据")
          or record_or_row.get("e") or {})
    if isinstance(ev, str):
        try:
            import ast
            ev = ast.literal_eval(ev)
        except Exception:
            ev = {}
    if isinstance(ev, dict):
        return ev.get("req") or ""
    return ""


def remember_biz_fp(rule_id, req_line, result, asset="", recorded_at=None):
    """落一条业务误报内容记忆(只在能取到请求路径时才记,否则指纹无意义)。"""
    path = _req_path(req_line)
    if not path or not rule_id:
        return None
    fp = biz_fingerprint(rule_id, req_line)
    _append_jsonl(BIZ_FP_PATH, {
        "bfp": fp, "rule_id": str(rule_id), "path": path,
        "result": result, "asset": asset,
        "at": recorded_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    return fp


def biz_fp_verdict(rule_id, req_line, days=90):
    """业务误报记忆命中判定。返回:
      None        -> 未命中/证据不足,照常研判
      dict(命中)   -> {'hit':True,'times':n,'ratio':r,'path':..} 可直接定业务误报
    门槛:同指纹历史被判业务误报 >= BIZ_MIN_TIMES 次且占比 >= BIZ_MIN_RATIO。"""
    path = _req_path(req_line)
    if not path or not rule_id:
        return None
    fp = biz_fingerprint(rule_id, req_line)
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    total = biz = 0
    for rec in _read_jsonl(BIZ_FP_PATH):
        if rec.get("bfp") != fp or rec.get("at", "") < cutoff:
            continue
        total += 1
        if rec.get("result") == "业务误报":
            biz += 1
    if total < BIZ_MIN_TIMES:
        return None
    ratio = biz / total
    if ratio < BIZ_MIN_RATIO:
        return None
    return {"hit": True, "times": biz, "total": total,
            "ratio": round(ratio, 3), "path": path, "bfp": fp}


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


def stats():
    mem = list(_read_jsonl(MEMORY_PATH))
    fps = {m.get("fp") for m in mem}
    return {
        "memory_records": len(mem),
        "distinct_fingerprints": len(fps),
    }


if __name__ == "__main__":
    import sys, io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    print(json.dumps(stats(), ensure_ascii=False, indent=2))
