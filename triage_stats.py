"""研判控制台聚合层。

读取 data/ 和 reports/ 下的运行产物,算成结构化指标供命令行/Web 控制台展示。
不依赖数据库,纯读 jsonl。所有时间按本地时间字符串 (YYYY-MM-DD HH:MM:SS) 处理。
"""
import glob
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
REPORT_DIR = ROOT / "reports"
LOG_DIR = ROOT / "logs"

RESULT_ORDER = ["确认成功", "需人工复核", "未见成功证据", "确认未成功", "扫描探测"]
SOURCE_LABEL = {
    "codex_direct": "单轮",
    "codex_direct_source": "源包复核",
    "codex_agent": "Agent",
    "rule_whitelist": "白名单规则",
}


def source_label(value):
    value = str(value or "")
    if value in SOURCE_LABEL:
        return SOURCE_LABEL[value]
    if value.startswith("rule_fallback"):
        return "降级兜底"
    return value or "未知"


def _read_jsonl(path):
    rows = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except OSError:
        pass
    return rows


def _parse_time(value):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(value)[:19], fmt)
        except (TypeError, ValueError):
            continue
    return None


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def load_judgements(days):
    """汇总近 N 天的逐条研判(去重:同一告警ID保留最新文件里的)。"""
    cutoff = datetime.now() - timedelta(days=days)
    rows = []
    for path in sorted(glob.glob(str(REPORT_DIR / "cfw_alert_center_judgement_*.jsonl"))):
        # 文件名带时间戳 cfw_alert_center_judgement_YYYYMMDD_HHMMSS
        stamp = os.path.basename(path).replace("cfw_alert_center_judgement_", "").replace(".jsonl", "")
        ts = _parse_time(stamp.replace("_", " ").replace("  ", " ")[:8] + " 00:00:00") if "_" in stamp else None
        try:
            file_dt = datetime.strptime(stamp, "%Y%m%d_%H%M%S")
        except ValueError:
            file_dt = ts
        if file_dt and file_dt < cutoff - timedelta(days=1):
            continue
        for row in _read_jsonl(path):
            at = _parse_time(row.get("告警时间")) or file_dt
            if at and at >= cutoff:
                row["_at"] = at
                row["_file_dt"] = file_dt
                rows.append(row)
    # 去重:同一告警ID保留来自最新文件的那条
    by_id = {}
    for row in rows:
        aid = row.get("告警ID") or id(row)
        prev = by_id.get(aid)
        if not prev or (row.get("_file_dt") and prev.get("_file_dt") and row["_file_dt"] >= prev["_file_dt"]):
            by_id[aid] = row
    return list(by_id.values())


def overview(days=7):
    rows = load_judgements(days)
    total = len(rows)
    results = Counter(r.get("模型研判", "") for r in rows)
    sources = Counter(source_label(r.get("研判来源", "")) for r in rows)
    levels = Counter(r.get("告警等级", "") for r in rows)
    evidence_src = Counter(r.get("证据来源", "") or "无" for r in rows)

    ignore_set = {"确认未成功", "未见成功证据", "扫描探测"}
    auto_ignored = sum(results.get(k, 0) for k in ignore_set)
    retained = total - auto_ignored

    tok_in = sum(_to_int(r.get("输入Token")) for r in rows)
    tok_out = sum(_to_int(r.get("输出Token")) for r in rows)
    tok_reason = sum(_to_int(r.get("推理Token")) for r in rows)

    # token 按研判来源拆分(看 Agent 到底吃了多少)
    tok_by_source = defaultdict(lambda: {"in": 0, "out": 0, "reason": 0, "count": 0})
    for r in rows:
        s = source_label(r.get("研判来源", ""))
        tok_by_source[s]["in"] += _to_int(r.get("输入Token"))
        tok_by_source[s]["out"] += _to_int(r.get("输出Token"))
        tok_by_source[s]["reason"] += _to_int(r.get("推理Token"))
        tok_by_source[s]["count"] += 1

    return {
        "days": days,
        "total": total,
        "auto_ignored": auto_ignored,
        "retained": retained,
        "ignore_rate": round(auto_ignored / total * 100, 1) if total else 0,
        "results": {k: results.get(k, 0) for k in RESULT_ORDER if results.get(k)},
        "sources": dict(sources),
        "levels": dict(levels),
        "evidence_source": dict(evidence_src),
        "tokens": {"input": tok_in, "output": tok_out, "reasoning": tok_reason,
                   "total": tok_in + tok_out + tok_reason},
        "tokens_by_source": {k: dict(v) for k, v in tok_by_source.items()},
    }


def trend(days=7):
    """按天聚合:告警量、研判结果堆叠、token 量。"""
    rows = load_judgements(days)
    by_day = defaultdict(lambda: {"total": 0, "tokens": 0,
                                  **{k: 0 for k in RESULT_ORDER}})
    for r in rows:
        at = r.get("_at")
        if not at:
            continue
        day = at.strftime("%Y-%m-%d")
        by_day[day]["total"] += 1
        res = r.get("模型研判", "")
        if res in by_day[day]:
            by_day[day][res] += 1
        by_day[day]["tokens"] += (_to_int(r.get("输入Token")) + _to_int(r.get("输出Token"))
                                  + _to_int(r.get("推理Token")))
    days_sorted = sorted(by_day.keys())
    return {
        "days": days_sorted,
        "total": [by_day[d]["total"] for d in days_sorted],
        "tokens": [by_day[d]["tokens"] for d in days_sorted],
        "results": {k: [by_day[d][k] for d in days_sorted] for k in RESULT_ORDER},
    }


def alerts(days=7, level=None, result=None, source=None, limit=300):
    rows = load_judgements(days)
    out = []
    for r in rows:
        if level and r.get("告警等级") != level:
            continue
        if result and r.get("模型研判") != result:
            continue
        if source and source_label(r.get("研判来源", "")) != source:
            continue
        out.append({
            "告警ID": r.get("告警ID", ""),
            "告警时间": r.get("告警时间", ""),
            "攻击IP": r.get("攻击IP", ""),
            "目标IP": r.get("目标IP", ""),
            "告警等级": r.get("告警等级", ""),
            "事件名称": r.get("事件名称", ""),
            "模型研判": r.get("模型研判", ""),
            "模型置信度": r.get("模型置信度", ""),
            "研判理由": r.get("研判理由", ""),
            "关键证据": r.get("关键证据", ""),
            "证据来源": r.get("证据来源", ""),
            "研判来源": source_label(r.get("研判来源", "")),
            "工具轨迹": r.get("工具轨迹", ""),
            "源包证据": r.get("源包证据", ""),
            "Token": _to_int(r.get("输入Token")) + _to_int(r.get("输出Token")) + _to_int(r.get("推理Token")),
        })
    out.sort(key=lambda x: x["告警时间"], reverse=True)
    return out[:limit]


import ipaddress as _ipaddress


def _is_public(ip):
    try:
        return _ipaddress.ip_address(str(ip).split("|")[0].strip()).is_global
    except ValueError:
        return False


def attacker_rank(days=7, limit=12):
    """攻击来源 TOP:按攻击IP聚合(手法数/告警数/方向/最高等级)。"""
    rows = load_judgements(days)
    agg = {}
    for r in rows:
        ip = str(r.get("攻击IP", "")).split("|")[0].strip()
        if not ip:
            continue
        g = agg.setdefault(ip, {"ip": ip, "count": 0, "events": set(),
                                "public": _is_public(ip), "high": 0, "success": 0})
        g["count"] += 1
        if r.get("事件名称"):
            g["events"].add(r.get("事件名称"))
        if r.get("告警等级") == "高危":
            g["high"] += 1
        if r.get("模型研判") == "确认成功":
            g["success"] += 1
    out = [{"ip": g["ip"], "count": g["count"], "techniques": len(g["events"]),
            "public": g["public"], "high": g["high"], "success": g["success"]}
           for g in agg.values()]
    out.sort(key=lambda x: (x["success"], x["high"], x["techniques"], x["count"]), reverse=True)
    return out[:limit]


def asset_rank(days=7, limit=12):
    """被攻击资产 TOP:按目标IP聚合(被打次数/攻击者数/最高等级)。"""
    rows = load_judgements(days)
    agg = {}
    for r in rows:
        for dst in str(r.get("目标IP", "")).split("|"):
            dst = dst.strip()
            if not dst:
                continue
            g = agg.setdefault(dst, {"dst": dst, "count": 0, "attackers": set(), "high": 0})
            g["count"] += 1
            src = str(r.get("攻击IP", "")).split("|")[0].strip()
            if src:
                g["attackers"].add(src)
            if r.get("告警等级") == "高危":
                g["high"] += 1
    out = [{"dst": g["dst"], "count": g["count"], "attackers": len(g["attackers"]), "high": g["high"]}
           for g in agg.values()]
    out.sort(key=lambda x: (x["high"], x["count"]), reverse=True)
    return out[:limit]


def realtime_attention(days=2, limit=30):
    """需重点关注的实时列表:确认成功/需人工复核/高危。"""
    rows = load_judgements(days)
    out = []
    for r in rows:
        if r.get("模型研判") in ("确认成功", "需人工复核") or r.get("告警等级") == "高危":
            out.append({
                "time": r.get("告警时间", ""),
                "level": r.get("告警等级", ""),
                "event": r.get("事件名称", ""),
                "src": r.get("攻击IP", ""),
                "dst": r.get("目标IP", ""),
                "result": r.get("模型研判", ""),
                "reason": r.get("研判理由", ""),
                "public": _is_public(str(r.get("攻击IP", "")).split("|")[0].strip()),
            })
    prio = {"确认成功": 0, "需人工复核": 1}
    out.sort(key=lambda x: (prio.get(x["result"], 5), x["time"]), reverse=False)
    out.sort(key=lambda x: (x["result"] == "确认成功", x["level"] == "高危"), reverse=True)
    return out[:limit]


# 危险手法关键词(连线标红)
_DANGER_KW = ("RCE", "代码执行", "命令注入", "命令执行", "webshell", "WebShell",
              "文件上传", "上传可疑", "反序列化", "njRAT", "木马", "注入", "文件读取", "目录遍历")


def _danger_level(event_name):
    n = str(event_name or "")
    if any(k in n for k in ("RCE", "代码执行", "命令注入", "命令执行", "webshell", "WebShell", "njRAT", "木马", "反序列化")):
        return 2  # 高危手法
    if any(k in n for k in _DANGER_KW):
        return 1  # 中
    return 0      # 扫描/探测类


def attack_graph(days=7, focus="key", max_edges=200, min_danger=0, collapse_solo=True, target=None):
    """攻击拓扑图数据(ECharts graph 格式)。

    min_danger: 只画危险度≥此值的边(0全部/1中危以上/2仅高危)。
    collapse_solo: 把"只打1个目标"的零散攻击者折叠成目标上的汇总(降低杂乱)。
    target: 只看打这个资产(目标IP)的攻击链,聚焦单资产,避免集火图糊成团。

    节点:公网攻击者(红)/中转节点(黄,既被攻击又对外攻击)/内网资产(蓝)。
    边:攻击者→目标,颜色按手法危险度。
    focus='key' 默认只画"值得看的"(高危手法 + 中转节点相关),避免糊成一团;
    focus='all' 画全部。
    """
    rows = load_judgements(days)
    # 先建原始边 + 节点角色
    raw = []  # (src, dst, event, danger, level, result)
    src_set, dst_set = set(), set()
    asset_name = {}  # ip -> 资产名
    for r in rows:
        src = str(r.get("攻击IP", "")).split("|")[0].strip()
        if not src:
            continue
        # 解析目标资产名:格式 id/name/type/ip(多个用 | 分隔),建 ip->name
        for part in str(r.get("目标资产", "")).split("|"):
            seg = part.split("/")
            if len(seg) >= 4 and seg[3].strip():
                asset_name[seg[3].strip()] = seg[1].strip() or seg[3].strip()
        ev = r.get("事件名称", "")
        danger = _danger_level(ev)
        for dst in str(r.get("目标IP", "")).split("|"):
            dst = dst.strip()
            if not dst:
                continue
            raw.append((src, dst, ev, danger, r.get("告警等级", ""), r.get("模型研判", "")))
            src_set.add(src)
            dst_set.add(dst)
    pivots = src_set & dst_set  # 中转节点

    # 被攻击资产清单(供前端下拉:按被攻击次数排序,带资产名)
    dst_count = {}
    for src, dst, ev, danger, level, result in raw:
        dst_count[dst] = dst_count.get(dst, 0) + 1
    target_list = [{"ip": ip, "name": asset_name.get(ip, ip), "count": c}
                   for ip, c in sorted(dst_count.items(), key=lambda kv: -kv[1])]

    # 边聚合(同 src-dst 合并,取最高危险度、累加次数)
    edge_agg = {}
    for src, dst, ev, danger, level, result in raw:
        k = (src, dst)
        e = edge_agg.setdefault(k, {"src": src, "dst": dst, "count": 0, "danger": 0, "events": set()})
        e["count"] += 1
        e["danger"] = max(e["danger"], danger)
        e["events"].add(str(ev)[:16])

    edges = list(edge_agg.values())
    # 按资产聚焦:只看打指定目标的攻击链。聚焦单资产时自动展开——关折叠、不做
    # focus 过滤、放宽危险度,把打这个资产的攻击者全显示(这正是聚焦的目的)。
    if target:
        edges = [e for e in edges if e["dst"] == target or e["src"] == target]
        collapse_solo = False
        focus = "all"
        min_danger = 0
    # 危险度过滤(用户筛选项)
    edges = [e for e in edges if e["danger"] >= min_danger]
    # focus=key:只保留 高危手法 或 涉及中转节点 的边
    if focus == "key":
        edges = [e for e in edges if e["danger"] >= 1 or e["src"] in pivots or e["dst"] in pivots]
    edges.sort(key=lambda e: (e["danger"], e["count"]), reverse=True)
    edges = edges[:max_edges]

    # 折叠"只打1个目标"的零散公网攻击者:不画独立点,聚合到目标上计数
    solo_per_target = {}  # dst -> {count: n, srcs: set}
    if collapse_solo:
        out_deg = {}
        for e in edges:
            out_deg[e["src"]] = out_deg.get(e["src"], 0) + 1
        kept = []
        for e in edges:
            # 源是公网、且只连这1个目标、且非中转 → 折叠
            if e["src"] not in pivots and _is_public(e["src"]) and out_deg.get(e["src"], 0) == 1:
                t = e["dst"]
                g = solo_per_target.setdefault(t, {"count": 0, "srcs": set(), "danger": 0})
                g["count"] += 1
                g["srcs"].add(e["src"])
                g["danger"] = max(g["danger"], e["danger"])
            else:
                kept.append(e)
        edges = kept

    used = set()
    for e in edges:
        used.add(e["src"]); used.add(e["dst"])
    used.update(solo_per_target.keys())  # 被折叠攻击的目标也要在

    degree = {}
    for e in edges:
        degree[e["src"]] = degree.get(e["src"], 0) + e["count"]
        degree[e["dst"]] = degree.get(e["dst"], 0) + e["count"]
    for t, g in solo_per_target.items():
        degree[t] = degree.get(t, 0) + g["count"]

    nodes = []
    for ip in used:
        is_pivot = ip in pivots
        is_pub = _is_public(ip)
        if is_pivot:
            cat, color = "中转", "#ffb547"
        elif is_pub:
            cat, color = "公网攻击者", "#ff5470"
        else:
            cat, color = "内网资产", "#3da9fc"
        deg = degree.get(ip, 1)
        nodes.append({
            "id": ip,
            "name": asset_name.get(ip, ip),
            "category": cat,
            "color": color,
            "value": deg,
            "size": min(8 + deg * 1.6, 48),
            "show_label": deg >= 3 or is_pivot or not is_pub,  # 只给枢纽/中转/资产显示标签
        })

    links = []
    for e in edges:
        ecolor = "#ff5470" if e["danger"] == 2 else ("#ffb547" if e["danger"] == 1 else "#56607a")
        links.append({
            "source": e["src"], "target": e["dst"],
            "value": e["count"], "danger": e["danger"],
            "events": "、".join(sorted(e["events"])[:4]), "color": ecolor,
        })

    # 折叠的零散攻击者:每个目标加一个"零散扫描源"汇总节点 + 一条边
    folded = 0
    for t, g in solo_per_target.items():
        sid = f"__solo__{t}"
        n = len(g["srcs"])
        folded += n
        nodes.append({
            "id": sid, "name": f"零散扫描 ×{n}", "category": "公网攻击者",
            "color": "#7a3b48", "value": n, "size": min(10 + n * 0.8, 30), "show_label": True,
        })
        links.append({
            "source": sid, "target": t, "value": g["count"], "danger": g["danger"],
            "events": f"{n} 个一次性扫描源", "color": "#56607a",
        })

    return {
        "nodes": nodes, "links": links,
        "stats": {"attackers": sum(1 for n in nodes if n["category"] == "公网攻击者" and not n["id"].startswith("__solo__")),
                  "pivots": sum(1 for n in nodes if n["category"] == "中转"),
                  "targets": sum(1 for n in nodes if n["category"] == "内网资产"),
                  "edges": len(links), "folded_solo": folded, "focus": focus},
        "targets_list": target_list,
    }


def health(days=7):
    """健康面板:LLM 错误/降级、处置失败、源包命中率、Agent 占比、企微发送。"""
    cutoff = datetime.now() - timedelta(days=days)
    # LLM 错误(降级原因)
    errors = []
    err_by_type = Counter()
    for e in _read_jsonl(LOG_DIR / "llm-errors.jsonl"):
        at = _parse_time(e.get("time"))
        if at and at >= cutoff:
            err_by_type[e.get("error_type", "?")] += 1
            errors.append({"time": e.get("time"), "provider": e.get("provider"),
                           "type": e.get("error_type"), "error": str(e.get("error", ""))[:160]})
    # 处置情况(从 hourly 记录)
    dispose_ignored = dispose_failed = 0
    for path in sorted(glob.glob(str(DATA_DIR / "alert-center-hourly-*.jsonl"))):
        for rec in _read_jsonl(path):
            at = _parse_time(rec.get("recorded_at"))
            if not (at and at >= cutoff):
                continue
            dispose_ignored += _to_int(rec.get("ignored_confirmed"))
            for action in (rec.get("omit_actions") or []) + (rec.get("white_actions") or []):
                if action.get("error") or action.get("return_code") not in (None, 0, "0"):
                    dispose_failed += 1
    # 源包命中率 / Agent 占比
    rows = load_judgements(days)
    with_evidence = sum(1 for r in rows if r.get("证据来源") in ("主动拉取", "本地缓存"))
    agent_count = sum(1 for r in rows if r.get("研判来源") == "codex_agent")
    degraded = sum(1 for r in rows if str(r.get("研判来源", "")).startswith("rule_fallback"))
    return {
        "errors_total": sum(err_by_type.values()),
        "errors_by_type": dict(err_by_type),
        "recent_errors": errors[-15:][::-1],
        "dispose_ignored": dispose_ignored,
        "dispose_failed": dispose_failed,
        "evidence_hit_rate": round(with_evidence / len(rows) * 100, 1) if rows else 0,
        "evidence_hit": with_evidence,
        "degraded": degraded,
        "degraded_rate": round(degraded / len(rows) * 100, 1) if rows else 0,
        "agent_count": agent_count,
        "total": len(rows),
    }


def profiles(days=7, limit=50):
    """读取最近 N 天的攻击者画像(每次运行落一条 summary,取并集后按评分去重)。"""
    cutoff = datetime.now() - timedelta(days=days)
    by_ip = {}
    for path in sorted(glob.glob(str(DATA_DIR / "attacker-profile-*.jsonl"))):
        for rec in _read_jsonl(path):
            at = _parse_time(rec.get("recorded_at"))
            if at and at < cutoff:
                continue
            run_at = rec.get("recorded_at", "")
            for p in rec.get("top_profiles", []):
                ip = p.get("ip")
                if not ip:
                    continue
                p = dict(p, _run_at=run_at)
                prev = by_ip.get(ip)
                # 同一 IP 保留最新运行的画像
                if not prev or run_at >= prev.get("_run_at", ""):
                    by_ip[ip] = p
    out = list(by_ip.values())
    out.sort(key=lambda p: -(p.get("profile", {}).get("final_score", 0)))
    # 拍平成前端友好的结构
    flat = []
    for p in out[:limit]:
        pr = p.get("profile", {})
        flat.append({
            "ip": p.get("ip", ""),
            "internal": p.get("internal", False),
            "country": p.get("country", ""),
            "attacker_type": pr.get("attacker_type", ""),
            "intent": pr.get("intent", ""),
            "stage": pr.get("stage", ""),
            "narrative": pr.get("narrative", ""),
            "score": pr.get("final_score", p.get("rule_score", 0)),
            "rule_score": p.get("rule_score", 0),
            "band": p.get("band", ""),
            "recommendation": pr.get("recommendation", ""),
            "alert_count": p.get("alert_count", 0),
            "technique_kinds": p.get("technique_kinds", 0),
            "target_count": p.get("target_count", 0),
            "killchain_max": p.get("killchain_max", ""),
            "high": p.get("high", 0),
            "cloud_success": p.get("cloud_success", 0),
            "span_hours": p.get("span_hours", 0),
            "first_seen": p.get("first_seen", ""),
            "last_seen": p.get("last_seen", ""),
            "events": p.get("events", {}),
            "targets": p.get("targets", []),
            "run_at": p.get("_run_at", ""),
        })
    return flat


def full_report(days=7):
    return {
        "overview": overview(days),
        "trend": trend(days),
        "health": health(days),
    }


def _print_console(days):
    ov = overview(days)
    he = health(days)
    line = "=" * 52
    print(line)
    print(f"  CFW 研判控制台   近 {days} 天")
    print(line)
    print(f"告警总量 {ov['total']}  |  自动忽略 {ov['auto_ignored']} ({ov['ignore_rate']}%)  |  保留 {ov['retained']}")
    print("研判分布:", "  ".join(f"{k} {v}" for k, v in ov["results"].items()))
    print("研判来源:", "  ".join(f"{k} {v}" for k, v in ov["sources"].items()))
    print("证据来源:", "  ".join(f"{k} {v}" for k, v in ov["evidence_source"].items()))
    t = ov["tokens"]
    print(f"Token: 输入 {t['input']:,}  输出 {t['output']:,}  推理 {t['reasoning']:,}  合计 {t['total']:,}")
    print("Token按来源:")
    for s, v in sorted(ov["tokens_by_source"].items(), key=lambda kv: -(kv[1]["in"] + kv[1]["out"])):
        print(f"   {s:10s} 调用{v['count']:4d}  in {v['in']:>9,}  out {v['out']:>7,}  reason {v['reason']:>7,}")
    print(line)
    print(f"源包命中率 {he['evidence_hit_rate']}% ({he['evidence_hit']}/{he['total']})  |  Agent 研判 {he['agent_count']}")
    print(f"处置忽略 {he['dispose_ignored']}  |  处置失败 {he['dispose_failed']}  |  LLM错误/降级 {he['errors_total']} {he['errors_by_type']}")
    if he["recent_errors"]:
        print("最近错误:")
        for e in he["recent_errors"][:5]:
            print(f"   {e['time']} {e['provider']} {e['type']}")
    print(line)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="CFW 研判控制台数据聚合")
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--json", action="store_true", help="输出完整 JSON 而非文字报表")
    args = parser.parse_args()
    if args.json:
        print(json.dumps(full_report(args.days), ensure_ascii=False, indent=2))
    else:
        _print_console(args.days)
