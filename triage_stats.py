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
PROFILE_NO_SUCCESS_RESULTS = {"确认未成功", "未见成功证据", "扫描探测", "业务误报"}
PROFILE_STAGE_ALIASES = {
    "": "",
    "无": "",
    "侦察": "探测",
    "侦察扫描": "探测",
    "扫描探测": "探测",
    "武器化": "尝试利用",
    "投递": "尝试利用",
    "利用": "尝试利用",
    "漏洞利用": "尝试利用",
    "利用尝试": "尝试利用",
    "尝试利用": "尝试利用",
    "已利用": "成功利用",
    "利用成功": "成功利用",
    "成功利用": "成功利用",
    "安装": "落地驻留",
    "落地": "落地驻留",
    "落地执行": "落地驻留",
    "落地驻留": "落地驻留",
    "控制": "控制回连",
    "命令控制": "控制回连",
    "控制回连": "控制回连",
    "横向": "横向扩散",
    "横向移动": "横向扩散",
    "横向扩散": "横向扩散",
    "窃取": "外传/破坏",
    "数据窃取": "外传/破坏",
    "数据外传": "外传/破坏",
    "影响破坏": "外传/破坏",
    "外传破坏": "外传/破坏",
    "数据/破坏": "外传/破坏",
    "行动": "外传/破坏",
    "外传/破坏": "外传/破坏",
}
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


def profile_stage_label(value, default="探测"):
    return PROFILE_STAGE_ALIASES.get(str(value or "").strip(), str(value or "").strip() or default)


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


def _read_json_file(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


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
        row = dict(r)
        row.pop("_at", None)
        row.pop("_file_dt", None)
        row["研判来源原始"] = r.get("研判来源", "")
        row["研判来源"] = source_label(r.get("研判来源", ""))
        row["输入Token"] = _to_int(r.get("输入Token"))
        row["输出Token"] = _to_int(r.get("输出Token"))
        row["推理Token"] = _to_int(r.get("推理Token"))
        row["Token"] = row["输入Token"] + row["输出Token"] + row["推理Token"]
        out.append(row)
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


def asset_cards(days=7, only_notable=True, limit=40):
    """按被攻击资产聚合成事件卡片(替代攻击拓扑图)。

    每张卡:资产名/IP、被打次数、攻击者数、手法分布、是否得手、最高等级、TOP攻击者。
    only_notable=True 只出"值得关注"的资产卡(高危手法/有得手/多攻击者),
    其余零散扫描合并成一张汇总卡。
    """
    rows = load_judgements(days)
    agg = {}
    asset_name = {}
    for r in rows:
        # 资产名映射
        for part in str(r.get("目标资产", "")).split("|"):
            seg = part.split("/")
            if len(seg) >= 4 and seg[3].strip():
                asset_name[seg[3].strip()] = seg[1].strip() or seg[3].strip()
        ev = r.get("事件名称", "")
        danger = _danger_level(ev)
        result = r.get("模型研判", "")
        level = r.get("告警等级", "")
        src = str(r.get("攻击IP", "")).split("|")[0].strip()
        for dst in str(r.get("目标IP", "")).split("|"):
            dst = dst.strip()
            if not dst:
                continue
            g = agg.setdefault(dst, {"ip": dst, "count": 0, "attackers": {},
                                     "events": {}, "max_danger": 0, "high": 0,
                                     "success": 0, "last": "", "results": {},
                                     "fp": 0, "real": 0})
            g["count"] += 1
            g["max_danger"] = max(g["max_danger"], danger)
            if src:
                g["attackers"][src] = g["attackers"].get(src, 0) + 1
            if ev:
                g["events"][ev] = g["events"].get(ev, 0) + 1
            if level == "高危":
                g["high"] += 1
            if result == "确认成功":
                g["success"] += 1
            if result:
                g["results"][result] = g["results"].get(result, 0) + 1
            # 误报 vs 真攻击:业务误报/扫描探测=误报噪声;其余(确认成功/未成功/未见成功/需人工)=真攻击
            if result in ("业务误报", "扫描探测"):
                g["fp"] += 1
            elif result:
                g["real"] += 1
            t = r.get("告警时间", "")
            if t > g["last"]:
                g["last"] = t

    cards, trivial = [], {"assets": 0, "count": 0}
    for dst, g in agg.items():
        # 值得关注:有真攻击(含得手/未成功/未见成功)即关注;全是误报的只在量大时才出卡
        notable = (g["success"] > 0 or g["real"] > 0 or g["max_danger"] >= 2
                   or len(g["attackers"]) >= 3 or g["count"] >= 8)
        # 卡片定性:有得手→已得手(红);有真攻击(未成功/未见成功证据)→真攻击(黄);
        # 全是误报/扫描→误报(灰,可忽略)。
        if g["success"]:
            band = "已得手"
        elif g["real"] > 0:
            band = "真攻击"
        else:
            band = "误报"
        card = {
            "ip": dst, "name": asset_name.get(dst, dst),
            "internal": not _is_public(dst),
            "count": g["count"], "attacker_count": len(g["attackers"]),
            "high": g["high"], "success": g["success"], "max_danger": g["max_danger"],
            "fp": g["fp"], "real": g["real"], "results": g["results"],
            "last": g["last"],
            "top_events": sorted(g["events"].items(), key=lambda kv: -kv[1])[:5],
            "top_attackers": sorted(g["attackers"].items(), key=lambda kv: -kv[1])[:5],
            "band": band,
        }
        if only_notable and not notable:
            trivial["assets"] += 1
            trivial["count"] += g["count"]
            continue
        cards.append(card)
    # 排序:得手 > 真攻击数 > 高危手法 > 攻击者数 > 次数(真攻击的资产排前面,误报沉底)
    cards.sort(key=lambda c: (c["success"], c["real"], c["max_danger"], c["attacker_count"], c["count"]), reverse=True)
    return {"cards": cards[:limit], "trivial": trivial,
            "total_assets": len(agg),
            "summary": {"real_assets": sum(1 for c in cards if c["band"] in ("已得手", "真攻击")),
                        "fp_assets": sum(1 for c in cards if c["band"] == "误报")}}


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


def pipeline_status(days=7, config=None, limit=12):
    """Aggregate realtime polling, disposition, and notification state for the pipeline view."""
    cutoff = datetime.now() - timedelta(days=days)
    config = config or {}
    realtime_cfg = config.get("realtime_triage") or {}
    wecom_cfg = config.get("wecom") or {}
    agent_cfg = config.get("agent") or {}
    llm_cfg = config.get("llm") or {}

    rounds = []
    for path in sorted(glob.glob(str(DATA_DIR / "realtime-poll-*.jsonl"))):
        for rec in _read_jsonl(path):
            at = _parse_time(rec.get("recorded_at") or rec.get("query_end"))
            if at and at < cutoff:
                continue
            item = _pipeline_round(rec, at)
            if item:
                rounds.append(item)
    rounds.sort(key=lambda x: x.get("_at") or datetime.min, reverse=True)

    recent = rounds[:limit]
    last_round = _strip_private(recent[0]) if recent else {}
    active_round = next((r for r in recent if _to_int(r.get("alert_count")) or _to_int(r.get("new_records"))), None)
    active_round = _strip_private(active_round) if active_round else last_round

    totals = {
        "rounds": len(rounds),
        "dry_runs": sum(1 for r in rounds if r.get("dry_run")),
        "query_total": sum(_to_int(r.get("query_total")) for r in rounds),
        "new_records": sum(_to_int(r.get("new_records")) for r in rounds),
        "alert_count": sum(_to_int(r.get("alert_count")) for r in rounds),
        "ignored": sum(_to_int(r.get("ignore_event_ids")) for r in rounds),
        "manual_candidates": sum(_to_int(r.get("manual_candidates")) for r in rounds),
        "manual_pending_push": sum(_to_int(r.get("manual_pending_push")) for r in rounds),
        "custom_rule_hits": sum(_to_int(r.get("custom_rule_hits")) for r in rounds),
        "whitelist_hit_events": sum(_to_int(r.get("whitelist_hit_events")) for r in rounds),
        "push_sent": sum(1 for r in rounds if (r.get("manual_push") or {}).get("sent")),
        "push_failed": sum(1 for r in rounds if _push_failed(r.get("manual_push") or {})),
        "action_failed": sum(_action_failed_count(r) for r in rounds),
    }

    latest_wecom = _latest_jsonl_record(DATA_DIR / f"wecom-notify-{datetime.now().strftime('%Y-%m-%d')}.jsonl", cutoff)
    if not latest_wecom:
        latest_wecom = _latest_jsonl_record(DATA_DIR / f"wecom-notify-{(datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')}.jsonl", cutoff)

    disposition = _latest_json_report("cfw_realtime_disposition_*.json", cutoff)
    disposition_round = _pipeline_round(
        disposition,
        _parse_time(disposition.get("recorded_at") or disposition.get("query_end")),
    ) if disposition else {}
    state_file = Path(realtime_cfg.get("state_file") or DATA_DIR / "realtime-poll-state.json")
    if not state_file.is_absolute():
        state_file = ROOT / state_file
    state = _read_json_file(state_file)

    return {
        "config": {
            "realtime_enabled": bool(realtime_cfg.get("enabled", False)),
            "interval_seconds": _to_int(realtime_cfg.get("interval_seconds")) or 60,
            "lookback_minutes": _to_int(realtime_cfg.get("lookback_minutes")) or 10,
            "max_records_per_round": _to_int(realtime_cfg.get("max_records_per_round")) or 80,
            "auto_dispose": bool(realtime_cfg.get("auto_dispose", True)),
            "push_manual": bool(realtime_cfg.get("push_manual", True)),
            "manual_notify_cooldown_minutes": _to_int(realtime_cfg.get("manual_notify_cooldown_minutes")) or 240,
            "daily_report_time": wecom_cfg.get("daily_report_time") or "17:50",
            "hourly_report_enabled": bool(wecom_cfg.get("hourly_enabled", False)),
            "daily_report_enabled": bool(wecom_cfg.get("daily_enabled", True)),
            "manual_push_enabled": bool(wecom_cfg.get("manual_enabled", True)),
            "agent_enabled": bool(agent_cfg.get("enabled", False)),
            "model": llm_cfg.get("model", ""),
        },
        "last_round": last_round,
        "active_round": active_round,
        "recent_rounds": [_strip_private(r) for r in recent],
        "totals": totals,
        "state": {
            "processed": len(state.get("processed") or {}),
            "manual_notified": len(state.get("manual_notified") or {}),
            "state_file_exists": state_file.exists(),
        },
        "latest_disposition": _strip_private(disposition_round),
        "latest_wecom": _sanitize_wecom(latest_wecom),
    }


def _pipeline_round(rec, at=None):
    manual_push = rec.get("manual_push") if isinstance(rec.get("manual_push"), dict) else {}
    judgement_counts = rec.get("judgement_counts") if isinstance(rec.get("judgement_counts"), dict) else {}
    return {
        "_at": at or _parse_time(rec.get("recorded_at") or rec.get("query_end")),
        "recorded_at": rec.get("recorded_at") or rec.get("query_end", ""),
        "mode": rec.get("mode", ""),
        "dry_run": bool(rec.get("dry_run", False)),
        "query_start": rec.get("query_start", ""),
        "query_end": rec.get("query_end", ""),
        "query_total": _to_int(rec.get("query_total")),
        "active_before": _to_int(rec.get("active_before")),
        "new_records": _to_int(rec.get("new_records")),
        "dedup_removed": _to_int(rec.get("dedup_removed")),
        "alert_count": _to_int(rec.get("alert_count")),
        "ignore_event_ids": _to_int(rec.get("ignore_event_ids")),
        "manual_candidates": _to_int(rec.get("manual_candidates")),
        "manual_pending_push": _to_int(rec.get("manual_pending_push")),
        "custom_rule_hits": _to_int(rec.get("custom_rule_hits")),
        "whitelist_hit_events": _to_int(rec.get("whitelist_hit_events")),
        "judgement_counts": {str(k): _to_int(v) for k, v in judgement_counts.items()},
        "manual_push": {
            "sent": bool(manual_push.get("sent", False)),
            "reason": manual_push.get("reason", ""),
            "error": str(manual_push.get("error", ""))[:160],
        },
        "white_actions_count": len(rec.get("white_actions") or []),
        "omit_actions_count": len(rec.get("omit_actions") or []),
        "action_failed": _action_failed_count(rec),
        "disposition_file": os.path.basename(str(rec.get("disposition_file") or "")),
        "judgement_jsonl": os.path.basename(str(rec.get("judgement_jsonl") or "")),
    }


def _strip_private(item):
    if not item:
        return {}
    out = dict(item)
    out.pop("_at", None)
    return out


def _action_failed_count(rec):
    failed = 0
    for action in (rec.get("white_actions") or []) + (rec.get("omit_actions") or []):
        if action.get("error") or action.get("return_code") not in (None, 0, "0"):
            failed += 1
    return failed


def _push_failed(push):
    if not push:
        return False
    if push.get("sent"):
        return False
    return bool(push.get("error")) or str(push.get("reason") or "") not in ("", "dry_run", "no_manual_items")


def _latest_jsonl_record(path, cutoff):
    rows = []
    for rec in _read_jsonl(path):
        at = _parse_time(rec.get("recorded_at") or rec.get("time"))
        if at and at >= cutoff:
            rows.append((at, rec))
    rows.sort(key=lambda x: x[0], reverse=True)
    return rows[0][1] if rows else {}


def _latest_json_report(pattern, cutoff):
    latest = None
    latest_at = None
    for path in glob.glob(str(REPORT_DIR / pattern)):
        rec = _read_json_file(path)
        at = _parse_time(rec.get("query_end") or rec.get("recorded_at"))
        if at and at < cutoff:
            continue
        if at and (latest_at is None or at > latest_at):
            latest_at = at
            latest = dict(rec, disposition_file=os.path.basename(path))
    return latest or {}


def _sanitize_wecom(rec):
    if not rec:
        return {}
    reason = str(rec.get("reason") or rec.get("error") or "")
    reason = reason.split(",", 1)[0]
    return {
        "recorded_at": rec.get("recorded_at", ""),
        "type": rec.get("type", ""),
        "enabled": bool(rec.get("enabled", False)),
        "sent": bool(rec.get("sent", False)),
        "reason": reason[:80],
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
            "stage": profile_stage_label(pr.get("stage", "")),
            "narrative": pr.get("narrative", ""),
            "score": pr.get("final_score", p.get("rule_score", 0)),
            "rule_score": p.get("rule_score", 0),
            "band": p.get("band", ""),
            "recommendation": pr.get("recommendation", ""),
            "alert_count": p.get("alert_count", 0),
            "technique_kinds": p.get("technique_kinds", 0),
            "target_count": p.get("target_count", 0),
            "killchain_max": profile_stage_label(p.get("killchain_max", "")),
            "high": p.get("high", 0),
            "cloud_success": p.get("cloud_success", 0),
            "span_hours": p.get("span_hours", 0),
            "first_seen": p.get("first_seen", ""),
            "last_seen": p.get("last_seen", ""),
            "events": p.get("events", {}),
            "targets": p.get("targets", []),
            "run_at": p.get("_run_at", ""),
        })
    return flat or _fallback_profiles_from_judgements(days, limit=limit)


def _country_for_ip(row, ip):
    for part in str(row.get("来源国家") or "").split("|"):
        if part.startswith(str(ip) + ":"):
            return part.split(":", 1)[1]
    return ""


def _fallback_profiles_from_judgements(days=7, limit=50):
    """Build rule-based attacker cards when attacker_profile.py has not run yet."""
    rows = load_judgements(days)
    agg = {}
    for row in rows:
        src_ips = [x.strip() for x in str(row.get("攻击IP") or "").split("|") if x.strip()]
        dst_ips = [x.strip() for x in str(row.get("目标IP") or "").split("|") if x.strip()]
        event = row.get("事件名称", "")
        result = row.get("模型研判", "")
        level = row.get("告警等级", "")
        at = row.get("告警时间", "")
        for ip in src_ips:
            g = agg.setdefault(ip, {
                "ip": ip,
                "internal": not _is_public(ip),
                "country": _country_for_ip(row, ip),
                "alert_count": 0,
                "events": Counter(),
                "targets": set(),
                "results": Counter(),
                "high": 0,
                "cloud_success": 0,
                "first_seen": at,
                "last_seen": at,
                "max_danger": 0,
            })
            if not g["country"]:
                g["country"] = _country_for_ip(row, ip)
            g["alert_count"] += 1
            if event:
                g["events"][event] += 1
                g["max_danger"] = max(g["max_danger"], _danger_level(event))
            for dst in dst_ips:
                g["targets"].add(dst)
            if result:
                g["results"][result] += 1
            if level == "高危":
                g["high"] += 1
            if result == "确认成功":
                g["cloud_success"] += 1
            if at and (not g["first_seen"] or at < g["first_seen"]):
                g["first_seen"] = at
            if at and at > g["last_seen"]:
                g["last_seen"] = at

    out = []
    for g in agg.values():
        technique_kinds = len(g["events"])
        target_count = len(g["targets"])
        success = g["cloud_success"]
        manual = g["results"].get("需人工复核", 0)
        unknown = g["results"].get("未见成功证据", 0)
        scan = g["results"].get("扫描探测", 0)
        false_positive = g["results"].get("业务误报", 0)
        safe_count = sum(g["results"].get(k, 0) for k in PROFILE_NO_SUCCESS_RESULTS)
        all_no_success = (
            success == 0
            and manual == 0
            and g["high"] == 0
            and g["alert_count"] > 0
            and safe_count >= g["alert_count"]
        )
        base_score = (
            10
            + min(g["alert_count"] * 2, 18)
            + min(technique_kinds * 5, 35)
            + min(target_count * 4, 20)
        )
        risk_bonus = g["high"] * 16 + success * 35 + manual * 14
        if all_no_success:
            if unknown or g["results"].get("确认未成功", 0):
                risk_bonus += min(g["max_danger"] * 4, 8)
        else:
            risk_bonus += g["max_danger"] * 8
        score = min(100, base_score + risk_bonus)
        if all_no_success:
            if scan + false_positive >= max(1, g["alert_count"] // 2):
                score = min(score, 34)
            elif g["max_danger"] >= 2 or technique_kinds >= 4 or g["alert_count"] >= 5:
                score = min(score, 45)
            else:
                score = min(score, 39)
        if success or (not all_no_success and score >= 70):
            band = "高危"
        elif manual or unknown or score >= 40:
            band = "关注"
        else:
            band = "一般"
        if success:
            attacker_type = "疑似成功攻击源"
            intent = "利用并落地"
            stage = "成功利用"
            killchain_stage = "成功利用"
            recommendation = "立即核查目标资产日志和落地痕迹"
        elif all_no_success and (g["max_danger"] >= 2 or unknown):
            attacker_type = "漏洞利用尝试源"
            intent = "尝试利用暴露服务,未见落地证据"
            stage = "尝试利用"
            killchain_stage = "尝试利用"
            recommendation = "持续观察并保留证据,无成功证据时不按高危攻击者处置"
        elif g["max_danger"] >= 2 or manual:
            attacker_type = "漏洞利用攻击源"
            intent = "尝试利用暴露服务"
            stage = "尝试利用"
            killchain_stage = "尝试利用"
            recommendation = "优先复核源包、目标服务日志和同源历史行为"
        elif scan >= max(1, g["alert_count"] // 2):
            attacker_type = "扫描探测源"
            intent = "资产探测与漏洞枚举"
            stage = "探测"
            killchain_stage = "探测"
            recommendation = "保持自动忽略,如命中受控扫描源可加入规则"
        else:
            attacker_type = "低频攻击源"
            intent = "失败尝试"
            stage = "尝试利用"
            killchain_stage = "尝试利用"
            recommendation = "持续观察,出现高危或成功证据时升级处理"
        top_event = g["events"].most_common(1)[0][0] if g["events"] else "未知事件"
        narrative = f"{g['ip']} 在窗口内触发 {g['alert_count']} 条告警,主要为 {top_event},覆盖 {target_count} 个目标,当前结论以 {g['results'].most_common(1)[0][0] if g['results'] else '未知'} 为主。"
        first = _parse_time(g["first_seen"])
        last = _parse_time(g["last_seen"])
        span = round((last - first).total_seconds() / 3600, 1) if first and last and last >= first else 0
        out.append({
            "ip": g["ip"],
            "internal": g["internal"],
            "country": g["country"],
            "attacker_type": attacker_type,
            "intent": intent,
            "stage": stage,
            "narrative": narrative,
            "score": score,
            "rule_score": score,
            "band": band,
            "recommendation": recommendation,
            "alert_count": g["alert_count"],
            "technique_kinds": technique_kinds,
            "target_count": target_count,
            "killchain_max": killchain_stage,
            "high": g["high"],
            "cloud_success": success,
            "span_hours": span,
            "first_seen": g["first_seen"],
            "last_seen": g["last_seen"],
            "events": dict(g["events"]),
            "targets": sorted(g["targets"]),
            "run_at": "rule_fallback",
            "profile_source": "rule_fallback",
        })
    out.sort(key=lambda p: (p["score"], p["alert_count"], p["technique_kinds"]), reverse=True)
    return out[:limit]


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
