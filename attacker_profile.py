"""攻击者画像 —— 从逐条告警升级到"按攻击者维度"的研判。

把一段时间窗内告警中心的全部告警按攻击源 IP 聚合,算出攻击序列/手法多样性/
杀伤链阶段/是否得手,再把聚合结果(及关键源包)喂模型做画像级研判:攻击者类型、
意图、攻击叙事、当前阶段、画像威胁评分、处置建议。高危画像推企微。

复用 cfw_alert_monitor 的 Codex 调用、源包抓取与企微发送,不依赖数据库。

用法:
    python attacker_profile.py --days 2              # 跑画像,高危推企微
    python attacker_profile.py --days 2 --dry-run    # 只算不推
    python attacker_profile.py --days 2 --top 10     # 只画像 top N 活跃攻击者
"""
import argparse
import ipaddress
import json
from collections import Counter, defaultdict
from datetime import timedelta

import cfw_alert_monitor as monitor
import cfw_alert_center_triage as triage


# 杀伤链阶段排序(用于判断攻击者推进到哪一步)
KILLCHAIN_ORDER = ["侦察扫描", "漏洞利用", "横向移动", "命令控制", "数据窃取", "影响破坏"]


def _is_internal(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def aggregate_attackers(config, days):
    """按攻击源 IP 聚合告警中心记录,返回画像基础数据列表。"""
    records, query = triage.fetch_unhandled_alert_center(config, days)
    by_ip = defaultdict(list)
    for record in records:
        for ip in (record.get("SrcIpList") or []):
            by_ip[str(ip)].append(record)

    attackers = []
    for ip, recs in by_ip.items():
        events = [str(r.get("EventName") or "") for r in recs]
        kill = [str(r.get("KillChain") or "") for r in recs if r.get("KillChain")]
        dst = set()
        for r in recs:
            dst.update(str(x) for x in (r.get("DstIpList") or []))
        levels = Counter(str(r.get("Level") or "") for r in recs)
        results = Counter(str(r.get("AttackResult") or "") for r in recs)
        times = sorted(str(r.get("EndTime") or "") for r in recs if r.get("EndTime"))
        country = ""
        for r in recs:
            for info in (r.get("SrcIpInfo") or []):
                if isinstance(info, dict) and info.get("Address"):
                    country = str(info.get("Address"))
                    break
            if country:
                break

        technique_kinds = len(set(events))
        cloud_success = results.get("1", 0)
        span_hours = 0.0
        if len(times) >= 2:
            t0 = triage.parse_local_time(times[0])
            t1 = triage.parse_local_time(times[-1])
            if t0 and t1:
                span_hours = round((t1 - t0).total_seconds() / 3600, 1)

        attackers.append({
            "ip": ip,
            "internal": _is_internal(ip),
            "country": country,
            "alert_count": len(recs),
            "technique_kinds": technique_kinds,
            "events": dict(Counter(events)),
            "killchain": dict(Counter(kill)),
            "killchain_max": _max_stage(kill),
            "target_count": len(dst),
            "targets": sorted(dst)[:8],
            "levels": dict(levels),
            "high": levels.get("High", 0),
            "cloud_success": cloud_success,
            "span_hours": span_hours,
            "first_seen": times[0] if times else "",
            "last_seen": times[-1] if times else "",
            "_records": recs,
        })

    attackers.sort(key=lambda a: (a["high"], a["technique_kinds"], a["alert_count"]), reverse=True)
    return attackers, query


def _max_stage(kill_list):
    best = ""
    best_idx = -1
    for k in kill_list:
        if k in KILLCHAIN_ORDER and KILLCHAIN_ORDER.index(k) > best_idx:
            best_idx = KILLCHAIN_ORDER.index(k)
            best = k
    return best


def rule_score(a):
    """规则画像评分 0-100:手法多样性 + 针对性 + 阶段 + 是否得手。"""
    score = 0
    score += min(a["technique_kinds"] * 6, 40)        # 手法越多越像有目标攻击者
    score += min(a["alert_count"], 15)                # 频次
    score += a["high"] * 5                            # 高危告警
    # 真实落地信号(木马/webshell/回连)才是高危依据;KillChain="横向移动" 只是腾讯云对
    # 内网→内网流量的默认打标,不能当作真横向证据,否则内网业务全被抬成高危。
    events_text = " ".join(a["events"].keys())
    landed = any(k in events_text for k in ("njRAT", "木马", "webshell", "WebShell", "反弹", "回连"))
    if landed:
        score += 25
    if a["cloud_success"]:
        score += 20
    # 内网源仅在有落地信号时才加权;无证据的内网告警不额外抬分(多为业务误报)
    if a["internal"] and (landed or a["cloud_success"]):
        score += 10
    return min(score, 100)


def attacker_band(score):
    if score >= 70:
        return "高危"
    if score >= 45:
        return "关注"
    return "一般"


# ---------------- 模型画像研判 ----------------

def build_profile_prompt(a):
    seq = sorted(a["events"].items(), key=lambda kv: -kv[1])
    payload = {
        "ip": a["ip"],
        "内外网": "内网源" if a["internal"] else "公网源",
        "来源": a["country"],
        "告警总数": a["alert_count"],
        "手法种类": a["technique_kinds"],
        "手法序列": [f"{name}x{cnt}" for name, cnt in seq][:12],
        "杀伤链阶段": a["killchain"],
        "已达最深阶段": a["killchain_max"],
        "目标资产数": a["target_count"],
        "高危告警数": a["high"],
        "云端标记成功数": a["cloud_success"],
        "活动时间跨度小时": a["span_hours"],
    }
    # 抓一条该源的真实源包样本,让模型据此区分"真攻击" vs "内网业务被误报"
    if a.get("evidence_sample"):
        payload["源包样本"] = a["evidence_sample"]
    return (
        "你是资深威胁分析师。基于一个攻击源IP在时间窗内的全部告警聚合,给出攻击者画像。"
        "只输出一个紧凑JSON对象,字段:"
        "attacker_type(自动化扫描器/脚本小子/有目标的攻击者/疑似APT/内部异常/正常业务误报),"
        "intent(攻击意图,≤30汉字),"
        "stage(当前杀伤链阶段判断,取:侦察/利用尝试/已利用/横向/控制/窃取/无),"
        "narrative(攻击叙事,用1-2句话讲清这个IP先做了什么再做了什么有没有得手,≤80汉字),"
        "threat_score(0-100整数),"
        "recommendation(处置建议,取:封禁/重点监控/继续观察/忽略,可加简短理由,≤25汉字)。"
        "判断依据:手法越多样越集中越像有目标攻击者;纯单一扫描特征是扫描器;"
        "有云端成功、木马通信(njRAT等)、命令回显或已达横向/控制阶段则威胁高。"
        "内网源研判分级(关键,避免把正常业务误画成攻击者):"
        "①若手法序列含木马通信(njRAT)/webshell/反弹回连,或云端标记成功数>0 → 真实威胁,"
        "判'内部异常',threat_score≥70,recommendation='封禁'或'重点监控'(这条优先级最高,样本即使正常也按此判);"
        "②否则若源包样本响应是正常业务(code:0/success/正常页面/error页/200空体)且无命令回显 → "
        "'正常业务误报',threat_score≤20,recommendation='忽略';"
        "③否则(内网源、无落地证据、样本也看不出明显攻击)→ 不要轻易判内部异常或横向,"
        "判'内网可疑待确认',threat_score 30-45,recommendation='继续观察',"
        "narrative如实说明'仅IDS规则告警,无落地证据,需人工确认是否业务'。"
        "切忌仅凭'SQL注入/文件上传'这类规则名就判横向——这些规则在内网业务上极易误报。"
        "聚合=" + json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    )


def model_profile(config, a, model):
    """对单个攻击者跑模型画像研判,返回画像 dict 或 None。"""
    prompt = build_profile_prompt(a)
    body_obj = monitor.codex_direct_request_body(
        model, prompt, (config.get("llm") or {}).get("reasoning_effort", "medium"))

    def _attempt():
        import urllib.request
        data = json.dumps(body_obj, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            (config.get("llm") or {}).get("codex_responses_url") or monitor.CODEX_RESPONSES_URL,
            data=data, method="POST", headers=monitor.load_codex_auth_headers())
        chunks = []
        with urllib.request.urlopen(req, timeout=float((config.get("llm") or {}).get("timeout_seconds", 180))) as resp:
            event_name = None
            lines = []
            for raw in resp:
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if not line:
                    if lines:
                        et, text, _, _ = monitor.handle_codex_direct_sse(event_name, "\n".join(lines))
                        if text and (et != "response.completed" or not chunks):
                            chunks.append(text)
                        if et == "response.completed":
                            break
                    event_name = None
                    lines = []
                    continue
                if line.startswith("event:"):
                    event_name = line.split(":", 1)[1].strip()
                elif line.startswith("data:"):
                    lines.append(line.split(":", 1)[1].lstrip())
        return "".join(chunks)

    try:
        text = monitor.with_codex_retry(config, _attempt, "attacker_profile")
        parsed = monitor.parse_llm_json(text)
    except Exception as exc:
        monitor.append_llm_error("attacker_profile", model, [], exc)
        return None
    if isinstance(parsed, list):
        parsed = parsed[0] if parsed else {}
    if not isinstance(parsed, dict):
        return None
    return {
        "attacker_type": str(parsed.get("attacker_type") or "")[:40],
        "intent": str(parsed.get("intent") or "")[:60],
        "stage": str(parsed.get("stage") or "")[:20],
        "narrative": str(parsed.get("narrative") or "")[:160],
        "threat_score": _to_int(parsed.get("threat_score")),
        "recommendation": str(parsed.get("recommendation") or "")[:50],
    }


def _to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


# ---------------- 企微卡片 ----------------

def profile_card(a, profile):
    seq = sorted(a["events"].items(), key=lambda kv: -kv[1])
    seq_text = " → ".join(f"{name}({cnt})" for name, cnt in seq[:6])
    src = "内网源" if a["internal"] else f"公网源 {a['country']}".strip()
    lines = [
        f"## 🎯 攻击者画像 · {profile.get('attacker_type', '未知')}",
        f"> **{a['ip']}**  ({src})",
        f"- 画像威胁评分:**{profile.get('threat_score', 0)}**  规则分 {a['_rule_score']} · {a['_band']}",
        f"- 攻击意图:{profile.get('intent', '-')}",
        f"- 当前阶段:**{profile.get('stage', '-')}**(杀伤链最深 {a['killchain_max'] or '-'})",
        f"- 攻击叙事:{profile.get('narrative', '-')}",
        f"- 手法序列:{seq_text}",
        f"- 规模:{a['alert_count']} 次告警 / {a['technique_kinds']} 种手法 / {a['target_count']} 个目标 / 跨度 {a['span_hours']}h",
        f"- 高危告警 {a['high']} · 云端标记成功 {a['cloud_success']}",
        f"- **处置建议:{profile.get('recommendation', '-')}**",
    ]
    return "\n".join(lines)


def run(config, days=2, top=None, dry_run=False, push_band="高危"):
    model = (config.get("llm") or {}).get("model", "gpt-5.5")
    attackers, query = aggregate_attackers(config, days)

    # 只对值得的攻击者做模型画像:多手法 / 高危 / 内网横向 / 频次高
    def worth(a):
        return (a["technique_kinds"] >= 2 or a["high"] >= 1 or a["internal"] or a["alert_count"] >= 3)

    candidates = [a for a in attackers if worth(a)]
    if top:
        candidates = candidates[:top]

    profiles = []
    pushed = []
    for a in candidates:
        a["_rule_score"] = rule_score(a)
        a["_band"] = attacker_band(a["_rule_score"])
        # 内网源抓一条真实源包样本,让模型据此区分真攻击 vs 业务误报
        if a["internal"] and a.get("_records"):
            try:
                ev = monitor.fetch_source_evidence_for_record(config, a["_records"][0])
                if ev:
                    a["evidence_sample"] = {k: str(ev.get(k))[:200] for k in
                                            ("req", "resp", "resp_mark", "resp_body", "cmd") if ev.get(k)}
            except Exception:
                pass
        profile = model_profile(config, a, model)
        if not profile:
            continue
        # 硬安全闸:聚合里只要有木马通信/webshell/云端成功等明确落地信号,
        # 绝不允许被判成"正常业务误报"(防止单条正常样本误导模型漏掉真威胁)。
        events_text = " ".join(a["events"].keys())
        hard_landed = (a["cloud_success"] > 0 or
                       any(k in events_text for k in ("njRAT", "木马", "webshell", "WebShell", "反弹", "回连")))
        if hard_landed and profile.get("attacker_type") == "正常业务误报":
            profile["attacker_type"] = "内部异常"
            profile["narrative"] = "[强制保留] 含木马/得手信号," + profile.get("narrative", "")
            profile["threat_score"] = max(profile["threat_score"], 70)

        # 综合评分:一般取模型分与规则分较高避免漏判;模型确认"正常业务误报"且无硬落地信号时,
        # 以模型低分为准(否则规则分会把误报又抬回高危,白修)。
        if profile.get("attacker_type") == "正常业务误报":
            final_score = min(profile["threat_score"], 20)
        else:
            final_score = max(profile["threat_score"], a["_rule_score"])
        profile["final_score"] = final_score
        record = {k: v for k, v in a.items() if not k.startswith("_")}
        record["rule_score"] = a["_rule_score"]
        record["band"] = a["_band"]
        record["profile"] = profile
        profiles.append(record)

        if not dry_run and attacker_band(final_score) == push_band:
            card = profile_card(a, profile)
            res = monitor.send_wecom_markdown(config, card, "attacker_profile")
            pushed.append({"ip": a["ip"], "score": final_score, "sent": res.get("sent")})

    summary = {
        "mode": "attacker_profile",
        "dry_run": dry_run,
        "query": query,
        "attackers_total": len(attackers),
        "profiled": len(profiles),
        "pushed": pushed,
        "top_profiles": sorted(profiles, key=lambda p: -p["profile"]["final_score"])[:20],
    }
    # 落盘供控制台读取
    monitor.DATA_DIR.mkdir(exist_ok=True)
    monitor.append_jsonl(
        monitor.DATA_DIR / f"attacker-profile-{monitor.now_local().strftime('%Y-%m-%d')}.jsonl",
        [dict(summary, recorded_at=monitor.dt_text(monitor.now_local()))],
    )
    return summary


def main():
    parser = argparse.ArgumentParser(description="攻击者画像研判")
    parser.add_argument("--days", type=int, default=2)
    parser.add_argument("--top", type=int)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    config = monitor.load_config()
    summary = run(config, days=args.days, top=args.top, dry_run=args.dry_run)
    # 精简打印
    out = dict(summary)
    out["top_profiles"] = [
        {"ip": p["ip"], "type": p["profile"]["attacker_type"], "score": p["profile"]["final_score"],
         "stage": p["profile"]["stage"], "narrative": p["profile"]["narrative"]}
        for p in out["top_profiles"]
    ]
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
