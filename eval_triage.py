"""研判效果评判标准 —— 客观、可重复的标尺,用于衡量每次改动是否真的变好。

不依赖模型自评(避免循环论证),而是用源包/告警里的客观信号定义"应该的结论",
再看系统实际研判与之的吻合度。每个指标越高越好(误报率越低越好)。

用法:
    python eval_triage.py --days 2            # 跑一次评分
    python eval_triage.py --days 2 --json     # 机器可读,供前后对比

指标:
  M1 内网业务误报率   内网→内网且响应为正常业务JSON,却被判攻击/横向的比例(越低越好)
  M2 成功证据严谨度   判"确认成功"的里,确实有落地证据(cmd/webshell/敏感数据/木马/云端成功)的比例
  M3 源包命中率       研判时有真实源包(主动拉取/本地缓存)的比例
  M4 待重试率         模型/API 异常导致未真正研判的比例(越低越好)
  M5 高危召回         含明确落地信号(njRAT/webshell/cmd_uid/云端成功)的告警未被自动忽略的比例
"""
import argparse
import glob
import json
import re
from datetime import datetime, timedelta

import triage_stats as stats

# 正常业务响应特征:云防火墙误报常见于内网 RPC,响应是标准业务 JSON
BUSINESS_OK = re.compile(r'"code"\s*:\s*0|"success"\s*:\s*true|活动执行成功|"message"\s*:\s*"(成功|success|ok)')
# 真实落地/得手信号(出现即应高度警惕,不能误报为正常)。
# 用词边界避免 c2/回连等短词在业务 JSON 里误匹配(如十六进制串里的 c2)。
LANDED = re.compile(
    r'njRAT|webshell|cmd_uid|\buid=\d+|root:.*:0:0:|/bin/bash|反弹shell|回连地址|\bC2\b|trojan|木马通信',
    re.I)
PRIVATE = re.compile(r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')


def _internal(ip):
    return bool(ip and PRIVATE.match(str(ip).split("|")[0].strip()))


def _has_landed(text):
    return bool(LANDED.search(str(text or "")))


def _business_ok(evidence_text):
    return bool(BUSINESS_OK.search(str(evidence_text or "")))


def _response_side(row):
    """只取源包证据里响应侧字段(resp/resp_body/resp_mark/cmd)+关键证据,
    排除请求侧 req(避免把攻击'尝试'误当成'得手')。"""
    parts = [str(row.get("关键证据", ""))]
    raw = row.get("源包证据", "")
    if isinstance(raw, str) and raw.strip().startswith("{"):
        try:
            ev = json.loads(raw)
            for k in ("resp", "resp_body", "resp_mark", "cmd", "ar"):
                if ev.get(k):
                    parts.append(str(ev[k]))
            return " ".join(parts)
        except (json.JSONDecodeError, AttributeError):
            pass
    # 解析不了就保守用整体(宁可多报落地也不漏)
    parts.append(str(raw))
    return " ".join(parts)


def evaluate(days=2):
    rows = stats.load_judgements(days)
    n = len(rows)
    if not n:
        return {"days": days, "total": 0, "note": "无研判数据"}

    # --- M1 内网业务误报 ---
    m1_pool = []      # 内网→内网 且响应像正常业务 的告警
    m1_misjudged = [] # 其中却被判成攻击/横向/需复核(非误报结论)的
    # --- M2 成功证据严谨 ---
    m2_success = []   # 判确认成功的
    m2_grounded = []  # 其中有落地证据的
    # --- M3 源包命中 ---
    m3_with_evidence = 0
    # --- M4 待重试 ---
    m4_retry_pending = 0
    # --- M5 高危召回 ---
    m5_landed_alerts = []   # 有明确落地信号的告警
    m5_retained = []        # 其中未被自动忽略的

    ignore_results = {"确认未成功", "未见成功证据", "扫描探测"}
    src_ip_field = "攻击IP"

    for r in rows:
        ip = r.get(src_ip_field, "") or r.get("源IP", "")
        dst = r.get("目标IP", "")
        result = r.get("模型研判", "")
        src_label = r.get("研判来源", "")
        evidence_blob = " ".join(str(r.get(k, "")) for k in
                                 ("源包证据", "关键证据", "研判理由", "事件名称"))

        # M3
        if r.get("证据来源") in ("主动拉取", "本地缓存"):
            m3_with_evidence += 1

        # M4 待重试
        if str(src_label).startswith(("retry_pending", "rule_fallback")) or src_label in ("待模型重试", "降级兜底"):
            m4_retry_pending += 1

        # M1 内网业务误报:源和目标都内网 + 响应像正常业务 + 无落地信号
        if _internal(ip) and _internal(dst) and _business_ok(evidence_blob) and not _has_landed(evidence_blob):
            m1_pool.append(r)
            # 误判 = 没有被判成"正常业务/疑似误报/确认未成功/未见成功证据"这类无害结论
            harmless = result in ("确认未成功", "未见成功证据", "扫描探测")
            if not harmless:
                m1_misjudged.append(r)

        # M2 确认成功严谨度
        if result == "确认成功":
            m2_success.append(r)
            if _has_landed(evidence_blob) or "成功" in str(r.get("源包证据", "")):
                m2_grounded.append(r)

        # M5 高危召回:只看"响应侧/落地侧"的落地信号(命令回显、木马通信、响应体敏感数据)。
        # 请求里带 webshell/注入串只是"尝试",不算得手,不应计入(否则误把尝试当落地)。
        resp_blob = _response_side(r)
        landed = _has_landed(resp_blob) or "木马通信" in str(r.get("事件名称", "")) or "njRAT" in str(r.get("事件名称", ""))
        if landed:
            m5_landed_alerts.append(r)
            if result not in ignore_results:
                m5_retained.append(r)

    def rate(a, b):
        return round(a / b * 100, 1) if b else None

    metrics = {
        "M1_内网业务误报率": {
            "value": rate(len(m1_misjudged), len(m1_pool)),
            "好坏": "越低越好",
            "样本": len(m1_pool), "误判": len(m1_misjudged),
            "误判例": [{"ip": x.get(src_ip_field), "事件": x.get("事件名称"), "研判": x.get("模型研判")}
                       for x in m1_misjudged[:5]],
        },
        "M2_成功证据严谨度": {
            "value": rate(len(m2_grounded), len(m2_success)),
            "好坏": "越高越好",
            "判成功数": len(m2_success), "有落地证据": len(m2_grounded),
            "存疑例": [{"ip": x.get(src_ip_field), "事件": x.get("事件名称")}
                       for x in m2_success if x not in m2_grounded][:5],
        },
        "M3_源包命中率": {
            "value": rate(m3_with_evidence, n), "好坏": "越高越好",
            "有源包": m3_with_evidence, "总数": n,
        },
        "M4_待重试率": {
            "value": rate(m4_retry_pending, n), "好坏": "越低越好",
            "待重试数": m4_retry_pending, "总数": n,
        },
        "M5_高危召回": {
            "value": rate(len(m5_retained), len(m5_landed_alerts)),
            "好坏": "越高越好(应=100)",
            "落地信号告警": len(m5_landed_alerts), "已保留": len(m5_retained),
            "漏判例": [{"ip": x.get(src_ip_field), "事件": x.get("事件名称"), "研判": x.get("模型研判")}
                       for x in m5_landed_alerts if x in
                       [a for a in m5_landed_alerts if a.get("模型研判") in ignore_results]][:5],
        },
    }
    return {"days": days, "total": n, "metrics": metrics}


def _print(report):
    print("=" * 56)
    print(f"  研判效果评判   近 {report['days']} 天   样本 {report.get('total', 0)}")
    print("=" * 56)
    if not report.get("metrics"):
        print(report.get("note", "无数据"))
        return
    for name, m in report["metrics"].items():
        v = m["value"]
        vs = "n/a" if v is None else f"{v}%"
        print(f"{name:22s} {vs:>7s}   ({m['好坏']})")
        for k, val in m.items():
            if k in ("value", "好坏"):
                continue
            if k.endswith("例") and val:
                print(f"    {k}:")
                for e in val:
                    print(f"      - {e}")
            elif not k.endswith("例"):
                print(f"    {k}: {val}")
    print("=" * 56)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="研判效果评判")
    parser.add_argument("--days", type=int, default=2)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = evaluate(args.days)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _print(report)
