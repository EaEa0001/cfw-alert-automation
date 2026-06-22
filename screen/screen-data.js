/* ============================================================
   CFW 大屏 —— 真实数据适配层
   ------------------------------------------------------------
   把 console.py 的真实接口拉取并重映射成各视图期望的 CFW.DEMO 结构，
   视图文件(view-*.js)完全不改。core.js 里的 CFW.DEMO 仅作为兜底默认值；
   本文件在 init 时用真实数据覆盖 CFW.DEMO，并在切换时间窗时重新拉取。

   接口字段 -> 视图字段 映射在各 map* 函数里。
   ============================================================ */
(function () {
  const API = (path, days) =>
    fetch(`/api/${path}?days=${days}`).then(r => r.ok ? r.json() : null).catch(() => null);

  // ---- 公网 IP 判定(内网网段以外视为公网)----
  const isPub = ip => {
    const f = String(ip || "").split("|")[0];
    return /\d+\.\d+\.\d+\.\d+/.test(f) &&
      !f.startsWith("10.") && !f.startsWith("172.") && !f.startsWith("192.168.");
  };

  // ---- /api/overview -> windows[d] ----
  function mapWindow(ov, tr, label) {
    ov = ov || {}; tr = tr || {};
    const k = ov.tokens || {};
    const trendDays = tr.days || [];
    const res = tr.results || {};
    return {
      label,
      kpi: {
        total: ov.total || 0,
        auto: ov.auto_ignored || 0,
        ignoreRate: ov.ignore_rate || 0,
        manual: (ov.results || {})["需人工复核"] || ov.retained || 0,
        success: (ov.results || {})["确认成功"] || 0,
      },
      deltas: { total: "", auto: "", manual: "", success: "" },
      results: ov.results || {},
      tokens: {
        input: k.input || 0, output: k.output || 0,
        reasoning: k.reasoning || 0, total: k.total || 0,
      },
      trend: {
        days: trendDays.map(d => String(d).slice(5)),
        total: tr.total || [],
        manual: (res["需人工复核"] || []),
        tokens: (tr.tokens || []).map(t => +(t / 1e6).toFixed(2)),
      },
    };
  }

  // ---- /api/health -> health ----
  function mapHealth(h) {
    h = h || {};
    const ebt = h.errors_by_type || {};
    return {
      evidenceHit: h.evidence_hit_rate || h.evidenceHit || 0,
      degradedRate: h.degraded_rate || h.degradedRate || 0,
      disposeIgnored: h.dispose_ignored || h.disposeIgnored || 0,
      disposeFailed: h.dispose_failed || h.disposeFailed || 0,
      llmErrors: h.errors_total || 0,
      agentCount: h.agent_count || h.agentCount || 0,
      retryQueue: h.retry_queue || h.retryQueue || 0,
      errorsByType: ebt,
    };
  }

  // ---- /api/attacker_rank -> attackerRank ----
  const mapAttackerRank = arr => (arr || []).map(a => ({
    ip: a.ip, pub: !!a.public, techniques: a.techniques || 0,
    count: a.count || 0, high: a.high || 0, country: a.country || "",
  }));

  // ---- /api/asset_rank -> assetRank ----
  const mapAssetRank = arr => (arr || []).map(a => ({
    dst: a.dst, count: a.count || 0, attackers: a.attackers || 0, high: a.high || 0,
  }));

  // ---- /api/realtime -> attention ----
  const mapAttention = arr => (arr || []).map(r => ({
    time: r.time, level: r.level, event: r.event,
    src: String(r.src || "").split("|")[0], dst: String(r.dst || "").split("|")[0],
    pub: isPub(r.src), result: r.result,
  }));

  // ---- /api/alerts(中文键) -> alerts(英文键) ----
  const mapAlerts = arr => (arr || []).map(a => ({
    time: a["告警时间"] || "", level: a["告警等级"] || "",
    event: a["事件名称"] || "", atkIp: String(a["攻击IP"] || "").split("|")[0],
    dstIp: String(a["目标IP"] || "").split("|")[0], result: a["模型研判"] || "",
    source: a["研判来源"] || "", evidenceFrom: a["证据来源"] || "",
    conf: a["模型置信度"] || a["置信度"] || "", token: a["token"] || a["Token"] || 0,
    why: a["研判理由"] || "", key: a["关键证据"] || "", trace: a["工具轨迹"] || "",
  }));

  // ---- /api/profiles(triage_stats 扁平结构) -> 视图字段 ----
  const bandOf = (b, score) => {
    if (b === "高危" || b === "关注" || b === "一般") return b;
    if (score >= 70) return "高危";
    if (score >= 45) return "关注";
    return "一般";
  };
  const mapProfiles = arr => (arr || []).map(p => {
    const score = p.score || p.rule_score || 0;
    const targets = Array.isArray(p.targets) ? p.targets.length : (p.target_count || 0);
    return {
      ip: p.ip || "",
      internal: !!p.internal,
      country: p.country || (p.internal ? "内网" : ""),
      type: p.attacker_type || p.type || "未分类",
      intent: p.intent || "—",
      stage: p.stage || p.killchain_max || "侦察",
      killchainMax: p.killchain_max || p.stage || "侦察",
      narrative: p.narrative || "(暂无 AI 叙述,运行 attacker_profile.py 生成)",
      score: score,
      band: bandOf(p.band, score),
      rec: p.recommendation || p.rec || "—",
      alertCount: p.alert_count || 0,
      techniques: p.technique_kinds || p.techniques || 0,
      targets: targets,
      span: p.span_hours || p.span || 0,
      high: p.high || 0,
      success: p.cloud_success || p.success || 0,
      events: p.events || {},
      first: p.first_seen || p.first || "",
      last: p.last_seen || p.last || "",
    };
  });

  // ---- ticker 取样池: 从真实告警里取低开销样本 ----
  const mapTicker = alerts => (alerts || []).slice(0, 12).map(a => ({
    level: a.level, event: a.event, src: a.atkIp, res: a.result,
  }));

  // 拉取某时间窗的全部数据并覆盖 CFW.DEMO
  async function load(days) {
    const [ov, tr, hp, ar, sr, rt, al, pf] = await Promise.all([
      API("overview", days), API("trend", days), API("health", days),
      API("attacker_rank", days), API("asset_rank", days),
      API("realtime", days), API("alerts", days + "&limit=300"), API("profiles", days),
    ]);
    const win = mapWindow(ov, tr, ({ 1: "今天", 3: "近 3 天", 7: "近 7 天" }[days] || days + " 天"));
    CFW.DEMO.windows[days] = win;
    CFW.DEMO.health = mapHealth(hp);
    CFW.DEMO.attackerRank = mapAttackerRank(ar);
    CFW.DEMO.assetRank = mapAssetRank(sr);
    CFW.DEMO.attention = mapAttention(rt);
    CFW.DEMO.alerts = mapAlerts(al);
    const pmapped = mapProfiles(pf);
    if (pmapped.length) CFW.DEMO.profiles = pmapped;
    CFW.DEMO.tickerPool = mapTicker(CFW.DEMO.alerts);
    // funnel 顶层用真实总量校准(其余分层用派生说明)
    if (ov && CFW.DEMO.funnel && CFW.DEMO.funnel.length) {
      CFW.DEMO.funnel = CFW.DEMO.funnel.map(f =>
        f.key === "noise" ? Object.assign({}, f, { n: ov.total || f.n }) :
        f.key === "keep" ? Object.assign({}, f, { n: ov.retained || f.n }) :
        f.key === "l3" ? Object.assign({}, f, { n: (ov.sources || {})["Agent"] || f.n }) : f);
    }
    // 去掉 DEMO 角标
    const badge = document.querySelector(".demo-badge");
    if (badge) { badge.textContent = "实时数据"; badge.classList.add("live-badge"); }
  }

  // 暴露给 app.js：在渲染前确保数据已拉取
  CFW.loadData = load;
})();
