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
      sources: ov.sources || {},
      tokensBySource: ov.tokens_by_source || {},
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
      retryPendingRate: h.retry_pending_rate || h.retryPendingRate || h.degraded_rate || h.degradedRate || 0,
      degradedRate: h.retry_pending_rate || h.retryPendingRate || h.degraded_rate || h.degradedRate || 0,
      disposeIgnored: h.dispose_ignored || h.disposeIgnored || 0,
      disposeFailed: h.dispose_failed || h.disposeFailed || 0,
      llmErrors: h.errors_total || 0,
      agentCount: h.agent_count || h.agentCount || 0,
      retryQueue: h.retry_queue || h.retryQueue || 0,
      evidenceHitCount: h.evidence_hit || h.evidenceHitCount || 0,
      retryPending: h.retry_pending || h.retryPending || h.degraded || 0,
      degraded: h.retry_pending || h.retryPending || h.degraded || 0,
      total: h.total || 0,
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
  const mapAlerts = arr => (arr || []).map(a => {
    const atk = String(a["攻击IP"] || "");
    const dst = String(a["目标IP"] || "");
    return {
      id: a["告警ID"] || "",
      date: a["日期"] || "",
      time: a["告警时间"] || "",
      level: a["告警等级"] || "",
      event: a["事件名称"] || "",
      atkIp: atk.split("|")[0],
      atkIps: atk,
      srcIp: a["源IP"] || atk,
      dstIp: dst.split("|")[0],
      dstIps: dst,
      dstAsset: a["目标资产"] || "",
      direction: a["方向"] || "",
      threatType: a["威胁类型"] || "",
      country: a["来源国家"] || "",
      ruleId: a["规则ID"] || "",
      strategy: a["策略"] || "",
      desc: a["威胁描述"] || "",
      cloudAdvice: a["云防火墙建议"] || "",
      localAdvice: a["本地建议"] || "",
      whiteState: a["白名单状态"] || "",
      result: a["模型研判"] || "",
      source: a["研判来源"] || "",
      sourceRaw: a["研判来源原始"] || "",
      model: a["研判模型"] || "",
      evidenceFrom: a["证据来源"] || "",
      evidenceHit: a["源包命中"] || "",
      sourceEvidence: a["源包证据"] || "",
      conf: a["模型置信度"] || a["置信度"] || "",
      token: a["token"] || a["Token"] || 0,
      tokenIn: a["输入Token"] || 0,
      tokenOut: a["输出Token"] || 0,
      tokenReason: a["推理Token"] || 0,
      why: a["研判理由"] || "",
      key: a["关键证据"] || "",
      next: a["下一步"] || "",
      trace: a["工具轨迹"] || "",
      raw: a,
    };
  });

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
      stage: p.stage || p.killchain_max || "探测",
      killchainMax: p.killchain_max || p.stage || "探测",
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

  // 真实漏斗:全部由 overview.sources / total / retained 派生,无硬编码占位
  function buildFunnel(ov) {
    ov = ov || {};
    const s = ov.sources || {};
    const total = ov.total || 0;
    const auto = ov.auto_ignored || 0;
    const retained = ov.retained || (ov.results || {})["需人工复核"] || 0;
    return [
      // intake 两格(raw=入库总量 / noise=自动处置后),view 的 .intake 需要两格
      { key: "raw", label: "入库告警", n: total, tone: "primary",
        note: "告警中心未处置告警(已排除腾讯云暴露面扫描与公司漏扫源)" },
      { key: "noise", label: "自动处置", n: auto, tone: "primary", drop: "保留人工",
        note: "确认未成功 / 扫描探测 / 未见成功证据 → 自动忽略加白" },
      { key: "l1", label: "第 1 层 · 规则/单轮过筛", n: s["单轮"] || 0, tone: "ok",
        note: "纯扫描器特征 / 源包失败,单轮即定性" },
      { key: "l2", label: "第 2 层 · 源包深度复核", n: s["源包复核"] || 0, tone: "warn",
        note: "主动拉取源数据包,基于真实 HTTP 包给结论" },
      { key: "l3", label: "第 3 层 · Agent 工具循环", n: s["Agent"] || 0, tone: "danger",
        note: "高危/复杂,模型自主取证(只读)多轮研判" },
      { key: "retry", label: "待模型重试", n: s["待模型重试"] || s["降级兜底"] || 0, tone: "warn",
        note: "模型/API 不可用时不生成本地结论,入重试队列自动补判" },
      { key: "keep", label: "保留人工复核", n: retained, tone: "danger",
        note: "需人工复核 + 确认成功" },
    ];
  }

  // 计算 delta(本期 vs 上一等长周期)
  function pct(cur, prev) {
    if (!prev) return cur ? "+100%" : "0%";
    const d = (cur - prev) / prev * 100;
    return (d >= 0 ? "+" : "") + d.toFixed(1) + "%";
  }

  // 拉取某时间窗的全部数据并覆盖 CFW.DEMO
  async function load(days) {
    const [ov, tr, hp, ar, sr, rt, al, pf, ps, ag, rules, whitelist, agentAlerts, ovPrev] = await Promise.all([
      API("overview", days), API("trend", days), API("health", days),
      API("attacker_rank", days), API("asset_rank", days),
      API("realtime", days), API("alerts", days + "&limit=300"), API("profiles", days),
      API("pipeline", days),
      API("agent/config", days), API("agent/rules", days), API("agent/whitelist", days), API("agent/alerts", days + "&limit=80"),
      API("overview", days * 2),  // 用 2 倍窗口减去本期,近似上一等长周期
    ]);
    const win = mapWindow(ov, tr, ({ 1: "今天", 3: "近 3 天", 7: "近 7 天" }[days] || days + " 天"));
    // 真实 delta:上一周期 = (2N窗口) - (N窗口)
    if (ov && ovPrev) {
      const pr = {
        total: (ovPrev.total || 0) - (ov.total || 0),
        auto: (ovPrev.auto_ignored || 0) - (ov.auto_ignored || 0),
        manual: ((ovPrev.results || {})["需人工复核"] || 0) - ((ov.results || {})["需人工复核"] || 0),
        success: ((ovPrev.results || {})["确认成功"] || 0) - ((ov.results || {})["确认成功"] || 0),
      };
      win.deltas = {
        total: pct(ov.total || 0, pr.total),
        auto: pct(ov.auto_ignored || 0, pr.auto),
        manual: pct((ov.results || {})["需人工复核"] || 0, pr.manual),
        success: "+" + ((ov.results || {})["确认成功"] || 0),
      };
    }
    CFW.DEMO.windows[days] = win;
    CFW.DEMO.health = mapHealth(hp);
    CFW.DEMO.attackerRank = mapAttackerRank(ar);
    CFW.DEMO.assetRank = mapAssetRank(sr);
    CFW.DEMO.attention = mapAttention(rt);
    CFW.DEMO.alerts = mapAlerts(al);
    const pmapped = mapProfiles(pf);
    if (pmapped.length) CFW.DEMO.profiles = pmapped;
    else CFW.DEMO.profiles = [];  // 无画像数据则留空,不显示 demo 兜底
    CFW.DEMO.tickerPool = mapTicker(CFW.DEMO.alerts);
    CFW.DEMO.funnel = buildFunnel(ov);  // 全真实派生
    CFW.DEMO.pipelineStatus = ps || {};
    CFW.DEMO.agent = ag || { model_routing: { routes: {}, providers: {} }, provider_health: {}, agent: {} };
    CFW.DEMO.customRules = rules || [];
    CFW.DEMO.whitelistConfig = whitelist || { tencent_scan_ips: [], company_scan_ips: [], whitelist_ips: [], counts: {} };
    CFW.DEMO.agentAlerts = Array.isArray(agentAlerts) ? agentAlerts : [];
    // 效能视图"近7天累计成效"固定读 windows[7],确保它也是真实值
    if (days !== 7) {
      const [ov7, tr7] = await Promise.all([API("overview", 7), API("trend", 7)]);
      CFW.DEMO.windows[7] = mapWindow(ov7, tr7, "近 7 天");
    }
    // 侧栏"告警研判台"徽章 = 真实需人工复核条数
    const tb = document.getElementById("triageBadge");
    if (tb) {
      const manual = (ov && (ov.results || {})["需人工复核"]) || 0;
      tb.textContent = manual;
      tb.style.display = manual ? "" : "none";
    }
    // 去掉 DEMO 角标
    const badge = document.querySelector(".demo-badge");
    if (badge) { badge.textContent = "实时数据"; badge.classList.add("live-badge"); }
  }

  // 暴露给 app.js：在渲染前确保数据已拉取
  CFW.loadData = load;
})();
