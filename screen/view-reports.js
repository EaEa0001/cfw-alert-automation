/* ===== 视图：日报周报 ===== */
(function () {
  const { esc, fmt, countUp } = CFW;
  const PERIODS = {
    daily: { title: "日报", days: 1, range: "近 1 天", file: "cfw-daily-report" },
    weekly: { title: "周报", days: 7, range: "近 7 天", file: "cfw-weekly-report" },
  };
  let mode = "daily";
  const cache = {};
  let copyState = "";

  CFW.renderReports = function () {
    const root = CFW.$("#view-reports");
    const period = PERIODS[mode];
    const report = cache[mode];
    if (!report) {
      root.innerHTML = loadingView(period);
      loadReport(mode);
      return;
    }

    const ov = report.overview || {};
    const health = report.health || {};
    const pipeline = report.pipeline || {};
    const cfg = pipeline.config || {};
    const results = ov.results || {};
    const levels = ov.levels || {};
    const retained = ov.retained || 0;
    const success = results["确认成功"] || 0;
    const manual = results["需人工复核"] || 0;
    const topAttackers = report.attackers || [];
    const topAssets = report.assets || [];
    const keyAlerts = report.key_alerts || [];
    const profiles = report.profiles || [];
    const reportText = buildReportText(report, period);

    root.innerHTML = `
      <div class="report-head panel">
        <div class="accent-top"></div>
        <div>
          <h2>报告视图</h2>
          <div class="report-title">${period.title} · ${period.range}</div>
          <div class="mut small">生成时间 ${esc(report.generated_at || "")} · 数据来自本地 reports/data 聚合</div>
        </div>
        <div class="report-switch" role="tablist">
          ${Object.entries(PERIODS).map(([key, item]) => `<button class="${key === mode ? "active" : ""}" data-report-mode="${key}">${item.title}</button>`).join("")}
        </div>
        <button class="btn primary" id="copyReportBtn">复制报告文本</button>
      </div>

      <div class="grid g-4 mt">
        <div class="kpi tone-primary"><div class="k-label">告警总量</div><div class="k-num" data-count="${ov.total || 0}">0</div><div class="k-foot">${esc(period.range)} 入库研判</div></div>
        <div class="kpi tone-ok"><div class="k-label">自动处置</div><div class="k-num" data-count="${ov.auto_ignored || 0}">0</div><div class="k-foot">处置率 <b style="color:var(--ok)">${ov.ignore_rate || 0}%</b></div></div>
        <div class="kpi tone-warn"><div class="k-label">需人工复核</div><div class="k-num" data-count="${manual}">0</div><div class="k-foot">${retained} 条留存项</div></div>
        <div class="kpi tone-danger${success ? " alarm" : ""}"><div class="k-label">确认成功</div><div class="k-num" data-count="${success}">0</div><div class="k-foot">真实落地优先跟进</div></div>
      </div>

      <div class="grid mt report-main">
        <div class="panel">
          <h2>${period.title}摘要 <span class="hint">${esc(copyState)}</span></h2>
          <div class="report-narrative">${summaryParagraphs(report, period).map(p => `<p>${esc(p)}</p>`).join("")}</div>
          <div class="report-section-grid">
            ${miniMetric("研判结果", resultLine(results))}
            ${miniMetric("等级分布", resultLine(levels))}
            ${miniMetric("源包命中", `${health.evidence_hit_rate || 0}% (${health.evidence_hit || 0}/${health.total || 0})`)}
            ${miniMetric("任务状态", `日报 ${cfg.daily_report_enabled ? "启用" : "关闭"} · 小时报 ${cfg.hourly_report_enabled ? "启用" : "关闭"}`)}
          </div>
          <textarea class="report-copy mono" readonly>${esc(reportText)}</textarea>
        </div>

        <div class="panel">
          <h2>处置重点 <span class="hint">确认成功 / 需人工 / 高危</span></h2>
          <div class="report-alert-list">
            ${keyAlerts.slice(0, 8).map(alertItem).join("") || `<div class="mut">暂无需人工聚焦项</div>`}
          </div>
        </div>
      </div>

      <div class="grid mt report-main">
        <div class="panel">
          <h2>攻击源与资产</h2>
          <div class="report-two-cols">
            <div>
              <div class="report-subtitle">攻击源 TOP</div>
              <table><thead><tr><th>来源 IP</th><th class="r">次数</th><th class="r">手法</th><th class="r">高危</th></tr></thead>
                <tbody>${topAttackers.map(a => `<tr><td class="mono ${a.public ? "net-pub" : "net-pri"}">${esc(a.ip)}</td><td class="r mono">${fmt(a.count || 0)}</td><td class="r">${a.techniques || 0}</td><td class="r ${a.high ? "net-pub" : "mut"}">${a.high || "—"}</td></tr>`).join("") || `<tr><td colspan="4" class="mut">暂无数据</td></tr>`}</tbody></table>
            </div>
            <div>
              <div class="report-subtitle">资产 TOP</div>
              <table><thead><tr><th>目标</th><th class="r">次数</th><th class="r">攻击者</th><th class="r">高危</th></tr></thead>
                <tbody>${topAssets.map(a => `<tr><td>${esc(a.dst || "")}</td><td class="r mono">${fmt(a.count || 0)}</td><td class="r">${a.attackers || 0}</td><td class="r ${a.high ? "net-pub" : "mut"}">${a.high || "—"}</td></tr>`).join("") || `<tr><td colspan="4" class="mut">暂无数据</td></tr>`}</tbody></table>
            </div>
          </div>
        </div>

        <div class="panel">
          <h2>防火墙下一步能力</h2>
          <div class="fw-roadmap">
            ${roadmapCards(report, profiles).map(card => `<div class="road-card ${card.tone}">
              <b>${esc(card.title)}</b><span>${esc(card.text)}</span>
            </div>`).join("")}
          </div>
        </div>
      </div>`;

    CFW.$$(".k-num[data-count]", root).forEach(n => countUp(n, +n.dataset.count));
    CFW.$$("[data-report-mode]", root).forEach(btn => btn.addEventListener("click", () => {
      mode = btn.dataset.reportMode || "daily";
      copyState = "";
      CFW.renderReports();
    }));
    const copy = CFW.$("#copyReportBtn", root);
    if (copy) copy.addEventListener("click", () => copyReport(reportText));
  };

  function loadingView(period) {
    return `<div class="panel mt">
      <div class="accent-top"></div>
      <h2>${period.title}</h2>
      <div class="mut">正在汇总 ${period.range} 的告警、画像、处置和通知状态...</div>
    </div>`;
  }

  async function loadReport(key) {
    const period = PERIODS[key] || PERIODS.daily;
    try {
      const res = await fetch(`/api/reports/summary?days=${period.days}`);
      cache[key] = await res.json();
    } catch (e) {
      cache[key] = { error: String(e), overview: {}, health: {}, key_alerts: [] };
    }
    if (mode === key) CFW.renderReports();
  }

  function summaryParagraphs(report, period) {
    const ov = report.overview || {};
    const results = ov.results || {};
    const sources = ov.sources || {};
    const success = results["确认成功"] || 0;
    const manual = results["需人工复核"] || 0;
    const auto = ov.auto_ignored || 0;
    const total = ov.total || 0;
    const sourceLine = resultLine(sources);
    const key = [];
    key.push(`${period.range}共研判 ${fmt(total)} 条云防火墙告警，自动处置 ${fmt(auto)} 条，自动处置率 ${ov.ignore_rate || 0}%。`);
    key.push(`留存人工关注 ${fmt(ov.retained || 0)} 条，其中需人工复核 ${fmt(manual)} 条，确认成功 ${fmt(success)} 条。研判来源分布：${sourceLine || "暂无"}。`);
    if (success > 0) key.push("存在确认成功告警，日报/周报应优先推动资产隔离、溯源取证和规则加固。");
    else if (manual > 0) key.push("当前主要风险是证据不足或高危待确认，建议按处置重点列表逐条补证。");
    else key.push("当前未发现确认成功或需人工复核告警，可继续观察攻击源趋势和规则命中稳定性。");
    return key;
  }

  function resultLine(obj) {
    return Object.entries(obj || {}).filter(([, v]) => v).map(([k, v]) => `${k} ${fmt(v)}`).join(" · ");
  }

  function miniMetric(title, value) {
    return `<div class="report-mini"><span>${esc(title)}</span><b>${esc(value || "暂无")}</b></div>`;
  }

  function alertItem(row) {
    const result = row["模型研判"] || "";
    const tone = result === "确认成功" ? "danger" : (row["告警等级"] === "高危" ? "warn" : "primary");
    return `<div class="report-alert ${tone}">
      <div class="flex between"><b>${esc(row["事件名称"] || "")}</b><span class="tag tag-${esc(row["告警等级"] || "")}">${esc(row["告警等级"] || "")}</span></div>
      <div class="mono small">${esc(row["攻击IP"] || "")} → ${esc(row["目标IP"] || "")}</div>
      <div class="mut small">${esc(String(row["告警时间"] || "").slice(5, 16))} · ${esc(result)} · ${esc(row["研判来源"] || "")}</div>
      <div class="small">${esc(row["研判理由"] || row["关键证据"] || "")}</div>
    </div>`;
  }

  function roadmapCards(report, profiles) {
    const ov = report.overview || {};
    const results = ov.results || {};
    const attackers = report.attackers || [];
    const hasSuccess = (results["确认成功"] || 0) > 0;
    const highAttacker = attackers.find(a => (a.high || 0) > 0 || (a.success || 0) > 0);
    const hasProfiles = (profiles || []).length > 0;
    return [
      {
        tone: hasSuccess ? "danger" : "primary",
        title: "一键处置编排",
        text: hasSuccess ? "对确认成功告警联动封禁、资产隔离、工单和回滚窗口。" : "把封禁、忽略、加白、回滚做成审批化动作链。",
      },
      {
        tone: highAttacker ? "warn" : "primary",
        title: "攻击源信誉库",
        text: highAttacker ? `优先沉淀 ${highAttacker.ip} 等高危来源的跨日信誉。` : "按来源 IP 聚合频率、手法、国家和命中结果，形成可过期信誉。",
      },
      {
        tone: "primary",
        title: "资产暴露面治理",
        text: "把被打资产、端口、业务标签和规则命中关联，形成资产热力图。",
      },
      {
        tone: hasProfiles ? "primary" : "warn",
        title: "攻击路径关联",
        text: hasProfiles ? "画像已可承接攻击阶段聚合，下一步关联同源多目标路径。" : "需要更多画像样本，按攻击阶段串联多条告警。",
      },
      {
        tone: "primary",
        title: "出站与 C2 监测",
        text: "基于防火墙南北向流量识别异常外联、周期心跳和新域名访问。",
      },
      {
        tone: "primary",
        title: "规则老化治理",
        text: "黑白名单增加到期、命中率、误报率和自动回收策略。",
      },
    ];
  }

  function buildReportText(report, period) {
    const ov = report.overview || {};
    const results = ov.results || {};
    const health = report.health || {};
    const alerts = report.key_alerts || [];
    const attackers = report.attackers || [];
    const lines = [
      `【云防火墙${period.title}】${period.range}`,
      `生成时间: ${report.generated_at || ""}`,
      "",
      `1. 总览: 告警 ${ov.total || 0} 条, 自动处置 ${ov.auto_ignored || 0} 条, 自动处置率 ${ov.ignore_rate || 0}%, 留存 ${ov.retained || 0} 条。`,
      `2. 结果: ${resultLine(results) || "暂无"}`,
      `3. 健康: 源包命中率 ${health.evidence_hit_rate || 0}%, 处置失败 ${health.dispose_failed || 0}, 重试队列 ${health.retry_queue || 0}。`,
      `4. 攻击源TOP: ${attackers.slice(0, 5).map(a => `${a.ip}(${a.count})`).join(", ") || "暂无"}`,
      "5. 重点告警:",
      ...(alerts.slice(0, 6).map((a, i) => `${i + 1}) ${a["告警等级"] || ""} ${a["事件名称"] || ""} ${a["攻击IP"] || ""} -> ${a["目标IP"] || ""} ${a["模型研判"] || ""}`)),
    ];
    if (!alerts.length) lines.push("无确认成功、需人工复核或高危留存项。");
    return lines.join("\n");
  }

  async function copyReport(text) {
    try {
      await navigator.clipboard.writeText(text);
      copyState = "已复制";
    } catch (e) {
      try {
        const box = CFW.$(".report-copy");
        if (!box) throw e;
        const readonly = box.readOnly;
        box.readOnly = false;
        box.focus();
        box.select();
        box.setSelectionRange(0, box.value.length);
        copyState = document.execCommand("copy") ? "已复制" : "已选中文本";
        box.readOnly = readonly;
      } catch (fallbackError) {
        copyState = "复制失败";
      }
    }
    const hint = CFW.$("#view-reports h2 .hint");
    if (hint) hint.textContent = copyState;
  }
})();
