/* ===== 视图：态势总览 ===== */
(function () {
  const { esc, fmt, win, sparkline, countUp, ICON } = CFW;
  let trendChart, donutChart, tickerTimer;

  function kpiCard(tone, icon, label, value, footHtml, spark, alarm) {
    return `<div class="kpi tone-${tone}${alarm ? " alarm" : ""}">
      <div class="k-label"><span class="k-icon">${ICON[icon]}</span>${label}</div>
      <div class="k-num" data-count="${value}">0</div>
      <div class="k-foot">${footHtml || ""}</div>
      ${spark ? sparkline(spark, 78, 30, tone === "ok" ? "var(--ok)" : "var(--primary)") : ""}
    </div>`;
  }

  CFW.renderOverview = function () {
    const w = win(), k = w.kpi, d = w.deltas, t = w.tokens;
    const root = CFW.$("#view-overview");

    root.innerHTML = `
      <div class="grid g-4">
        ${kpiCard("primary", "bolt", "告警总量", k.total, `<span class="delta up">${d.total}</span> 较上一周期`, w.trend.total)}
        ${kpiCard("ok", "auto", "自动处置", k.auto, `处置率 <b style="color:var(--ok)">${k.ignoreRate}%</b>`, w.trend.total)}
        ${kpiCard("warn", "eye", "需人工复核", k.manual, `<span class="delta down">${d.manual}</span> 待跟进`, w.trend.manual)}
        ${kpiCard("danger", "skull", "确认成功 · 得手", k.success, `真实落地 · 须立即处置`, null, k.success > 0)}
      </div>

      <div class="grid g-3 mt">
        <div class="panel span-2">
          <div class="accent-top"></div>
          <h2>每日告警趋势 <span class="hint">柱:告警量　线:Token(百万)</span></h2>
          <div class="chart-box"><canvas id="ovTrend"></canvas></div>
        </div>
        <div class="panel">
          <h2>研判结果分布</h2>
          <div class="chart-box sm"><canvas id="ovDonut"></canvas></div>
          <div class="legend" id="ovLegend"></div>
        </div>
      </div>

      <div class="grid g-3 mt">
        <div class="panel">
          <h2>攻击来源 TOP</h2>
          <table><thead><tr><th>来源 IP</th><th class="r">手法</th><th class="r">次数</th><th class="r">高危</th></tr></thead>
          <tbody>${CFW.DEMO.attackerRank.map(a => `<tr>
            <td class="mono ${a.pub ? "net-pub" : "net-pri"}">${a.pub ? "🌐 " : "🏠 "}${esc(a.ip)}</td>
            <td class="r dim">${a.techniques}</td><td class="r mono">${fmt(a.count)}</td>
            <td class="r ${a.high ? "net-pub" : "mut"}">${a.high || "—"}</td></tr>`).join("")}</tbody></table>
        </div>
        <div class="panel">
          <h2>被攻击资产 TOP</h2>
          <table><thead><tr><th>目标资产</th><th class="r">被打</th><th class="r">攻击者</th><th class="r">高危</th></tr></thead>
          <tbody>${CFW.DEMO.assetRank.map(a => `<tr>
            <td class="dim">${esc(a.dst)}</td>
            <td class="r mono">${fmt(a.count)}</td><td class="r dim">${a.attackers}</td>
            <td class="r ${a.high ? "net-pub" : "mut"}">${a.high || "—"}</td></tr>`).join("")}</tbody></table>
        </div>
        <div class="panel">
          <h2>系统健康</h2>
          ${healthRows()}
        </div>
      </div>

      <div class="grid g-3 mt">
        <div class="panel span-2">
          <div class="accent-top"></div>
          <h2 class="flex between"><span>🔴 需重点关注 · 实时</span><span class="hint">高危 / 确认成功 / 需人工</span></h2>
          <table><thead><tr><th>时间</th><th>等级</th><th>事件</th><th>来源 → 目标</th><th>研判</th></tr></thead>
          <tbody>${CFW.DEMO.attention.map(a => `<tr>
            <td class="mut mono">${esc(a.time.slice(5, 16))}</td>
            <td><span class="tag tag-${a.level}">${a.level}</span></td>
            <td>${esc(a.event)}</td>
            <td class="${a.pub ? "net-pub" : "net-pri"} mono" style="font-size:11.5px">${esc(a.src)} → ${esc(a.dst)}</td>
            <td class="res res-${a.result}">${a.result}</td></tr>`).join("")}</tbody></table>
        </div>
        <div class="panel">
          <h2 class="flex between"><span>实时告警流</span><span class="updated"><span class="dot live"></span>LIVE</span></h2>
          <div class="ticker" id="ovTicker"></div>
        </div>
      </div>`;

    // 数字滚动
    CFW.$$(".k-num", root).forEach(n => countUp(n, +n.dataset.count));
    drawTrend(w);
    drawDonut(w);
    startTicker();
  };

  function healthRows() {
    const h = CFW.DEMO.health;
    const bar = (pct, color) => `<div class="meter"><span style="width:${pct}%;background:${color}"></span></div>`;
    return `
      <div class="hrow"><div style="flex:1"><div class="hl">源包命中率</div>${bar(h.evidenceHit, "var(--primary)")}</div><div class="hv net-pri">${h.evidenceHit}%</div></div>
      <div class="hrow"><div style="flex:1"><div class="hl">模型待重试率</div>${bar(h.retryPendingRate ?? h.degradedRate, "var(--warn)")}</div><div class="hv" style="color:var(--warn)">${h.retryPendingRate ?? h.degradedRate}%</div></div>
      <div class="hrow"><div class="hl">处置忽略累计</div><div class="hv">${fmt(h.disposeIgnored)}</div></div>
      <div class="hrow"><div class="hl">处置失败</div><div class="hv" style="color:${h.disposeFailed ? "var(--danger)" : "var(--ok)"}">${h.disposeFailed}</div></div>
      <div class="hrow"><div class="hl">LLM 错误 / 重试队列</div><div class="hv">${h.llmErrors} / ${h.retryQueue}</div></div>
      <div class="hrow"><div class="hl">Agent 研判轮次</div><div class="hv" style="color:var(--violet)">${h.agentCount}</div></div>`;
  }

  function drawTrend(w) {
    const ctx = CFW.$("#ovTrend");
    if (trendChart) trendChart.destroy();
    trendChart = new Chart(ctx, {
      data: {
        labels: w.trend.days,
        datasets: [
          { type: "bar", label: "告警量", data: w.trend.total, backgroundColor: "rgba(0,101,253,.58)", hoverBackgroundColor: "#0065fd", borderRadius: 5, borderSkipped: false, yAxisID: "y", maxBarThickness: 34 },
          { type: "line", label: "Token(M)", data: w.trend.tokens, borderColor: "#d97706", backgroundColor: "#d97706", tension: .4, pointRadius: 3, pointBackgroundColor: "#d97706", yAxisID: "y1", borderWidth: 2 }
        ]
      },
      options: {
        maintainAspectRatio: false, responsive: true,
        plugins: { legend: { labels: { color: "#7f8d9f", boxWidth: 12, font: { size: 11.5 } } } },
        scales: { y: CFW.axis({ beginAtZero: true }), y1: CFW.axis({ position: "right", grid: { display: false } }), x: CFW.axis({ grid: { display: false } }) }
      }
    });
  }

  function drawDonut(w) {
    const labels = Object.keys(w.results), data = Object.values(w.results);
    const colorOf = l => l === "确认成功" ? "#ef4444" : l === "需人工复核" ? "#d97706" : l === "扫描探测" ? "#7f8d9f" : l === "未见成功证据" ? "#0065fd" : "#059669";
    const colors = labels.map(colorOf);
    if (donutChart) donutChart.destroy();
    donutChart = new Chart(CFW.$("#ovDonut"), {
      type: "doughnut",
      data: { labels, datasets: [{ data, backgroundColor: colors, borderColor: "#ffffff", borderWidth: 3, hoverOffset: 6 }] },
      options: { maintainAspectRatio: false, cutout: "62%", plugins: { legend: { display: false } } }
    });
    CFW.$("#ovLegend").innerHTML = labels.map((l, i) =>
      `<span><i style="background:${colors[i]}"></i>${l} <b class="mono">${fmt(data[i])}</b></span>`).join("");
  }

  function startTicker() {
    const box = CFW.$("#ovTicker");
    if (!box) return;
    if (tickerTimer) clearInterval(tickerTimer);
    const pool = Array.isArray(CFW.DEMO.tickerPool) ? CFW.DEMO.tickerPool : [];
    if (!pool.length) {
      box.innerHTML = `<div class="empty"><div class="big">暂无实时告警流</div><div>有新告警进入后会自动显示。</div></div>`;
      return;
    }
    const make = () => {
      const p = pool[Math.floor(Math.random() * pool.length)];
      const now = new Date();
      const ts = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}`;
      const row = CFW.el("div", "tick-row");
      row.innerHTML = `<span class="ts">${ts}</span>
        <span class="tag tag-${p.level}">${p.level}</span>
        <span>${esc(p.event)} <span class="mut mono" style="font-size:11px">${esc(p.src)}</span></span>
        <span class="res res-${p.res}" style="font-size:11.5px">${p.res}</span>`;
      box.prepend(row);
      while (box.children.length > 8) box.lastChild.remove();
    };
    box.innerHTML = "";
    for (let i = 0; i < 6; i++) make();
    tickerTimer = setInterval(make, 3500);
  }

  CFW.stopTicker = () => { if (tickerTimer) clearInterval(tickerTimer); };
})();
