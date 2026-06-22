/* ===== 视图：效能与成本 (问题 → 方案 → 成效) ===== */
(function () {
  const { fmt, win, countUp } = CFW;
  const MIN_PER_ALERT = 3; // 假设：人工逐条研判约 3 分钟/条（占位，可调）

  CFW.renderEfficiency = function () {
    const root = CFW.$("#view-efficiency");
    const w = win(), k = w.kpi, t = w.tokens;
    const savedH = Math.round(k.auto * MIN_PER_ALERT / 60);
    const manualH = Math.round(k.total * MIN_PER_ALERT / 60);
    const perAlert = Math.round(t.total / k.total);

    const srcSplit = [
      { k: "源包复核", pct: 41, color: "var(--primary)" },
      { k: "单轮研判", pct: 38, color: "var(--text-dim)" },
      { k: "Agent 循环", pct: 19, color: "var(--violet)" },
      { k: "降级兜底", pct: 2, color: "var(--danger)" }
    ].map(s => ({ ...s, val: Math.round(t.total * s.pct / 100) }));

    root.innerHTML = `
      <div class="panel value-banner">
        <div class="accent-top"></div>
        <div class="vb-side">
          <div class="vb-tag">问题</div>
          <div class="vb-h">告警过载，人工研判跟不上</div>
          <div class="vb-p mut">云防火墙日均产生 <b class="dim">${fmt(k.total)}</b> 条告警，逐条人工研判约需
            <b class="dim">${fmt(manualH)} 工时/天</b>。绝大多数是扫描噪声与失败尝试，真正得手的极少，
            人力淹没在重复判断里，真攻击容易被漏看。</div>
        </div>
        <div class="vb-arrow">→</div>
        <div class="vb-side">
          <div class="vb-tag ok">方案</div>
          <div class="vb-h">三层漏斗 + LLM + Agent 自动研判</div>
          <div class="vb-p mut">确定性规则、源包深度复核与 Agent 工具循环逐层过滤，
            自动忽略扫描与确认失败，只把 <b style="color:var(--warn)">确认成功 / 证据不足 / 高危</b> 推给人，
            并自动推送企微通知与日报。</div>
        </div>
      </div>

      <div class="grid g-4 mt">
        <div class="kpi tone-ok"><div class="k-label">自动处置率</div><div class="k-num" data-count="${k.ignoreRate}" data-float="1">0</div><div class="k-foot">${fmt(k.auto)} / ${fmt(k.total)} 条</div></div>
        <div class="kpi tone-primary"><div class="k-label">节省人工 (工时/天)</div><div class="k-num" data-count="${savedH}">0</div><div class="k-foot">按 ${MIN_PER_ALERT} 分钟/条估算</div></div>
        <div class="kpi tone-warn"><div class="k-label">人工聚焦</div><div class="k-num" data-count="${k.manual}">0</div><div class="k-foot">仅需看 ${(100 - k.ignoreRate).toFixed(1)}% 告警</div></div>
        <div class="kpi tone-primary"><div class="k-label">单条平均 Token</div><div class="k-num" data-count="${perAlert}">0</div><div class="k-foot">复用 Codex 订阅 · 无 API Key</div></div>
      </div>

      <div class="grid g-2 mt">
        <div class="panel">
          <h2>Token 用量 · 按研判来源 <span class="hint">合计 ${(t.total / 1e6).toFixed(2)}M</span></h2>
          ${srcSplit.map(s => `<div class="bar-row">
            <div class="br-label">${s.k}</div>
            <div class="br-track"><span style="width:${s.pct}%;background:${s.color}"></span></div>
            <div class="br-val mono">${fmt(s.val)}<span class="mut"> · ${s.pct}%</span></div>
          </div>`).join("")}
          <div class="tok-foot mut">入 ${fmt(t.input)} · 出 ${fmt(t.output)} · 推理 ${fmt(t.reasoning)}</div>
        </div>

        <div class="panel">
          <h2>研判质量与稳定性</h2>
          ${gauge("源包命中率", CFW.DEMO.health.evidenceHit, "var(--primary)", "拉到真实数据包的告警占比，越高研判越有据")}
          ${gauge("模型降级率", CFW.DEMO.health.degradedRate, "var(--warn)", "连接异常回退本地规则的比例，降级只增不漏")}
          <div class="qrow">
            <div><div class="q-num mono net-pri">${CFW.DEMO.health.agentCount}</div><div class="mut">Agent 研判轮次</div></div>
            <div><div class="q-num mono" style="color:var(--ok)">${CFW.DEMO.health.disposeFailed}</div><div class="mut">处置失败</div></div>
            <div><div class="q-num mono">${CFW.DEMO.health.retryQueue}</div><div class="mut">重试队列</div></div>
          </div>
        </div>
      </div>

      <div class="panel mt cumulative">
        <h2>近 7 天累计成效</h2>
        <div class="cum-grid">
          <div><div class="cum-n mono">${fmt(CFW.DEMO.windows[7].kpi.total)}</div><div class="mut">处理告警</div></div>
          <div><div class="cum-n mono" style="color:var(--ok)">${fmt(CFW.DEMO.windows[7].kpi.auto)}</div><div class="mut">自动处置</div></div>
          <div><div class="cum-n mono" style="color:var(--warn)">${fmt(CFW.DEMO.windows[7].kpi.manual)}</div><div class="mut">人工复核</div></div>
          <div><div class="cum-n mono" style="color:var(--danger)">${CFW.DEMO.windows[7].kpi.success}</div><div class="mut">确认得手</div></div>
          <div><div class="cum-n mono net-pri">${fmt(Math.round(CFW.DEMO.windows[7].kpi.auto * MIN_PER_ALERT / 60))}</div><div class="mut">节省工时</div></div>
        </div>
      </div>`;

    CFW.$$(".k-num[data-count]", root).forEach(n => {
      const isFloat = n.dataset.float;
      countUp(n, +n.dataset.count, 900, v => isFloat ? v.toFixed(1) : fmt(v));
    });
    requestAnimationFrame(() => CFW.$$(".gauge-fill", root).forEach(g => g.style.width = g.dataset.w + "%"));
  };

  function gauge(label, pct, color, note) {
    return `<div class="gauge">
      <div class="g-top"><span class="dim">${label}</span><b class="mono" style="color:${color}">${pct}%</b></div>
      <div class="g-track"><span class="gauge-fill" data-w="${pct}" style="width:0;background:${color}"></span></div>
      <div class="g-note mut">${note}</div>
    </div>`;
  }
})();
