/* ===== 视图：研判流水线 (工作流 + 三层漏斗) ===== */
(function () {
  const { esc, fmt, ICON } = CFW;

  const toneColor = { primary: "var(--primary)", ok: "var(--ok)", warn: "var(--warn)", danger: "var(--danger)" };

  CFW.renderPipeline = function () {
    const root = CFW.$("#view-pipeline");
    const pipe = CFW.DEMO.pipeline;
    const fn = CFW.DEMO.funnel;
    const intake = fn.filter(s => s.key === "raw" || s.key === "noise");
    const bands = fn.filter(s => !["raw", "noise"].includes(s.key));
    const maxN = Math.max(1, ...bands.map(s => s.n || 0));
    const w = CFW.win();
    const totalN = (intake[0] && intake[0].n) || 0;
    const keepN = (bands.find(s => s.key === "keep") || {}).n || 0;
    const ignoreRate = (w.kpi && w.kpi.ignoreRate) || 0;

    root.innerHTML = `
      <div class="panel">
        <div class="accent-top"></div>
        <h2>端到端工作流 <span class="hint">每小时自动执行 · 模型只研判与只读取证，云端处置由本地规则执行</span></h2>
        <div class="wf">${pipe.map((p, i) => `
          <div class="wf-step">
            <div class="wf-ic">${ICON[p.icon]}</div>
            <div class="wf-t">${esc(p.t)}</div>
            <div class="wf-d">${esc(p.d)}</div>
          </div>
          ${i < pipe.length - 1 ? `<div class="wf-arrow"><span class="flow"></span></div>` : ""}`).join("")}
        </div>
      </div>

      <div class="grid mt" style="grid-template-columns:1.6fr 1fr">
        <div class="panel">
          <h2>分层研判 <span class="hint">入库告警 ${fmt(totalN)} 条 → 保留人工 ${fmt(keepN)} 条</span></h2>

          <div class="intake">
            ${intake.map((s, i) => `<div class="intake-cell">
              <div class="intake-n mono">${fmt(s.n)}</div>
              <div class="intake-l">${esc(s.label)}</div>
              <div class="intake-note">${esc(s.note)}</div>
            </div>${i < intake.length - 1 ? '<div class="intake-sep">剔除噪声</div>' : ""}`).join("")}
          </div>

          <div class="funnel">
            ${bands.map(s => {
              const pct = Math.max(7, (s.n / maxN) * 100);
              const c = toneColor[s.tone];
              return `<div class="fn-row">
                <div class="fn-bar" style="width:${pct.toFixed(1)}%;--c:${c}">
                  <span class="fn-n mono">${fmt(s.n)}</span>
                </div>
                <div class="fn-meta">
                  <div class="fn-label" style="color:${c}">${esc(s.label)}</div>
                  <div class="fn-note">${esc(s.note)}</div>
                </div>
              </div>`;
            }).join("")}
          </div>
        </div>

        <div class="panel">
          <h2>这套漏斗为什么有效</h2>
          <div class="why-big">
            <div class="why-num mono">${ignoreRate.toFixed(1)}<span>%</span></div>
            <div class="why-cap">告警被自动定性 / 处置<br>仅 <b style="color:var(--warn)">${(100 - ignoreRate).toFixed(1)}%</b> 需要人工研判</div>
          </div>
          <div class="why-list">
            <div class="why-i"><span class="dot" style="background:var(--ok)"></span><div><b>越早越省</b><div class="mut">第 0/1 层用规则与白名单直接定性，几乎不耗 token。</div></div></div>
            <div class="why-i"><span class="dot" style="background:var(--warn)"></span><div><b>不放过真攻击</b><div class="mut">5xx、注入、横向一律拉源包深度复核，基于真实数据包给结论。</div></div></div>
            <div class="why-i"><span class="dot" style="background:var(--danger)"></span><div><b>高危上 Agent</b><div class="mut">模型自主多轮取证(只读)，给出带工具轨迹的结论。</div></div></div>
            <div class="why-i"><span class="dot" style="background:var(--primary)"></span><div><b>安全兜底</b><div class="mut">模型不可用时回退本地规则，证据不足一律保留，绝不误忽略。</div></div></div>
          </div>
        </div>
      </div>

      <div class="grid g-3 mt">
        <div class="panel safety">
          <h2>🚫 不做什么</h2>
          <ul class="bullets">
            <li>不自动封禁任何攻击 IP</li>
            <li>白名单扫描源不执行封禁</li>
            <li>模型不直接操作云资源</li>
            <li>证据不足绝不自动判成功 / 忽略</li>
          </ul>
        </div>
        <div class="panel safety">
          <h2>✅ 才会自动忽略</h2>
          <ul class="bullets">
            <li><span class="res res-扫描探测">扫描探测</span> — 纯扫描器特征</li>
            <li><span class="res res-确认未成功">确认未成功</span> — 源包确认失败</li>
            <li><span class="res res-未见成功证据">未见成功证据</span> — 利用未落地</li>
            <li class="mut">5xx 不再算安全失败</li>
          </ul>
        </div>
        <div class="panel safety">
          <h2>🔒 一律保留人工</h2>
          <ul class="bullets">
            <li><span class="res res-确认成功">确认成功</span> — 真实得手</li>
            <li><span class="res res-需人工复核">需人工复核</span> — 证据不足</li>
            <li>高危且缺充分证据</li>
            <li class="mut">命令回显 / 文件落地 / WebShell 才算成功</li>
          </ul>
        </div>
      </div>`;
  };
})();
