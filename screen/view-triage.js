/* ===== 视图：告警研判台 (筛选 + 证据链下钻) ===== */
(function () {
  const { esc, fmt } = CFW;
  const state = { level: "", result: "", source: "" };
  let openRow = -1;

  CFW.renderTriage = function () {
    const root = CFW.$("#view-triage");
    root.innerHTML = `
      <div class="panel">
        <div class="accent-top"></div>
        <h2 class="flex between"><span>告警研判明细</span><span class="hint">点击任意行展开证据链与工具轨迹</span></h2>
        <div class="filters">
          ${sel("level", "全部等级", ["高危", "中危", "低危"])}
          ${sel("result", "全部研判", ["确认成功", "需人工复核", "未见成功证据", "确认未成功", "扫描探测"])}
          ${sel("source", "全部来源", ["单轮", "源包复核", "Agent", "降级兜底"])}
          <span class="filt-count mut" id="filtCount"></span>
        </div>
        <div class="scroll-y" style="max-height:none;overflow:visible">
          <table id="triageTable"></table>
        </div>
      </div>`;
    CFW.$$(".filters select", root).forEach(s => s.addEventListener("change", e => { state[e.target.dataset.k] = e.target.value; openRow = -1; renderRows(); }));
    renderRows();
  };

  function sel(k, all, opts) {
    return `<select data-k="${k}"><option value="">${all}</option>${opts.map(o => `<option>${o}</option>`).join("")}</select>`;
  }

  function renderRows() {
    const rows = CFW.DEMO.alerts.filter(r =>
      (!state.level || r.level === state.level) &&
      (!state.result || r.result === state.result) &&
      (!state.source || r.source === state.source));
    CFW.$("#filtCount").textContent = `共 ${rows.length} 条`;
    const head = `<thead><tr>
      <th>时间</th><th>等级</th><th>事件</th><th>攻击 IP</th><th>目标</th>
      <th>研判结果</th><th>来源</th><th>证据</th><th class="r">Token</th></tr></thead>`;
    CFW.$("#triageTable").innerHTML = head + "<tbody>" + rows.map((r, i) => `
      <tr class="click" data-i="${i}">
        <td class="mut mono" style="white-space:nowrap">${esc(r.time.slice(5, 16))}</td>
        <td><span class="tag tag-${r.level}">${r.level}</span></td>
        <td>${esc(r.event)}</td>
        <td class="mono ${r.atkIp.includes(".") && !r.atkIp.startsWith("10.") && !r.atkIp.startsWith("172.") ? "net-pub" : "net-pri"}">${esc(r.atkIp)}</td>
        <td class="dim mono" style="font-size:11.5px">${esc(r.dstIp)}</td>
        <td class="res res-${r.result}">${r.result}</td>
        <td><span class="src-pill src-${r.source}">${r.source}</span></td>
        <td class="mut" style="font-size:11.5px">${esc(r.evidenceFrom)}</td>
        <td class="r mono mut">${fmt(r.token)}</td>
      </tr>
      <tr class="detail-row" data-d="${i}" style="display:none"><td colspan="9" style="padding:0;border:0">${detail(r)}</td></tr>
    `).join("") + "</tbody>";

    CFW.$$("#triageTable tr.click").forEach(tr => tr.addEventListener("click", () => {
      const i = +tr.dataset.i;
      const dr = CFW.$(`#triageTable tr[data-d="${i}"]`);
      const show = dr.style.display === "none";
      CFW.$$("#triageTable .detail-row").forEach(x => x.style.display = "none");
      dr.style.display = show ? "" : "none";
    }));
  }

  function detail(r) {
    const conf = { "高": "var(--ok)", "中": "var(--warn)", "低": "var(--danger)" }[r.conf] || "var(--text-dim)";
    return `<div class="detail">
      <span class="dl">研判置信度</span> <b style="color:${conf}">${r.conf}</b>　·　<span class="dl">研判来源</span> ${esc(r.source)}　·　<span class="dl">证据来源</span> ${esc(r.evidenceFrom)}
${r.trace ? `\n<span class="dl">工具轨迹</span> ${esc(r.trace)}` : ""}
${r.key ? `\n<span class="ev">关键证据</span> ${esc(r.key)}` : ""}
<span class="dl">研判理由</span> ${esc(r.why)}</div>`;
  }
})();
