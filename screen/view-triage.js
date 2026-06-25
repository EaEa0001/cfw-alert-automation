/* ===== 视图：告警人工研判台 (筛选 + 完整详情) ===== */
(function () {
  const { esc, fmt } = CFW;
  const state = { level: "", result: "", source: "", q: "", manualOnly: false };

  CFW.renderTriage = function () {
    const root = CFW.$("#view-triage");
    root.innerHTML = `
      <div class="panel">
        <div class="accent-top"></div>
        <h2 class="flex between"><span>告警人工研判台</span><span class="hint">点击任意行展开完整告警、证据和处置上下文</span></h2>
        <div class="filters triage-filters">
          ${sel("level", "全部等级", ["高危", "中危", "低危"])}
          ${sel("result", "全部研判", ["确认成功", "需人工复核", "待模型重试", "未见成功证据", "确认未成功", "扫描探测", "业务误报"])}
          ${sel("source", "全部来源", ["单轮", "源包复核", "Agent", "白名单规则", "待模型重试", "custom_rule"])}
          <input id="triageSearch" class="triage-search" placeholder="搜索事件 / IP / 规则 / 资产 / 告警ID" value="${esc(state.q)}">
          <label class="triage-check"><input type="checkbox" id="manualOnly" ${state.manualOnly ? "checked" : ""}> 只看需人工</label>
          <span class="filt-count mut" id="filtCount"></span>
        </div>
        <div class="scroll-y" style="max-height:none;overflow:visible">
          <table id="triageTable"></table>
        </div>
      </div>`;
    CFW.$$(".filters select", root).forEach(s => s.addEventListener("change", e => { state[e.target.dataset.k] = e.target.value; renderRows(); }));
    const search = CFW.$("#triageSearch", root);
    if (search) search.addEventListener("input", e => { state.q = e.target.value; renderRows(); });
    const manual = CFW.$("#manualOnly", root);
    if (manual) manual.addEventListener("change", e => { state.manualOnly = e.target.checked; renderRows(); });
    renderRows();
  };

  function sel(k, all, opts) {
    return `<select data-k="${k}"><option value="">${all}</option>${opts.map(o => `<option>${esc(o)}</option>`).join("")}</select>`;
  }

  function isManual(r) {
    if (["确认成功", "需人工复核"].includes(r.result)) return true;
    if (r.level === "高危" && !["确认未成功", "扫描探测", "业务误报"].includes(r.result)) return true;
    if (r.result === "未见成功证据" && r.conf === "低") return true;
    return false;
  }

  function searchBlob(r) {
    return [
      r.id, r.time, r.level, r.event, r.atkIps, r.dstIps, r.dstAsset, r.direction,
      r.threatType, r.country, r.ruleId, r.strategy, r.desc, r.result, r.source,
      r.evidenceFrom, r.evidenceHit, r.why, r.key, r.next, r.trace,
    ].join(" ").toLowerCase();
  }

  function filteredRows() {
    const q = String(state.q || "").trim().toLowerCase();
    return CFW.DEMO.alerts.filter(r =>
      (!state.level || r.level === state.level) &&
      (!state.result || r.result === state.result) &&
      (!state.source || r.source === state.source || r.sourceRaw === state.source) &&
      (!state.manualOnly || isManual(r)) &&
      (!q || searchBlob(r).includes(q))
    );
  }

  function renderRows() {
    const rows = filteredRows();
    const manualCount = rows.filter(isManual).length;
    CFW.$("#filtCount").textContent = `共 ${rows.length} 条 · 需人工 ${manualCount} 条`;
    const head = `<thead><tr>
      <th>时间</th><th>等级</th><th>事件</th><th>攻击源</th><th>目标</th>
      <th>研判结果</th><th>来源</th><th>证据</th><th class="r">Token</th></tr></thead>`;
    CFW.$("#triageTable").innerHTML = head + "<tbody>" + rows.map((r, i) => `
      <tr class="click ${isManual(r) ? "manual-row" : ""}" data-i="${i}">
        <td class="mut mono" style="white-space:nowrap">${esc(String(r.time || "").slice(5, 16))}</td>
        <td><span class="tag tag-${esc(r.level)}">${esc(r.level)}</span></td>
        <td>
          <div>${esc(r.event)}</div>
          <div class="mut mono small">${esc(r.id)}</div>
        </td>
        <td class="mono ${isPublicIp(r.atkIp) ? "net-pub" : "net-pri"}">${esc(r.atkIps || r.atkIp)}</td>
        <td class="dim mono small">${esc(r.dstIps || r.dstIp)}${r.dstAsset ? `<br>${esc(r.dstAsset)}` : ""}</td>
        <td class="res res-${esc(r.result)}">${esc(r.result)}</td>
        <td><span class="src-pill src-${esc(r.source)}">${esc(r.source)}</span></td>
        <td class="mut small">${esc(r.evidenceHit || r.evidenceFrom || "无")}</td>
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

  function isPublicIp(ip) {
    return String(ip || "").includes(".") && !String(ip).startsWith("10.") && !String(ip).startsWith("172.") && !String(ip).startsWith("192.168.");
  }

  function detail(r) {
    const conf = { "高": "var(--ok)", "中": "var(--warn)", "低": "var(--danger)" }[r.conf] || "var(--text-dim)";
    return `<div class="detail triage-detail">
      <div class="detail-grid">
        ${kv("告警ID", r.id, "mono")}
        ${kv("时间", r.time, "mono")}
        ${kv("方向", r.direction)}
        ${kv("威胁类型", r.threatType)}
        ${kv("规则ID", r.ruleId, "mono")}
        ${kv("策略", r.strategy)}
        ${kv("来源国家", r.country)}
        ${kv("白名单状态", r.whiteState)}
        ${kv("攻击IP", r.atkIps, "mono")}
        ${kv("目标IP", r.dstIps, "mono")}
        ${kv("目标资产", r.dstAsset)}
        ${kv("研判模型", r.model || r.sourceRaw)}
      </div>
      <div class="detail-section">
        <span class="dl">置信度</span> <b style="color:${conf}">${esc(r.conf || "未知")}</b>
        <span class="dl">研判来源</span> ${esc(r.source)}
        <span class="dl">证据来源</span> ${esc(r.evidenceFrom || "无")}
        <span class="dl">Token</span> 入 ${fmt(r.tokenIn)} / 出 ${fmt(r.tokenOut)} / 推理 ${fmt(r.tokenReason)}
      </div>
      ${block("威胁描述", r.desc)}
      ${block("本地建议", r.localAdvice)}
      ${block("下一步", r.next)}
      ${block("研判理由", r.why)}
      ${block("关键证据", r.key, "ev")}
      ${block("工具轨迹", r.trace)}
      ${block("源包命中", r.evidenceHit)}
      ${sourceEvidenceBlock(r.sourceEvidence)}
    </div>`;
  }

  function kv(label, value, cls) {
    return `<div class="detail-kv"><span>${esc(label)}</span><b class="${cls || ""}">${esc(value || "—")}</b></div>`;
  }

  function block(label, value, cls) {
    if (!value) return "";
    return `<div class="detail-block"><span class="${cls || "dl"}">${esc(label)}</span> ${esc(value)}</div>`;
  }

  function sourceEvidenceBlock(value) {
    if (!value) return "";
    let pretty = value;
    if (typeof value === "object") {
      pretty = JSON.stringify(value, null, 2);
    } else try {
      pretty = JSON.stringify(JSON.parse(value), null, 2);
    } catch (e) {}
    return `<div class="detail-block"><span class="ev">源包证据</span><pre class="evidence-json">${esc(pretty)}</pre></div>`;
  }
})();
