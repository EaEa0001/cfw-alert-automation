/* ===== 视图：告警人工研判台 (筛选 + 完整详情) ===== */
(function () {
  const { esc, fmt } = CFW;
  const state = { level: "", result: "", source: "", q: "", manualOnly: false, actionMessage: "" };

  CFW.renderTriage = function () {
    const root = CFW.$("#view-triage");
    root.innerHTML = `
      <div class="panel">
        <div class="accent-top"></div>
        <h2 class="flex between"><span>告警人工研判台</span><span class="hint">点击任意行展开完整告警、证据和处置上下文</span></h2>
        <div class="filters triage-filters">
          ${sel("level", "全部等级", ["高危", "中危", "低危"])}
          ${sel("result", "全部研判", ["确认成功", "需人工复核", "待模型重试", "未见成功证据", "确认未成功", "扫描探测", "业务误报", "转发重复告警"])}
          ${sel("source", "全部来源", ["单轮", "源包复核", "Agent", "白名单规则", "待模型重试", "custom_rule"])}
          <input id="triageSearch" class="triage-search" placeholder="搜索事件 / IP / 规则 / 资产 / 告警ID" value="${esc(state.q)}">
          <label class="triage-check"><input type="checkbox" id="manualOnly" ${state.manualOnly ? "checked" : ""}> 只看需人工</label>
          <span class="filt-count mut" id="filtCount"></span>
        </div>
        <div class="triage-action-msg" id="triageActionMsg" style="${state.actionMessage ? "" : "display:none"}">${esc(state.actionMessage)}</div>
        <div class="triage-table-wrap">
          <table id="triageTable" class="triage-table"></table>
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
    return !!r.manualRequired;
  }

  function searchBlob(r) {
    return [
      r.id, r.time, r.level, r.event, r.atkIps, r.dstIps, r.dstAsset, r.direction,
      r.threatType, r.country, r.ruleId, r.strategy, r.desc, r.result, r.source,
      r.evidenceFrom, r.evidenceHit, r.why, r.key, r.next, r.trace,
      r.rootSourceIp, r.observedSourceIp, r.intermediateAsset, r.dispositionTarget, r.traceType,
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
    const colgroup = `<colgroup>
      <col class="triage-col-time">
      <col class="triage-col-level">
      <col class="triage-col-event">
      <col class="triage-col-source-ip">
      <col class="triage-col-target">
      <col class="triage-col-result">
      <col class="triage-col-source">
      <col class="triage-col-evidence">
      <col class="triage-col-token">
    </colgroup>`;
    const head = `<thead><tr>
      <th>时间</th><th>等级</th><th>事件</th><th>攻击源</th><th>目标</th>
      <th>研判结果</th><th>来源</th><th>证据</th><th class="r">Token</th></tr></thead>`;
    CFW.$("#triageTable").innerHTML = colgroup + head + "<tbody>" + rows.map((r, i) => `
      <tr class="click ${isManual(r) ? "manual-row" : ""} ${r.manualHandled ? "handled-row" : ""}" data-i="${i}">
        <td class="triage-time mut mono">${esc(String(r.time || "").slice(5, 16))}</td>
        <td class="triage-level"><span class="tag tag-${esc(r.level)}">${esc(r.level)}</span></td>
        <td class="triage-event">
          <div>${esc(r.event)}</div>
          <div class="mut mono small">${esc(r.id)}${r.manualHandled ? ` · ${esc(r.manualActionLabel || "已处理")}` : ""}</div>
        </td>
        <td class="triage-ip mono ${isPublicIp(r.atkIp) ? "net-pub" : "net-pri"}">${esc(r.atkIps || r.atkIp)}</td>
        <td class="triage-target dim mono small">${esc(r.dstIps || r.dstIp)}${r.dstAsset ? `<br>${esc(r.dstAsset)}` : ""}</td>
        <td class="triage-result res res-${esc(r.result)}">${esc(r.result)}</td>
        <td class="triage-source"><span class="src-pill src-${esc(r.source)}">${esc(r.source)}</span></td>
        <td class="triage-evidence mut small">${esc(r.evidenceHit || r.evidenceFrom || "无")}</td>
        <td class="triage-token r mono mut">${fmt(r.token)}</td>
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
    CFW.$$("[data-triage-action]").forEach(btn => btn.addEventListener("click", ev => {
      ev.preventDefault();
      ev.stopPropagation();
      handleAction(btn, btn.dataset.alertId || "", btn.dataset.triageAction || "");
    }));
  }

  function isPublicIp(ip) {
    const parts = String(ip || "").split(".").map(x => parseInt(x, 10));
    if (parts.length !== 4 || parts.some(x => Number.isNaN(x) || x < 0 || x > 255)) return false;
    if (parts[0] === 10 || parts[0] === 127 || parts[0] === 0) return false;
    if (parts[0] === 192 && parts[1] === 168) return false;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
    if (parts[0] === 169 && parts[1] === 254) return false;
    if (parts[0] >= 224) return false;
    return true;
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
      ${traceChain(r)}
      ${actionPanel(r)}
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

  function actionPanel(r) {
    const blockIp = dispositionPublicIp(r);
    const sourceIp = firstIp(r.rootSourceIp, r.dispositionTarget, r.atkIp);
    const status = r.manualHandled
      ? `<div class="triage-action-status ok">已处理 · ${esc(r.manualActionLabel || "人工处理")} ${r.manualActionTime ? `· ${esc(r.manualActionTime)}` : ""}${r.manualActionTarget ? ` · ${esc(r.manualActionTarget)}` : ""}</div>`
      : r.manualActionStatus
        ? `<div class="triage-action-status warn">${esc(r.manualActionStatusText || "待人工")} · ${esc(r.manualActionLabel || "人工处理")} ${r.manualActionTime ? `· ${esc(r.manualActionTime)}` : ""}${r.manualActionTarget ? ` · ${esc(r.manualActionTarget)}` : ""}</div>`
      : `<div class="triage-action-status warn">待人工处理 · 选择下方动作后会写入处理留痕</div>`;
    const id = encodeURIComponent(r.id || "");
    if (r.manualHandled) {
      return `<div class="triage-actions">
        ${status}
        <div class="triage-action-buttons">
          ${actionButton(id, "reopen", "撤销处理", "btn")}
        </div>
        ${r.manualActionNote ? `<div class="triage-action-note">${esc(r.manualActionNote)}</div>` : ""}
      </div>`;
    }
    return `<div class="triage-actions">
      ${status}
      <div class="triage-action-buttons">
        ${actionButton(id, "block_source", "登记人工封禁", "btn danger", !blockIp, blockIp ? `登记 ${blockIp}，不自动调用腾讯云` : "未解析到公网处置对象")}
        ${actionButton(id, "false_positive", "业务误报加白", "btn")}
        ${actionButton(id, "scanner_whitelist", "扫描源白名单", "btn", !sourceIp, sourceIp ? `加白 ${sourceIp}` : "未解析到来源 IP")}
        ${actionButton(id, "mark_handled", "标记已处理", "btn primary")}
      </div>
      <div class="triage-action-note">处置对象：<b class="mono">${esc(blockIp || sourceIp || r.dispositionTarget || r.rootSourceIp || r.atkIp || "—")}</b></div>
    </div>`;
  }

  function actionButton(alertId, action, label, cls, disabled, title) {
    const icon = action === "block_source" ? CFW.ICON.shield : action === "false_positive" ? CFW.ICON.skip : action === "scanner_whitelist" ? CFW.ICON.target : CFW.ICON.list;
    return `<button class="${cls}" data-alert-id="${alertId}" data-triage-action="${action}" ${disabled ? "disabled" : ""} title="${esc(title || label)}"><span class="btn-ic">${icon || ""}</span>${esc(label)}</button>`;
  }

  function firstIp(...values) {
    for (const value of values) {
      const m = String(value || "").match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/);
      if (m) return m[0];
    }
    return "";
  }

  function dispositionPublicIp(r) {
    const values = [r.dispositionTarget, r.rootSourceIp, r.atkIp, r.atkIps];
    for (const value of values) {
      const ip = firstIp(value);
      if (ip && isPublicIp(ip)) return ip;
    }
    return "";
  }

  async function handleAction(btn, encodedAlertId, action) {
    const alertId = decodeURIComponent(encodedAlertId || "");
    const row = CFW.DEMO.alerts.find(x => x.id === alertId) || {};
    const labels = {
      block_source: "确认登记该处置对象为待人工封禁？平台不会自动调用腾讯云，人工封禁完成后再点标记已处理。",
      false_positive: "确认将这类告警加入业务误报白名单并标记已处理？",
      scanner_whitelist: "确认将该来源加入扫描源白名单并标记已处理？",
      mark_handled: "确认仅标记该告警已处理？不会下发腾讯云或新增规则。",
      reopen: "确认撤销该告警的已处理状态？",
    };
    if (!confirm(labels[action] || "确认执行该处理动作？")) return;
    btn.disabled = true;
    const oldText = btn.textContent;
    btn.textContent = "处理中...";
    try {
      const res = await fetch(`/api/agent/alerts/${encodedAlertId}/handle`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action,
          target_ip: dispositionPublicIp(row) || firstIp(row.rootSourceIp, row.dispositionTarget, row.atkIp),
          days: 30,
        }),
      });
      const payload = await res.json().catch(() => ({}));
      if (!res.ok || payload.error) {
        throw new Error(payload.error || `HTTP ${res.status}`);
      }
      const doneLabel = payload.action?.status === "handled" ? "处理完成" : "已登记";
      state.actionMessage = `${doneLabel}：${payload.action?.action_label || action} · ${alertId}`;
      if (CFW.loadData) await CFW.loadData(CFW.state.days || 1);
      CFW.renderTriage();
    } catch (err) {
      btn.disabled = false;
      btn.textContent = oldText;
      state.actionMessage = `处理失败：${err.message || err}`;
      const msg = CFW.$("#triageActionMsg");
      if (msg) {
        msg.style.display = "";
        msg.textContent = state.actionMessage;
      }
    }
  }

  function traceChain(r) {
    const hasTrace = r.rootSourceIp || r.observedSourceIp || r.dispositionTarget || r.traceType || r.intermediateAsset;
    if (!hasTrace) return "";
    const root = r.rootSourceIp || "未知";
    const observed = r.observedSourceIp || r.atkIp || "未知";
    const target = r.dstIp || "未知";
    const targetLabel = r.dstAsset ? `${target} · ${r.dstAsset}` : target;
    return `<div class="trace-chain">
      <div class="trace-title">
        <span class="dl">溯源链路</span>
        <b>${esc(r.traceType || "未标注")}</b>
      </div>
      <div class="trace-path">
        ${traceNode("真实攻击源", root, "pub")}
        <span class="trace-arrow">→</span>
        ${traceNode("观测源 / 中间节点", observed, "mid", r.intermediateAsset)}
        <span class="trace-arrow">→</span>
        ${traceNode("目标", targetLabel, "dst")}
      </div>
      <div class="trace-action">
        <span>处置对象</span>
        <b class="mono ${isPublicIp(r.dispositionTarget || root) ? "net-pub" : "net-pri"}">${esc(r.dispositionTarget || root || "—")}</b>
        <em>当前内网观测源只作为链路节点，不作为默认封禁对象。</em>
      </div>
    </div>`;
  }

  function traceNode(label, value, tone, sub) {
    return `<div class="trace-node trace-${tone}">
      <span>${esc(label)}</span>
      <b class="mono">${esc(value || "—")}</b>
      ${sub ? `<small>${esc(sub)}</small>` : ""}
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
