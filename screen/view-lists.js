/* ===== 视图：规则中心 ===== */
(function () {
  const { esc } = CFW;
  const LOG_KEY = "cfw.rule.actions.v1";
  let activePane = "library";
  let createMode = "manual";
  let currentDraft = null;
  let lastResult = null;
  let manualForm = { type: "block_ip", ips: "", reason: "人工确认", days: "30" };
  let naturalText = "";

  CFW.renderLists = function () {
    const root = CFW.$("#view-lists");
    const rules = Array.isArray(CFW.DEMO.customRules) ? CFW.DEMO.customRules : [];
    const stats = ruleStats(rules);

    root.innerHTML = `
      <div class="panel mt rule-shell">
        <div class="accent-top"></div>
        <div class="rule-shell-head">
          <div>
            <h2>规则中心</h2>
            <div class="rule-title">规则库、创建入口、默认白名单与执行记录分离管理</div>
            <div class="mut small">黑名单只记录人工封禁对象，白名单负责研判抑制；平台不自动调用腾讯云封禁。</div>
          </div>
          <div class="rule-tabs" role="tablist">
            ${tabButton("library", "规则库")}
            ${tabButton("create", "新建规则")}
            ${tabButton("whitelist", "默认白名单")}
            ${tabButton("actions", "执行记录")}
          </div>
        </div>
      </div>

      <div class="rule-kpis mt">
        ${statCard("全部规则", rules.length, "含系统默认规则")}
        ${statCard("生效中", stats.active, "正在参与实时研判")}
        ${statCard("黑名单", stats.block, "仅登记人工封禁对象")}
        ${statCard("白名单", stats.allow + stats.suppress, "扫描源与业务误报")}
      </div>

      ${pane(rules)}
    `;

    bindEvents(root);
  };

  function tabButton(key, label) {
    return `<button class="${activePane === key ? "active" : ""}" data-rule-pane="${key}">${label}</button>`;
  }

  function statCard(label, value, hint) {
    return `<div class="rule-stat"><span>${esc(label)}</span><b>${esc(String(value))}</b><em>${esc(hint)}</em></div>`;
  }

  function pane(rules) {
    if (activePane === "create") return createPane();
    if (activePane === "whitelist") return whitelistPane();
    if (activePane === "actions") return actionsPane();
    return libraryPane(rules);
  }

  function bindEvents(root) {
    CFW.$$("[data-rule-pane]", root).forEach(btn => btn.addEventListener("click", () => {
      activePane = btn.dataset.rulePane || "library";
      CFW.renderLists();
    }));
    CFW.$$("[data-create-mode]", root).forEach(btn => btn.addEventListener("click", () => {
      createMode = btn.dataset.createMode || "manual";
      CFW.renderLists();
    }));
    const manualDraft = CFW.$("#manualDraftBtn", root);
    if (manualDraft) manualDraft.addEventListener("click", draftManualRule);
    const localDraft = CFW.$("#draftRuleBtn", root);
    if (localDraft) localDraft.addEventListener("click", () => draftNaturalRule(false));
    const llmDraft = CFW.$("#draftRuleLlmBtn", root);
    if (llmDraft) llmDraft.addEventListener("click", () => draftNaturalRule(true));
    CFW.$$("[data-save-rule]", root).forEach(btn => btn.addEventListener("click", () => saveRule(btn.dataset.saveRule === "activate")));
    CFW.$$("[data-rule-action]", root).forEach(btn => btn.addEventListener("click", () => updateRule(btn.dataset.ruleId, btn.dataset.ruleAction)));
    const saveWhitelist = CFW.$("#saveWhitelistBtn", root);
    if (saveWhitelist) saveWhitelist.addEventListener("click", saveWhitelistConfig);
    const importCandidates = CFW.$("#importWhitelistCandidatesBtn", root);
    if (importCandidates) importCandidates.addEventListener("click", importWhitelistCandidates);
    const clearLogs = CFW.$("#clearRuleLogsBtn", root);
    if (clearLogs) clearLogs.addEventListener("click", () => {
      localStorage.removeItem(LOG_KEY);
      CFW.renderLists();
    });
  }

  function libraryPane(rules) {
    const rows = rules.map(ruleRow).join("") || `<tr><td colspan="8" class="mut">暂无规则</td></tr>`;
    return `<div class="panel mt">
      <div class="rule-section-head">
        <div>
          <h2>规则库 <span class="hint">${rules.length} 条</span></h2>
          <div class="mut small">只在这里管理规则状态；创建、解析和默认白名单已拆到独立页。</div>
        </div>
        <button class="btn primary" data-rule-pane="create">新建规则</button>
      </div>
      <table class="rule-table">
        <thead><tr><th>状态</th><th>类型</th><th>匹配对象</th><th>处置动作</th><th>外部同步</th><th>过期</th><th>来源</th><th>操作</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
  }

  function createPane() {
    return `<div class="rule-workbench mt">
      <div class="panel rule-editor-panel">
        <div class="rule-section-head">
          <div>
            <h2>新建规则</h2>
            <div class="mut small">先生成草案，再决定保存草案或确认生效。</div>
          </div>
          <div class="rule-tabs compact">
            ${modeButton("manual", "手动创建")}
            ${modeButton("natural", "自然语言")}
          </div>
        </div>
        ${createMode === "manual" ? manualCreatePane() : naturalCreatePane()}
      </div>
      <div class="panel rule-preview-panel">
        <h2>草案预览</h2>
        ${draftPreview()}
        ${lastResult ? `<h2 class="mt">最近结果</h2><pre class="draft-box result-box">${esc(JSON.stringify(lastResult, null, 2))}</pre>` : ""}
      </div>
    </div>`;
  }

  function modeButton(key, label) {
    return `<button class="${createMode === key ? "active" : ""}" data-create-mode="${key}">${label}</button>`;
  }

  function manualCreatePane() {
    return `<div>
      <div class="classic-rule-grid">
        <label><span>规则类型</span><select id="manualRuleType" class="agent-input">
          <option value="block_ip" ${manualForm.type === "block_ip" ? "selected" : ""}>攻击源黑名单 · 封禁来源 IP</option>
          <option value="scanner_whitelist" ${manualForm.type === "scanner_whitelist" ? "selected" : ""}>受控扫描源白名单</option>
        </select></label>
        <label><span>有效期</span><input id="manualExpireDays" class="agent-input mono" type="number" min="1" max="365" value="${esc(manualForm.days)}"></label>
      </div>
      <label class="rule-label">规则对象</label>
      <textarea id="manualIpText" class="rule-input" placeholder="每行一个 IPv4，支持粘贴 txt 列表和 # 注释">${esc(manualForm.ips)}</textarea>
      <label class="rule-label">原因</label>
      <input id="manualReason" class="agent-input" value="${esc(manualForm.reason)}">
      <div class="rule-toolbar mt-sm">
        <button class="btn primary" id="manualDraftBtn">生成草案</button>
        <span class="hint">黑名单只登记对象，不自动下发腾讯云；封禁需人工执行。</span>
      </div>
    </div>`;
  }

  function naturalCreatePane() {
    return `<div>
      <label class="rule-label">自然语言输入</label>
      <textarea id="ruleText" class="rule-input natural-input" placeholder="例如：事件编号 xxx 是正常业务，以后同源同目标同规则不研判&#10;&#10;例如：45.79.8.221 是公司漏扫扫描源，以后直接加白&#10;&#10;例如：封禁以下IP&#10;1.2.3.4&#10;5.6.7.8">${esc(naturalText)}</textarea>
      <div class="rule-toolbar mt-sm">
        <div class="flex" style="gap:8px;flex-wrap:wrap">
          <button class="btn" id="draftRuleBtn">本地解析</button>
          <button class="btn primary" id="draftRuleLlmBtn">LLM 解析</button>
        </div>
        <span class="hint">LLM 解析失败会回退本地保守解析。</span>
      </div>
    </div>`;
  }

  function draftPreview() {
    if (!currentDraft) {
      return `<div class="rule-empty">
        <b>等待草案</b>
        <span>从左侧手动创建或自然语言解析生成规则草案。</span>
      </div>`;
    }
    const meta = describeRule(currentDraft);
    const notes = Array.isArray(currentDraft.notes) ? currentDraft.notes : [];
    return `<div class="rule-draft-card ${meta.tone}">
      <div class="rule-draft-top">
        <div>
          <div class="rule-draft-kind">${esc(meta.kind)}</div>
          <div class="mut small">${esc(meta.summary)}</div>
        </div>
        <span class="tag">${esc(currentDraft.status || "draft")}</span>
      </div>
      <div class="rule-preview-grid">
        ${previewItem("匹配对象", meta.target)}
        ${previewItem("处置动作", meta.action)}
        ${previewItem("有效期", currentDraft.expires_at || "长期")}
        ${previewItem("来源", currentDraft._ui_source || (currentDraft.parser === "llm" ? "LLM 解析" : "本地解析"))}
      </div>
      ${notes.length ? `<div class="rule-notes">${notes.map(n => `<span>${esc(n)}</span>`).join("")}</div>` : ""}
      <details class="rule-json">
        <summary>调试详情 JSON</summary>
        <pre class="draft-box">${esc(JSON.stringify(currentDraft, null, 2))}</pre>
      </details>
      <div class="rule-toolbar mt-sm">
        <div class="flex" style="gap:8px;flex-wrap:wrap">
          <button class="btn" data-save-rule="draft">保存草案</button>
          <button class="btn primary" data-save-rule="activate">确认生效</button>
        </div>
        <span class="hint">${currentDraft.action === "block_ip" ? "确认生效只登记人工封禁对象，不调用腾讯云。" : "生效后进入实时研判规则链路。"}</span>
      </div>
    </div>`;
  }

  function previewItem(label, value) {
    return `<div><span>${esc(label)}</span><b>${esc(value || "-")}</b></div>`;
  }

  function whitelistPane() {
    const cfg = CFW.DEMO.whitelistConfig || {};
    const counts = cfg.counts || {};
    const tencentIps = Array.isArray(cfg.tencent_scan_ips) ? cfg.tencent_scan_ips : [];
    const companyIps = Array.isArray(cfg.company_scan_ips) ? cfg.company_scan_ips : [];
    const candidates = Array.isArray(cfg.candidates) ? cfg.candidates : [];
    return `<div class="panel mt">
      <div class="rule-section-head">
        <div>
          <h2>默认白名单</h2>
          <div class="mut small">系统级扫描源白名单，保存后直接进入实时研判链路；规则库中只读展示。</div>
        </div>
      </div>
      <div class="classic-rule-grid">
        <div class="rule-stat"><span>腾讯云扫描源</span><b>${counts.tencent_scan_ips || tencentIps.length || 0}</b><em>系统默认</em></div>
        <div class="rule-stat"><span>公司扫描源</span><b>${counts.company_scan_ips || companyIps.length || 0}</b><em>受控来源</em></div>
        <div class="rule-stat"><span>合计去重</span><b>${counts.total || 0}</b><em>实时命中</em></div>
      </div>
      ${candidates.length ? `<div class="whitelist-candidates">
        <div>
          <b>发现历史白名单候选</b>
          <span>${esc(candidates.map(c => `${c.ip} (${c.label || c.target || "candidate"})`).join("、"))}</span>
        </div>
        <button class="btn tiny" id="importWhitelistCandidatesBtn">填入候选</button>
      </div>` : ""}
      <div class="whitelist-config-grid">
        <label>
          <span>腾讯云扫描源 IP</span>
          <textarea id="tencentWhitelistIps" class="rule-input whitelist-input" placeholder="每行一个 IPv4，支持 # 注释">${esc(tencentIps.join("\n"))}</textarea>
        </label>
        <label>
          <span>公司 / 受控扫描源 IP</span>
          <textarea id="companyWhitelistIps" class="rule-input whitelist-input" placeholder="每行一个 IPv4，支持 # 注释">${esc(companyIps.join("\n"))}</textarea>
        </label>
      </div>
      <div class="rule-toolbar mt-sm">
        <button class="btn primary" id="saveWhitelistBtn">保存默认白名单</button>
        <span class="hint">这里不创建普通规则，只更新系统默认白名单配置。</span>
      </div>
      ${lastResult ? `<h2 class="mt">最近结果</h2><pre class="draft-box result-box">${esc(JSON.stringify(lastResult, null, 2))}</pre>` : ""}
    </div>`;
  }

  function actionsPane() {
    const logs = loadActionLogs();
    return `<div class="panel mt">
      <div class="rule-section-head">
        <div>
          <h2>执行记录 <span class="hint">${logs.length} 条</span></h2>
          <div class="mut small">第一版先记录本浏览器上的保存、生效、禁用、白名单保存和下发返回；后续可迁移到后端审计日志。</div>
        </div>
        <button class="btn tiny" id="clearRuleLogsBtn">清空本地记录</button>
      </div>
      <div class="rule-action-feed">
        ${logs.map(actionItem).join("") || `<div class="rule-empty"><b>暂无执行记录</b><span>保存或启停规则后会出现在这里。</span></div>`}
      </div>
    </div>`;
  }

  function actionItem(item) {
    return `<div class="rule-action-item">
      <div>
        <b>${esc(item.title || "规则操作")}</b>
        <span>${esc(item.summary || "")}</span>
      </div>
      <time>${esc(item.time || "")}</time>
    </div>`;
  }

  async function draftManualRule() {
    manualForm = {
      type: CFW.$("#manualRuleType")?.value || "block_ip",
      ips: CFW.$("#manualIpText")?.value || "",
      reason: CFW.$("#manualReason")?.value.trim() || "人工确认",
      days: CFW.$("#manualExpireDays")?.value || "30",
    };
    const ips = extractIps(manualForm.ips);
    if (!ips.length) {
      currentDraft = null;
      lastResult = { error: "未解析到有效 IPv4" };
      CFW.renderLists();
      return;
    }
    const text = manualForm.type === "block_ip"
      ? `封禁以下IP\n${ips.join("\n")}\n原因:${manualForm.reason}`
      : `以下 IP 是公司受控扫描源，以后直接加白\n${ips.join("\n")}\n原因:${manualForm.reason}`;
    await draftRuleFromPayload({ text, use_llm: false, ui_source: "手动创建" });
    applyExpireDaysToDraft(manualForm.days);
  }

  async function draftNaturalRule(useLlm) {
    naturalText = CFW.$("#ruleText")?.value || "";
    await draftRuleFromPayload({
      text: naturalText,
      use_llm: !!useLlm,
      ui_source: useLlm ? "自然语言 LLM 解析" : "自然语言本地解析",
    });
  }

  async function draftRuleFromPayload(payload) {
    lastResult = { status: payload.use_llm ? "LLM 解析中..." : "本地解析中..." };
    CFW.renderLists();
    try {
      const res = await fetch("/api/agent/rules/draft", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      currentDraft = await res.json();
      currentDraft._ui_source = payload.ui_source || (payload.use_llm ? "LLM 解析" : "本地解析");
      lastResult = null;
      pushActionLog("生成草案", describeRule(currentDraft).summary);
    } catch (e) {
      currentDraft = null;
      lastResult = { error: "生成失败: " + e };
    }
    CFW.renderLists();
  }

  function applyExpireDaysToDraft(value) {
    if (!currentDraft) return;
    const days = Math.max(1, Math.min(365, Number(value || 30)));
    const expires = new Date(Date.now() + days * 86400000);
    currentDraft.expires_at = formatDateTime(expires);
    CFW.renderLists();
  }

  async function saveRule(activate) {
    if (!currentDraft) {
      lastResult = { error: "请先生成规则草案" };
      CFW.renderLists();
      return;
    }
    if (activate) {
      const isBlockRule = currentDraft.action === "block_ip";
      const message = isBlockRule
        ? `确认登记黑名单对象 ${blockIps(currentDraft).length} 个 IP？平台不会自动调用腾讯云封禁。`
        : "确认让这条自定义规则生效？生效后命中的告警会进入对应规则处理。";
      if (!confirm(message)) return;
    }
    lastResult = { status: activate ? "正在保存并生效..." : "正在保存草案..." };
    CFW.renderLists();
    try {
      const res = await fetch("/api/agent/rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rule: persistedDraft(currentDraft),
          activate,
        })
      });
      lastResult = await res.json();
      pushActionLog(activate ? "规则生效" : "保存草案", describeRule(lastResult).summary);
      if (CFW.loadData) await CFW.loadData(CFW.state.days);
      activePane = "library";
      CFW.renderLists();
    } catch (e) {
      lastResult = { error: "保存失败: " + e };
      CFW.renderLists();
    }
  }

  async function updateRule(ruleId, action) {
    const decoded = decodeURIComponent(ruleId || "");
    const rules = Array.isArray(CFW.DEMO.customRules) ? CFW.DEMO.customRules : [];
    const rule = rules.find(r => r.rule_id === decoded) || {};
    if (action === "activate") {
      const isBlockRule = rule.action === "block_ip";
      const message = isBlockRule
        ? `确认登记黑名单对象 ${blockIps(rule).length} 个 IP？平台不会自动调用腾讯云封禁。`
        : "确认让这条规则生效？";
      if (!confirm(message)) return;
    }
    if (action === "disable" && !confirm("确认禁用这条规则？")) return;
    try {
      const res = await fetch(`/api/agent/rules/${encodeURIComponent(decoded)}/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({})
      });
      lastResult = await res.json();
      pushActionLog(action === "activate" ? "规则生效" : "规则禁用", describeRule(lastResult).summary);
      if (CFW.loadData) await CFW.loadData(CFW.state.days);
      CFW.renderLists();
    } catch (e) {
      lastResult = { error: "操作失败: " + e };
      CFW.renderLists();
    }
  }

  async function saveWhitelistConfig() {
    const tencentIps = extractIps(CFW.$("#tencentWhitelistIps")?.value || "");
    const companyIps = extractIps(CFW.$("#companyWhitelistIps")?.value || "");
    const total = new Set([...tencentIps, ...companyIps]).size;
    if (!confirm(`确认保存默认白名单配置？合计 ${total} 个去重 IP，后续实时研判会直接使用。`)) return;
    lastResult = { status: "正在保存默认白名单..." };
    CFW.renderLists();
    try {
      const res = await fetch("/api/agent/whitelist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tencent_scan_ips: tencentIps,
          company_scan_ips: companyIps,
        })
      });
      lastResult = await res.json();
      pushActionLog("保存默认白名单", `合计 ${total} 个去重 IP`);
      if (CFW.loadData) await CFW.loadData(CFW.state.days);
      activePane = "whitelist";
      CFW.renderLists();
    } catch (e) {
      lastResult = { error: "保存失败: " + e };
      CFW.renderLists();
    }
  }

  function importWhitelistCandidates() {
    const cfg = CFW.DEMO.whitelistConfig || {};
    const candidates = Array.isArray(cfg.candidates) ? cfg.candidates : [];
    const tencentBox = CFW.$("#tencentWhitelistIps");
    const companyBox = CFW.$("#companyWhitelistIps");
    const append = (box, ips) => {
      if (!box || !ips.length) return;
      const current = extractIps(box.value);
      box.value = Array.from(new Set([...current, ...ips])).join("\n");
    };
    append(tencentBox, candidates.filter(c => c.target === "tencent_scan_ips").map(c => c.ip));
    append(companyBox, candidates.filter(c => c.target !== "tencent_scan_ips").map(c => c.ip));
    lastResult = { status: "历史候选已填入，请确认后保存默认白名单。" };
    CFW.renderLists();
  }

  function ruleRow(rule) {
    const meta = describeRule(rule);
    const encoded = encodeURIComponent(rule.rule_id || "");
    return `<tr>
      <td><span class="tag">${esc(rule.status || "draft")}</span></td>
      <td>${esc(meta.kind)}</td>
      <td class="mono small">${esc(meta.target)}</td>
      <td>${esc(meta.action)}</td>
      <td>${esc(syncStatus(rule))}</td>
      <td class="mono mut">${esc(rule.expires_at || "长期")}</td>
      <td>${esc(sourceText(rule))}</td>
      <td>${ruleButtons(rule, encoded)}</td>
    </tr>`;
  }

  function ruleButtons(rule, encoded) {
    if (!rule.rule_id) return "";
    if (rule.system || rule.readonly) return `<span class="tag">系统配置</span>`;
    if (rule.status === "active") {
      return `<button class="btn tiny" data-rule-action="disable" data-rule-id="${encoded}">禁用</button>`;
    }
    return `<button class="btn tiny" data-rule-action="activate" data-rule-id="${encoded}">生效</button>`;
  }

  function describeRule(rule) {
    const action = String(rule?.action || "");
    const type = String(rule?.type || "");
    const target = ruleTarget(rule);
    if (action === "block_ip" || type === "ip_blocklist") {
      return { kind: "攻击源黑名单", tone: "danger", target, action: "人工封禁登记", summary: `登记封禁来源 ${target}` };
    }
    if (action === "allow_scanner_ip" || type === "scanner_whitelist") {
      return { kind: "扫描源白名单", tone: "ok", target, action: "标记扫描源", summary: `受控扫描源 ${target}` };
    }
    if (action === "skip_llm_and_omit") {
      return { kind: "业务误报白名单", tone: "ok", target, action: "跳过研判并忽略", summary: `命中后自动按误报处理 ${target}` };
    }
    if (action === "omit_once") {
      return { kind: "单次忽略", tone: "warn", target, action: "仅忽略本次", summary: `仅处理单条告警 ${target}` };
    }
    return { kind: "自定义规则", tone: "neutral", target, action: action || "-", summary: target || "未指定匹配对象" };
  }

  function ruleTarget(rule) {
    const match = rule?.match || {};
    const ips = blockIps(rule);
    if (ips.length) return ips.join(", ");
    if (match.src_ip) return match.src_ip;
    if (match.source_alert_id) return "事件 " + match.source_alert_id;
    if (match.alert_id) return "告警 " + match.alert_id;
    const compact = Object.entries(match).filter(([, v]) => v).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("|") : v}`);
    return compact.join(", ") || "未指定";
  }

  function sourceText(rule) {
    const text = String(rule?.source_text || "");
    return text.length > 44 ? text.slice(0, 44) + "..." : text;
  }

  function syncStatus(rule) {
    if (rule?.action !== "block_ip") return "不需要";
    const res = rule?._tencent_block_result || {};
    return res.status || (rule.status === "active" ? "待人工确认" : "未生效");
  }

  function persistedDraft(draft) {
    const out = Object.assign({}, draft || {});
    delete out._ui_source;
    return out;
  }

  function blockIps(rule) {
    const match = rule?.match || {};
    const ips = rule?.ips || match.src_ips || [];
    return Array.isArray(ips) ? ips : [];
  }

  function extractIps(text) {
    const seen = new Set();
    const ips = [];
    String(text || "").replace(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g, ip => {
      if (!seen.has(ip)) {
        seen.add(ip);
        ips.push(ip);
      }
      return ip;
    });
    return ips;
  }

  function ruleStats(rules) {
    return rules.reduce((acc, rule) => {
      if (rule.status === "active") acc.active++;
      if (rule.action === "block_ip" || rule.type === "ip_blocklist") acc.block++;
      else if (rule.action === "allow_scanner_ip" || rule.type === "scanner_whitelist") acc.allow++;
      else if (rule.action === "skip_llm_and_omit" || rule.action === "omit_once") acc.suppress++;
      if (rule.system || rule.readonly) acc.system++;
      return acc;
    }, { active: 0, block: 0, allow: 0, suppress: 0, system: 0 });
  }

  function formatDateTime(d) {
    const pad = n => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  function loadActionLogs() {
    try {
      const rows = JSON.parse(localStorage.getItem(LOG_KEY) || "[]");
      return Array.isArray(rows) ? rows : [];
    } catch {
      return [];
    }
  }

  function pushActionLog(title, summary) {
    const rows = loadActionLogs();
    rows.unshift({ title, summary, time: formatDateTime(new Date()) });
    localStorage.setItem(LOG_KEY, JSON.stringify(rows.slice(0, 50)));
  }
})();
