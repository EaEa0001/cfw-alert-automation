/* ===== 视图：Agent 配置 (模型路由 + Provider/API + dry-run 预览) ===== */
(function () {
  const { esc } = CFW;
  const STAGES = ["batch_triage", "source_review", "agent_triage", "critical_review", "rule_parse", "fallback"];
  const STAGE_LABELS = {
    batch_triage: "批量研判",
    source_review: "源包复核",
    agent_triage: "Agent 工具循环",
    critical_review: "高危复核",
    rule_parse: "自然语言规则解析",
    fallback: "兜底路由",
  };
  let lastPreview = null;
  let configResult = null;
  let selectedAlertId = "";

  CFW.renderAgent = function () {
    const root = CFW.$("#view-agent");
    const agent = CFW.DEMO.agent || {};
    const settings = agent.llm_settings || {};
    const routing = agent.model_routing || {};
    const routes = settings.routing || routing.routes || {};
    const providers = settings.providers || routing.providers || {};
    const health = agent.provider_health || {};
    const alerts = Array.isArray(CFW.DEMO.agentAlerts) ? CFW.DEMO.agentAlerts : [];
    const providerNames = Object.keys(providers);
    if (!selectedAlertId && alerts[0]) selectedAlertId = alerts[0]["告警ID"] || "";

    root.innerHTML = `
      <div class="grid mt" style="grid-template-columns:1.15fr .85fr">
        <div class="panel">
          <div class="accent-top"></div>
          <h2>模型路由 <span class="hint">每个阶段可独立选择订阅或 API Provider</span></h2>
          <div class="route-grid">
            ${STAGES.map(stage => routeCard(stage, routes[stage], providers[routes[stage]] || {}, health[routes[stage]] || {})).join("")}
          </div>
        </div>

        <div class="panel">
          <h2>全局开关 <span class="hint">只保存配置,不触发真实研判</span></h2>
          <label class="inline-check"><input id="llmEnabled" type="checkbox" ${settings.enabled === false ? "" : "checked"}> 启用 LLM 研判</label>
          <label class="inline-check"><input id="ruleParseEnabled" type="checkbox" ${(settings.rule_parse || {}).enabled === false ? "" : "checked"}> 启用 LLM 自然语言规则解析</label>
          <div class="agent-context">
            <label>解析超时</label>
            <input id="ruleParseTimeout" class="agent-input mono" type="number" min="5" max="300" value="${esc((settings.rule_parse || {}).timeout_seconds || 90)}">
          </div>
          <button class="btn primary" id="saveLlmGlobalBtn">保存开关</button>
          <pre class="draft-box config-result">${configResult ? esc(JSON.stringify(configResult, null, 2)) : "等待配置变更..."}</pre>
        </div>
      </div>

      <div class="panel mt">
        <h2>路由编辑 <span class="hint">rule_parse 控制自然语言黑白名单解析使用哪个模型</span></h2>
        <div class="route-form-grid">
          ${STAGES.map(stage => routeEditor(stage, routes[stage], providerNames)).join("")}
        </div>
        <div class="flex between mt-sm">
          <span class="hint">推荐: 批量研判用低成本模型,Agent/高危复核用推理能力更强的模型。</span>
          <button class="btn primary" id="saveRoutesBtn">保存路由</button>
        </div>
      </div>

      <div class="panel mt">
        <h2>Provider / API 配置 <span class="hint">支持 Codex/Claude 订阅,以及 OpenAI 兼容 API(DeepSeek/GLM/Codex API)</span></h2>
        <div class="provider-grid">
          ${providerNames.map(name => providerCard(name, providers[name] || {}, health[name] || {})).join("") || `<div class="mut">未配置 Provider</div>`}
        </div>
      </div>

      <div class="grid mt" style="grid-template-columns:1.2fr .9fr">
        <div class="panel">
          <h2>最近告警上下文 <span class="hint">${alerts.length} 条 · 用于 dry-run 预览</span></h2>
          <table>
            <thead><tr><th>时间</th><th>等级</th><th>事件</th><th>源/目标</th><th>结论</th><th>操作</th></tr></thead>
            <tbody>
              ${alerts.slice(0, 12).map(alertRow).join("") || `<tr><td colspan="6" class="mut">暂无可用告警</td></tr>`}
            </tbody>
          </table>
        </div>

        <div class="panel">
          <h2>Agent dry-run <span class="hint">只预览策略闸结果,不执行云端写操作</span></h2>
          <div class="agent-context">
            <label>告警ID</label>
            <input id="agentAlertId" class="agent-input mono" value="${esc(selectedAlertId)}" placeholder="选择或输入告警ID">
          </div>
          <div class="flex" style="gap:8px;flex-wrap:wrap">
            <button class="btn" id="policyPreviewBtn">策略预览</button>
            <button class="btn primary" id="agentPreviewBtn">完整 Agent dry-run</button>
          </div>
          <div class="preview-summary">${previewSummary()}</div>
          <pre class="draft-box preview-box" id="triagePreview">${lastPreview ? esc(JSON.stringify(lastPreview, null, 2)) : "等待预览..."}</pre>
        </div>
      </div>`;

    const alertInput = CFW.$("#agentAlertId", root);
    if (alertInput) alertInput.addEventListener("input", () => { selectedAlertId = alertInput.value.trim(); });
    const saveGlobal = CFW.$("#saveLlmGlobalBtn", root);
    if (saveGlobal) saveGlobal.addEventListener("click", saveGlobalConfig);
    const saveRoutes = CFW.$("#saveRoutesBtn", root);
    if (saveRoutes) saveRoutes.addEventListener("click", saveRoutesConfig);
    const policyPreview = CFW.$("#policyPreviewBtn", root);
    if (policyPreview) policyPreview.addEventListener("click", () => previewTriage(false));
    const agentPreview = CFW.$("#agentPreviewBtn", root);
    if (agentPreview) agentPreview.addEventListener("click", () => previewTriage(true));
    CFW.$$("[data-provider-save]", root).forEach(b => b.addEventListener("click", () => saveProviderConfig(b.dataset.providerSave)));
    CFW.$$("[data-provider-test]", root).forEach(b => b.addEventListener("click", () => testProviderConfig(b.dataset.providerTest)));
    CFW.$$("[data-alert-select]", root).forEach(b => b.addEventListener("click", () => selectAlert(decodeURIComponent(b.dataset.alertSelect || ""))));
    CFW.$$("[data-alert-preview]", root).forEach(b => b.addEventListener("click", () => {
      selectAlert(decodeURIComponent(b.dataset.alertPreview || ""));
      previewTriage(false);
    }));
  };

  function routeCard(stage, name, provider, health) {
    const ok = health.ok === true;
    return `<div class="mini-card">
      <div class="flex between"><b>${esc(STAGE_LABELS[stage] || stage)}</b><span class="dot ${ok ? "live" : ""}"></span></div>
      <div class="mono route-name">${esc(name || "未配置")}</div>
      <div class="mut small">${esc(provider.type || "")} · ${esc(provider.model || "")}</div>
      <div class="mut small">${esc(provider.base_url || provider.url || provider.api_key_env || "")}</div>
      ${health.error ? `<div class="small" style="color:var(--warn)">${esc(health.error)}</div>` : ""}
    </div>`;
  }

  function routeEditor(stage, current, providerNames) {
    return `<label class="route-editor">
      <span>${esc(STAGE_LABELS[stage] || stage)}</span>
      <select data-route-stage="${esc(stage)}">
        ${providerNames.map(name => `<option value="${esc(name)}" ${name === current ? "selected" : ""}>${esc(name)}</option>`).join("")}
      </select>
    </label>`;
  }

  function providerCard(name, provider, health) {
    const ok = health.ok === true;
    const command = Array.isArray(provider.command) ? provider.command.join(" ") : (provider.command || "");
    return `<div class="provider-card" data-provider-card="${esc(name)}">
      <div class="flex between">
        <div>
          <b>${esc(name)}</b>
          <div class="mut small">${esc(provider.type || "")} · ${esc(provider.model || "")}</div>
        </div>
        <span class="dot ${ok ? "live" : ""}"></span>
      </div>
      <div class="provider-form">
        ${field("类型", "type", provider.type || "")}
        ${field("模型", "model", provider.model || "")}
        ${field("API Base", "base_url", provider.base_url || "")}
        ${field("API URL", "url", provider.url || "")}
        ${field("Key 环境变量", "api_key_env", provider.api_key_env || "")}
        ${field("推理强度", "reasoning_effort", provider.reasoning_effort || "")}
        ${field("超时秒", "timeout_seconds", provider.timeout_seconds || "")}
        ${field("Max Tokens", "max_tokens", provider.max_tokens || "")}
        ${field("Anthropic版本", "anthropic_version", provider.anthropic_version || "")}
        <label class="inline-check provider-json"><input type="checkbox" data-provider-field="json_mode" ${provider.json_mode === false ? "" : "checked"}> JSON Mode</label>
      </div>
      ${command ? `<div class="provider-command mono">${esc(command)}</div>` : ""}
      ${health.error ? `<div class="small mt-sm" style="color:var(--warn)">${esc(health.error)}</div>` : ""}
      <div class="provider-actions">
        <button class="btn" data-provider-test="${esc(name)}">检查配置</button>
        <button class="btn primary" data-provider-save="${esc(name)}">保存 Provider</button>
      </div>
    </div>`;
  }

  function field(label, key, value) {
    return `<label><span>${esc(label)}</span><input class="agent-input mono" data-provider-field="${esc(key)}" value="${esc(value)}"></label>`;
  }

  function alertRow(row) {
    const id = row["告警ID"] || "";
    const encoded = encodeURIComponent(id);
    const active = id && id === selectedAlertId ? " selected" : "";
    return `<tr class="agent-alert-row${active}">
      <td class="mono mut">${esc(String(row["告警时间"] || "").slice(5, 16))}</td>
      <td>${esc(row["告警等级"] || "")}</td>
      <td>${esc(row["事件名称"] || "")}</td>
      <td class="mono small">${esc(row["攻击IP"] || "")}<br><span class="mut">${esc(row["目标IP"] || "")}</span></td>
      <td>${esc(row["模型研判"] || "")}</td>
      <td>
        <button class="btn tiny" data-alert-select="${encoded}">选择</button>
        <button class="btn tiny" data-alert-preview="${encoded}">预览</button>
      </td>
    </tr>`;
  }

  function previewSummary() {
    if (!lastPreview) return `<div class="mut">尚未运行</div>`;
    if (lastPreview.error) return `<div style="color:var(--warn)">${esc(lastPreview.error)}</div>`;
    const verdict = (lastPreview.verdict || {})["模型研判"] || "";
    const allowed = ((lastPreview.policy || {}).allowed_actions || []).length;
    const blocked = ((lastPreview.policy || {}).blocked_actions || []).length;
    const msg = lastPreview.operator_message || "";
    return `<div class="agent-preview-kpis">
      <div><span class="mut">结论</span><b>${esc(verdict)}</b></div>
      <div><span class="mut">允许</span><b style="color:var(--ok)">${allowed}</b></div>
      <div><span class="mut">阻断</span><b style="color:var(--warn)">${blocked}</b></div>
      <div><span class="mut">状态</span><b>${esc(msg)}</b></div>
    </div>`;
  }

  function selectAlert(alertId) {
    selectedAlertId = alertId || "";
    lastPreview = null;
    const input = CFW.$("#agentAlertId");
    if (input) input.value = selectedAlertId;
    CFW.renderAgent();
  }

  function activeAlertId() {
    const input = CFW.$("#agentAlertId");
    return (input ? input.value : selectedAlertId || "").trim();
  }

  async function postConfig(payload) {
    const res = await fetch("/api/agent/llm/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "config_update_failed");
    configResult = data;
    if (CFW.loadData) await CFW.loadData(CFW.state.days);
    CFW.renderAgent();
  }

  async function saveGlobalConfig() {
    try {
      await postConfig({
        enabled: !!CFW.$("#llmEnabled").checked,
        rule_parse: {
          enabled: !!CFW.$("#ruleParseEnabled").checked,
          timeout_seconds: Number(CFW.$("#ruleParseTimeout").value || 90),
        }
      });
    } catch (e) {
      configResult = { error: String(e) };
      CFW.renderAgent();
    }
  }

  async function saveRoutesConfig() {
    const routing = {};
    CFW.$$("[data-route-stage]").forEach(el => { routing[el.dataset.routeStage] = el.value; });
    try {
      await postConfig({ routing });
    } catch (e) {
      configResult = { error: String(e) };
      CFW.renderAgent();
    }
  }

  async function saveProviderConfig(name) {
    const card = CFW.$$("[data-provider-card]").find(el => el.dataset.providerCard === name);
    if (!card) {
      configResult = { provider: name, error: "provider_card_not_found" };
      CFW.renderAgent();
      return;
    }
    const provider = { name };
    CFW.$$("[data-provider-field]", card).forEach(el => {
      if (el.type === "checkbox") provider[el.dataset.providerField] = !!el.checked;
      else provider[el.dataset.providerField] = el.value.trim();
    });
    try {
      await postConfig({ provider });
    } catch (e) {
      configResult = { provider: name, error: String(e) };
      CFW.renderAgent();
    }
  }

  async function testProviderConfig(name) {
    configResult = { provider: name, status: "checking" };
    CFW.renderAgent();
    try {
      const res = await fetch(`/api/agent/providers/${encodeURIComponent(name)}/test`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ live: false, timeout: 10 })
      });
      configResult = await res.json();
    } catch (e) {
      configResult = { provider: name, error: String(e) };
    }
    CFW.renderAgent();
  }

  async function previewTriage(runModel) {
    const id = activeAlertId();
    const box = CFW.$("#triagePreview");
    if (!id) {
      box.textContent = "请先选择或输入告警ID";
      return;
    }
    if (runModel && !confirm("完整 dry-run 会调用当前模型路由和只读取证工具,确认继续？")) return;
    box.textContent = runModel ? "Agent dry-run 中..." : "策略预览中...";
    try {
      const res = await fetch("/api/agent/triage/preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alert_id: id, days: CFW.state.days, live: false, run_model: runModel })
      });
      lastPreview = await res.json();
      box.textContent = JSON.stringify(lastPreview, null, 2);
      CFW.renderAgent();
    } catch (e) {
      box.textContent = "预览失败: " + e;
    }
  }
})();
