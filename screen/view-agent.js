/* ===== 视图：Agent 配置 (模型路由 + Provider/API + dry-run 预览) ===== */
(function () {
  const { esc } = CFW;
  const STAGES = ["batch_triage", "source_review", "agent_triage", "critical_review", "rule_parse"];
  const STAGE_LABELS = {
    batch_triage: "批量研判",
    source_review: "源包复核",
    agent_triage: "Agent 工具循环",
    critical_review: "高危复核",
    rule_parse: "自然语言规则解析",
  };
  const PROVIDER_TEMPLATES = {
    deepseek_fast: {
      label: "DeepSeek 快速",
      name: "deepseek_fast",
      type: "openai_compatible",
      model: "deepseek-chat",
      base_url: "https://api.deepseek.com",
      api_key_env: "DEEPSEEK_API_KEY",
      json_mode: true,
      timeout_seconds: 180,
    },
    deepseek_reasoner: {
      label: "DeepSeek 推理",
      name: "deepseek_reasoner",
      type: "openai_compatible",
      model: "deepseek-reasoner",
      base_url: "https://api.deepseek.com",
      api_key_env: "DEEPSEEK_API_KEY",
      json_mode: true,
      timeout_seconds: 240,
    },
    glm_fast: {
      label: "GLM",
      name: "glm_fast",
      type: "openai_compatible",
      model: "",
      base_url: "https://open.bigmodel.cn/api/paas/v4",
      api_key_env: "GLM_API_KEY",
      json_mode: true,
      timeout_seconds: 180,
    },
    openai_api: {
      label: "OpenAI / Codex API",
      name: "openai_api",
      type: "openai_compatible",
      model: "",
      base_url: "https://api.openai.com/v1",
      api_key_env: "OPENAI_API_KEY",
      json_mode: true,
      timeout_seconds: 300,
    },
    claude_api: {
      label: "Claude API",
      name: "claude_api",
      type: "anthropic",
      model: "",
      api_key_env: "ANTHROPIC_API_KEY",
      max_tokens: 4096,
      timeout_seconds: 240,
    },
    codex_direct: {
      label: "Codex 订阅",
      name: "codex_direct",
      type: "codex_direct",
      model: "gpt-5.5",
      url: "https://chatgpt.com/backend-api/codex/responses",
      reasoning_effort: "high",
      timeout_seconds: 300,
    },
    claude_subscription: {
      label: "Claude Code 订阅",
      name: "claude_subscription",
      type: "claude_cli",
      model: "claude-code-subscription",
      command: "claude -p --output-format text",
      timeout_seconds: 240,
    },
    custom_openai: {
      label: "自定义 OpenAI 兼容",
      name: "custom_api",
      type: "openai_compatible",
      model: "",
      base_url: "",
      api_key_env: "CUSTOM_API_KEY",
      json_mode: true,
      timeout_seconds: 180,
    },
  };
  let newProviderTemplate = "deepseek_fast";
  let newProviderModelOptions = {};
  let newProviderModelStatus = {};
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
    const envStatus = settings.env || {};
    const tencentAuth = agent.tencent_auth || {};
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
        <h2>腾讯云鉴权 <span class="hint">AK/SK 优先,也兼容服务器上的 tccli profile</span></h2>
        ${tencentAuthPanel(tencentAuth)}
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
        ${newProviderPane(providers, envStatus)}
        <div class="provider-grid">
          ${providerNames.map(name => providerCard(name, providers[name] || {}, health[name] || {}, envStatus)).join("") || `<div class="mut">未配置 Provider</div>`}
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
    const saveTencentAuth = CFW.$("#saveTencentAuthBtn", root);
    if (saveTencentAuth) saveTencentAuth.addEventListener("click", saveTencentAuthConfig);
    const templateSelect = CFW.$("#newProviderTemplate", root);
    if (templateSelect) templateSelect.addEventListener("change", e => { newProviderTemplate = e.target.value; CFW.renderAgent(); });
    const fetchModels = CFW.$("#fetchModelsBtn", root);
    if (fetchModels) fetchModels.addEventListener("click", fetchNewProviderModels);
    const addProvider = CFW.$("#addProviderBtn", root);
    if (addProvider) addProvider.addEventListener("click", saveNewProviderConfig);
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

  function tencentAuthPanel(auth) {
    const env = (auth.env || {}).keys || {};
    const profiles = Array.isArray(auth.credential_profiles) ? auth.credential_profiles.join(",") : "akonly,default";
    const sourceLabel = auth.source === "env" ? "AK/SK 环境变量" : (auth.source === "tccli" ? "tccli profile" : "未配置");
    const tccli = Array.isArray(auth.tccli_profiles) ? auth.tccli_profiles : [];
    return `<div class="tencent-auth-box">
      <div class="flex between">
        <div>
          <b>${auth.ready ? "鉴权可用" : "鉴权未就绪"}</b>
          <div class="mut small">当前来源: ${esc(sourceLabel)} · 密钥写入 ${esc((auth.env || {}).file || "服务器环境文件")}</div>
        </div>
        <span class="pill ${auth.ready ? "ok" : "warn"}">${auth.ready ? "READY" : "MISSING"}</span>
      </div>
      <div class="tencent-auth-grid">
        ${plainInput("Region", "tencentRegion", auth.region || "ap-shanghai")}
        ${plainInput("Endpoint", "tencentEndpoint", auth.endpoint || "cfw.tencentcloudapi.com")}
        ${plainInput("CLI Profiles", "tencentProfiles", profiles)}
        ${tencentSecret("SecretId", "TENCENTCLOUD_SECRET_ID", env)}
        ${tencentSecret("SecretKey", "TENCENTCLOUD_SECRET_KEY", env)}
        ${tencentSecret("Token(可选)", "TENCENTCLOUD_TOKEN", env)}
      </div>
      <div class="auth-profile-list">
        ${tccli.map(item => `<span class="profile-chip ${item.ready ? "ready" : ""}">${esc(item.name)} · ${item.ready ? "可用" : (item.exists ? "文件存在但未识别" : "无文件")}</span>`).join("")}
      </div>
      <div class="flex between mt-sm">
        <span class="hint">保存 AK/SK 后,告警拉取和源包取证会走这组凭证；封禁只登记人工对象，不自动调用腾讯云。</span>
        <button class="btn primary" id="saveTencentAuthBtn">保存腾讯云鉴权</button>
      </div>
    </div>`;
  }

  function newProviderPane(providers, envStatus) {
    const tpl = PROVIDER_TEMPLATES[newProviderTemplate] || PROVIDER_TEMPLATES.custom_openai;
    const nameTaken = !!providers[tpl.name];
    const modelOptions = newProviderModelOptions[newProviderTemplate] || [];
    const status = newProviderModelStatus[newProviderTemplate] || "";
    const needsKey = !!tpl.api_key_env;
    const isCustom = newProviderTemplate === "custom_openai";
    return `<div class="new-provider-box">
      <div class="flex between">
        <div>
          <b>新增 AI / API Provider</b>
          <div class="mut small">选择模板,填一条 API Key,获取模型列表后保存；Key 不进入 config.json。</div>
        </div>
        <select id="newProviderTemplate" class="agent-input provider-template">
          ${Object.entries(PROVIDER_TEMPLATES).map(([key, item]) => `<option value="${esc(key)}" ${key === newProviderTemplate ? "selected" : ""}>${esc(item.label)}</option>`).join("")}
        </select>
      </div>
      <div class="quick-provider" data-new-provider>
        ${hiddenField("name", tpl.name)}
        ${hiddenField("type", tpl.type)}
        ${hiddenField("base_url", tpl.base_url || "")}
        ${hiddenField("url", tpl.url || "")}
        ${hiddenField("api_key_env", tpl.api_key_env || "")}
        ${hiddenField("command", Array.isArray(tpl.command) ? tpl.command.join(" ") : (tpl.command || ""))}
        ${hiddenField("reasoning_effort", tpl.reasoning_effort || "")}
        ${hiddenField("timeout_seconds", tpl.timeout_seconds || "")}
        ${hiddenField("max_tokens", tpl.max_tokens || "")}
        <input type="checkbox" data-provider-field="json_mode" ${tpl.json_mode === false ? "" : "checked"} hidden>
        <div class="quick-provider-grid">
          ${needsKey ? secretField(tpl.api_key_env || "", envStatus, "new") : `<div class="quick-provider-note">订阅/本地 CLI 模式无需 API Key</div>`}
          ${isCustom ? field("API Base", "base_url", tpl.base_url || "") : ""}
          <div id="newProviderModelWrap">${modelControlHtml(tpl.model || "", modelOptions)}</div>
          <button class="btn" id="fetchModelsBtn" ${needsKey || isCustom ? "" : "disabled"}>获取模型列表</button>
        </div>
        <div class="model-fetch-status" id="newProviderModelStatus">${esc(status)}</div>
        <details class="provider-advanced">
          <summary>高级配置</summary>
          <div class="provider-form advanced-provider-form">
            ${field("Provider 名称", "name", tpl.name)}
            ${field("类型", "type", tpl.type)}
            ${field("API Base", "base_url", tpl.base_url || "")}
            ${field("API URL", "url", tpl.url || "")}
            ${field("Key 环境变量", "api_key_env", tpl.api_key_env || "")}
            ${field("CLI Command", "command", tpl.command || "")}
            ${field("推理强度", "reasoning_effort", tpl.reasoning_effort || "")}
            ${field("超时秒", "timeout_seconds", tpl.timeout_seconds || "")}
            ${field("Max Tokens", "max_tokens", tpl.max_tokens || "")}
          </div>
        </details>
      </div>
      <div class="flex between mt-sm">
        <span class="hint">${nameTaken ? "同名 Provider 已存在,保存会覆盖配置。" : `保存为 ${esc(tpl.name)},之后可在上方路由编辑里选择。`}</span>
        <button class="btn primary" id="addProviderBtn">保存新增 Provider</button>
      </div>
    </div>`;
  }

  function providerCard(name, provider, health, envStatus) {
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
        ${secretField(provider.api_key_env || "", envStatus, name)}
        ${field("CLI Command", "command", command)}
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

  function hiddenField(key, value) {
    return `<input type="hidden" data-provider-field="${esc(key)}" value="${esc(value)}">`;
  }

  function modelControlHtml(value, options) {
    const current = String(value || "");
    if (Array.isArray(options) && options.length) {
      const selected = options.includes(current) ? current : options[0];
      return `<label><span>模型</span><select class="agent-input mono" data-provider-field="model">
        ${options.map(model => `<option value="${esc(model)}" ${model === selected ? "selected" : ""}>${esc(model)}</option>`).join("")}
      </select></label>`;
    }
    return `<label><span>模型</span><input class="agent-input mono" data-provider-field="model" value="${esc(current)}" placeholder="先获取模型列表"></label>`;
  }

  function plainInput(label, id, value) {
    return `<label><span>${esc(label)}</span><input id="${esc(id)}" class="agent-input mono" value="${esc(value)}"></label>`;
  }

  function secretField(envName, envStatus, owner) {
    const env = String(envName || "").trim();
    const info = env ? (((envStatus || {}).keys || {})[env] || {}) : {};
    const present = !!info.present;
    const hint = env ? `${env} · ${present ? "已配置" : "未配置"}` : "先填写 Key 环境变量";
    return `<label class="provider-secret">
      <span>API Key</span>
      <input class="agent-input mono" type="password" data-provider-secret="${esc(owner)}" data-provider-secret-env="${esc(env)}" placeholder="${esc(hint)}">
    </label>`;
  }

  function tencentSecret(label, key, env) {
    const info = (env || {})[key] || {};
    const hint = `${key} · ${info.present ? "已配置" : "未配置"}`;
    return `<label class="provider-secret">
      <span>${esc(label)}</span>
      <input class="agent-input mono" type="password" data-tencent-secret="${esc(key)}" placeholder="${esc(hint)}">
    </label>`;
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

  async function saveTencentAuthConfig() {
    const secrets = {};
    CFW.$$("[data-tencent-secret]").forEach(el => {
      const value = (el.value || "").trim();
      if (value) secrets[el.dataset.tencentSecret] = value;
    });
    const payload = {
      region: (CFW.$("#tencentRegion")?.value || "").trim(),
      endpoint: (CFW.$("#tencentEndpoint")?.value || "").trim(),
      credential_profiles: (CFW.$("#tencentProfiles")?.value || "").trim(),
      secrets,
    };
    try {
      const res = await fetch("/api/tencent/auth/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "tencent_auth_update_failed");
      configResult = data;
      if (CFW.loadData) await CFW.loadData(CFW.state.days);
      CFW.renderAgent();
    } catch (e) {
      configResult = { error: String(e) };
      CFW.renderAgent();
    }
  }

  function collectNewProviderPayload() {
    const box = CFW.$("[data-new-provider]");
    const provider = {};
    const secrets = {};
    if (!box) return { provider, secrets };
    CFW.$$("[data-provider-field]", box).forEach(el => {
      const advanced = el.closest(".provider-advanced");
      if (advanced && !advanced.open) return;
      if (el.type === "checkbox") provider[el.dataset.providerField] = !!el.checked;
      else provider[el.dataset.providerField] = el.value.trim();
    });
    provider.name = (provider.name || "").trim();
    const secretInput = CFW.$("[data-provider-secret]", box);
    const envName = (provider.api_key_env || secretInput?.dataset.providerSecretEnv || "").trim();
    const secretValue = (secretInput?.value || "").trim();
    if (envName && secretValue) secrets[envName] = secretValue;
    return { provider, secrets };
  }

  async function fetchNewProviderModels() {
    const { provider, secrets } = collectNewProviderPayload();
    const status = CFW.$("#newProviderModelStatus");
    if (!provider.base_url && String(provider.type || "").includes("openai")) {
      if (status) status.textContent = "请先填写 API Base";
      return;
    }
    if (status) status.textContent = "正在获取模型列表...";
    try {
      const res = await fetch("/api/agent/providers/models", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider, secrets })
      });
      const data = await res.json();
      if (!data.ok || !Array.isArray(data.models) || !data.models.length) {
        const msg = data.error ? `获取失败: ${data.error}` : "未返回模型列表";
        newProviderModelStatus[newProviderTemplate] = msg;
        if (status) status.textContent = msg;
        return;
      }
      newProviderModelOptions[newProviderTemplate] = data.models;
      newProviderModelStatus[newProviderTemplate] = `已获取 ${data.models.length} 个模型`;
      const wrap = CFW.$("#newProviderModelWrap");
      if (wrap) wrap.innerHTML = modelControlHtml(provider.model || data.models[0], data.models);
      if (status) status.textContent = newProviderModelStatus[newProviderTemplate];
    } catch (e) {
      const msg = "获取失败: " + String(e);
      newProviderModelStatus[newProviderTemplate] = msg;
      if (status) status.textContent = msg;
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
    const secrets = {};
    CFW.$$("[data-provider-field]", card).forEach(el => {
      if (el.type === "checkbox") provider[el.dataset.providerField] = !!el.checked;
      else provider[el.dataset.providerField] = el.value.trim();
    });
    const secretInput = CFW.$("[data-provider-secret]", card);
    const envName = (provider.api_key_env || secretInput?.dataset.providerSecretEnv || "").trim();
    const secretValue = (secretInput?.value || "").trim();
    if (envName && secretValue) secrets[envName] = secretValue;
    try {
      await postConfig({ provider, secrets });
    } catch (e) {
      configResult = { provider: name, error: String(e) };
      CFW.renderAgent();
    }
  }

  async function saveNewProviderConfig() {
    const { provider, secrets } = collectNewProviderPayload();
    if (!provider.name) {
      configResult = { error: "请填写 Provider 名称" };
      CFW.renderAgent();
      return;
    }
    const apiLike = ["openai_compatible", "openai", "deepseek", "glm", "anthropic", "claude_api"].includes(String(provider.type || "").toLowerCase());
    if (apiLike && !provider.model) {
      configResult = { error: "请先获取并选择模型" };
      CFW.renderAgent();
      return;
    }
    try {
      await postConfig({ provider, secrets });
    } catch (e) {
      configResult = { provider: provider.name, error: String(e) };
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
