/* ===== 视图：研判流水线 (实时处理链路) ===== */
(function () {
  const { esc, fmt, ICON, win } = CFW;

  const STAGE_COLORS = {
    primary: "var(--primary)",
    ok: "var(--ok)",
    warn: "var(--warn)",
    danger: "var(--danger)",
    violet: "var(--violet)",
  };

  CFW.renderPipeline = function () {
    const root = CFW.$("#view-pipeline");
    const w = win();
    const h = CFW.DEMO.health || {};
    const ps = CFW.DEMO.pipelineStatus || {};
    const cfg = ps.config || {};
    const last = ps.last_round || {};
    const active = Object.keys(ps.active_round || {}).length ? ps.active_round : last;
    const totals = ps.totals || {};
    const state = ps.state || {};
    const mode = pipelineMode(cfg, last);

    root.innerHTML = `
      <div class="grid g-4 pipe-kpis">
        ${kpi(mode.tone, "clock", "轮询状态", mode.label, mode.detail)}
        ${kpi("primary", "collect", "最近有效新事件", fmt(n(active.new_records)), `${roundTime(active)} · 查询 ${fmt(n(active.query_total))}`)}
        ${kpi("ok", "auto", "自动忽略", fmt(n(active.ignore_event_ids)), `${fmt(n(w.kpi.auto))} / ${fmt(n(w.kpi.total))} 条 · ${pctText(w.kpi.ignoreRate)}`)}
        ${kpi(n(active.manual_pending_push) ? "warn" : "primary", "notify", "人工待推", fmt(n(active.manual_pending_push)), pushText(active))}
      </div>

      <div class="panel pipe-map mt">
        <div class="accent-top"></div>
        <h2>实时处理链路 <span class="hint">最近有效轮次 ${roundTime(active)} · ${active.dry_run ? "演练模式" : "真实执行"}</span></h2>
        <div class="pipe-stage-grid">
          ${stage("collect", "采集", n(last.query_total) || n(active.query_total) || n(w.kpi.total), "告警中心窗口查询", `近 ${n(cfg.lookback_minutes) || 10} 分钟`, "primary")}
          ${stage("filter", "去重", n(active.new_records), "只处理新 EventId", `活跃 ${fmt(n(active.active_before))} · 去重 ${fmt(n(active.dedup_removed))}`, "primary")}
          ${stage("funnel", "研判", n(active.alert_count) || n(w.kpi.total), "规则 / 模型 / Agent", sourceBrief(w.sources), "violet")}
          ${stage("eye", "取证", n(h.evidenceHitCount), "源包或缓存命中", `${pctText(h.evidenceHit)} · ${fmt(n(h.evidenceHitCount))}/${fmt(n(h.total))}`, "warn")}
          ${stage("auto", "处置", n(active.ignore_event_ids) || n(w.kpi.auto), "忽略加白候选", `失败 ${fmt(n(totals.action_failed) + n(h.disposeFailed))}`, "ok")}
          ${stage("notify", "通知", n(active.manual_candidates), "人工研判候选", pushText(active), n(active.manual_candidates) ? "warn" : "ok")}
        </div>
      </div>

      <div class="grid pipe-main mt">
        <div class="panel">
          <h2>最近有效轮次 <span class="hint">${active.mode || "暂无轮询"}</span></h2>
          ${roundSummary(active, cfg, state)}
        </div>

        <div class="panel">
          <h2>研判结果流向 <span class="hint">当前时间窗</span></h2>
          ${resultFlow(w, active)}
        </div>
      </div>

      <div class="grid pipe-main mt">
        <div class="panel">
          <h2>最近轮询记录 <span class="hint">${fmt(n(totals.rounds))} 轮 · 新事件 ${fmt(n(totals.new_records))}</span></h2>
          ${roundTable(ps.recent_rounds || [])}
        </div>

        <div class="panel">
          <h2>策略闸与通知 <span class="hint">处置前保护条件</span></h2>
          ${guardPanel(cfg, CFW.DEMO.agent || {}, ps.latest_wecom || {})}
        </div>
      </div>

      <div class="panel mt">
        <h2>需要人工看的事件 <span class="hint">确认成功 / 需人工 / 高危</span></h2>
        ${attentionTable(CFW.DEMO.attention || [])}
      </div>`;
  };

  function kpi(tone, icon, label, value, foot) {
    return `<div class="kpi tone-${tone}">
      <div class="k-label"><span class="k-icon">${iconHtml(icon)}</span>${esc(label)}</div>
      <div class="k-num pipe-k-num">${esc(value)}</div>
      <div class="k-foot">${esc(foot || "")}</div>
    </div>`;
  }

  function stage(icon, title, value, label, meta, tone) {
    const c = STAGE_COLORS[tone] || STAGE_COLORS.primary;
    return `<div class="pipe-stage" style="--stage:${c}">
      <div class="pipe-stage-icon">${iconHtml(icon)}</div>
      <div class="pipe-stage-body">
        <div class="pipe-stage-top">
          <span>${esc(title)}</span>
          <b class="mono">${fmt(value)}</b>
        </div>
        <div class="pipe-stage-label">${esc(label)}</div>
        <div class="pipe-stage-meta">${esc(meta || "")}</div>
      </div>
    </div>`;
  }

  function roundSummary(round, cfg, state) {
    if (!round || !Object.keys(round).length) {
      return `<div class="empty"><div class="big">暂无实时轮询记录</div><div>启动实时轮询后会展示每轮查询、去重、研判和推送状态。</div></div>`;
    }
    const counts = round.judgement_counts || {};
    return `<div class="pipe-round-grid">
      ${kv("查询窗口", `${short(round.query_start)} ~ ${short(round.query_end)}`)}
      ${kv("轮询间隔", `${n(cfg.interval_seconds) || 60}s`)}
      ${kv("本轮查询", fmt(n(round.query_total)))}
      ${kv("新事件", fmt(n(round.new_records)))}
      ${kv("已研判", fmt(n(round.alert_count)))}
      ${kv("自动忽略", fmt(n(round.ignore_event_ids)))}
      ${kv("人工候选", fmt(n(round.manual_candidates)))}
      ${kv("状态缓存", `${fmt(n(state.processed))} 已处理`)}
      <div class="pipe-wide">
        <div class="pipe-mini-title">结论分布</div>
        <div class="wrap-chips">${resultChips(counts)}</div>
      </div>
      <div class="pipe-wide">
        <div class="pipe-mini-title">执行状态</div>
        <div class="pipe-status-line">
          ${statusChip(round.dry_run ? "演练未落库" : "真实执行", round.dry_run ? "warn" : "ok")}
          ${statusChip(`加白 ${fmt(n(round.white_actions_count))}`, "primary")}
          ${statusChip(`忽略 ${fmt(n(round.omit_actions_count))}`, "ok")}
          ${statusChip(`推送 ${pushText(round)}`, n(round.manual_pending_push) ? "warn" : "primary")}
        </div>
      </div>
    </div>`;
  }

  function resultFlow(w, active) {
    const results = w.results || {};
    const sources = w.sources || {};
    const total = n(w.kpi.total);
    const sourceTotal = Object.values(sources).reduce((a, b) => a + n(b), 0) || total;
    return `<div class="pipe-flow-block">
      ${meter("自动处置率", n(w.kpi.auto), total, "ok", `${pctText(w.kpi.ignoreRate)} · ${fmt(n(w.kpi.auto))}/${fmt(total)}`)}
      ${meter("人工保留", n(w.kpi.manual) + n(w.kpi.success), total, "warn", `${fmt(n(w.kpi.manual))} 复核 · ${fmt(n(w.kpi.success))} 成功`)}
      ${meter("本轮忽略", n(active.ignore_event_ids), Math.max(1, n(active.alert_count)), "ok", `${fmt(n(active.ignore_event_ids))}/${fmt(n(active.alert_count))}`)}
      <div class="pipe-mini-title mt-sm">研判来源</div>
      ${Object.entries(sources).sort((a, b) => n(b[1]) - n(a[1])).map(([name, count]) =>
        meter(name, n(count), sourceTotal, sourceTone(name), `${fmt(n(count))} 条`)
      ).join("") || `<div class="empty"><div class="big">暂无来源分布</div></div>`}
      <div class="pipe-mini-title mt-sm">结论</div>
      <div class="wrap-chips">${resultChips(results)}</div>
    </div>`;
  }

  function roundTable(rows) {
    if (!rows.length) {
      return `<div class="empty"><div class="big">暂无轮询记录</div><div>实时轮询日志写入后这里会自动更新。</div></div>`;
    }
    return `<div class="scroll-y pipe-round-scroll"><table>
      <thead><tr><th>时间</th><th class="r">查询</th><th class="r">新事件</th><th class="r">忽略</th><th class="r">人工</th><th>推送</th></tr></thead>
      <tbody>${rows.map(r => `<tr>
        <td class="mono mut">${esc(short(r.recorded_at || r.query_end))}</td>
        <td class="r mono">${fmt(n(r.query_total))}</td>
        <td class="r mono">${fmt(n(r.new_records))}</td>
        <td class="r mono">${fmt(n(r.ignore_event_ids))}</td>
        <td class="r mono ${n(r.manual_pending_push) ? "net-pub" : "mut"}">${fmt(n(r.manual_pending_push))}</td>
        <td>${statusChip(pushText(r), r.dry_run ? "warn" : ((r.manual_push || {}).sent ? "ok" : "primary"))}</td>
      </tr>`).join("")}</tbody>
    </table></div>`;
  }

  function guardPanel(cfg, agent, wecom) {
    const guard = ((agent.agent || {}).policy_guard) || {};
    return `<div class="pipe-guard">
      ${guardRow("实时轮询", cfg.realtime_enabled, `${n(cfg.interval_seconds) || 60}s / ${n(cfg.lookback_minutes) || 10}min`)}
      ${guardRow("自动处置", cfg.auto_dispose, "仅扫描/失败/未见成功证据")}
      ${guardRow("人工推送", cfg.push_manual && cfg.manual_push_enabled, cfg.manual_notify_cooldown_minutes ? `${cfg.manual_notify_cooldown_minutes}min 冷却` : "")}
      ${guardRow("日报", cfg.daily_report_enabled, `${cfg.daily_report_time || "17:50"} 发送`)}
      ${guardRow("小时报", cfg.hourly_report_enabled, cfg.hourly_report_enabled ? "启用" : "已关闭")}
      ${guardRow("成功不忽略", guard.confirmed_success_never_omit !== false && guard.cloud_success_never_omit !== false, "PolicyGuard")}
      ${guardRow("高危要证据", guard.high_alert_requires_evidence !== false, "证据不足保留")}
      <div class="pipe-wecom">
        <div class="pipe-mini-title">企微最近状态</div>
        <div class="pipe-status-line">
          ${statusChip(wecom.sent ? "已发送" : (wecom.reason || "无人工项"), wecom.sent ? "ok" : "warn")}
          ${wecom.recorded_at ? `<span class="mut mono">${esc(short(wecom.recorded_at))}</span>` : ""}
        </div>
      </div>
    </div>`;
  }

  function attentionTable(rows) {
    if (!rows.length) {
      return `<div class="empty"><div class="big">当前没有需要人工看的事件</div><div>确认成功、需人工复核或高危事件会出现在这里。</div></div>`;
    }
    return `<table><thead><tr><th>时间</th><th>等级</th><th>事件</th><th>来源 → 目标</th><th>研判</th></tr></thead>
      <tbody>${rows.slice(0, 10).map(a => `<tr>
        <td class="mut mono">${esc(short(a.time))}</td>
        <td><span class="tag tag-${a.level}">${esc(a.level)}</span></td>
        <td>${esc(a.event)}</td>
        <td class="${a.pub ? "net-pub" : "net-pri"} mono small">${esc(a.src)} → ${esc(a.dst)}</td>
        <td class="res res-${a.result}">${esc(a.result)}</td>
      </tr>`).join("")}</tbody></table>`;
  }

  function kv(label, value) {
    return `<div class="pipe-kv"><span>${esc(label)}</span><b>${esc(value)}</b></div>`;
  }

  function meter(label, value, total, tone, note) {
    const pct = total ? Math.min(100, Math.round(value / total * 100)) : 0;
    const c = STAGE_COLORS[tone] || STAGE_COLORS.primary;
    return `<div class="pipe-meter">
      <div class="pipe-meter-top"><span>${esc(label)}</span><b class="mono">${esc(note || fmt(value))}</b></div>
      <div class="pipe-meter-track"><span style="width:${pct}%;background:${c}"></span></div>
    </div>`;
  }

  function guardRow(label, enabled, detail) {
    return `<div class="pipe-guard-row">
      <div><b>${esc(label)}</b><span>${esc(detail || "")}</span></div>
      ${statusChip(enabled ? "开启" : "关闭", enabled ? "ok" : "warn")}
    </div>`;
  }

  function statusChip(text, tone) {
    return `<span class="pipe-chip ${tone || "primary"}">${esc(text || "—")}</span>`;
  }

  function resultChips(counts) {
    const entries = Object.entries(counts || {}).filter(([, v]) => n(v) > 0);
    if (!entries.length) return `<span class="chip">无结论</span>`;
    return entries.sort((a, b) => n(b[1]) - n(a[1])).map(([k, v]) =>
      `<span class="chip"><span class="res res-${k}">${esc(k)}</span><span class="x">×${fmt(n(v))}</span></span>`
    ).join("");
  }

  function pipelineMode(cfg, last) {
    if (!cfg.realtime_enabled) return { tone: "warn", label: "未启用", detail: "realtime_triage.enabled=false" };
    if (!last || !last.recorded_at) return { tone: "warn", label: "待轮询", detail: `${n(cfg.interval_seconds) || 60}s 间隔` };
    if (last.dry_run) return { tone: "warn", label: "演练", detail: `演练模式 · 最近 ${roundTime(last)}` };
    return { tone: "ok", label: "运行中", detail: `最近 ${roundTime(last)}` };
  }

  function pushText(round) {
    const push = (round && round.manual_push) || {};
    if (!round || !Object.keys(round).length) return "暂无记录";
    if (round.dry_run) return "演练未发送";
    if (push.sent) return "已推送";
    if (n(round.manual_pending_push)) return push.error || push.reason || "待发送";
    return "无人工项";
  }

  function sourceBrief(sources) {
    const entries = Object.entries(sources || {}).sort((a, b) => n(b[1]) - n(a[1]));
    if (!entries.length) return "暂无来源";
    return entries.slice(0, 2).map(([k, v]) => `${k} ${fmt(n(v))}`).join(" · ");
  }

  function sourceTone(name) {
    if (name === "Agent") return "violet";
    if (name === "源包复核") return "primary";
    if (name === "降级兜底") return "danger";
    return "ok";
  }

  function iconHtml(name) {
    return ICON[name] || ICON.flow || "";
  }

  function n(value) {
    return Number(value) || 0;
  }

  function pctText(value) {
    return `${(Number(value) || 0).toFixed(1)}%`;
  }

  function roundTime(round) {
    return short((round && (round.recorded_at || round.query_end)) || "");
  }

  function short(value) {
    const s = String(value || "");
    return s.length >= 16 ? s.slice(5, 16) : (s || "—");
  }
})();
