/* ===== 视图：攻击者画像 ===== */
(function () {
  const { esc, fmt } = CFW;
  const CHAIN = ["侦察", "武器化", "投递", "利用", "安装", "命令控制", "行动"];
  const bandColor = { "高危": "var(--danger)", "关注": "var(--warn)", "一般": "var(--text-dim)" };

  CFW.renderAttackers = function () {
    const root = CFW.$("#view-attackers");
    const list = CFW.DEMO.profiles;
    const bands = { 高危: 0, 关注: 0, 一般: 0 };
    list.forEach(p => bands[p.band]++);

    root.innerHTML = `
      <div class="grid g-4">
        <div class="kpi tone-primary"><div class="k-label">画像攻击者</div><div class="k-num">${list.length}</div><div class="k-foot">按攻击源 IP 聚合</div></div>
        <div class="kpi tone-danger"><div class="k-label">高危画像</div><div class="k-num">${bands["高危"]}</div><div class="k-foot">需立即处置</div></div>
        <div class="kpi tone-warn"><div class="k-label">内网来源</div><div class="k-num">${list.filter(p => p.internal).length}</div><div class="k-foot">横向 / 异常外联</div></div>
        <div class="kpi tone-ok"><div class="k-label">已得手</div><div class="k-num">${list.filter(p => p.success > 0).length}</div><div class="k-foot">存在真实落地证据</div></div>
      </div>

      <div class="atk-wall mt">
        ${list.map(card).join("")}
      </div>`;
  };

  function chainTrack(stageMax) {
    const idx = CHAIN.indexOf(stageMax);
    return `<div class="chain">${CHAIN.map((s, i) => `
      <div class="chain-node ${i <= idx ? "on" : ""} ${i === idx ? "cur" : ""}">
        <span class="cn-dot"></span><span class="cn-t">${s}</span>
      </div>${i < CHAIN.length - 1 ? `<div class="chain-line ${i < idx ? "on" : ""}"></div>` : ""}`).join("")}</div>`;
  }

  function card(p) {
    const c = bandColor[p.band];
    const evs = Object.entries(p.events).sort((a, b) => b[1] - a[1])
      .map(([k, v]) => `<span class="chip">${esc(k)}<span class="x">×${v}</span></span>`).join("");
    return `<div class="atk-card" style="--c:${c}">
      <div class="atk-head">
        <div>
          <div class="atk-ip mono">${p.internal ? "🏠" : "🌐"} ${esc(p.ip)}</div>
          <div class="atk-sub">${p.internal ? "内网源" : "公网源 · " + esc(p.country)} · ${esc(p.type)} · 意图 ${esc(p.intent)}</div>
        </div>
        <div class="atk-score">
          <div class="as-num mono" style="color:${c}">${p.score}<span>/100</span></div>
          <div class="as-band" style="color:${c};border-color:${c}">${p.band}</div>
        </div>
      </div>

      <div class="atk-narr">${esc(p.narrative)}</div>

      <div class="atk-lab">杀伤链阶段 · 当前 <b style="color:${c}">${esc(p.stage)}</b></div>
      ${chainTrack(p.killchainMax)}

      <div class="atk-stats">
        <div><span class="mut">告警</span><b>${p.alertCount}</b></div>
        <div><span class="mut">手法</span><b>${p.techniques}</b></div>
        <div><span class="mut">目标</span><b>${p.targets}</b></div>
        <div><span class="mut">跨度</span><b>${p.span}h</b></div>
        <div><span class="mut">高危</span><b style="color:var(--danger)">${p.high}</b></div>
        <div><span class="mut">得手</span><b style="color:${p.success ? "var(--danger)" : "var(--ok)"}">${p.success}</b></div>
      </div>

      <div class="atk-lab">手法序列</div>
      <div class="wrap-chips">${evs}</div>

      <div class="atk-rec"><b>处置建议</b> ${esc(p.rec)}</div>
      <div class="atk-foot mut mono">活动 ${esc(p.first.slice(5, 16))} ~ ${esc(p.last.slice(5, 16))}</div>
    </div>`;
  }
})();
