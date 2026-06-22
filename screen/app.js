/* ===== 应用外壳：导航 / 时钟 / 时间窗 / 初始化 ===== */
(function () {
  const VIEWS = {
    overview: { title: "态势总览", crumb: "实时安全态势 · KPI 与告警分布", render: () => CFW.renderOverview() },
    pipeline: { title: "研判流水线", crumb: "端到端工作流 · 三层漏斗研判", render: () => CFW.renderPipeline() },
    triage: { title: "告警研判台", crumb: "告警明细 · 证据链与工具轨迹下钻", render: () => CFW.renderTriage() },
    attackers: { title: "攻击者画像", crumb: "按攻击源聚合 · 杀伤链与威胁评分", render: () => CFW.renderAttackers() },
    efficiency: { title: "效能与成本", crumb: "自动化成效 · Token 用量与人工节省", render: () => CFW.renderEfficiency() }
  };

  function go(view) {
    CFW.state.view = view;
    CFW.stopTicker && CFW.stopTicker();
    CFW.$$(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.view === view));
    CFW.$$(".view").forEach(v => v.classList.toggle("active", v.id === "view-" + view));
    const meta = VIEWS[view];
    CFW.$("#topTitle").textContent = meta.title;
    CFW.$("#topCrumb").textContent = meta.crumb;
    meta.render();
    window.scrollTo(0, 0);
  }

  async function setDays(d) {
    CFW.state.days = d;
    CFW.$$("#daySeg button").forEach(b => b.classList.toggle("active", +b.dataset.d === d));
    if (CFW.loadData) { try { await CFW.loadData(d); } catch (e) { console.warn("loadData failed", e); } }
    VIEWS[CFW.state.view].render();
    bumpUpdated();
  }

  function clock() {
    const n = new Date();
    const p = x => String(x).padStart(2, "0");
    CFW.$("#clock").textContent = `${n.getFullYear()}-${p(n.getMonth() + 1)}-${p(n.getDate())} ${p(n.getHours())}:${p(n.getMinutes())}:${p(n.getSeconds())}`;
  }

  function bumpUpdated() {
    const n = new Date();
    const p = x => String(x).padStart(2, "0");
    CFW.$("#updated").textContent = `更新于 ${p(n.getHours())}:${p(n.getMinutes())}:${p(n.getSeconds())}`;
  }

  CFW.init = async function () {
    CFW.$$(".nav-item").forEach(n => n.addEventListener("click", () => go(n.dataset.view)));
    CFW.$$("#daySeg button").forEach(b => b.addEventListener("click", () => setDays(+b.dataset.d)));
    clock(); setInterval(clock, 1000);
    bumpUpdated(); setInterval(bumpUpdated, 30000);
    if (CFW.loadData) { try { await CFW.loadData(CFW.state.days); } catch (e) { console.warn("loadData failed", e); } }
    go("overview");
    // 每 60s 自动刷新当前时间窗数据并重渲染
    setInterval(async () => {
      if (CFW.loadData) { try { await CFW.loadData(CFW.state.days); VIEWS[CFW.state.view].render(); bumpUpdated(); } catch (e) {} }
    }, 60000);
  };
})();
