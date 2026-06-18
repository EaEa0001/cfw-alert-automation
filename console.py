"""CFW 研判控制台 — 本地 Web 看板。

用法:
    python console.py            # 默认 127.0.0.1:8787
    python console.py --port 9000 --host 0.0.0.0

数据来自 triage_stats(读 data/ 与 reports/ 的 jsonl),无数据库,刷新即最新。
默认只绑定本机回环,数据不出本机。
"""
import argparse

from flask import Flask, jsonify, request

import triage_stats as stats

app = Flask(__name__)


@app.route("/")
def index():
    return PAGE


@app.route("/api/overview")
def api_overview():
    return jsonify(stats.overview(_days()))


@app.route("/api/trend")
def api_trend():
    return jsonify(stats.trend(_days()))


@app.route("/api/health")
def api_health():
    return jsonify(stats.health(_days()))


@app.route("/api/profiles")
def api_profiles():
    return jsonify(stats.profiles(_days()))


@app.route("/api/alerts")
def api_alerts():
    return jsonify(stats.alerts(
        _days(),
        level=request.args.get("level") or None,
        result=request.args.get("result") or None,
        source=request.args.get("source") or None,
        limit=int(request.args.get("limit", 300)),
    ))


@app.route("/api/attacker_rank")
def api_attacker_rank():
    return jsonify(stats.attacker_rank(_days()))


@app.route("/api/asset_rank")
def api_asset_rank():
    return jsonify(stats.asset_rank(_days()))


@app.route("/api/realtime")
def api_realtime():
    return jsonify(stats.realtime_attention(_days()))


@app.route("/api/attack_graph")
def api_attack_graph():
    try:
        md = int(request.args.get("min_danger", 2))
    except (TypeError, ValueError):
        md = 2
    return jsonify(stats.attack_graph(
        _days(),
        focus=request.args.get("focus", "key"),
        min_danger=md,
        collapse_solo=request.args.get("collapse", "1") != "0",
        target=request.args.get("target") or None,
    ))


@app.route("/screen")
def screen():
    return SCREEN_PAGE


def _days():
    try:
        return max(1, min(60, int(request.args.get("days", 7))))
    except (TypeError, ValueError):
        return 7


PAGE = r"""<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CFW 研判控制台</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
  :root { --bg:#0f1419; --card:#1a2230; --line:#2a3547; --fg:#e6edf3; --mut:#8b98a9;
          --hi:#ff6b6b; --ok:#3fb950; --warn:#d29922; --acc:#58a6ff; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:14px/1.5 -apple-system,Segoe UI,Roboto,"Microsoft YaHei",sans-serif; }
  header { padding:16px 24px; border-bottom:1px solid var(--line); display:flex;
           align-items:center; gap:16px; flex-wrap:wrap; }
  h1 { font-size:18px; margin:0; }
  select,button { background:var(--card); color:var(--fg); border:1px solid var(--line);
                  border-radius:6px; padding:6px 10px; font-size:13px; cursor:pointer; }
  .wrap { padding:20px 24px; max-width:1400px; margin:0 auto; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }
  .card .k { color:var(--mut); font-size:12px; }
  .card .v { font-size:26px; font-weight:600; margin-top:4px; }
  .card .s { color:var(--mut); font-size:12px; margin-top:2px; }
  .grid2 { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-top:18px; }
  .panel { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px; }
  .panel h2 { font-size:14px; margin:0 0 12px; color:var(--mut); font-weight:600; }
  table { width:100%; border-collapse:collapse; font-size:12.5px; }
  th,td { text-align:left; padding:7px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--mut); font-weight:600; position:sticky; top:0; background:var(--card); }
  tr.alert:hover { background:#202a3a; cursor:pointer; }
  .tag { display:inline-block; padding:1px 7px; border-radius:10px; font-size:11px; }
  .lv-高危 { background:#3d1f1f; color:var(--hi); }
  .lv-中危 { background:#3a3320; color:var(--warn); }
  .r-确认成功 { color:var(--hi); font-weight:600; }
  .r-需人工复核 { color:var(--warn); }
  .r-扫描探测,.r-未见成功证据,.r-确认未成功 { color:var(--mut); }
  .src-Agent { color:var(--acc); }
  .src-降级兜底 { color:var(--hi); }
  .filters { display:flex; gap:8px; margin-bottom:10px; flex-wrap:wrap; }
  .detail { background:#11161f; border:1px solid var(--line); border-radius:6px;
            padding:10px; margin-top:6px; white-space:pre-wrap; word-break:break-all;
            font-family:Consolas,monospace; font-size:11.5px; color:var(--mut); display:none; }
  .tabletall { max-height:560px; overflow:auto; }
  .err { color:var(--hi); }
  .muted { color:var(--mut); }
  .tabs { display:inline-flex; gap:4px; }
  .tab { background:transparent; border:1px solid var(--line); }
  .tab.active { background:var(--acc); color:#0f1419; border-color:var(--acc); }
  .acard { background:var(--card); border:1px solid var(--line); border-left:3px solid var(--mut);
           border-radius:10px; padding:14px 16px; margin-bottom:12px; }
  .acard.b-高危 { border-left-color:var(--hi); }
  .acard.b-关注 { border-left-color:var(--warn); }
  .acard .top { display:flex; justify-content:space-between; align-items:baseline; gap:12px; flex-wrap:wrap; }
  .acard .ip { font-size:16px; font-weight:600; font-family:Consolas,monospace; }
  .acard .score { font-size:24px; font-weight:700; }
  .acard .score.高危 { color:var(--hi); } .acard .score.关注 { color:var(--warn); } .acard .score.一般 { color:var(--mut); }
  .acard .narr { margin:8px 0; line-height:1.6; }
  .acard .meta { color:var(--mut); font-size:12px; display:flex; gap:16px; flex-wrap:wrap; }
  .acard .seq { margin-top:8px; font-size:12px; color:var(--mut); }
  .chip { display:inline-block; background:#11161f; border:1px solid var(--line); border-radius:4px;
          padding:1px 7px; margin:2px 4px 2px 0; font-size:11.5px; }
  .rec { display:inline-block; margin-top:8px; padding:2px 10px; border-radius:6px; font-size:12px;
         background:#3d1f1f; color:var(--hi); }
</style>
</head>
<body>
<header>
  <h1>🛡️ CFW 研判控制台</h1>
  <label>时间窗
    <select id="days" onchange="loadAll()">
      <option value="1">今天</option>
      <option value="3">近3天</option>
      <option value="7" selected>近7天</option>
      <option value="14">近14天</option>
      <option value="30">近30天</option>
    </select>
  </label>
  <button onclick="loadAll()">刷新</button>
  <span class="tabs">
    <button id="tab-overview" class="tab active" onclick="switchView('overview')">研判总览</button>
    <button id="tab-attackers" class="tab" onclick="switchView('attackers')">攻击者画像</button>
  </span>
  <span id="updated" class="muted"></span>
</header>

<div class="wrap view" id="view-overview">
  <div class="cards" id="cards"></div>

  <div class="grid2">
    <div class="panel"><h2>每日告警量 / Token</h2><canvas id="trendChart" height="120"></canvas></div>
    <div class="panel"><h2>研判结果分布</h2><canvas id="resultChart" height="120"></canvas></div>
  </div>

  <div class="grid2">
    <div class="panel">
      <h2>Token 按研判来源</h2>
      <table id="tokTable"></table>
    </div>
    <div class="panel">
      <h2>健康 / 降级</h2>
      <div id="healthBox"></div>
    </div>
  </div>

  <div class="panel" style="margin-top:18px;">
    <h2>研判明细(点行展开证据链)</h2>
    <div class="filters">
      <select id="fLevel" onchange="loadAlerts()"><option value="">全部等级</option><option>高危</option><option>中危</option><option>低危</option></select>
      <select id="fResult" onchange="loadAlerts()"><option value="">全部结果</option><option>确认成功</option><option>需人工复核</option><option>未见成功证据</option><option>确认未成功</option><option>扫描探测</option></select>
      <select id="fSource" onchange="loadAlerts()"><option value="">全部来源</option><option>单轮</option><option>源包复核</option><option>Agent</option><option>降级兜底</option></select>
    </div>
    <div class="tabletall"><table id="alertTable"></table></div>
  </div>
</div>

<div class="wrap view" id="view-attackers" style="display:none">
  <div class="cards" id="attackerCards"></div>
  <div id="attackerList"></div>
</div>

<script>
let trendChart, resultChart;
const $ = s => document.querySelector(s);
function days(){ return $('#days').value; }

async function get(path, params={}){
  const q = new URLSearchParams({days:days(), ...params});
  const r = await fetch(path + '?' + q);
  return r.json();
}

function card(k, v, s){ return `<div class="card"><div class="k">${k}</div><div class="v">${v}</div>${s?`<div class="s">${s}</div>`:''}</div>`; }
function fmt(n){ return (n||0).toLocaleString(); }

async function loadOverview(){
  const o = await get('/api/overview');
  const t = o.tokens;
  $('#cards').innerHTML =
    card('告警总量', fmt(o.total)) +
    card('自动忽略', fmt(o.auto_ignored), o.ignore_rate + '%') +
    card('保留人工', fmt(o.retained)) +
    card('确认成功', fmt(o.results['确认成功']||0)) +
    card('Token 合计', fmt(t.total), `入${fmt(t.input)} 出${fmt(t.output)} 推理${fmt(t.reasoning)}`);

  // token by source
  const rows = Object.entries(o.tokens_by_source).sort((a,b)=>(b[1].in+b[1].out)-(a[1].in+a[1].out));
  $('#tokTable').innerHTML = '<tr><th>来源</th><th>调用</th><th>输入</th><th>输出</th><th>推理</th></tr>' +
    rows.map(([k,v])=>`<tr><td class="src-${k}">${k}</td><td>${v.count}</td><td>${fmt(v.in)}</td><td>${fmt(v.out)}</td><td>${fmt(v.reason)}</td></tr>`).join('');

  // result doughnut
  const labels = Object.keys(o.results), data = Object.values(o.results);
  const colors = labels.map(l=> l==='确认成功'?'#ff6b6b': l==='需人工复核'?'#d29922': '#8b98a9');
  if(resultChart) resultChart.destroy();
  resultChart = new Chart($('#resultChart'), {type:'doughnut',
    data:{labels, datasets:[{data, backgroundColor:colors, borderColor:'#1a2230'}]},
    options:{plugins:{legend:{position:'right', labels:{color:'#e6edf3'}}}}});
}

async function loadTrend(){
  const t = await get('/api/trend');
  if(trendChart) trendChart.destroy();
  trendChart = new Chart($('#trendChart'), {
    data:{labels:t.days, datasets:[
      {type:'bar', label:'告警量', data:t.total, backgroundColor:'#58a6ff', yAxisID:'y'},
      {type:'line', label:'Token', data:t.tokens, borderColor:'#d29922', backgroundColor:'#d29922', yAxisID:'y1', tension:.3}
    ]},
    options:{scales:{
      y:{position:'left', ticks:{color:'#8b98a9'}, grid:{color:'#2a3547'}},
      y1:{position:'right', ticks:{color:'#8b98a9'}, grid:{display:false}},
      x:{ticks:{color:'#8b98a9'}, grid:{display:false}}},
      plugins:{legend:{labels:{color:'#e6edf3'}}}}});
}

async function loadHealth(){
  const h = await get('/api/health');
  const errTypes = Object.entries(h.errors_by_type).map(([k,v])=>`${k} ${v}`).join(', ') || '无';
  $('#healthBox').innerHTML = `
    <table>
      <tr><td class="muted">源包命中率</td><td>${h.evidence_hit_rate}% <span class="muted">(${h.evidence_hit}/${h.total})</span></td></tr>
      <tr><td class="muted">Agent 研判</td><td>${h.agent_count}</td></tr>
      <tr><td class="muted">处置忽略累计</td><td>${fmt(h.dispose_ignored)}</td></tr>
      <tr><td class="muted">处置失败</td><td class="${h.dispose_failed?'err':''}">${h.dispose_failed}</td></tr>
      <tr><td class="muted">LLM错误/降级</td><td class="${h.errors_total?'err':''}">${h.errors_total} <span class="muted">${errTypes}</span></td></tr>
    </table>
    ${h.recent_errors.length?'<div class="muted" style="margin-top:8px">最近错误:</div>':''}
    ${h.recent_errors.slice(0,6).map(e=>`<div class="muted" style="font-size:11.5px">${e.time} · ${e.provider} · ${e.type}</div>`).join('')}`;
}

async function loadAlerts(){
  const a = await get('/api/alerts', {level:$('#fLevel').value, result:$('#fResult').value, source:$('#fSource').value});
  const head = '<tr><th>时间</th><th>等级</th><th>事件</th><th>攻击IP</th><th>研判</th><th>来源</th><th>证据</th><th>理由</th><th>Tok</th></tr>';
  $('#alertTable').innerHTML = head + a.map((r,i)=>`
    <tr class="alert" onclick="toggle(${i})">
      <td class="muted">${(r['告警时间']||'').slice(5,16)}</td>
      <td><span class="tag lv-${r['告警等级']}">${r['告警等级']||''}</span></td>
      <td>${esc(r['事件名称'])}</td>
      <td class="muted">${esc((r['攻击IP']||'').slice(0,30))}</td>
      <td class="r-${r['模型研判']}">${r['模型研判']||''}</td>
      <td class="src-${r['研判来源']}">${r['研判来源']||''}</td>
      <td class="muted">${r['证据来源']||''}</td>
      <td class="muted">${esc(r['研判理由'])}</td>
      <td class="muted">${r['Token']||0}</td>
    </tr>
    <tr><td colspan="9" style="padding:0"><div class="detail" id="d${i}">${detail(r)}</div></td></tr>
  `).join('');
}

function detail(r){
  let s = '';
  if(r['工具轨迹']) s += '工具轨迹: ' + esc(r['工具轨迹']) + '\n';
  if(r['关键证据']) s += '关键证据: ' + esc(r['关键证据']) + '\n';
  if(r['目标IP']) s += '目标IP: ' + esc(r['目标IP']) + '\n';
  if(r['模型置信度']) s += '置信度: ' + esc(r['模型置信度']) + '\n';
  if(r['源包证据']) s += '源包证据: ' + esc(String(r['源包证据']).slice(0,1500));
  return s || '(无附加证据)';
}
function toggle(i){ const d=$('#d'+i); d.style.display = d.style.display==='block'?'none':'block'; }
function esc(s){ return String(s==null?'':s).replace(/[&<>]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

let currentView = 'overview';
function switchView(v){
  currentView = v;
  $('#view-overview').style.display = v==='overview'?'':'none';
  $('#view-attackers').style.display = v==='attackers'?'':'none';
  $('#tab-overview').classList.toggle('active', v==='overview');
  $('#tab-attackers').classList.toggle('active', v==='attackers');
  if(v==='attackers') loadAttackers();
}

async function loadAttackers(){
  const list = await get('/api/profiles');
  const bands = {高危:0, 关注:0, 一般:0};
  list.forEach(p => bands[p.band] = (bands[p.band]||0)+1);
  $('#attackerCards').innerHTML =
    card('画像总数', list.length) +
    card('高危攻击者', bands['高危']||0) +
    card('关注', bands['关注']||0) +
    card('内网源', list.filter(p=>p.internal).length) +
    card('已得手', list.filter(p=>p.cloud_success>0).length);

  if(!list.length){
    $('#attackerList').innerHTML = '<div class="panel muted">暂无画像数据。运行 <code>python attacker_profile.py --days 2</code> 或等日报任务生成。</div>';
    return;
  }
  $('#attackerList').innerHTML = list.map(p=>{
    const seq = Object.entries(p.events||{}).sort((a,b)=>b[1]-a[1]).slice(0,8)
      .map(([k,v])=>`<span class="chip">${esc(k)} ×${v}</span>`).join('');
    const src = p.internal ? '内网源' : ('公网源 ' + esc(p.country||''));
    return `<div class="acard b-${p.band}">
      <div class="top">
        <div>
          <span class="ip">${esc(p.ip)}</span>
          <span class="muted"> · ${src} · ${esc(p.attacker_type||'未知')}</span>
        </div>
        <div class="score ${p.band}">${p.score}<span class="muted" style="font-size:12px"> / 100</span></div>
      </div>
      <div class="narr">${esc(p.narrative||'-')}</div>
      <div class="meta">
        <span>意图: ${esc(p.intent||'-')}</span>
        <span>阶段: <b>${esc(p.stage||'-')}</b></span>
        <span>杀伤链最深: ${esc(p.killchain_max||'-')}</span>
        <span>告警 ${p.alert_count} · 手法 ${p.technique_kinds} · 目标 ${p.target_count} · 跨度 ${p.span_hours}h</span>
        <span>高危 ${p.high} · 得手 ${p.cloud_success}</span>
      </div>
      <div class="seq">手法序列: ${seq}</div>
      ${p.recommendation?`<div class="rec">处置建议: ${esc(p.recommendation)}</div>`:''}
      <div class="muted" style="font-size:11px;margin-top:6px">活动 ${esc((p.first_seen||'').slice(5,16))} ~ ${esc((p.last_seen||'').slice(5,16))} · 画像于 ${esc(p.run_at||'')}</div>
    </div>`;
  }).join('');
}

function loadAll(){
  loadOverview(); loadTrend(); loadHealth(); loadAlerts();
  if(currentView==='attackers') loadAttackers();
  $('#updated').textContent = '更新于 ' + new Date().toLocaleTimeString();
}
loadAll();
setInterval(loadAll, 120000); // 2 分钟自动刷新
</script>
</body>
</html>"""


SCREEN_PAGE = r"""<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>云防火墙安全态势大屏</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/echarts@5.5.0/dist/echarts.min.js"></script>
<style>
  :root{--bg:#070b14;--panel:#0e1726;--line:#1b2942;--fg:#e8f0fb;--mut:#6b7d99;
        --hi:#ff5470;--ok:#28d49a;--warn:#ffb547;--acc:#3da9fc;--acc2:#9d7bff;}
  *{box-sizing:border-box;margin:0;padding:0;}
  body{background:radial-gradient(circle at 50% -20%,#10203a,#070b14 60%);color:var(--fg);
       font:14px/1.5 "Segoe UI","Microsoft YaHei",sans-serif;height:100vh;overflow:hidden;}
  .top{display:flex;align-items:center;justify-content:space-between;padding:14px 28px;
       border-bottom:1px solid var(--line);background:rgba(13,23,42,.6);}
  .top h1{font-size:22px;letter-spacing:2px;font-weight:700;}
  .top h1 .dot{color:var(--ok);font-size:13px;}
  .top .clock{font-size:18px;color:var(--acc);font-variant-numeric:tabular-nums;}
  .grid{display:grid;grid-template-columns:repeat(4,1fr);grid-auto-rows:minmax(0,1fr);
        gap:14px;padding:14px 20px;height:calc(100vh - 60px);}
  .kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;
       padding:16px 20px;display:flex;flex-direction:column;justify-content:center;}
  .kpi .label{color:var(--mut);font-size:13px;letter-spacing:1px;}
  .kpi .num{font-size:42px;font-weight:800;line-height:1.1;margin-top:6px;}
  .kpi .sub{color:var(--mut);font-size:12px;margin-top:4px;}
  .num.ok{color:var(--ok);} .num.hi{color:var(--hi);} .num.warn{color:var(--warn);} .num.acc{color:var(--acc);}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;
         display:flex;flex-direction:column;min-height:0;}
  .panel h2{font-size:13px;color:var(--mut);letter-spacing:1px;margin-bottom:10px;font-weight:600;flex:0 0 auto;}
  .panel .body{flex:1 1 auto;min-height:0;position:relative;overflow:auto;}
  .span2{grid-column:span 2;} .span4{grid-column:span 4;} .row2{grid-row:span 2;}
  table{width:100%;border-collapse:collapse;font-size:13px;}
  td,th{padding:5px 8px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap;
        overflow:hidden;text-overflow:ellipsis;max-width:280px;}
  th{color:var(--mut);font-weight:600;position:sticky;top:0;background:var(--panel);}
  .tag{padding:1px 8px;border-radius:10px;font-size:11px;}
  .t-高危{background:#3a1622;color:var(--hi);} .t-中危{background:#3a3016;color:var(--warn);}
  .r-确认成功{color:var(--hi);font-weight:700;} .r-需人工复核{color:var(--warn);}
  .pub{color:var(--hi);} .pri{color:var(--acc);}
  .bar{height:7px;border-radius:4px;background:linear-gradient(90deg,var(--acc),var(--acc2));}
  .blink{animation:bk 1.4s infinite;} @keyframes bk{50%{opacity:.4;}}
  .updated{color:var(--mut);font-size:12px;}
  .tabs{display:flex;gap:6px;}
  .stab{background:transparent;color:var(--mut);border:1px solid var(--line);border-radius:8px;
        padding:6px 16px;font-size:14px;cursor:pointer;}
  .stab.active{background:var(--acc);color:#06101f;border-color:var(--acc);font-weight:600;}
  .glegend{display:flex;align-items:center;gap:18px;font-size:13px;color:var(--mut);margin-bottom:8px;}
  .glegend i{display:inline-block;width:12px;height:12px;border-radius:50%;margin-right:5px;vertical-align:middle;}
  .gst{color:var(--fg);}
  .glegend select{background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:3px 6px;margin-left:4px;}
  .glegend label{display:inline-flex;align-items:center;gap:4px;}
</style>
</head>
<body>
<div class="top">
  <h1>🛡️ 云防火墙安全态势大屏 <span class="dot">● 实时</span></h1>
  <div class="tabs">
    <button id="tb1" class="stab active" onclick="showPage(1)">近期动态</button>
    <button id="tb2" class="stab" onclick="showPage(2)">攻击画像</button>
  </div>
  <div><span class="clock" id="clock"></span>　<span class="updated" id="upd"></span></div>
</div>
<div class="grid" id="page1">
  <div class="kpi"><div class="label">今日告警总量</div><div class="num acc" id="k_total">-</div><div class="sub" id="k_total_s"></div></div>
  <div class="kpi"><div class="label">自动处置</div><div class="num ok" id="k_auto">-</div><div class="sub" id="k_auto_s"></div></div>
  <div class="kpi"><div class="label">需人工复核</div><div class="num warn" id="k_manual">-</div><div class="sub">待处理</div></div>
  <div class="kpi"><div class="label">确认成功</div><div class="num hi" id="k_success">-</div><div class="sub">真实得手</div></div>

  <div class="panel span2 row2"><h2>📈 每日告警趋势</h2><div class="body"><canvas id="trend"></canvas></div></div>
  <div class="panel row2"><h2>🍩 研判结果分布</h2><div class="body"><canvas id="result"></canvas></div></div>
  <div class="panel row2"><h2>🩺 系统健康</h2><div class="body"><table id="health"></table></div></div>

  <div class="panel"><h2>🌍 攻击来源 TOP</h2><div class="body"><table id="attackers"></table></div></div>
  <div class="panel"><h2>🎯 被攻击资产 TOP</h2><div class="body"><table id="assets"></table></div></div>
  <div class="panel span2 row2"><h2>🔴 需重点关注(实时)</h2><div class="body"><table id="attention"></table></div></div>
  <div class="panel"><h2>🟡 研判来源</h2><div class="body"><table id="sources"></table></div></div>
  <div class="panel"><h2>🪙 Token 用量</h2><div class="body"><table id="tokens"></table></div></div>
</div>

<div id="page2" style="display:none;height:calc(100vh - 60px);padding:14px 20px;">
  <div class="glegend">
    <span><i style="background:#ff5470"></i>公网攻击者</span>
    <span><i style="background:#ffb547"></i>中转节点</span>
    <span><i style="background:#3da9fc"></i>内网资产</span>
    <label>资产
      <select id="gtarget" onchange="loadGraph()"><option value="">全部资产</option></select>
    </label>
    <label>危险
      <select id="gdanger" onchange="loadGraph()">
        <option value="2" selected>仅高危</option>
        <option value="1">高危+中危</option>
        <option value="0">全部</option>
      </select>
    </label>
    <label><input type="checkbox" id="gcollapse" checked onchange="loadGraph()">折叠零散扫描</label>
    <span class="gst" id="gstats"></span>
    <span style="margin-left:auto">点节点高亮其攻击关系</span>
  </div>
  <div id="graph" style="width:100%;height:calc(100% - 36px);"></div>
</div>
<script>
let trendC,resultC;
const $=s=>document.querySelector(s);
const esc=s=>String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const fmt=n=>(n||0).toLocaleString();
async function J(p){const r=await fetch(p+'?days=1');return r.json();}
async function J7(p){const r=await fetch(p+'?days=7');return r.json();}

function tick(){$('#clock').textContent=new Date().toLocaleString('zh-CN');}
setInterval(tick,1000);tick();

async function load(){
  const [ov,tr,he,atk,ast,att]=await Promise.all([
    J('/api/overview'),J7('/api/trend'),J('/api/health'),
    J('/api/attacker_rank'),J('/api/asset_rank'),J('/api/realtime')]);
  // KPI
  $('#k_total').textContent=fmt(ov.total);
  $('#k_total_s').textContent='忽略率 '+ov.ignore_rate+'%';
  $('#k_auto').textContent=fmt(ov.auto_ignored);
  $('#k_auto_s').textContent='保留 '+fmt(ov.retained);
  $('#k_manual').textContent=fmt(ov.results['需人工复核']||0);
  const sc=ov.results['确认成功']||0;
  $('#k_success').textContent=fmt(sc);
  $('#k_success').classList.toggle('blink',sc>0);

  // 趋势
  if(trendC)trendC.destroy();
  trendC=new Chart($('#trend'),{data:{labels:tr.days,datasets:[
    {type:'bar',label:'告警',data:tr.total,backgroundColor:'#3da9fc',borderRadius:4,yAxisID:'y'},
    {type:'line',label:'Token',data:tr.tokens,borderColor:'#ffb547',tension:.35,yAxisID:'y1',pointRadius:2}]},
    options:{maintainAspectRatio:false,plugins:{legend:{labels:{color:'#e8f0fb'}}},
    scales:{y:{ticks:{color:'#6b7d99'},grid:{color:'#1b2942'}},y1:{position:'right',ticks:{color:'#6b7d99'},grid:{display:false}},x:{ticks:{color:'#6b7d99'},grid:{display:false}}}}});

  // 研判分布
  const labels=Object.keys(ov.results),data=Object.values(ov.results);
  const colors=labels.map(l=>l==='确认成功'?'#ff5470':l==='需人工复核'?'#ffb547':l==='扫描探测'?'#6b7d99':'#3da9fc');
  if(resultC)resultC.destroy();
  resultC=new Chart($('#result'),{type:'doughnut',data:{labels,datasets:[{data,backgroundColor:colors,borderColor:'#0e1726',borderWidth:2}]},
    options:{maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:'#e8f0fb',boxWidth:12,font:{size:11}}}}}});

  // 健康
  $('#health').innerHTML=`
    <tr><td>源包命中率</td><td class="pri">${he.evidence_hit_rate}%</td></tr>
    <tr><td>降级率</td><td class="${he.degraded_rate>30?'pub':(he.degraded_rate>10?'warn':'')}">${he.degraded_rate}%　<span class="updated">(${he.degraded}/${he.total})</span></td></tr>
    <tr><td>处置忽略累计</td><td>${fmt(he.dispose_ignored)}</td></tr>
    <tr><td>处置失败</td><td class="${he.dispose_failed?'pub':''}">${he.dispose_failed}</td></tr>
    <tr><td>LLM错误/降级</td><td class="${he.errors_total?'warn':''}">${he.errors_total}</td></tr>
    <tr><td>Agent 研判</td><td>${he.agent_count}</td></tr>`;

  // 攻击来源
  $('#attackers').innerHTML='<tr><th>来源IP</th><th>手法</th><th>次数</th><th>高危</th></tr>'+
    atk.map(a=>`<tr><td class="${a.public?'pub':'pri'}">${esc(a.ip)}${a.public?' 🌐':' 🏠'}</td><td>${a.techniques}</td><td>${a.count}</td><td class="${a.high?'pub':''}">${a.high||''}</td></tr>`).join('');

  // 被攻击资产
  $('#assets').innerHTML='<tr><th>目标</th><th>被打</th><th>攻击者</th><th>高危</th></tr>'+
    ast.map(a=>`<tr><td>${esc(a.dst)}</td><td>${a.count}</td><td>${a.attackers}</td><td class="${a.high?'pub':''}">${a.high||''}</td></tr>`).join('');

  // 需重点关注
  $('#attention').innerHTML='<tr><th>时间</th><th>等级</th><th>事件</th><th>来源→目标</th><th>研判</th></tr>'+
    (att.length?att.map(a=>`<tr>
      <td>${esc((a.time||'').slice(5,16))}</td>
      <td><span class="tag t-${a.level}">${a.level||''}</span></td>
      <td>${esc(a.event)}</td>
      <td class="${a.public?'pub':'pri'}">${esc((a.src||'').slice(0,24))} → ${esc((a.dst||'').slice(0,20))}</td>
      <td class="r-${a.result}">${a.result||''}</td></tr>`).join('')
     :'<tr><td colspan="5" style="color:var(--ok);padding:20px">✅ 当前无需重点关注的告警</td></tr>');

  // 研判来源 + Token
  $('#sources').innerHTML=Object.entries(ov.sources).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${v}</td></tr>`).join('');
  const t=ov.tokens;
  $('#tokens').innerHTML=`<tr><td>输入</td><td>${fmt(t.input)}</td></tr><tr><td>输出</td><td>${fmt(t.output)}</td></tr><tr><td>推理</td><td>${fmt(t.reasoning)}</td></tr><tr><td>合计</td><td class="pri">${fmt(t.total)}</td></tr>`;

  $('#upd').textContent='更新 '+new Date().toLocaleTimeString();
}

// ===== 第2页:攻击拓扑图 =====
let gChart=null, gLoaded=false;
function showPage(p){
  document.getElementById('page1').style.display = p===1?'':'none';
  document.getElementById('page2').style.display = p===2?'':'none';
  document.getElementById('tb1').classList.toggle('active',p===1);
  document.getElementById('tb2').classList.toggle('active',p===2);
  if(p===2){ if(!gChart) gChart=echarts.init(document.getElementById('graph'),'dark'); loadGraph(); setTimeout(()=>gChart.resize(),50); }
}
let gTargetsLoaded=false;
async function loadGraph(){
  const days=$('#days')?$('#days').value:7;
  const md=$('#gdanger')?$('#gdanger').value:2;
  const cl=($('#gcollapse')&&$('#gcollapse').checked)?1:0;
  const tg=$('#gtarget')?$('#gtarget').value:'';
  const g=await (await fetch(`/api/attack_graph?days=${days}&min_danger=${md}&collapse=${cl}&target=${encodeURIComponent(tg)}`)).json();
  const st=g.stats||{};
  // 填充资产下拉(只首次/换天时填,保留当前选择)
  if(g.targets_list){
    const sel=$('#gtarget'), cur=sel.value;
    sel.innerHTML='<option value=\"\">全部资产</option>'+g.targets_list.map(t=>`<option value=\"${esc(t.ip)}\">${esc(t.name)} (${t.count})</option>`).join('');
    sel.value=cur;
  }
  $('#gstats').textContent=`攻击者 ${st.attackers} · 中转 ${st.pivots} · 资产 ${st.targets} · 边 ${st.edges}`+(st.folded_solo?` · 已折叠零散 ${st.folded_solo}`:'');
  const cats=[{name:'公网攻击者'},{name:'中转'},{name:'内网资产'}];
  const nodes=g.nodes.map(n=>({
    id:n.id, name:n.name, symbolSize:n.size,
    category:cats.findIndex(c=>c.name===n.category),
    itemStyle:{color:n.color},
    label:{show:n.show_label!==false}
  }));
  const links=g.links.map(l=>({
    source:l.source, target:l.target,
    lineStyle:{color:l.color, width:Math.min(1+l.value*0.4,6), opacity:l.danger>=2?0.9:0.5, curveness:0.15},
    tooltip:{formatter:`${l.source} → ${l.target}<br/>手法:${l.events}<br/>次数:${l.value}`}
  }));
  gChart.setOption({
    backgroundColor:'transparent',
    tooltip:{},
    legend:[{data:cats.map(c=>c.name),textStyle:{color:'#e8f0fb'},top:0}],
    series:[{
      type:'graph', layout:'force', roam:true, draggable:true,
      categories:cats,
      data:nodes, links:links,
      force:{repulsion:120, edgeLength:[40,140], gravity:0.08},
      emphasis:{focus:'adjacency', lineStyle:{width:5}},
      lineStyle:{color:'source',curveness:0.15},
      label:{position:'right',color:'#cfd8e6',fontSize:11},
      edgeSymbol:['none','arrow'], edgeSymbolSize:6,
      scaleLimit:{min:0.3,max:4}
    }]
  });
}
window.addEventListener('resize',()=>{ if(gChart) gChart.resize(); });

load();setInterval(()=>{load(); if(document.getElementById('page2').style.display!=='none') loadGraph();},30000);
</script>
</body>
</html>"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CFW 研判控制台 Web 服务")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    print(f"CFW 研判控制台: http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)
