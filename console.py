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


@app.route("/api/alerts")
def api_alerts():
    return jsonify(stats.alerts(
        _days(),
        level=request.args.get("level") or None,
        result=request.args.get("result") or None,
        source=request.args.get("source") or None,
        limit=int(request.args.get("limit", 300)),
    ))


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
  <span id="updated" class="muted"></span>
</header>
<div class="wrap">
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

function loadAll(){
  loadOverview(); loadTrend(); loadHealth(); loadAlerts();
  $('#updated').textContent = '更新于 ' + new Date().toLocaleTimeString();
}
loadAll();
setInterval(loadAll, 120000); // 2 分钟自动刷新
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
