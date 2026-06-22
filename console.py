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
    from flask import redirect
    return redirect("/soc/")


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


@app.route("/api/asset_cards")
def api_asset_cards():
    return jsonify(stats.asset_cards(
        _days(),
        only_notable=request.args.get("all", "0") != "1",
    ))


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


# ---- cfw-soc 大屏(Claude Design 版,静态文件在 screen/ 目录) ----
import os as _os
from flask import send_from_directory as _send

_SCREEN_DIR = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "screen")


@app.route("/soc")
def soc_redirect():
    from flask import redirect
    return redirect("/soc/")


@app.route("/soc/")
def soc_index():
    return _send(_SCREEN_DIR, "index.html")


@app.route("/soc/<path:filename>")
def soc_static(filename):
    return _send(_SCREEN_DIR, filename)


def _days():
    try:
        return max(1, min(60, int(request.args.get("days", 7))))
    except (TypeError, ValueError):
        return 7



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CFW 研判控制台 Web 服务")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    print(f"CFW 研判控制台: http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)
