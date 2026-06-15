"""微信 claw bot (WeChat iLink) 推送 —— 专门推"需人工研判"的告警。

复用本机 weclaw 已登录的 iLink bot 凭证(~/.weclaw/accounts/*-im-bot.json),
通过 https://ilinkai.weixin.qq.com/ilink/bot/sendmessage 把需要人工处理的告警
推到你的微信。与企微通知并存,企微继续发汇总,这里只发需人工的高优先级条目。
"""
import glob
import json
import subprocess
from pathlib import Path

WECLAW_DIR = Path.home() / ".weclaw" / "accounts"
WECLAW_BIN = Path.home() / "go" / "bin" / "weclaw.exe"


def load_bot_account():
    """读取 weclaw 最近登录的 im-bot 账号凭证(按修改时间取最新,避免用到过期账号)。"""
    import os
    files = [f for f in glob.glob(str(WECLAW_DIR / "*-im-bot.json")) if not f.endswith(".sync.json")]
    if not files:
        raise RuntimeError(f"未找到 weclaw bot 账号: {WECLAW_DIR}")
    files.sort(key=os.path.getmtime, reverse=True)
    with open(files[0], "r", encoding="utf-8") as fh:
        return json.load(fh)


def send_text(text, to_user_id=None):
    """通过 weclaw 官方 CLI 发文本。session 由 weclaw 自己维护,过期会提示重登。

    用 CLI 而非裸调 iLink API:登录态由 weclaw 管理,更稳;接收人默认取
    bot 绑定的 owner(ilink_user_id)。
    """
    if not to_user_id:
        to_user_id = load_bot_account().get("ilink_user_id")
    if not to_user_id:
        return {"sent": False, "error": "未配置接收人 to_user_id"}
    try:
        proc = subprocess.run(
            [str(WECLAW_BIN), "send", "--to", str(to_user_id), "--text", text],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
    except Exception as exc:
        return {"sent": False, "error": str(exc)[:300]}
    out = (proc.stdout or "") + (proc.stderr or "")
    ok = proc.returncode == 0 and "session timeout" not in out.lower() and "error" not in out.lower()
    result = {"sent": bool(ok), "output": out.strip()[:300]}
    if "session timeout" in out.lower() or "login" in out.lower():
        result["hint"] = "weclaw 登录态过期,请运行: weclaw login 重新扫码"
    return result


def enabled(config):
    cfg = (config.get("weclaw") or {}) if config else {}
    return bool(cfg.get("enabled", True))


def push_manual_review(config, items, title="需人工研判告警"):
    """推送需人工研判的告警列表。items: [{告警时间,事件名称,攻击IP,目标IP,模型研判,研判理由,...}]"""
    if not enabled(config):
        return {"sent": False, "reason": "disabled"}
    if not items:
        return {"sent": False, "reason": "no_items"}
    cfg = (config.get("weclaw") or {})
    limit = int(cfg.get("max_items", 10))
    lines = [f"🔔 {title} ({len(items)} 条需处理)", ""]
    for it in items[:limit]:
        t = str(it.get("告警时间", ""))[5:16]
        lines.append(f"• [{it.get('告警等级','')}] {it.get('事件名称','')}")
        lines.append(f"  {it.get('攻击IP','')} → {it.get('目标IP','')}")
        lines.append(f"  研判: {it.get('模型研判','')} | {it.get('研判理由','')}")
        if it.get("关键证据"):
            lines.append(f"  证据: {str(it.get('关键证据'))[:80]}")
        lines.append(f"  时间: {t}")
        lines.append("")
    if len(items) > limit:
        lines.append(f"...另有 {len(items) - limit} 条,见控制台")
    to_user = cfg.get("to_user_id") or None  # 空串回退到 bot 绑定的 owner
    return send_text("\n".join(lines).strip(), to_user_id=to_user)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="微信 claw bot 推送测试")
    parser.add_argument("--text", default="[CFW告警] 微信推送通道连通测试 ✅")
    args = parser.parse_args()
    acct = load_bot_account()
    print("bot:", acct.get("ilink_bot_id"), "-> user:", str(acct.get("ilink_user_id"))[:16] + "...")
    print(json.dumps(send_text(args.text), ensure_ascii=False, indent=2))
