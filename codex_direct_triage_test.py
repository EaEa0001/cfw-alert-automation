import argparse
import json
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORT_DIR = BASE_DIR / "reports"
CONFIG_PATH = BASE_DIR / "config.json"
AUTH_PATH = Path.home() / ".codex" / "auth.json"
CODEX_RESPONSES_URL = "https://chatgpt.com/backend-api/codex/responses"


def load_json(path):
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_codex_auth():
    auth = load_json(AUTH_PATH)
    tokens = auth.get("tokens") or {}
    access_token = tokens.get("access_token")
    account_id = tokens.get("account_id")
    if not access_token:
        raise RuntimeError(f"missing access_token in {AUTH_PATH}")
    if not account_id:
        raise RuntimeError(f"missing account_id in {AUTH_PATH}")
    return access_token, account_id


def whitelist_ips(config):
    return set(config.get("tencent_scan_ips") or []) | set(config.get("company_scan_ips") or [])


def load_events(day, limit, config):
    path = DATA_DIR / f"events-{day}.jsonl"
    if not path.exists():
        raise RuntimeError(f"events file not found: {path}")
    whitelist = whitelist_ips(config)
    rows = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            event = json.loads(line)
            ip = event.get("attack_ip") or ""
            if not ip or ip in whitelist:
                continue
            rows.append(compact_event(len(rows) + 1, event))
            if len(rows) >= limit:
                break
    return rows


def compact_event(index, event):
    target = event.get("asset_name") or event.get("target_ip") or ""
    port = event.get("target_port") or ""
    desc = (event.get("threat_desc") or "").strip()
    suggestion = (event.get("threat_suggestion") or "").strip()
    row = {
        "id": index,
        "t": event.get("event_time", ""),
        "ip": event.get("attack_ip", ""),
        "src": event.get("source_ip", ""),
        "dst": event.get("target_ip", ""),
        "port": port,
        "asset": target,
        "lv": event.get("level", ""),
        "ev": event.get("event_name", ""),
        "typ": event.get("threat_type", ""),
        "dir": event.get("direction", ""),
        "country": event.get("source_country", ""),
        "rule": event.get("rule_id", ""),
        "strategy": event.get("strategy", ""),
    }
    if desc:
        row["desc"] = desc[:160]
    if suggestion:
        row["suggest"] = suggestion[:120]
    return row


def build_prompt(rows):
    return (
        "你是云防火墙告警复核助手。逐条判断是否有攻击成功证据。"
        "结果只能取: 确认成功,确认未成功,未见成功证据,扫描探测,需人工复核。"
        "没有明确成功证据时不要判确认成功。"
        "只输出JSON数组，每项字段:id,result,confidence,evidence,next。"
        "confidence取high/medium/low，evidence和next不超过18个汉字。"
        "告警="
        + json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
    )


def build_request(model, prompt):
    return {
        "model": model,
        "instructions": "你是安全告警复核助手。只输出符合用户要求的紧凑JSON，不输出解释。",
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": prompt}],
            }
        ],
        "tools": [],
        "tool_choice": "none",
        "parallel_tool_calls": False,
        "reasoning": {"effort": "low"},
        "store": False,
        "stream": True,
        "include": [],
        "text": {"verbosity": "low"},
    }


def parse_usage(usage):
    usage = usage or {}
    output_details = usage.get("output_tokens_details") or {}
    input_details = usage.get("input_tokens_details") or {}
    return {
        "input_tokens": usage.get("input_tokens"),
        "cached_input_tokens": input_details.get("cached_tokens"),
        "output_tokens": usage.get("output_tokens"),
        "reasoning_output_tokens": output_details.get("reasoning_tokens"),
        "total_tokens": usage.get("total_tokens"),
        "raw": usage,
    }


def post_sse(model, prompt, timeout):
    access_token, account_id = load_codex_auth()
    body = json.dumps(build_request(model, prompt), ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        CODEX_RESPONSES_URL,
        data=body,
        method="POST",
        headers={
            "Accept": "text/event-stream",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
            "ChatGPT-Account-ID": account_id,
            "OAI-Product-Sku": "codex",
        },
    )

    output = []
    usage = None
    response_id = None
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            event_name = None
            data_lines = []
            for raw_line in resp:
                line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                if not line:
                    if data_lines:
                        event_type, event_usage, event_response_id, event_text = handle_sse_event(
                            event_name, "\n".join(data_lines)
                        )
                        if event_text:
                            output.append(event_text)
                        if event_usage is not None:
                            usage = event_usage
                        if event_response_id:
                            response_id = event_response_id
                        if event_type == "response.completed":
                            break
                    event_name = None
                    data_lines = []
                    continue
                if line.startswith("event:"):
                    event_name = line.split(":", 1)[1].strip()
                elif line.startswith("data:"):
                    data_lines.append(line.split(":", 1)[1].lstrip())
    except urllib.error.HTTPError as err:
        body_text = err.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {err.code}: {body_text[:800]}") from err

    return {
        "response_id": response_id,
        "elapsed_seconds": round(time.perf_counter() - start, 3),
        "usage": parse_usage(usage),
        "output_text": "".join(output).strip(),
    }


def handle_sse_event(event_name, data):
    if data == "[DONE]":
        return event_name, None, None, ""
    item = json.loads(data)
    event_type = item.get("type") or event_name
    if event_type == "response.output_text.delta":
        return event_type, None, None, item.get("delta", "")
    if event_type == "response.completed":
        resp = item.get("response") or {}
        fallback_text = extract_output_text(resp)
        return event_type, resp.get("usage"), resp.get("id"), fallback_text
    if event_type in {"response.failed", "response.incomplete"}:
        resp = item.get("response") or {}
        err = resp.get("error") or item.get("error") or {}
        raise RuntimeError(f"{event_type}: {json.dumps(err, ensure_ascii=False)[:800]}")
    return event_type, None, None, ""


def extract_output_text(response):
    parts = []
    for item in response.get("output") or []:
        if item.get("type") != "message":
            continue
        for content in item.get("content") or []:
            if content.get("type") == "output_text" and content.get("text"):
                parts.append(content["text"])
    return "".join(parts)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--date", default=datetime.now().strftime("%Y-%m-%d"))
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--model", default="gpt-5.5")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()

    REPORT_DIR.mkdir(exist_ok=True)
    config = load_json(CONFIG_PATH)
    if args.smoke:
        rows = [{"id": 1, "t": args.date, "ip": "1.2.3.4", "lv": "低危", "ev": "端口扫描"}]
    else:
        rows = load_events(args.date, args.limit, config)
    prompt = build_prompt(rows)
    result = post_sse(args.model, prompt, args.timeout)
    result.update(
        {
            "mode": "codex_direct_responses",
            "date": args.date,
            "alert_count": len(rows),
            "model": args.model,
            "prompt_chars": len(prompt),
            "request_url": CODEX_RESPONSES_URL,
        }
    )
    out_path = REPORT_DIR / f"codex-direct-test-{args.date}-{args.limit}.json"
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "output_text"}, ensure_ascii=False, indent=2))
    print("output_preview=", result["output_text"][:500])
    print("result_file=", out_path)


if __name__ == "__main__":
    main()
