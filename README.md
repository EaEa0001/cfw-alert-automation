# Tencent Cloud Firewall Alert Automation

腾讯云云防火墙告警采集、研判、自动忽略和企微通知工具。

## 工作流程

1. 每小时拉取上一小时全流量检测与响应日志。
2. 排除腾讯云暴露面扫描 IP 和公司漏扫 IP。
3. 对告警字段进行压缩后，调用 Codex Responses 接口批量研判。
4. 对需要复核的告警关联源包摘要，再进行一次成功性复核。
5. 自动忽略扫描探测、确认未成功和未见成功证据的告警。
6. 保留确认成功、证据不足和高危告警，并发送企微通知。
7. 每日生成告警汇总报告。

项目当前使用 `codex_direct`：读取本机 `~/.codex/auth.json` 的 Codex 登录鉴权，直接请求 Responses 接口并要求模型返回结构化 JSON。它不是 ReAct 工具调用循环，也没有通过 OpenAI SDK function call 驱动处置。腾讯云查询和处置由本地 Python 代码直接执行。

## 安装

```powershell
python -m pip install -r requirements.txt
Copy-Item config.example.json config.json
```

配置腾讯云 CLI 凭证，或设置：

```powershell
$env:TENCENTCLOUD_SECRET_ID = "..."
$env:TENCENTCLOUD_SECRET_KEY = "..."
```

使用 `codex_direct` 前，需要本机 Codex 已登录并存在 `~/.codex/auth.json`。

## 配置

编辑本地 `config.json`：

- `tencent_scan_ips`：腾讯云扫描 IP，排除处置。
- `company_scan_ips`：公司漏扫 IP，排除处置。
- `wecom.webhook_url`：企微机器人 webhook。
- `llm.model`：研判模型。
- `llm.auto_dispose.ignore_results`：允许自动忽略的研判结果。

真实 `config.json`、告警数据、日志和报告均被 `.gitignore` 排除。

## 使用

拉取并处理最近一小时：

```powershell
python .\cfw_alert_monitor.py collect --lookback-hours 1
```

仅采集，不执行研判和处置：

```powershell
python .\cfw_alert_monitor.py collect --lookback-hours 1 --skip-triage
```

研判告警中心最近两天未处理告警：

```powershell
python .\cfw_alert_center_triage.py --days 2
```

指定时间窗预览，不处置：

```powershell
python .\cfw_alert_center_triage.py `
  --start "2026-06-09 18:00:00" `
  --end "2026-06-09 23:59:59" `
  --dry-run
```

生成当日日报：

```powershell
python .\cfw_alert_monitor.py report --refresh
```

Windows 计划任务可分别调用：

- `run_collect.ps1`
- `run_daily_report.ps1`

## 安全边界

- 工具不会自动封禁攻击 IP。
- 白名单扫描源不会执行封禁。
- 只有配置允许的明确失败、扫描探测和未见成功证据告警会自动忽略。
- 确认成功、高危或证据不足告警会保留复核。
