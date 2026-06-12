# Tencent Cloud Firewall Alert Automation

腾讯云云防火墙告警采集、研判、自动忽略和企微通知工具。

项目运行、架构和问题清单见 [项目报告](docs/reports/project-status-2026-06-12.md)。

## 工作流程

1. 每小时拉取上一小时全流量检测与响应日志。
2. 排除腾讯云暴露面扫描 IP 和公司漏扫 IP。
3. 三层漏斗研判:
   - 第 0 层(确定性):白名单扫描源、云端确认成功、高危,直接定性,不耗 token。
   - 第 1 层(明显失败,规则过筛):源包完整且响应全为 4xx 失败码、或纯扫描器特征且云端判失败,直接忽略。**5xx 不再算安全失败**(可能是 RCE/注入打崩服务),`attack_result=2/3` 也不再单独构成忽略理由。
   - 第 2 层(不明显,深度研判):其余告警一律 **主动拉取源数据包** —— 公网攻击查 `rule_threatinfo`,内网横向(10.x/172.x)查 `netflow_nta` 全流量并解码 HTTP 请求/响应体。**拉到 HTTP 源包后,模型必须基于真实包给出有依据的初步结论**(确认成功/未成功/未见成功证据等 + `关键证据` 原文),不再只贴标签。高危批次自动升 high 推理强度。只要抓到源包就走源包深度复核,不因首轮浅标签而跳过。
4. 自动忽略模型判定为扫描探测、确认未成功和未见成功证据的告警。
5. 保留确认成功、证据不足和高危告警，并发送企微通知。
6. 每日生成告警汇总报告。

### 源包抓取说明

- HTTP 是唯一能稳定拿到应用层 payload 的协议:`netflow_nta` 按 `app_protocol=HTTP` 过滤(而非 `event_type`,后者会把部分本质 HTTP 的流标成 TCP),可解码请求头/响应头/响应体。
- `netflow_nta` 的 `DescribeLogs` 仅对整点对齐的时间窗返回数据,带分秒边界会返回空;抓取时已将查询窗口下/上取整到整点。
- TLS 为密文、UNKNOWN 无结构、纯 TCP/UDP 无 payload,均无法拉到内容,这类回退到聚合字段研判(证据不足时保留人工)。

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
