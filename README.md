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
   - 第 3 层(高危/需人工复核,Agent 工具循环):对高危或仍需人工复核的告警,升级为 **Agent 工具循环研判** —— 给模型一组只读取证工具(`pull_packets`/`decode_hex`/`get_related_alerts`),模型自主决定取哪些证、取几轮,最后基于真实证据给出带 `工具轨迹` 的结论。复用 Codex 订阅鉴权(无需 API key)。工具只读取证,处置仍由本地规则执行。
4. 自动忽略模型判定为扫描探测、确认未成功和未见成功证据的告警。
5. 保留确认成功、证据不足和高危告警，并发送企微通知。
6. 每日生成告警汇总报告。

### Agent 工具循环说明

- 通过 `chatgpt.com/backend-api/codex/responses` 的原生 function calling 实现,鉴权复用 `~/.codex/auth.json`,不需要 OpenAI API key。
- 只对高危/需人工复核的告警触发(贵+慢),由 `llm.agent_triage` 配置控制开关、轮数、并发、单次上限。
- 最后一轮强制 `tool_choice=none`,确保模型必须给出结论而非无限取证。
- 安全闸:Agent 判“确认成功”但该告警无落地源包证据时,降回“未见成功证据”。Agent 失败时保留原研判,不影响主流程。

### 调用重试

所有 Codex 调用(单轮/源包复核/Agent)在连接类错误(超时、连接被拒、流中断)上自动指数退避重试,降低 `WinError 10060/10061` 导致的降级。`HTTPError` 等业务错误不重试。重试事件记入 `logs/llm-errors.jsonl`,控制台健康面板可见。由 `llm.retry`(`max_retries`/`backoff_seconds`/`backoff_factor`)配置。

### 源包抓取说明

- HTTP 是唯一能稳定拿到应用层 payload 的协议:`netflow_nta` 按 `app_protocol=HTTP` 过滤(而非 `event_type`,后者会把部分本质 HTTP 的流标成 TCP),可解码请求头/响应头/响应体。
- `netflow_nta` 的 `DescribeLogs` 仅对整点对齐的时间窗返回数据,带分秒边界会返回空;抓取时已将查询窗口下/上取整到整点。
- TLS 为密文、UNKNOWN 无结构、纯 TCP/UDP 无 payload,均无法拉到内容,这类回退到聚合字段研判(证据不足时保留人工)。

项目使用 `codex_direct`：读取本机 `~/.codex/auth.json` 的 Codex 登录鉴权，直接请求 Responses 接口。普通告警走单轮结构化 JSON 研判；高危/需人工复核的告警额外走 Agent 工具调用循环(同样复用 Codex 订阅,经 Responses 原生 function calling)。模型只做研判与只读取证，腾讯云查询和忽略/加白处置由本地 Python 代码按固定规则执行，模型不直接操作云资源。

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

## 攻击者画像

把逐条告警升级到"按攻击者维度"研判:将一段时间窗内告警中心的全部告警按攻击源 IP 聚合(攻击序列、手法多样性、杀伤链阶段、目标数、是否得手),再喂模型给出攻击者类型、意图、**攻击叙事**(一句话讲清这个 IP 先做了什么再做了什么、有没有得手)、当前杀伤链阶段、画像威胁评分和处置建议。高危画像自动推企微卡片。

```powershell
python .\attacker_profile.py --days 2            # 跑画像,高危推企微
python .\attacker_profile.py --days 2 --dry-run  # 只算不推
python .\attacker_profile.py --days 2 --top 10   # 只画像 top N 活跃攻击者
```

日报任务 `run_daily_report.ps1` 已自动包含画像环节。只对值得的攻击者(多手法/高危/内网横向/高频次)做模型画像以控成本;综合模型分与规则分取较高,避免任一侧漏判。

## 通知渠道

全部走企微机器人(`wecom` 配置):

- **小时/日报汇总**:`hourly_enabled` / `daily_enabled`。
- **需人工研判推送**:研判结果为"需人工复核"或"确认成功"的,单独推一张企微卡片,并发一条 `@所有人` 的 text 提醒(企微 markdown 不支持 @,故补一条 text)。误报不推。

`config.json` 的 `wecom` 相关键:

- `webhook_url`:企微机器人 webhook(汇总和需人工默认共用)。
- `manual_enabled`:是否推需人工研判(默认开)。
- `manual_at_all`:需人工时是否 @所有人(默认开)。
- `manual_max_items`:单条卡片最多列几条(默认 10)。
- `manual_webhook_url`:需人工研判专用 webhook,留空则用 `webhook_url`(想推到独立告警群就配这个)。

## 控制台

本地 Web 看板，看告警量、研判分布、token 消耗(按研判来源拆分)、源包命中率、降级/处置健康，并可下钻每条告警的证据链和工具轨迹。数据读 `data/` 与 `reports/`，无数据库，默认只绑定本机回环。

```powershell
python -m pip install flask
python .\console.py            # 打开 http://127.0.0.1:8787
# 或
.\run_console.ps1 8787
```

命令行快速汇总(无需浏览器)：

```powershell
python .\triage_stats.py --days 7          # 文字报表
python .\triage_stats.py --days 7 --json   # 完整 JSON
```

## 安全边界

- 工具不会自动封禁攻击 IP。
- 白名单扫描源不会执行封禁。
- 只有配置允许的明确失败、扫描探测和未见成功证据告警会自动忽略。
- 确认成功、高危或证据不足告警会保留复核。
