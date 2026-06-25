# 云火哨兵 · CFW SOC Agent

面向腾讯云防火墙的本地 SOC Agent。项目从“告警采集脚本”升级为“实时轮询、证据增强研判、人工研判台、自定义规则和多模型路由”的安全运营工具。

## 当前能力

- 实时轮询腾讯云告警中心未处理事件，默认每 60 秒回看最近 10 分钟。
- 对新 `EventId` 立即研判，自动忽略确认无害项，把需要人工确认的告警推送到企业微信。
- 保留每天 17:50 日报，小时报默认关闭。
- 支持攻击者画像、告警研判台、研判流水线、自定义规则、Agent 配置、日报周报等本地 SOC 页面。
- 支持 Codex 订阅、Codex/OpenAI API、Claude API、Claude Code、本地 CLI、DeepSeek、GLM 等模型路由。
- 支持自然语言生成自定义规则，例如“事件编号 xxx 是正常业务，以后同源同目标同规则不研判”。
- 支持自然语言封禁草案；真正调用腾讯云黑名单接口需要二次确认。

## 研判流程

```text
腾讯云告警中心
→ 实时轮询新告警
→ 默认白名单 / 自定义规则
→ 主动拉取源包和流量证据
→ LLM 批量初判
→ 源包二次复核
→ 高危 / 需人工复核进入 Agent 工具循环
→ PolicyGuard 策略闸
→ 自动忽略 / 人工研判推送 / 日报归档
```

### 本地规则层

本地规则先定边界，避免把安全动作完全交给模型：

- 腾讯云扫描源、公司扫描源命中后判定为扫描探测。
- 自定义规则可跳过模型、忽略单次、扫描源加白或标记人工复核。
- 腾讯云标记攻击成功的告警永不自动忽略。
- 高危告警默认保留，只有明确无害且有证据时才可能自动忽略。
- 只有源包完整关联且响应为安全失败码时才直接忽略。
- `5xx` 不作为安全失败，因为利用尝试可能打崩服务。

### 证据增强

模型研判前会尽量补真实证据：

- 公网攻击优先查询 `rule_threatinfo`。
- 内网横向和内网业务误报 fallback 查询 `netflow_nta`。
- 能解析 HTTP 时提取 `req`、`resp`、`resp_body`、`cmd`、`req_mark`、`resp_mark`。
- TLS、UNKNOWN、纯 TCP/UDP 没有应用层 payload 时，回退到聚合字段和人工研判。

### Agent 工具循环

高危或仍需人工复核的告警会进入 Agent 工具循环。Agent 只能读取证据，不能直接处置云资源。

可用工具：

- `pull_packets`：拉取源包证据。
- `query_flow`：查询 NTA 流量上下文。
- `identify_asset`：识别源/目标资产。
- `check_ip_history`：查询源 IP 历史告警。
- `get_related_alerts`：查询相关告警。
- `decode_hex`：解码 payload。

### PolicyGuard

所有自动处置都经过本地策略闸：

- `确认成功` 永不忽略。
- 云端 `AttackResult=1` 永不忽略。
- 有命令回显、webshell、敏感数据返回、文件落地等成功证据时永不忽略。
- 高危告警低置信度不自动忽略。
- 扫描源加白必须来自可信规则，高危扫描源不自动加白。

## Agent 化模块

`agent/` 是后续主线改造边界：

- `agent.schemas`：告警、证据、研判结论、处置计划、策略结果的数据结构。
- `agent.policy`：本地 `PolicyGuard`，模型/Agent 只能建议，写操作必须过闸。
- `agent.rules`：自定义规则、自然语言规则草案、规则匹配。
- `agent.triage_flow`：规则、证据、模型、Agent、策略闸的流水线骨架。
- `agent.triage_service`：单条告警 dry-run 预览，供控制台验证。
- `agent.llm`：Codex、Claude、DeepSeek、GLM、OpenAI-compatible provider 路由。

## 多模型路由

`llm.routing` 可按阶段选择模型：

- `batch_triage`：普通告警批量初判，适合 DeepSeek/GLM 快模型。
- `source_review`：源包复核，适合强推理模型。
- `agent_triage`：高危/疑难告警工具循环，适合 Codex/Claude。
- `rule_parse`：自然语言规则解析。

支持 provider 类型：

- `codex_direct`：复用本机 Codex/ChatGPT 订阅登录态。
- `openai_compatible`：OpenAI API、DeepSeek、GLM 等兼容 Chat Completions 的 API。
- `anthropic`：Claude API。
- `claude_cli` / `local_cli`：Claude Code 或其他本地订阅 CLI。

## 安装

```powershell
python -m pip install -r requirements.txt
Copy-Item config.example.json config.json
```

配置腾讯云 CLI 凭证，或设置环境变量：

```powershell
$env:TENCENTCLOUD_SECRET_ID = "..."
$env:TENCENTCLOUD_SECRET_KEY = "..."
```

使用 `codex_direct` 前，需要本机 Codex 已登录并存在 `~/.codex/auth.json`。

真实 `config.json`、`.private-tccli/`、告警数据、日志和报告均被 `.gitignore` 排除。

## 常用命令

启动实时轮询：

```powershell
.\run_realtime_triage.ps1
```

手动跑一轮，不执行云端写操作：

```powershell
python .\cfw_alert_center_triage.py --realtime-once --dry-run
```

每小时只采集，不研判、不处置、不发小时报：

```powershell
python .\cfw_alert_monitor.py collect --lookback-hours 1 --skip-triage
```

生成当日日报：

```powershell
python .\cfw_alert_monitor.py report --refresh
```

启动本地 SOC 控制台：

```powershell
python .\console.py
```

访问：

- `http://127.0.0.1:8787/soc/`：SOC 控制台。
- `http://127.0.0.1:8787/screen`：安全态势大屏。

## 页面

- 态势总览：告警量、研判分布、自动处置、系统健康。
- 告警研判台：告警明细、源包证据、工具轨迹、人工研判。
- 攻击者画像：按攻击源聚合，展示攻击阶段、评分和建议。
- 研判流水线：轮询、研判、策略闸、通知链路。
- 自定义规则：规则库、传统黑白名单、自然语言规则、默认白名单。
- Agent 配置：模型路由、provider 健康、API/订阅配置。
- 日报周报：安全运营摘要和防火墙能力规划。

## 企业微信通知

全部走 `wecom` 配置：

- `manual_enabled`：是否推送需人工研判告警。
- `manual_at_all`：人工研判时是否 `@所有人`。
- `manual_webhook_url`：人工研判专用 webhook；为空则使用 `webhook_url`。
- `daily_enabled`：是否保留日报推送。
- `hourly_enabled`：小时报开关，当前默认关闭。

## 自定义规则

自然语言规则会先生成草案，保存/生效后才进入实时研判流程。

例子：

```text
事件编号 123456 是正常业务，以后同源同目标同规则不研判。
```

```text
把下面 txt 里的 IP 加入黑名单：1.2.3.4 5.6.7.8
```

规则命中后仍会经过 `PolicyGuard`，不能覆盖“云端成功”“确认成功”“高危证据不足”等硬保留条件。

## 攻击者画像

```powershell
python .\attacker_profile.py --days 2
python .\attacker_profile.py --days 2 --dry-run
python .\attacker_profile.py --days 2 --top 10
```

画像按攻击源 IP 聚合告警，输出攻击阶段、手法序列、目标范围、是否得手、画像评分和处置建议。当前阶段标签为：

```text
探测 → 尝试利用 → 成功利用 → 落地驻留 → 控制回连 → 横向扩散 → 外传/破坏
```

## Windows 计划任务

建议拆成三类任务：

- `run_realtime_triage.ps1`：常驻实时轮询，发现新告警立即研判。
- `run_collect.ps1`：每小时采集流量日志，不发小时报。
- `run_daily_report.ps1`：每天 17:50 生成日报并推送。

## 安全边界

- 模型和 Agent 不直接操作腾讯云资源。
- 自动忽略、扫描源加白、黑名单封禁都由本地 Python 代码执行。
- 封禁类动作必须显式确认，不在实时轮询里自动执行。
- 所有自动忽略必须经过 `PolicyGuard`。
- 所有真实凭证、运行数据、报告和日志都不进入 Git。
