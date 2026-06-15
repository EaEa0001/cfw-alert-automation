$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogDir = Join-Path $Root "logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$LogFile = Join-Path $LogDir "daily-report.log"
$Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
"[$Stamp] daily report start" | Out-File -FilePath $LogFile -Append -Encoding utf8
$env:PYTHONIOENCODING = "utf-8"
# 日报回看 7 天:小时任务管最近 24h 增量,日报兜底清更早的积压,避免老告警长期未处理
python (Join-Path $Root "cfw_alert_center_triage.py") --days 7 2>&1 | Out-File -FilePath $LogFile -Append -Encoding utf8
if ($LASTEXITCODE -ne 0) {
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] alert center backlog triage exit=$LASTEXITCODE" | Out-File -FilePath $LogFile -Append -Encoding utf8
}
python (Join-Path $Root "attacker_profile.py") --days 2 2>&1 | Out-File -FilePath $LogFile -Append -Encoding utf8
if ($LASTEXITCODE -ne 0) {
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] attacker profile exit=$LASTEXITCODE" | Out-File -FilePath $LogFile -Append -Encoding utf8
}
python (Join-Path $Root "cfw_alert_monitor.py") report --refresh 2>&1 | Out-File -FilePath $LogFile -Append -Encoding utf8
$ExitCode = $LASTEXITCODE
$Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
"[$Stamp] daily report exit=$ExitCode" | Out-File -FilePath $LogFile -Append -Encoding utf8
exit $ExitCode
