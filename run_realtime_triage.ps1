$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogDir = Join-Path $Root "logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$LogFile = Join-Path $LogDir "realtime-triage.log"
$Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
"[$Stamp] realtime triage poller start" | Out-File -FilePath $LogFile -Append -Encoding utf8
$env:PYTHONIOENCODING = "utf-8"

python (Join-Path $Root "cfw_alert_center_triage.py") --poll 2>&1 | Out-File -FilePath $LogFile -Append -Encoding utf8
$ExitCode = $LASTEXITCODE

$Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
"[$Stamp] realtime triage poller exit=$ExitCode" | Out-File -FilePath $LogFile -Append -Encoding utf8
exit $ExitCode
