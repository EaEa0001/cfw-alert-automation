$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogDir = Join-Path $Root "logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$LogFile = Join-Path $LogDir "collect.log"
$Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
"[$Stamp] collect start" | Out-File -FilePath $LogFile -Append -Encoding utf8
$env:PYTHONIOENCODING = "utf-8"
$RunId = [Guid]::NewGuid().ToString("N")
$StdoutFile = Join-Path $LogDir "collect-$RunId.stdout.tmp"
$StderrFile = Join-Path $LogDir "collect-$RunId.stderr.tmp"
$ExitCode = 1

try {
    $Process = Start-Process `
        -FilePath "python" `
        -ArgumentList @((Join-Path $Root "cfw_alert_monitor.py"), "collect", "--lookback-hours", "1", "--skip-triage") `
        -NoNewWindow `
        -Wait `
        -PassThru `
        -RedirectStandardOutput $StdoutFile `
        -RedirectStandardError $StderrFile
    $ExitCode = $Process.ExitCode
    if (Test-Path -LiteralPath $StdoutFile) {
        Get-Content -LiteralPath $StdoutFile | Out-File -FilePath $LogFile -Append -Encoding utf8
    }
    if (Test-Path -LiteralPath $StderrFile) {
        Get-Content -LiteralPath $StderrFile | Out-File -FilePath $LogFile -Append -Encoding utf8
    }
}
catch {
    "collect launcher error: $($_.Exception.Message)" | Out-File -FilePath $LogFile -Append -Encoding utf8
}
finally {
    Remove-Item -LiteralPath $StdoutFile, $StderrFile -Force -ErrorAction SilentlyContinue
    $Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$Stamp] collect exit=$ExitCode" | Out-File -FilePath $LogFile -Append -Encoding utf8
}

exit $ExitCode
