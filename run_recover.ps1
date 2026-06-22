$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogDir = Join-Path $Root "logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$LogFile = Join-Path $LogDir "recover.log"
$Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$env:PYTHONIOENCODING = "utf-8"
$RunId = [Guid]::NewGuid().ToString("N")
$StdoutFile = Join-Path $LogDir "recover-$RunId.stdout.tmp"
$StderrFile = Join-Path $LogDir "recover-$RunId.stderr.tmp"
$ExitCode = 1

try {
    $Process = Start-Process `
        -FilePath "python" `
        -ArgumentList @((Join-Path $Root "cfw_alert_center_triage.py"), "--recover") `
        -NoNewWindow `
        -Wait `
        -PassThru `
        -RedirectStandardOutput $StdoutFile `
        -RedirectStandardError $StderrFile
    $ExitCode = $Process.ExitCode
    $out = ""
    if (Test-Path -LiteralPath $StdoutFile) { $out = (Get-Content -LiteralPath $StdoutFile -Raw) }
    if (Test-Path -LiteralPath $StderrFile) { $out += (Get-Content -LiteralPath $StderrFile -Raw) }
    # 只在真正复判(非 empty/idle)时记一行日志,避免空队列时刷屏
    if ($out -notmatch '"status": "(empty|idle)"') {
        "[$Stamp] $($out.Trim())" | Out-File -FilePath $LogFile -Append -Encoding utf8
    }
}
catch {
    "[$Stamp] recover launcher error: $($_.Exception.Message)" | Out-File -FilePath $LogFile -Append -Encoding utf8
}
finally {
    Remove-Item -LiteralPath $StdoutFile, $StderrFile -Force -ErrorAction SilentlyContinue
}

exit $ExitCode
