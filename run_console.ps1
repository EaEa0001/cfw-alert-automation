$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:PYTHONIOENCODING = "utf-8"
$Port = if ($args.Count -ge 1) { $args[0] } else { 8787 }
Write-Host "CFW 研判控制台启动: http://127.0.0.1:$Port"
python (Join-Path $Root "console.py") --port $Port
