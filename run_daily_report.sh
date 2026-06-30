#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p logs

REPORT_DATE="${1:-$(date +%F)}"
REPORT_TIME="${CFW_DAILY_REPORT_TIME:-17:50:00}"
END="${REPORT_DATE} ${REPORT_TIME}"
END_EPOCH="$(date -d "${END}" +%s)"
START="$(date -d "@$((END_EPOCH - 86400))" '+%F %T')"

DAILY_ARGS=()
if [[ "${CFW_DAILY_NO_SEND:-0}" == "1" ]]; then
  DAILY_ARGS+=(--no-send)
fi

{
  echo "[$(date '+%F %T')] daily report start window=${START} ~ ${END}"
  .venv/bin/python cfw_alert_center_triage.py --start "${START}" --end "${END}"
  .venv/bin/python attacker_profile.py --days 2
  .venv/bin/python cfw_daily_report.py --date "${REPORT_DATE}" --start "${START}" --end "${END}" "${DAILY_ARGS[@]}"
  echo "[$(date '+%F %T')] daily report done"
} >> logs/daily-report.log 2>&1
