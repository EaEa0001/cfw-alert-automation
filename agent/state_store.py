"""Optional PostgreSQL state ledger for CFW alert processing.

The alert/log source of truth remains Tencent Cloud.  This module stores the
local processing state, triage summaries, and disposal receipts so polling and
backfill jobs can be audited without turning the local database into a log lake.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from typing import Any, Iterable


def enabled(config: dict[str, Any] | None) -> bool:
    cfg = _state_db_config(config)
    return bool(cfg.get("enabled")) and bool(_dsn(cfg))


def record_raw_alerts(config: dict[str, Any] | None, records: Iterable[dict[str, Any]], source: str) -> None:
    records = list(records or [])
    if not records or not enabled(config):
        return
    try:
        with StateStore(config) as store:
            store.upsert_raw_alerts(records, source=source)
    except Exception as exc:
        _log_error(config, "record_raw_alerts", exc)


def record_triage_result(
    config: dict[str, Any] | None,
    summary: dict[str, Any],
    judged_rows: Iterable[dict[str, Any]] | None = None,
    ignore_ids: Iterable[str] | None = None,
    manual_rows: Iterable[dict[str, Any]] | None = None,
) -> None:
    if not enabled(config):
        return
    try:
        with StateStore(config) as store:
            store.record_triage_result(
                summary or {},
                judged_rows=list(judged_rows or []),
                ignore_ids={str(x) for x in (ignore_ids or []) if str(x)},
                manual_ids={str(r.get("告警ID") or "") for r in (manual_rows or []) if str(r.get("告警ID") or "")},
            )
    except Exception as exc:
        _log_error(config, "record_triage_result", exc)


class StateStore:
    def __init__(self, config: dict[str, Any] | None):
        self.config = _state_db_config(config)
        self.conn = None

    def __enter__(self) -> "StateStore":
        self.conn = _connect(self.config)
        self.conn.autocommit = False
        self.ensure_schema()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if not self.conn:
            return
        if exc_type:
            self.conn.rollback()
        else:
            self.conn.commit()
        self.conn.close()

    def ensure_schema(self) -> None:
        schema = _ident(self.config.get("schema") or "public")
        with self.conn.cursor() as cur:
            cur.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS {schema}.cfw_raw_alerts (
                    event_id text PRIMARY KEY,
                    source text NOT NULL,
                    first_seen_at timestamptz NOT NULL DEFAULT now(),
                    last_seen_at timestamptz NOT NULL DEFAULT now(),
                    alert_start_at timestamptz,
                    alert_end_at timestamptz,
                    event_name text,
                    level text,
                    src_ips text[] NOT NULL DEFAULT ARRAY[]::text[],
                    dst_ips text[] NOT NULL DEFAULT ARRAY[]::text[],
                    processing_status text,
                    hide_status text,
                    state text NOT NULL DEFAULT 'seen',
                    activity_id text,
                    payload jsonb NOT NULL DEFAULT '{{}}'::jsonb,
                    updated_at timestamptz NOT NULL DEFAULT now()
                )
            """)
            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS {schema}.cfw_triage_runs (
                    run_id text PRIMARY KEY,
                    mode text NOT NULL,
                    dry_run boolean NOT NULL DEFAULT false,
                    query_start timestamptz,
                    query_end timestamptz,
                    query_total integer,
                    alert_count integer,
                    judgement_counts jsonb NOT NULL DEFAULT '{{}}'::jsonb,
                    summary jsonb NOT NULL DEFAULT '{{}}'::jsonb,
                    created_at timestamptz NOT NULL DEFAULT now()
                )
            """)
            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS {schema}.cfw_triage_results (
                    event_id text PRIMARY KEY,
                    run_id text REFERENCES {schema}.cfw_triage_runs(run_id) ON DELETE SET NULL,
                    result text,
                    confidence text,
                    triage_source text,
                    model text,
                    reason text,
                    key_evidence text,
                    next_step text,
                    status text NOT NULL DEFAULT 'triaged',
                    judgement jsonb NOT NULL DEFAULT '{{}}'::jsonb,
                    updated_at timestamptz NOT NULL DEFAULT now()
                )
            """)
            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS {schema}.cfw_disposal_actions (
                    id bigserial PRIMARY KEY,
                    run_id text REFERENCES {schema}.cfw_triage_runs(run_id) ON DELETE SET NULL,
                    action_type text NOT NULL,
                    event_ids text[] NOT NULL DEFAULT ARRAY[]::text[],
                    result jsonb NOT NULL DEFAULT '{{}}'::jsonb,
                    created_at timestamptz NOT NULL DEFAULT now()
                )
            """)
            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS {schema}.cfw_activities (
                    activity_id text PRIMARY KEY,
                    cluster_key text NOT NULL,
                    state text NOT NULL DEFAULT 'open',
                    first_seen_at timestamptz,
                    last_seen_at timestamptz,
                    src_ips text[] NOT NULL DEFAULT ARRAY[]::text[],
                    dst_ips text[] NOT NULL DEFAULT ARRAY[]::text[],
                    event_families text[] NOT NULL DEFAULT ARRAY[]::text[],
                    alert_count integer NOT NULL DEFAULT 0,
                    summary jsonb NOT NULL DEFAULT '{{}}'::jsonb,
                    updated_at timestamptz NOT NULL DEFAULT now()
                )
            """)
            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS {schema}.cfw_activity_alerts (
                    activity_id text REFERENCES {schema}.cfw_activities(activity_id) ON DELETE CASCADE,
                    event_id text REFERENCES {schema}.cfw_raw_alerts(event_id) ON DELETE CASCADE,
                    created_at timestamptz NOT NULL DEFAULT now(),
                    PRIMARY KEY (activity_id, event_id)
                )
            """)
            cur.execute(f"CREATE INDEX IF NOT EXISTS cfw_raw_alerts_state_idx ON {schema}.cfw_raw_alerts(state)")
            cur.execute(f"CREATE INDEX IF NOT EXISTS cfw_raw_alerts_alert_end_idx ON {schema}.cfw_raw_alerts(alert_end_at)")
            cur.execute(f"CREATE INDEX IF NOT EXISTS cfw_triage_runs_created_idx ON {schema}.cfw_triage_runs(created_at)")

    def upsert_raw_alerts(self, records: list[dict[str, Any]], source: str) -> None:
        schema = _ident(self.config.get("schema") or "public")
        sql = f"""
            INSERT INTO {schema}.cfw_raw_alerts (
                event_id, source, alert_start_at, alert_end_at, event_name, level,
                src_ips, dst_ips, processing_status, hide_status, state, payload
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (event_id) DO UPDATE SET
                last_seen_at = now(),
                alert_start_at = EXCLUDED.alert_start_at,
                alert_end_at = EXCLUDED.alert_end_at,
                event_name = EXCLUDED.event_name,
                level = EXCLUDED.level,
                src_ips = EXCLUDED.src_ips,
                dst_ips = EXCLUDED.dst_ips,
                processing_status = EXCLUDED.processing_status,
                hide_status = EXCLUDED.hide_status,
                payload = EXCLUDED.payload,
                updated_at = now()
        """
        rows = []
        for record in records:
            event_id = _event_id(record)
            if not event_id:
                continue
            rows.append((
                event_id,
                source,
                _parse_time(record.get("StartTime")),
                _parse_time(record.get("EndTime")),
                str(record.get("EventName") or ""),
                str(record.get("Level") or ""),
                _list(record.get("SrcIpList") or record.get("SourceIp") or []),
                _list(record.get("DstIpList") or record.get("DstIp") or []),
                str(record.get("ProcessingStatus", "")),
                str(record.get("HideStatus", "")),
                _initial_state(record),
                _json(record),
            ))
        if not rows:
            return
        with self.conn.cursor() as cur:
            cur.executemany(sql, rows)

    def record_triage_result(
        self,
        summary: dict[str, Any],
        judged_rows: list[dict[str, Any]],
        ignore_ids: set[str],
        manual_ids: set[str],
    ) -> str:
        schema = _ident(self.config.get("schema") or "public")
        run_id = str(summary.get("run_id") or uuid.uuid4())
        mode = str(summary.get("mode") or "unknown")
        with self.conn.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO {schema}.cfw_triage_runs (
                    run_id, mode, dry_run, query_start, query_end, query_total,
                    alert_count, judgement_counts, summary
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (run_id) DO UPDATE SET summary = EXCLUDED.summary
                """,
                (
                    run_id,
                    mode,
                    bool(summary.get("dry_run", False)),
                    _parse_time(summary.get("query_start")),
                    _parse_time(summary.get("query_end")),
                    _int_or_none(summary.get("query_total")),
                    _int_or_none(summary.get("alert_count")),
                    _json(summary.get("judgement_counts") or {}),
                    _json(summary),
                ),
            )
            result_rows = []
            for row in judged_rows:
                event_id = str(row.get("告警ID") or "")
                if not event_id:
                    continue
                status = "disposed" if event_id in ignore_ids else ("manual" if event_id in manual_ids else "triaged")
                result_rows.append((
                    event_id,
                    run_id,
                    row.get("模型研判") or "",
                    row.get("模型置信度") or "",
                    row.get("研判来源") or "",
                    row.get("研判模型") or "",
                    row.get("研判理由") or "",
                    row.get("关键证据") or "",
                    row.get("下一步") or "",
                    status,
                    _json(row),
                ))
            if result_rows:
                cur.executemany(
                    f"""
                    INSERT INTO {schema}.cfw_triage_results (
                        event_id, run_id, result, confidence, triage_source,
                        model, reason, key_evidence, next_step, status, judgement
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (event_id) DO UPDATE SET
                        run_id = EXCLUDED.run_id,
                        result = EXCLUDED.result,
                        confidence = EXCLUDED.confidence,
                        triage_source = EXCLUDED.triage_source,
                        model = EXCLUDED.model,
                        reason = EXCLUDED.reason,
                        key_evidence = EXCLUDED.key_evidence,
                        next_step = EXCLUDED.next_step,
                        status = EXCLUDED.status,
                        judgement = EXCLUDED.judgement,
                        updated_at = now()
                    """,
                    result_rows,
                )
                cur.executemany(
                    f"UPDATE {schema}.cfw_raw_alerts SET state = %s, updated_at = now() WHERE event_id = %s",
                    [(row[9], row[0]) for row in result_rows],
                )
            if ignore_ids:
                cur.execute(
                    f"""
                    INSERT INTO {schema}.cfw_disposal_actions (run_id, action_type, event_ids, result)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (run_id, "alert_center_omit", sorted(ignore_ids), _json(summary.get("omit_actions") or [])),
                )
            manual_push = summary.get("manual_push") if isinstance(summary.get("manual_push"), dict) else {}
            if manual_ids or manual_push:
                cur.execute(
                    f"""
                    INSERT INTO {schema}.cfw_disposal_actions (run_id, action_type, event_ids, result)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (run_id, "manual_review_push", sorted(manual_ids), _json(manual_push)),
                )
        return run_id


def _state_db_config(config: dict[str, Any] | None) -> dict[str, Any]:
    return dict((config or {}).get("state_db") or {})


def _dsn(cfg: dict[str, Any]) -> str:
    return str(cfg.get("dsn") or os.environ.get(str(cfg.get("dsn_env") or "CFW_STATE_DB_DSN"), "")).strip()


def _connect(cfg: dict[str, Any]):
    dsn = _dsn(cfg)
    try:
        import psycopg2
    except ImportError as exc:
        raise RuntimeError("state_db requires psycopg2-binary") from exc
    return psycopg2.connect(dsn, connect_timeout=int(cfg.get("connect_timeout_seconds", 5)))


def _json(value: Any):
    from psycopg2.extras import Json
    return Json(_jsonable(value), dumps=lambda v: json.dumps(v, ensure_ascii=False))


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items() if not str(k).startswith("_")}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


def _event_id(record: dict[str, Any]) -> str:
    return str(record.get("EventId") or record.get("AlertClusterId") or "")


def _initial_state(record: dict[str, Any]) -> str:
    if str(record.get("ProcessingStatus", "0")) != "0" or str(record.get("HideStatus", "0")) != "0":
        return "disposed"
    return "seen"


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(x) for x in value if str(x)]
    return [str(value)] if str(value) else []


def _parse_time(value: Any):
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text[:19] if "T" in text else text, fmt)
        except ValueError:
            continue
    return None


def _int_or_none(value: Any):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _ident(value: str) -> str:
    if not value.replace("_", "").isalnum():
        raise ValueError(f"invalid PostgreSQL identifier: {value!r}")
    return '"' + value.replace('"', '""') + '"'


def _log_error(config: dict[str, Any] | None, where: str, exc: Exception) -> None:
    try:
        from pathlib import Path
        import cfw_alert_monitor as monitor
        path = Path(__file__).resolve().parents[1] / "logs" / "state-db-errors.jsonl"
        path.parent.mkdir(exist_ok=True)
        monitor.append_jsonl(path, [{
            "time": monitor.dt_text(monitor.now_local()),
            "where": where,
            "error": str(exc)[:1000],
            "enabled": bool((_state_db_config(config)).get("enabled")),
        }])
    except Exception:
        pass
