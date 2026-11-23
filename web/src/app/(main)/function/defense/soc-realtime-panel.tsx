"use client";

import * as React from "react";
import Link from "next/link";
import { Activity, AlertTriangle, Clock3, RefreshCw, ShieldAlert, Wifi, WifiOff } from "lucide-react";
import { http } from "@/lib/api";
import { useSOCLive } from "./use-soc-live";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type ReviewAlert = {
  id: number;
  event_id: number;
  case_id: number;
  case_status: string;
  title: string;
  summary: string;
  severity: string;
  priority: number;
  needs_case: boolean;
  rule_id: string;
  created_at: string;
  asset_ids: number[];
};
type ReviewQueue = { alerts: ReviewAlert[]; note: string };
type SourceHealth = { source: string; events_last_hour: number; last_ingest: string };
type SOCHealth = {
  as_of: string;
  ingest_state: "unknown" | "receiving" | "no_recent_ingest";
  last_ingested_at: string | null;
  last_observed_at: string | null;
  last_source: string;
  sensor_clock_lag_seconds: number | null;
  events_last_5m: number;
  events_last_hour: number;
  alerts_last_5m: number;
  alerts_last_hour: number;
  sources: SourceHealth[];
  freshness_threshold_seconds: number;
  note: string;
};

function when(value: string | null | undefined) {
  if (!value) return "Not observed";
  const stamp = new Date(value);
  return Number.isNaN(stamp.getTime()) ? "Invalid source time" : stamp.toLocaleString();
}

export function SOCRealtimePanel() {
  const [health, setHealth] = React.useState<SOCHealth | null>(null);
  const [queue, setQueue] = React.useState<ReviewQueue | null>(null);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [severity, setSeverity] = React.useState("all");
  const [unassignedOnly, setUnassignedOnly] = React.useState(false);
  const loading = React.useRef(false);

  const refresh = React.useCallback(async () => {
    if (loading.current || document.hidden) return;
    loading.current = true;
    try {
      const [nextHealth, nextQueue] = await Promise.all([
        http<SOCHealth>("/defense/soc/health"),
        http<ReviewQueue>("/defense/soc/queue"),
      ]);
      setHealth(nextHealth);
      setQueue(nextQueue);
      setError("");
      // The existing events/alerts/summary cards refresh on the same
      // authenticated server watermark instead of waiting 15 seconds.
      window.dispatchEvent(new Event("artex:soc-revision"));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Live SOC status unavailable");
    } finally {
      loading.current = false;
    }
  }, []);

  const live = useSOCLive(refresh);
  React.useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => { void refresh(); }, 30000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  async function createCase(row: ReviewAlert) {
    if (!window.confirm(
      `Open a human-review case for alert #${row.id}? This only queues evidence analysis and cannot execute containment.`
    )) return;
    setBusy(true);
    try {
      await http("/defense/cases", {
        method: "POST",
        body: JSON.stringify({ alert_id: row.id }),
      });
      await refresh();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to open case");
    } finally {
      setBusy(false);
    }
  }

  const selected = (queue?.alerts ?? []).filter(a =>
    (severity === "all" || a.severity === severity) && (!unassignedOnly || a.needs_case)
  );

  const stateLabel = live === "live"
    ? "LIVE · streamed watermarks"
    : live === "connecting"
      ? "CONNECTING · fallback active"
      : "POLLING · retrying live stream";

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex flex-wrap items-center gap-2 text-base">
            {live === "live" ? <Wifi className="size-5" /> : <WifiOff className="size-5" />}
            Real-time SOC operations
            <span className={`ml-auto text-xs font-normal ${live === "live" ? "text-green-600" : "text-amber-600"}`}>
              {stateLabel}
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 text-sm">
          <p className="text-muted-foreground">
            The live channel announces database revisions only. Actual telemetry is read using authenticated APIs.
            Connectivity does not prove a sensor is healthy, and missing events are not proof of no attack.
          </p>
          {error && <p role="alert" className="rounded-md border border-amber-500/40 p-2 text-amber-600">{error}</p>}
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-muted-foreground">Last server health check: {when(health?.as_of)}</span>
            <Button variant="outline" size="sm" onClick={() => void refresh()}><RefreshCw className="mr-2 size-4" /> Refresh</Button>
          </div>
          {health && (
            <>
              <div className="grid gap-3 sm:grid-cols-4">
                <div className="rounded-md border p-3">
                  <strong className="flex items-center gap-1"><Activity className="size-4" /> Ingest signal</strong>
                  <div className="mt-2 text-xl">{health.ingest_state.replaceAll("_", " ")}</div>
                  <p className="text-xs text-muted-foreground">No data within {health.freshness_threshold_seconds / 60} minutes → review collector</p>
                </div>
                <div className="rounded-md border p-3">
                  <strong>Events · last 5m / 1h</strong>
                  <div className="mt-2 text-xl">{health.events_last_5m} / {health.events_last_hour}</div>
                </div>
                <div className="rounded-md border p-3">
                  <strong className="flex items-center gap-1"><ShieldAlert className="size-4" /> Alerts · 5m / 1h</strong>
                  <div className="mt-2 text-xl">{health.alerts_last_5m} / {health.alerts_last_hour}</div>
                </div>
                <div className="rounded-md border p-3">
                  <strong className="flex items-center gap-1"><Clock3 className="size-4" /> Sensor clock delta</strong>
                  <div className="mt-2 text-xl">{health.sensor_clock_lag_seconds === null
                    ? "Unknown" : `${Math.round(health.sensor_clock_lag_seconds)}s`}</div>
                  <p className="text-xs text-muted-foreground">Ingest minus observed; negative = possible clock skew</p>
                </div>
              </div>
              <p className="text-xs text-muted-foreground">
                Most recent ingestion: {when(health.last_ingested_at)} · Sensor observation: {when(health.last_observed_at)}
                {" · "}Last source: {health.last_source || "Unknown"}.
                {" "}{health.note}
              </p>
              <div className="flex flex-wrap gap-2">
                {health.sources.map(source => (
                  <div key={source.source} className="rounded-md border px-3 py-2 text-xs">
                    <strong>{source.source}</strong> · {source.events_last_hour} events last hour
                    <span className="ml-2 text-muted-foreground">Latest: {when(source.last_ingest)}</span>
                  </div>
                ))}
                {!health.sources.length && <span className="text-xs text-muted-foreground">No source reported telemetry in the last hour.</span>}
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><AlertTriangle className="size-5" /> Priority review queue</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-muted-foreground text-sm">
            {queue?.note ?? "Loading evidence-backed alert priorities…"}
            {" "}The queue is capped at 50; use the Cases page for full investigation history.
          </p>
          <div className="flex flex-wrap gap-3 text-sm">
            <label>Severity
              <select value={severity} onChange={e => setSeverity(e.target.value)}
                className="ml-2 rounded-md border bg-background px-2 py-1">
                <option value="all">All</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={unassignedOnly}
                onChange={e => setUnassignedOnly(e.target.checked)} />
              Without a case
            </label>
            <Link className="ml-auto underline underline-offset-4" href="/function/defense/cases">
              Review investigations and approvals →
            </Link>
          </div>
          <div className="max-h-[450px] space-y-2 overflow-y-auto">
            {selected.map(alert => (
              <div key={alert.id} className="flex flex-wrap items-center justify-between gap-3 rounded-md border p-3 text-sm">
                <div className="max-w-3xl">
                  <div className="flex flex-wrap gap-2">
                    <strong className={alert.severity === "critical" ? "text-red-600" : ""}>
                      {alert.severity.toUpperCase()} · Priority {alert.priority}/100 · Alert #{alert.id}
                    </strong>
                    <span className="text-muted-foreground">
                      {alert.needs_case ? "Not assigned to a case" : `Case #${alert.case_id} · ${alert.case_status}`}
                    </span>
                  </div>
                  <p className="font-medium">{alert.title}</p>
                  <p className="text-muted-foreground text-xs">
                    {alert.rule_id} · Event #{alert.event_id} · {when(alert.created_at)}
                  </p>
                  <p className="mt-1 text-xs">{alert.summary}</p>
                </div>
                {alert.needs_case ? (
                  <Button disabled={busy} size="sm" variant="outline"
                    onClick={() => void createCase(alert)}>
                    Open review case
                  </Button>
                ) : (
                  <Button variant="outline" size="sm" asChild>
                    <Link href={`/function/defense/intelligence?case=${alert.case_id}`}>Investigate</Link>
                  </Button>
                )}
              </div>
            ))}
            {!selected.length && <p className="py-3 text-sm text-muted-foreground">
              {queue ? "No alerts match these filters." : "Loading prioritized alerts…"}
            </p>}
          </div>
        </CardContent>
      </Card>
    </>
  );
}
