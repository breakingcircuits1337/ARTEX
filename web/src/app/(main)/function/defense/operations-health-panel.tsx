"use client";

import * as React from "react";
import { Activity, AlertTriangle, Database, RefreshCw } from "lucide-react";
import { http } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type OperationalHealth = {
  operations: {
    as_of: string;
    status: "ready" | "attention" | "unknown";
    database_ready: boolean;
    collectors_active: number;
    collectors_revoked: number;
    collectors_unassigned: number;
    collector_sampled: number;
    collectors_never_seen: number;
    collectors_silent_15m: number;
    collector_sample_truncated: boolean;
    events_last_5m: number;
    investigations_queued: number;
    investigations_failed_last_hour: number;
    emergency_pending: number;
    emergency_failed_last_hour: number;
    emergency_paused: boolean;
    investigator_paused: boolean;
    warnings: string[];
    interpretation: string;
  };
  ingestion_process: {
    requests_total: number;
    accepted: number;
    rejected: number;
    rate_limited: number;
    failed: number;
  };
  metrics_scope: string;
};

const warningLabels: Record<string, string> = {
  no_enrolled_active_collectors: "No active collectors enrolled",
  collectors_require_company_binding: "Collectors need company assignment",
  collector_has_no_telemetry: "Some collectors have no recorded telemetry",
  collector_no_recent_telemetry: "Some collectors have not reported in 15 minutes",
  collector_sample_incomplete: "Collector freshness sample is incomplete",
  emergency_action_failed: "An emergency action failed in the last hour",
  investigation_failed: "An investigation failed in the last hour",
  investigation_backlog: "Investigations are backlogged",
};

export function OperationsHealthPanel() {
  const [data, setData] = React.useState<OperationalHealth | null>(null);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const refresh = React.useCallback(async () => {
    if (document.hidden) return;
    setBusy(true);
    try {
      const value = await http<OperationalHealth>("/defense/operations/health");
      setData(value);
      setError("");
    } catch (reason) {
      setData(null); // Never display stale green status after a health API failure.
      setError(reason instanceof Error ? reason.message : "Operational health unavailable");
    } finally {
      setBusy(false);
    }
  }, []);

  React.useEffect(() => {
    void refresh();
    const handleVisible = () => { if (!document.hidden) void refresh(); };
    document.addEventListener("visibilitychange", handleVisible);
    const timer = window.setInterval(() => { void refresh(); }, 30000);
    return () => {
      document.removeEventListener("visibilitychange", handleVisible);
      window.clearInterval(timer);
    };
  }, [refresh]);

  const o = data?.operations;
  const state = error ? "Unavailable" :
    o?.status === "ready" ? "Ready for monitoring" :
    o?.status === "attention" ? "Operator attention" : "Unknown — inspect deployment";

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Activity className="size-4" /> Operational health · PR #13
        </CardTitle>
        <Button variant="outline" size="sm" onClick={() => void refresh()} disabled={busy}>
          <RefreshCw className="mr-2 size-3" /> Refresh
        </Button>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="font-medium">{state}</p>
        {error && (
          <p role="alert" className="rounded border border-amber-500/50 p-2 text-amber-700">
            Operational data unavailable: {error}. Do not infer the system is healthy.
          </p>
        )}
        {o && (
          <>
            <p className="text-xs text-muted-foreground">
              Snapshot {new Date(o.as_of).toLocaleString()}; {data.metrics_scope}.
            </p>
            <div className="grid gap-3 sm:grid-cols-4">
              <div className="rounded-md border p-3"><Database className="mb-1 size-4" />
                <div className="text-xl font-semibold">{o.database_ready ? "Reachable" : "Unknown"}</div>
                <p className="text-xs text-muted-foreground">PostgreSQL</p>
              </div>
              <div className="rounded-md border p-3">
                <div className="text-xl font-semibold">{o.collectors_active}</div>
                <p className="text-xs text-muted-foreground">Enrolled active collectors</p>
              </div>
              <div className="rounded-md border p-3">
                <div className="text-xl font-semibold">{o.collector_sample_truncated ? "Partial" : o.collectors_silent_15m}</div>
                <p className="text-xs text-muted-foreground">No recorded data in 15 minutes (not confirmed offline)</p>
              </div>
              <div className="rounded-md border p-3">
                <div className="text-xl font-semibold">{o.investigations_queued}</div>
                <p className="text-xs text-muted-foreground">Queued investigations</p>
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              Ingested 5m: {o.events_last_5m} · Handler failures (this process): {data.ingestion_process.failed}
              {" · "}429s: {data.ingestion_process.rate_limited}
              {" · "}Emergency failures 1h: {o.emergency_failed_last_hour}
              {" · "}Investigation failures 1h: {o.investigations_failed_last_hour}.
            </p>
            {o.warnings.length > 0 && (
              <div className="rounded border border-amber-500/40 bg-amber-500/5 p-3">
                <p className="mb-1 flex items-center gap-2 font-medium"><AlertTriangle className="size-4" /> Review signals</p>
                <ul className="list-disc pl-5 text-xs">
                  {o.warnings.map(warning => <li key={warning}>{warningLabels[warning] ?? "Unknown operational signal"}</li>)}
                </ul>
              </div>
            )}
            <p className="text-xs text-muted-foreground">{o.interpretation}</p>
          </>
        )}
      </CardContent>
    </Card>
  );
}
