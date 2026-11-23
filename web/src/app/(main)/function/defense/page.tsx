"use client";

import * as React from "react";
import Link from "next/link";
import { Activity, AlertTriangle, Database, ShieldCheck } from "lucide-react";
import { http } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

type PackRule = {
  engine: "suricata" | "yara";
  id: string;
  name: string;
  severity: string;
  false_positive_risk: string;
  limitations: string;
  auto_containment_eligible: boolean;
};
type PackCatalog = {
  catalog: {
    name: string;
    version: string;
    policy: "alert_only";
    rule_count: number;
    quarantined_count: number;
    rules: PackRule[];
  };
  automatic_activation: boolean;
  autonomous_containment: boolean;
};
type Summary = {
  events: number;
  alerts: number;
  linked_events: number;
  mode: string;
  detection_model: string;
};
type EventRow = {
  id: number;
  observed_at: string;
  source: string;
  kind: string;
  src_ip: string;
  host: string;
  signature: string;
  asset_ids: number[];
};
type AlertRow = {
  id: number;
  created_at: string;
  rule_id: string;
  severity: string;
  title: string;
  summary: string;
  event_id: number;
  asset_ids: number[];
};
const fmt = (date: string) => {
  const parsed = new Date(date);
  return Number.isNaN(parsed.getTime()) ? date : parsed.toLocaleString();
};

export default function DefenseSOCPage() {
  const [summary, setSummary] = React.useState<Summary | null>(null);
  const [pack, setPack] = React.useState<PackCatalog | null>(null);
  const [events, setEvents] = React.useState<EventRow[]>([]);
  const [alerts, setAlerts] = React.useState<AlertRow[]>([]);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    let active = true;
    async function refresh() {
      try {
        const [nextSummary, nextEvents, nextAlerts] = await Promise.all([
          http<Summary>("/defense/summary"),
          http<{ events: EventRow[] }>("/defense/events?limit=50"),
          http<{ alerts: AlertRow[] }>("/defense/alerts?limit=50"),
        ]);
        if (!active) return;
        setSummary(nextSummary);
        setEvents(nextEvents.events);
        setAlerts(nextAlerts.alerts);
        setError("");
      } catch (reason) {
        if (!active) return;
        setError(reason instanceof Error ? reason.message : "Unable to read defense telemetry");
      } finally {
        if (active) setLoading(false);
      }
    }
    void refresh();
    void http<PackCatalog>("/defense/detection-pack")
      .then(result => { if (active) setPack(result); })
      .catch(() => { if (active) setPack(null); });
    const timer = window.setInterval(() => { if (!document.hidden) void refresh(); }, 15000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  async function downloadRules(engine: "suricata" | "yara") {
    try {
      const token = window.localStorage.getItem("artex_token");
      const response = await fetch(`/api/defense/detection-pack/${engine}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!response.ok) throw new Error("Unable to retrieve authenticated detection rule file");
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = engine === "suricata" ? "artex-alert-only.rules" : "artex-alert-only.yar";
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => window.URL.revokeObjectURL(url), 1000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Detection pack download failed");
    }
  }

  return (
    <div className="flex flex-col gap-6 p-5">
      <header>
        <h1 className="flex items-center gap-2 text-2xl font-semibold"><ShieldCheck className="size-6" /> Defense SOC</h1>
        <p className="text-muted-foreground mt-2 text-sm">
          Phase 2 telemetry preview: passive ingestion, deterministic detection and asset correlations.
          Alerts are investigative signals, not confirmed intrusions.
        </p>
        <Link href="/function/defense/cases" className="mt-3 inline-flex rounded-md border px-3 py-2 text-sm font-medium hover:bg-muted">
          Review cases and manual response approvals →
        </Link>
      </header>
      {loading && <p className="text-muted-foreground">Loading authorized telemetry…</p>}
      {error && (
        <p role="alert" className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
          {error}. This view requires ARTEX_MODE=defense and an authenticated session.
        </p>
      )}
      {summary && (
        <div className="grid gap-3 sm:grid-cols-3">
          <Card><CardHeader><CardTitle className="flex items-center gap-2 text-base"><Activity className="size-4" /> Events</CardTitle></CardHeader><CardContent className="text-3xl font-semibold">{summary.events}</CardContent></Card>
          <Card><CardHeader><CardTitle className="flex items-center gap-2 text-base"><AlertTriangle className="size-4" /> Alerts</CardTitle></CardHeader><CardContent className="text-3xl font-semibold">{summary.alerts}</CardContent></Card>
          <Card><CardHeader><CardTitle className="flex items-center gap-2 text-base"><Database className="size-4" /> Asset-linked events</CardTitle></CardHeader><CardContent className="text-3xl font-semibold">{summary.linked_events}</CardContent></Card>
        </div>
      )}
      {pack && (
        <Card>
          <CardHeader><CardTitle>Detection Pack · {pack.catalog.version} · Alert-only</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <p className="text-muted-foreground text-sm">
              {pack.catalog.rule_count} curated signatures ({pack.catalog.rules.filter(r => r.engine === "suricata").length} Suricata,
              {" "}{pack.catalog.rules.filter(r => r.engine === "yara").length} YARA).
              {" "}{pack.catalog.quarantined_count} noisy or unverified source rules were quarantined.
              No rules are automatically installed and none authorize containment.
              Review HOME_NET, scope, false positives and sensor-side alert policy before deployment.
            </p>
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" onClick={() => void downloadRules("suricata")}>Download Suricata rules</Button>
              <Button variant="outline" onClick={() => void downloadRules("yara")}>Download YARA rules</Button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[680px] text-left text-sm">
                <thead><tr className="border-b text-muted-foreground">
                  <th className="py-2">Engine</th><th>Rule</th><th>Risk</th><th>Review caveat</th>
                </tr></thead>
                <tbody>
                  {pack.catalog.rules.map(rule => (
                    <tr key={`${rule.engine}:${rule.id}`} className="border-b align-top">
                      <td className="py-2">{rule.engine}</td>
                      <td className="py-2"><strong>{rule.name}</strong><div className="text-muted-foreground text-xs">{rule.id}</div></td>
                      <td className="py-2">{rule.false_positive_risk} false-positive risk</td>
                      <td className="py-2 max-w-md text-xs">{rule.limitations}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
      <Card>
        <CardHeader><CardTitle>Recent detections</CardTitle></CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[680px] text-left text-sm">
              <thead><tr className="border-b text-muted-foreground"><th className="py-2">When</th><th>Severity</th><th>Detection</th><th>Evidence</th><th>Asset IDs</th></tr></thead>
              <tbody>
                {alerts.map(alert => (
                  <tr key={alert.id} className="border-b align-top">
                    <td className="py-3 whitespace-nowrap">{fmt(alert.created_at)}</td>
                    <td className="uppercase">{alert.severity}</td>
                    <td><div className="font-medium">{alert.title}</div><div className="text-muted-foreground text-xs">{alert.rule_id}</div><p className="max-w-xl py-1 text-xs">{alert.summary}</p></td>
                    <td>Event #{alert.event_id}</td>
                    <td>{alert.asset_ids?.join(", ") || "Unlinked"}</td>
                  </tr>
                ))}
                {alerts.length === 0 && <tr><td colSpan={5} className="text-muted-foreground py-4">No detections recorded.</td></tr>}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle>Recent normalized events</CardTitle></CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[680px] text-left text-sm">
              <thead><tr className="border-b text-muted-foreground"><th className="py-2">Observed</th><th>Source</th><th>Kind</th><th>Host / IP</th><th>Evidence summary</th><th>Asset IDs</th></tr></thead>
              <tbody>
                {events.map(event => (
                  <tr key={event.id} className="border-b align-top">
                    <td className="py-3 whitespace-nowrap">{fmt(event.observed_at)}</td>
                    <td>{event.source}</td>
                    <td>{event.kind}</td>
                    <td>{event.host || event.src_ip || "—"}</td>
                    <td className="max-w-md">{event.signature || "No vendor signature"}</td>
                    <td>{event.asset_ids?.join(", ") || "Unlinked"}</td>
                  </tr>
                ))}
                {events.length === 0 && <tr><td colSpan={6} className="text-muted-foreground py-4">No telemetry ingested yet.</td></tr>}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
