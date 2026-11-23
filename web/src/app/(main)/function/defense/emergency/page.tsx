"use client";

import * as React from "react";
import Link from "next/link";
import {
  AlertTriangle,
  ArrowDown,
  Clock3,
  LockKeyhole,
  Pause,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { http } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type EmergencyStatus = {
  mode: string;
  armed: boolean;
  paused: boolean;
  backend_ready: boolean;
  protected_cidrs: number;
  ttl_seconds: number;
  max_active: number;
  max_per_hour: number;
  active: number;
  action_count: number;
  description: string;
  warning: string;
  error?: string;
};

type Action = {
  id: number;
  event_id: number;
  source_ip: string;
  destination_ip: string;
  rule_id: string;
  explanation: string;
  backend: string;
  status: string;
  created_at: string;
  applied_at?: string;
  expires_at: string;
  reversed_at?: string;
  latency_ms: number;
  outcome_detail: string;
  reversible: boolean;
};

type ActionPage = {
  actions: Action[];
  next_before_id: number;
  has_more: boolean;
};

type AuditRow = {
  id: number;
  action_id: number;
  actor: string;
  event_type: string;
  detail: string;
  occurred_at: string;
};

type StopResult = {
  paused: boolean;
  reverted: number;
  failed: number;
  remaining: number;
  warning: string;
};

const clock = (date: string) => {
  const stamp = new Date(date);
  return Number.isNaN(stamp.getTime()) ? date : stamp.toLocaleString();
};

const actionStatusText = (value: string) => {
  switch (value) {
    case "active": return "ACTIVE — kernel block";
    case "pending": return "PENDING — awaiting kernel";
    case "simulated": return "SIMULATION — no live effect";
    case "reverted": return "REVERSED";
    case "expired": return "EXPIRED — TTL reached";
    case "failed": return "FAILED — verify gateway";
    default: return value;
  }
};

const danger = (value: string) => value === "active" || value === "failed";

export default function EmergencyContainmentPage() {
  const [status, setStatus] = React.useState<EmergencyStatus | null>(null);
  const [actions, setActions] = React.useState<Action[]>([]);
  const [audit, setAudit] = React.useState<AuditRow[]>([]);
  const [hasMore, setHasMore] = React.useState(false);
  const [nextCursor, setNextCursor] = React.useState(0);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [reversing, setReversing] = React.useState<number | null>(null);
  const [error, setError] = React.useState("");
  const [message, setMessage] = React.useState("");
  const [now, setNow] = React.useState(Date.now());

  const refresh = React.useCallback(async () => {
    const [freshStatus, freshActions, freshAudit] = await Promise.all([
      http<EmergencyStatus>("/defense/emergency/status"),
      http<ActionPage>("/defense/emergency/actions?limit=100"),
      http<{ audit: AuditRow[] }>("/defense/emergency/audit?limit=50"),
    ]);
    setStatus(freshStatus);
    setActions(freshActions.actions);
    setNextCursor(freshActions.next_before_id);
    setHasMore(freshActions.has_more);
    setAudit(freshAudit.audit);
    setNow(Date.now());
  }, []);

  React.useEffect(() => {
    let mounted = true;
    void refresh()
      .catch(reason => {
        if (mounted) setError(reason instanceof Error ? reason.message : "Emergency console unavailable");
      })
      .finally(() => { if (mounted) setLoading(false); });
    const timer = window.setInterval(() => {
      if (!document.hidden && !busy && reversing === null) {
        void refresh().catch(() => { /* preserve existing display */ });
      }
    }, 2500);
    return () => { mounted = false; window.clearInterval(timer); };
  }, [refresh, busy, reversing]);

  async function execute(path: string, outcome: string) {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await http(path, { method: "POST" });
      await refresh();
      setMessage(outcome);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Emergency control failed");
    } finally {
      setBusy(false);
    }
  }

  async function arm() {
    if (!status || status.mode === "off" || !status.backend_ready || !status.protected_cidrs) {
      setError("A validated non-off mode, protected destination scope, and ready backend are required.");
      return;
    }
    if (!window.confirm(
      "ARM emergency containment? Fresh, corroborated detections can change live firewall state without waiting for operator approval. " +
      "Review network scope, exemptions, safety-critical exclusions and rollback access first.",
    )) return;
    await execute("/defense/emergency/arm", "Emergency policy armed. Every containment will appear below with Undo.");
  }

  async function revertOne(action: Action) {
    setReversing(action.id);
    setError("");
    setMessage("");
    try {
      await http(`/defense/emergency/actions/${action.id}/revert`, { method: "POST" });
      await refresh();
      setMessage(`Action #${action.id} reversed. Source ${action.source_ip} is suppressed for 30 minutes.`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Kernel reversal not confirmed");
    } finally {
      setReversing(null);
    }
  }

  async function stopAll() {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const result = await http<StopResult>("/defense/emergency/revert-all", { method: "POST" });
      await refresh();
      setMessage(
        `Emergency mode PAUSED. Reversed ${result.reverted} actions; ${result.failed} failed, ${result.remaining} remain. ` +
        (result.failed || result.remaining ? "VERIFY THE GATEWAY DIRECTLY." : "All listed live actions cleared."),
      );
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Panic stop could not be confirmed");
    } finally {
      setBusy(false);
    }
  }

  async function loadOlder() {
    if (!nextCursor || !hasMore) return;
    setBusy(true);
    try {
      const page = await http<ActionPage>(`/defense/emergency/actions?limit=100&before_id=${nextCursor}`);
      setActions(prev => [...prev, ...page.actions.filter(item => !prev.some(a => a.id === item.id))]);
      setNextCursor(page.next_before_id);
      setHasMore(page.has_more);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Older actions unavailable");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-5 p-5">
      <header className="space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h1 className="flex items-center gap-2 text-2xl font-semibold">
            <ShieldAlert className="size-6" /> Emergency Auto-Containment
          </h1>
          <Link href="/function/defense" className="text-sm underline underline-offset-4">Back to Defense SOC</Link>
        </div>
        <p className="max-w-4xl text-sm text-muted-foreground">
          Deterministic machine-speed triage, bounded temporary IP containment and immediate operator reversal.
          No LLM approval delay. Every decision is persisted and independently auto-expires.
        </p>
      </header>

      {loading && <p className="text-sm text-muted-foreground">Checking authorized emergency controls…</p>}
      {error && <p role="alert" className="rounded-md border border-destructive p-3 text-sm text-destructive">{error}</p>}
      {message && <p role="status" className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">{message}</p>}

      {status && (
        <>
          <div className="grid gap-3 sm:grid-cols-4">
            <Card><CardHeader><CardTitle className="text-sm">Mode</CardTitle></CardHeader>
              <CardContent className="text-lg font-semibold uppercase">{status.mode}</CardContent></Card>
            <Card><CardHeader><CardTitle className="text-sm">Operator control</CardTitle></CardHeader>
              <CardContent className={status.armed ? "font-semibold text-amber-500" : "font-semibold"}>
                {status.armed ? "ARMED" : "DISARMED / PAUSED"}
              </CardContent></Card>
            <Card><CardHeader><CardTitle className="text-sm">Kernel/pending actions</CardTitle></CardHeader>
              <CardContent className="text-3xl font-semibold">{status.active}</CardContent></Card>
            <Card><CardHeader><CardTitle className="text-sm">Action history</CardTitle></CardHeader>
              <CardContent className="text-3xl font-semibold">{status.action_count}</CardContent></Card>
          </div>
          <Card>
            <CardHeader><CardTitle className="flex items-center gap-2"><LockKeyhole className="size-5" /> Operator arming & safety</CardTitle></CardHeader>
            <CardContent className="space-y-3 text-sm">
              <p>{status.description}</p>
              <p className="text-muted-foreground">
                Protected destination scopes: {status.protected_cidrs ?? 0} · Kernel timeout: {status.ttl_seconds ?? 0}s ·
                Max concurrent: {status.max_active ?? 0} · Max/hour: {status.max_per_hour ?? 0}
              </p>
              <p className="rounded-md bg-amber-500/10 p-3">{status.warning || status.error}</p>
              <div className="flex flex-wrap gap-2">
                <Button disabled={busy || status.armed || !status.backend_ready || status.mode === "off" || status.mode === "invalid"}
                  onClick={() => void arm()}>
                  <ShieldCheck className="mr-2 size-4" /> Arm emergency policy
                </Button>
                <Button variant="outline" disabled={busy || status.paused}
                  onClick={() => void execute("/defense/emergency/pause", "New automated actions are paused; existing blocks remain until undone or expired.")}>
                  <Pause className="mr-2 size-4" /> Pause new actions
                </Button>
                <Button variant="destructive" disabled={busy}
                  onClick={() => void stopAll()}>
                  <RotateCcw className="mr-2 size-4" /> PANIC STOP — pause & undo all
                </Button>
              </div>
            </CardContent>
          </Card>
        </>
      )}

      <Card>
        <CardHeader><CardTitle className="flex items-center gap-2"><Clock3 className="size-5" /> Containment action ledger</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <p className="text-xs text-muted-foreground">
            Undo is a single click. Live rules expire independently in the kernel if the service crashes.
            Undo restores filtering policy, but cannot restore already dropped packets or interrupted sessions.
          </p>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-left text-sm">
              <thead><tr className="border-b text-muted-foreground">
                <th className="p-2">Created</th><th>Source → Destination</th><th>Rule & evidence</th>
                <th>Status</th><th>TTL</th><th>Enforcement</th><th>Reverse</th>
              </tr></thead>
              <tbody>
                {actions.map(action => {
                  const seconds = Math.max(0, Math.ceil((new Date(action.expires_at).getTime() - now) / 1000));
                  return (
                    <tr key={action.id} className="border-b align-top">
                      <td className="p-2 whitespace-nowrap">{clock(action.created_at)}<div className="text-muted-foreground">#{action.id}</div></td>
                      <td className="p-2 font-mono text-xs whitespace-nowrap">
                        {action.source_ip} → {action.destination_ip}
                        <div className="mt-1 font-sans text-muted-foreground">{action.backend}</div>
                      </td>
                      <td className="p-2">
                        <strong>{action.rule_id}</strong>
                        <p className="text-muted-foreground text-xs">Event #{action.event_id}</p>
                        <p className="mt-1 max-w-xs text-xs">{action.explanation}</p>
                      </td>
                      <td className={danger(action.status) ? "p-2 font-semibold text-amber-500" : "p-2"}>
                        {actionStatusText(action.status)}
                      </td>
                      <td className="p-2">
                        <span className="font-medium">{seconds}s</span>
                        <div className="text-xs text-muted-foreground">{clock(action.expires_at)}</div>
                      </td>
                      <td className="p-2">
                        {action.latency_ms}ms
                        <p className="max-w-[200px] text-xs text-muted-foreground">{action.outcome_detail}</p>
                      </td>
                      <td className="p-2">
                        {action.reversible ? (
                          <Button size="sm" variant="outline" disabled={busy || reversing !== null}
                            onClick={() => void revertOne(action)}>
                            <RotateCcw className="mr-1 size-4" />
                            {reversing === action.id ? "Reversing…" : "Undo now"}
                          </Button>
                        ) : <span className="text-xs text-muted-foreground">Already cleared</span>}
                      </td>
                    </tr>
                  );
                })}
                {actions.length === 0 && <tr><td colSpan={7} className="p-4 text-muted-foreground">No autonomous actions recorded.</td></tr>}
              </tbody>
            </table>
          </div>
          {hasMore && (
            <Button variant="outline" disabled={busy} onClick={() => void loadOlder()}>
              <ArrowDown className="mr-2 size-4" /> Load older actions
            </Button>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="flex items-center gap-2"><AlertTriangle className="size-5" /> Recent containment audit</CardTitle></CardHeader>
        <CardContent className="space-y-2 text-sm">
          {audit.map(entry => (
            <div key={entry.id} className="rounded-md border p-3">
              <strong>{entry.event_type.replaceAll("_", " ")}</strong>
              <span className="ml-2 text-muted-foreground">{clock(entry.occurred_at)}</span>
              <p className="text-xs">Actor: {entry.actor} · Action: {entry.action_id || "global"}</p>
              <p className="mt-1 text-muted-foreground">{entry.detail}</p>
            </div>
          ))}
          {audit.length === 0 && <p className="text-muted-foreground">No emergency audit activity.</p>}
        </CardContent>
      </Card>
    </div>
  );
}
