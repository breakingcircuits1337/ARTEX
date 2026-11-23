"use client";

import * as React from "react";
import Link from "next/link";
import { AlertTriangle, ClipboardCheck, Eye, ShieldCheck } from "lucide-react";
import { http } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type Alert = {
  id: number;
  title: string;
  severity: string;
  event_id: number;
  asset_ids: number[];
};
type Case = {
  id: number;
  alert_id: number;
  status: string;
  title: string;
  severity: string;
  summary: string;
  event_id: number;
  asset_ids: number[];
  mitre_technique: string;
  updated_at: string;
};
type Response = {
  id: number;
  case_id: number;
  playbook: string;
  justification: string;
  status: string;
  decision_reason: string;
  created_at: string;
  case_status: string;
};
type Playbook = {
  id: string;
  name: string;
  risk: string;
  explanation: string;
  steps: string[];
};
type AuditRow = {
  id: number;
  response_id: number;
  event_type: string;
  actor: string;
  reason: string;
  occurred_at: string;
};
type Preview = {
  executed: boolean;
  warning: string;
  playbook: Playbook;
};
type EvidenceGraph = {
  case_id: number;
  mode: string;
  note: string;
  nodes: { id: string; kind: string; label: string }[];
  edges: { source: string; target: string; relation: string }[];
};

const stamp = (s: string) => new Date(s).toLocaleString();
const active = (status: string) => status === "open" || status === "investigating";
const minimumReason = "Enter an operator rationale of at least 12 characters.";

export default function ResponseReviewPage() {
  const [alerts, setAlerts] = React.useState<Alert[]>([]);
  const [cases, setCases] = React.useState<Case[]>([]);
  const [responses, setResponses] = React.useState<Response[]>([]);
  const [playbooks, setPlaybooks] = React.useState<Playbook[]>([]);
  const [selectedCase, setSelectedCase] = React.useState("");
  const [playbook, setPlaybook] = React.useState("collect_additional_evidence");
  const [proposalReason, setProposalReason] = React.useState("");
  const [decisionReason, setDecisionReason] = React.useState("");
  const [auditCase, setAuditCase] = React.useState<number | null>(null);
  const [audit, setAudit] = React.useState<AuditRow[]>([]);
  const [graph, setGraph] = React.useState<EvidenceGraph | null>(null);
  const [preview, setPreview] = React.useState<Preview | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");

  const refresh = React.useCallback(async () => {
    const [a, c, r, p] = await Promise.all([
      http<{ alerts: Alert[] }>("/defense/alerts?limit=100"),
      http<{ cases: Case[] }>("/defense/cases?limit=100"),
      http<{ responses: Response[] }>("/defense/responses?limit=100"),
      http<{ playbooks: Playbook[] }>("/defense/playbooks"),
    ]);
    setAlerts(a.alerts);
    setCases(c.cases);
    setResponses(r.responses);
    setPlaybooks(p.playbooks);
    setSelectedCase(current => c.cases.some(row => active(row.status) && String(row.id) === current)
      ? current : String(c.cases.find(row => active(row.status))?.id ?? ""));
  }, []);

  React.useEffect(() => {
    let mounted = true;
    void refresh().catch(reason => {
      if (mounted) setError(reason instanceof Error ? reason.message : "Response review unavailable");
    }).finally(() => {
      if (mounted) setLoading(false);
    });
    return () => { mounted = false; };
  }, [refresh]);

  async function mutate(path: string, data?: object) {
    setBusy(true);
    setError("");
    setPreview(null);
    try {
      await http(path, { method: "POST", ...(data ? { body: JSON.stringify(data) } : {}) });
      await refresh();
      if (auditCase !== null) await readAudit(auditCase);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }

  async function readAudit(id: number) {
    try {
      const response = await http<{ audit: AuditRow[] }>(`/defense/cases/${id}/audit`);
      setAuditCase(id);
      setAudit(response.audit);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Audit unavailable");
    }
  }

  async function readGraph(id: number) {
    try {
      const result = await http<EvidenceGraph>(`/defense/cases/${id}/graph`);
      setGraph(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Graph unavailable");
    }
  }

  async function triage(c: Case, next: string) {
    const reason = decisionReason.trim();
    if (reason.length < 12) { setError(minimumReason); return; }
    if (!window.confirm(`Change case #${c.id} from ${c.status} to ${next} and record your rationale?`)) return;
    await mutate(`/defense/cases/${c.id}/triage`, { status: next, reason });
  }

  async function decide(response: Response, decision: "approve" | "reject") {
    const reason = decisionReason.trim();
    if (reason.length < 12) { setError(minimumReason); return; }
    if (!window.confirm(
      `${decision === "approve" ? "Approve" : "Reject"} manual response #${response.id}? Approval never runs external containment.`
    )) return;
    await mutate(`/defense/responses/${response.id}/decision`, { decision, reason });
  }

  async function simulate(response: Response) {
    if (!window.confirm(
      `Generate an audit-logged dry-run for response #${response.id}? No firewall, EDR or identity operation will run.`
    )) return;
    setBusy(true);
    setError("");
    try {
      const result = await http<Preview>(`/defense/responses/${response.id}/simulate`, { method: "POST" });
      setPreview(result);
      await refresh();
      if (auditCase !== null) await readAudit(auditCase);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Simulation failed");
    } finally {
      setBusy(false);
    }
  }

  const openCases = cases.filter(c => active(c.status));
  const pending = responses.filter(r => r.status === "pending");
  const selected = playbooks.find(p => p.id === playbook);

  return (
    <div className="flex flex-col gap-6 p-5">
      <header className="space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h1 className="flex items-center gap-2 text-2xl font-semibold">
            <ShieldCheck className="size-6" /> Defense — Cases & Approvals
          </h1>
          <Link href="/function/defense" className="text-sm underline underline-offset-4">Back to SOC telemetry</Link>
        </div>
        <p className="text-muted-foreground max-w-3xl text-sm">
          Human-reviewed response planning with an append-only decision trail. Approval is an internal
          authorization record, never execution. All playbooks produce advisory-only dry runs.
        </p>
      </header>

      {loading && <p className="text-muted-foreground">Loading authorized incidents…</p>}
      {error && <p role="alert" className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">{error}</p>}
      <div className="grid gap-3 sm:grid-cols-3">
        <Card><CardHeader><CardTitle className="text-sm">Cases requiring review</CardTitle></CardHeader>
          <CardContent className="text-3xl font-semibold">{openCases.length}</CardContent></Card>
        <Card><CardHeader><CardTitle className="text-sm">Pending response proposals</CardTitle></CardHeader>
          <CardContent className="text-3xl font-semibold">{pending.length}</CardContent></Card>
        <Card><CardHeader><CardTitle className="text-sm">Execution mode</CardTitle></CardHeader>
          <CardContent className="flex items-center gap-2 font-semibold"><Eye className="size-4" /> Dry run only</CardContent></Card>
      </div>

      <Card>
        <CardHeader><CardTitle className="flex items-center gap-2"><AlertTriangle className="size-5" /> New alerts</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          {alerts.filter(a => !cases.some(c => c.alert_id === a.id)).map(a => (
            <div key={a.id} className="flex flex-wrap items-center justify-between gap-3 rounded-md border p-3 text-sm">
              <div><strong>Alert #{a.id} — {a.title}</strong>
                <p className="text-muted-foreground">Severity {a.severity} · Event #{a.event_id} · Asset IDs {a.asset_ids?.join(", ") || "unlinked"}</p>
              </div>
              <Button disabled={busy} variant="outline" onClick={() => void mutate("/defense/cases", { alert_id: a.id })}>
                Open case
              </Button>
            </div>
          ))}
          {alerts.every(a => cases.some(c => c.alert_id === a.id)) && (
            <p className="text-muted-foreground text-sm">All recent alerts already have a case.</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle><ClipboardCheck className="mr-2 inline size-5" /> Investigations</CardTitle></CardHeader>
        <CardContent className="space-y-4">
          <label className="block text-sm">Operator rationale (required for triage and approval)
            <textarea value={decisionReason} onChange={e => setDecisionReason(e.target.value)}
              maxLength={1200} rows={2} className="mt-1 w-full rounded-md border bg-background p-2"
              placeholder="Explain source evidence, business impact, ownership or rejection basis…" />
          </label>
          {cases.map(c => (
            <div key={c.id} className="rounded-md border p-3 text-sm">
              <div className="flex flex-wrap justify-between gap-2">
                <div><strong>Case #{c.id} · {c.title}</strong>
                  <p className="text-muted-foreground">
                    {c.status.toUpperCase()} · Severity {c.severity} · Alert #{c.alert_id} ·
                    Event #{c.event_id} · Updated {stamp(c.updated_at)}
                  </p>
                  <p className="mt-2 max-w-4xl">{c.summary}</p>
                  <p className="text-muted-foreground mt-1">Asset IDs {c.asset_ids?.join(", ") || "unlinked"}{
                    c.mitre_technique ? ` · ATT&CK hypothesis ${c.mitre_technique}` : ""
                  }</p>
                </div>
                <div className="flex flex-wrap items-start gap-2">
                  {c.status === "open" && <Button disabled={busy} variant="outline"
                    onClick={() => void triage(c, "investigating")}>Investigate</Button>}
                  {c.status === "investigating" && <Button disabled={busy} variant="outline"
                    onClick={() => void triage(c, "resolved")}>Resolve</Button>}
                  {active(c.status) && <Button disabled={busy} variant="outline"
                    onClick={() => void triage(c, "dismissed")}>Dismiss</Button>}
                  <Button disabled={busy} variant="outline" onClick={() => void readAudit(c.id)}>Audit trail</Button>
                  <Button disabled={busy} variant="outline" onClick={() => void readGraph(c.id)}>Evidence graph</Button>
                </div>
              </div>
            </div>
          ))}
          {cases.length === 0 && <p className="text-muted-foreground text-sm">No cases opened yet.</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Propose a manual response review</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-3 md:grid-cols-2">
            <label className="text-sm">Active case
              <select className="mt-1 w-full rounded-md border bg-background p-2"
                value={selectedCase} onChange={e => setSelectedCase(e.target.value)}>
                <option value="">Select an active case</option>
                {openCases.map(c => <option key={c.id} value={c.id}>Case #{c.id}: {c.title}</option>)}
              </select>
            </label>
            <label className="text-sm">Reviewed playbook
              <select className="mt-1 w-full rounded-md border bg-background p-2"
                value={playbook} onChange={e => setPlaybook(e.target.value)}>
                {playbooks.map(p => <option key={p.id} value={p.id}>{p.name} · {p.risk} risk</option>)}
              </select>
            </label>
          </div>
          {selected && <div className="rounded-md border bg-muted/20 p-3 text-sm">
            <p className="font-medium">{selected.name} — {selected.risk} impact risk</p>
            <p className="text-muted-foreground mt-1">{selected.explanation}</p>
            <ol className="mt-2 list-decimal space-y-1 pl-5">{selected.steps.map(step => <li key={step}>{step}</li>)}</ol>
          </div>}
          <label className="block text-sm">Evidence-based justification
            <textarea rows={3} maxLength={1200} value={proposalReason} onChange={e => setProposalReason(e.target.value)}
              className="mt-1 w-full rounded-md border bg-background p-2"
              placeholder="Why review this proposed measure? What evidence and dependencies have been verified?" />
          </label>
          <Button disabled={busy || !selectedCase || !selected || proposalReason.trim().length < 12}
            onClick={() => void mutate(`/defense/cases/${selectedCase}/responses`,
              { playbook, justification: proposalReason.trim() })}>Submit for human approval</Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Human approval queue</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          {responses.map(r => (
            <div key={r.id} className="rounded-md border p-3 text-sm">
              <div className="font-semibold">Response #{r.id} · {r.playbook}</div>
              <p className="text-muted-foreground">Case #{r.case_id} · Status {r.status.toUpperCase()} · {stamp(r.created_at)}</p>
              <p className="my-2">{r.justification}</p>
              {r.decision_reason && <p className="text-muted-foreground text-xs">Decision rationale: {r.decision_reason}</p>}
              <div className="mt-2 flex flex-wrap gap-2">
                {r.status === "pending" && active(r.case_status) && <>
                  <Button disabled={busy} variant="outline" onClick={() => void decide(r, "approve")}>Approve manual plan</Button>
                  <Button disabled={busy} variant="destructive" onClick={() => void decide(r, "reject")}>Reject</Button>
                </>}
                {r.status === "approved" && active(r.case_status) &&
                  <Button disabled={busy} variant="outline" onClick={() => void simulate(r)}>Simulate (no execution)</Button>}
              </div>
            </div>
          ))}
          {responses.length === 0 && <p className="text-muted-foreground text-sm">No response proposals yet.</p>}
        </CardContent>
      </Card>

      {preview && (
        <Card className="border-amber-500/40">
          <CardHeader><CardTitle>Audited simulation — external execution: {String(preview.executed)}</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p>{preview.warning}</p>
            <p className="font-semibold">{preview.playbook.name}</p>
            <ol className="list-decimal space-y-1 pl-5">{preview.playbook.steps.map(step => <li key={step}>{step}</li>)}</ol>
          </CardContent>
        </Card>
      )}

      {graph && (
        <Card>
          <CardHeader><CardTitle>Case #{graph.case_id} — linked evidence graph</CardTitle></CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p className="text-muted-foreground">{graph.note}</p>
            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-2">
                <p className="font-semibold">Recorded nodes</p>
                {graph.nodes.map(node => (
                  <div key={node.id} className="rounded-md border p-2">
                    <strong>{node.kind.replaceAll("_", " ")}</strong> · {node.id}
                    <p className="text-muted-foreground">{node.label}</p>
                  </div>
                ))}
              </div>
              <div className="space-y-2">
                <p className="font-semibold">Evidence relationships</p>
                {graph.edges.map((edge, index) => (
                  <div key={`${edge.source}:${edge.target}:${index}`} className="rounded-md border p-2">
                    {edge.source} → <strong>{edge.relation.replaceAll("_", " ")}</strong> → {edge.target}
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {auditCase !== null && (
        <Card>
          <CardHeader><CardTitle>Case #{auditCase} — append-only audit history</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {audit.map(entry => (
              <div key={entry.id} className="rounded-md border p-3 text-sm">
                <div className="font-medium">{entry.event_type.replaceAll("_", " ")} · {stamp(entry.occurred_at)}</div>
                <p className="text-muted-foreground text-xs">Actor: {entry.actor} · Audit #{entry.id} · Response #{entry.response_id || "none"}</p>
                <p className="mt-1">{entry.reason}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
