"use client";

import * as React from "react";
import { Activity, PauseCircle, PlayCircle, RefreshCw, ShieldCheck } from "lucide-react";
import { http } from "@/lib/api";
import { AIReviewPanel } from "./ai-review-panel";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type InvestigationControl = {
  auto_intake: boolean;
  paused: boolean;
  queued: number;
  running: number;
  finished: number;
  engine: string;
  actions_enabled: boolean;
  automatic_containment: boolean;
  auto_intake_max_per_hour: number;
  note: string;
};
type InvestigationRun = {
  id: number;
  trigger: string;
  status: string;
  attempts: number;
  summary: string;
  last_error: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
};
type InvestigationFinding = {
  id: number;
  run_id: number;
  category: string;
  title: string;
  explanation: string;
  confidence: number;
  evidence_event_id: number;
  created_at: string;
  review_verdict: string;
  review_reason: string;
  reviewed_at: string | null;
};
type InvestigationReport = {
  case_id: number;
  runs: InvestigationRun[];
  findings: InvestigationFinding[];
  note: string;
};

export function InvestigationPanel({ caseID }: { caseID: number }) {
  const [control, setControl] = React.useState<InvestigationControl | null>(null);
  const [report, setReport] = React.useState<InvestigationReport | null>(null);
  const [reason, setReason] = React.useState("");
  const [error, setError] = React.useState("");
  const [message, setMessage] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const reload = React.useCallback(async () => {
    if (!Number.isSafeInteger(caseID) || caseID < 1) return;
    const [status, findings] = await Promise.all([
      http<InvestigationControl>("/defense/investigations/control"),
      http<InvestigationReport>(`/defense/cases/${caseID}/investigations`),
    ]);
    setControl(status);
    setReport(findings);
  }, [caseID]);

  React.useEffect(() => {
    if (!Number.isSafeInteger(caseID) || caseID < 1) return;
    let alive = true;
    void reload().catch(err => {
      if (alive) setError(err instanceof Error ? err.message : "Investigation status unavailable");
    });
    const timer = window.setInterval(() => {
      if (alive) void reload().catch(() => {});
    }, 5000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [reload, caseID]);

  async function post(path: string, body?: object) {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await http(path, { method: "POST", ...(body ? { body: JSON.stringify(body) } : {}) });
      await reload();
      setMessage("Recorded in ARTEX. This operation did not execute containment.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Investigation operation failed");
    } finally {
      setBusy(false);
    }
  }

  async function changeControl(partial: { auto_intake?: boolean; paused?: boolean }) {
    if (reason.trim().length < 12) {
      setError("Provide at least 12 characters explaining the control change.");
      return;
    }
    if (!window.confirm(
      "Change autonomous evidence-review controls? This never grants firewall, identity or agent execution rights."
    )) return;
    await post("/defense/investigations/control", { ...partial, reason: reason.trim() });
  }

  async function cancelRun(id: number) {
    if (reason.trim().length < 12) {
      setError("Record a cancellation reason of at least 12 characters.");
      return;
    }
    if (!window.confirm(`Cancel investigation #${id}? An already-committing SQL transaction may complete first.`)) return;
    await post(`/defense/investigations/${id}/cancel`, { reason: reason.trim() });
  }

  async function reviewFinding(id: number, verdict: string) {
    if (reason.trim().length < 12) {
      setError("Record the source evidence and a 12+ character review rationale.");
      return;
    }
    if (!window.confirm(
      `Record ${verdict.replaceAll("_", " ")} for finding #${id}? Verdicts are immutable. This does not authorize containment.`
    )) return;
    await post(`/defense/investigations/findings/${id}/review`, {
      verdict, reason: reason.trim(),
    });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Activity className="size-5" /> Autonomous Defensive Investigation
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        <p className="text-muted-foreground">
          Durable evidence-only jobs review case signals, Phase 6 correlations,
          asset context, ATT&CK hypotheses, and missing corroboration.
          Findings require a human verdict and cannot arm emergency containment.
          Deterministic v1 remains independent of the opt-in AI advisory panel below.
        </p>
        {error && <p role="alert" className="rounded-md border border-destructive p-3 text-destructive">{error}</p>}
        {message && <p role="status" className="rounded-md border p-3">{message}</p>}

        {control && (
          <div className="rounded-md border p-3">
            <p className="font-semibold">Control state · {control.paused ? "PAUSED" : "ACTIVE"}</p>
            <p className="mt-1 text-muted-foreground">
              Engine {control.engine} · Queued {control.queued} · Running {control.running} · Finished {control.finished}
              {" · "}Auto case intake {control.auto_intake ? "enabled" : "disabled"}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">{control.note}</p>
            <label className="mt-3 block">Operator rationale (required for controls, cancel and reviews)
              <textarea rows={2} maxLength={1200} value={reason}
                onChange={e => setReason(e.target.value)}
                className="mt-1 w-full rounded-md border bg-background p-2"
                placeholder="Document authorization, case evidence, false positives or safety dependencies…" />
            </label>
            <div className="mt-3 flex flex-wrap gap-2">
              <Button disabled={busy} variant="outline"
                onClick={() => void changeControl({ paused: !control.paused })}>
                {control.paused ? <PlayCircle className="mr-2 size-4" /> : <PauseCircle className="mr-2 size-4" />}
                {control.paused ? "Resume new investigations" : "Pause new investigations"}
              </Button>
              <Button disabled={busy} variant="outline"
                onClick={() => void changeControl({ auto_intake: !control.auto_intake })}>
                {control.auto_intake ? "Disable auto case intake" : "Enable high/critical auto case intake"}
              </Button>
              <Button disabled={busy || control.paused} onClick={() => void post(`/defense/cases/${caseID}/investigations`)}>
                <ShieldCheck className="mr-2 size-4" /> Queue this case for analysis
              </Button>
              <Button variant="outline" disabled={busy} onClick={() => void reload()}>
                <RefreshCw className="mr-2 size-4" /> Refresh
              </Button>
            </div>
          </div>
        )}

        {report && (
          <>
            <p className="text-muted-foreground">{report.note}</p>
            <div className="space-y-2">
              <h3 className="font-semibold">Investigation jobs</h3>
              {report.runs.map(run => (
                <div key={run.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-3">
                  <div>
                    <strong>Run #{run.id}</strong> · {run.status.toUpperCase()} · {run.trigger.replaceAll("_", " ")}
                    <p className="text-xs text-muted-foreground">
                      Attempts {run.attempts}/3 · Created {new Date(run.created_at).toLocaleString()}
                    </p>
                    {run.summary && <p className="mt-1">{run.summary}</p>}
                    {run.last_error && <p className="mt-1 text-amber-600">{run.last_error}</p>}
                  </div>
                  {(run.status === "queued" || run.status === "running") &&
                    <Button variant="outline" disabled={busy}
                      onClick={() => void cancelRun(run.id)}>Cancel investigation</Button>}
                </div>
              ))}
              {!report.runs.length && <p className="text-muted-foreground">No investigation has been queued for this case.</p>}
            </div>

            <div className="space-y-3">
              <h3 className="font-semibold">Evidence-backed findings and human review</h3>
              {report.findings.map(f => (
                <div key={f.id} className="rounded-md border p-3">
                  <div className="font-semibold">{f.title}</div>
                  <p className="mt-1 text-xs text-muted-foreground">
                    Finding #{f.id} · Run #{f.run_id} · {f.category.replaceAll("_", " ")}
                    {" · "}Supporting event #{f.evidence_event_id}
                    {" · "}Review confidence {f.confidence}/90 (not threat probability)
                  </p>
                  <p className="my-2">{f.explanation}</p>
                  {f.review_verdict ? (
                    <div className="rounded-md border p-2 text-xs">
                      Human verdict: <strong>{f.review_verdict.replaceAll("_", " ")}</strong>
                      {" · "}{f.review_reason}
                    </div>
                  ) : (
                    <div className="flex flex-wrap gap-2">
                      <Button disabled={busy} variant="outline" onClick={() => void reviewFinding(f.id, "supported")}>
                        Supported for investigation
                      </Button>
                      <Button disabled={busy} variant="outline" onClick={() => void reviewFinding(f.id, "refuted")}>
                        Refuted
                      </Button>
                      <Button disabled={busy} variant="outline" onClick={() => void reviewFinding(f.id, "needs_more_evidence")}>
                        Needs more evidence
                      </Button>
                    </div>
                  )}
                </div>
              ))}
              {!report.findings.length && <p className="text-muted-foreground">No investigator findings recorded yet.</p>}
            </div>
          </>
        )}
        <AIReviewPanel caseID={caseID} />
      </CardContent>
    </Card>
  );
}
