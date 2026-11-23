"use client";

import * as React from "react";
import { AlertTriangle, BrainCircuit, RefreshCw, ShieldCheck } from "lucide-react";
import { http } from "@/lib/api";
import { Button } from "@/components/ui/button";

type AIRun = {
  id: number;
  status: "running" | "completed" | "failed";
  summary: string;
  error_code: string;
  packet_sha256: string;
  created_at: string;
  completed_at: string | null;
};
type AIFinding = {
  id: number;
  run_id: number;
  category: string;
  explanation: string;
  evidence_event_id: number;
  review_verdict: string;
  review_reason: string;
};
type AIReport = {
  enabled: boolean;
  model_configured: boolean;
  runs: AIRun[];
  findings: AIFinding[];
  note: string;
};
type AIPreview = {
  packet_sha256: string;
  no_model_call: boolean;
  requires_fresh_consent: boolean;
  note: string;
  packet: {
    schema: string;
    alert_severity: string;
    facts: Array<{
      ref: string; source: string; kind: string;
      relation: string; link_confidence: number;
    }>;
    interpretation: string;
  };
};
function label(text: string): string { return text.replaceAll("_", " "); }

export function AIReviewPanel({ caseID }: { caseID: number }) {
  const [report, setReport] = React.useState<AIReport | null>(null);
  const [consent, setConsent] = React.useState(false);
  const [preview, setPreview] = React.useState<AIPreview | null>(null);
  const [reason, setReason] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const [message, setMessage] = React.useState("");

  const refresh = React.useCallback(async () => {
    if (!Number.isSafeInteger(caseID) || caseID < 1) return;
    const result = await http<AIReport>(`/defense/cases/${caseID}/ai-reviews`);
    setReport(result);
  }, [caseID]);

  React.useEffect(() => {
    setPreview(null);
    setConsent(false);
    let live = true;
    void refresh().catch(e => { if (live) setError(e instanceof Error ? e.message : "AI review data unavailable"); });
    const timer = window.setInterval(() => {
      if (live && !document.hidden) void refresh().catch(() => {
        if (live) setError("AI review data unavailable; refresh before making decisions.");
      });
    }, 12000);
    return () => { live = false; window.clearInterval(timer); };
  }, [refresh]);

  async function loadPreview() {
    if (busy || !report?.enabled) return;
    setBusy(true);
    setPreview(null);
    setConsent(false);
    setError("");
    setMessage("");
    try {
      const result = await http<AIPreview>(`/defense/cases/${caseID}/ai-reviews/preview`);
      if (!result.no_model_call || !result.requires_fresh_consent ||
          result.packet.schema !== "artex-redacted-evidence-v1" ||
          !/^[0-9a-f]{64}$/.test(result.packet_sha256)) {
        throw new Error("Server did not return a valid read-only evidence preview");
      }
      setPreview(result);
      setMessage("Inspect the exact model-bound evidence below; no AI request was made.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to prepare evidence preview");
    } finally {
      setBusy(false);
    }
  }

  async function requestReview() {
    if (!consent || !preview || busy) return;
    if (!window.confirm(
      "Send only categorical case evidence (not raw logs, IPs, usernames or credentials) to your configured AI provider? " +
      "The model may be remote and the provider may retain requests under its own policy. " +
      "This creates unverified advice for manual review only; it cannot execute tools or containment. " +
      "The request must match preview SHA-256 " + preview.packet_sha256.slice(0, 16) + "…."
    )) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await http(`/defense/cases/${caseID}/ai-reviews`, {
        method: "POST",
        body: JSON.stringify({
          consent_to_model: true, reviewed_packet_sha256: preview.packet_sha256,
        }),
      });
      setMessage("Unverified AI suggestions saved. Review each citation and the original sensor evidence.");
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "AI review failed");
      await refresh().catch(() => {});
    } finally {
      setConsent(false); // Every model call requires a new explicit preflight.
      setPreview(null);
      setBusy(false);
    }
  }

  async function decide(finding: AIFinding, verdict: "supported" | "refuted" | "needs_more_evidence") {
    if (reason.trim().length < 12 || busy) {
      setError("Provide a 12+ character evidence-based rationale before recording a decision.");
      return;
    }
    if (!window.confirm(
      `Record an immutable ${label(verdict)} verdict for AI suggestion #${finding.id}? This does NOT confirm compromise or authorize action.`
    )) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await http(`/defense/ai-reviews/${finding.id}/decision`, {
        method: "POST", body: JSON.stringify({ verdict, reason: reason.trim() }),
      });
      setMessage("Human advisory verdict recorded. No response or containment was approved.");
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to record verdict");
    } finally { setBusy(false); }
  }

  const canRequest = report?.enabled && report.model_configured;
  const hasRunning = report?.runs.some(run => run.status === "running") ?? false;
  return (
    <section className="mt-6 space-y-4 rounded-lg border p-4" aria-label="AI-assisted defensive investigation">
      <div className="flex items-center gap-2">
        <BrainCircuit className="size-5" />
        <h3 className="font-semibold">AI-assisted investigation · PR #15 evidence safety</h3>
      </div>
      <div className="rounded border border-amber-500/50 bg-amber-500/5 p-3 text-sm">
        <p className="flex items-center gap-2 font-medium">
          <AlertTriangle className="size-4" /> Unverified AI advice — analyst verification required
        </p>
        <p className="mt-1 text-muted-foreground">
          Only redacted categorical evidence and temporary references are sent to the configured model
          after the analyst previews the exact packet and explicitly consents to that digest.
          The model has no tools. It cannot update deterministic findings,
          change ATT&amp;CK mappings, alter the case status or authorize emergency containment.
        </p>
      </div>
      {!report && !error && <p className="text-muted-foreground">Loading AI review status…</p>}
      {report && (
        <p className="text-xs text-muted-foreground">
          {report.enabled ? "Operator feature enabled" : "Disabled by server configuration"}
          {" · "}{report.model_configured ? "AI provider configured" : "No AI provider configured"}
          {" · "}{report.note}
        </p>
      )}
      {error && <p role="alert" className="rounded border border-destructive p-2 text-destructive">{error}</p>}
      {message && <p role="status" className="rounded border p-2">{message}</p>}
      <div className="flex flex-wrap gap-2">
        <Button disabled={!canRequest || busy || hasRunning} variant="outline"
          onClick={() => void loadPreview()}>
          Preview exact redacted evidence · no model call
        </Button>
        <Button disabled={busy} variant="outline" onClick={() => void refresh()}>
          <RefreshCw className="mr-2 size-4" /> Refresh
        </Button>
      </div>
      {preview && (
        <div className="rounded border p-3 text-sm">
          <p className="font-medium">Evidence egress preview · SHA-256 {preview.packet_sha256}</p>
          <p className="mt-2 text-muted-foreground">
            These are the exact categorical JSON facts the model will receive.
            Nothing has been sent to the model. Changes to case evidence require another preview.
          </p>
          <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-words rounded bg-muted p-3 text-xs"
            aria-label="Redacted model evidence packet">
            {JSON.stringify(preview.packet, null, 2)}
          </pre>
          <p className="mt-2 text-xs text-muted-foreground">{preview.note}</p>
        </div>
      )}
      <label className="flex items-start gap-3 text-sm">
        <input className="mt-1" type="checkbox" checked={consent} disabled={busy || !canRequest || !preview}
          onChange={event => setConsent(event.target.checked)} />
        <span>I have reviewed this exact evidence packet and approve ONE AI request.
          I understand that an external configured provider may receive these categorical facts
          and retain them under its own policy. Model output remains unverified.</span>
      </label>
      <Button disabled={!canRequest || !consent || !preview || busy || hasRunning}
        onClick={() => void requestReview()}>
        <ShieldCheck className="mr-2 size-4" /> Request AI review of previewed evidence
      </Button>
      {busy && <p role="status" className="text-muted-foreground">Waiting for the model or saving an analyst decision…</p>}
      {(report?.runs ?? []).map(run => (
        <div key={run.id} className="rounded border p-3 text-sm">
          <p className="font-semibold">Advisory #{run.id} · {run.status.toUpperCase()}</p>
          <p className="text-xs text-muted-foreground">
            {new Date(run.created_at).toLocaleString()} · Packet SHA-256: {run.packet_sha256.slice(0, 16)}…
          </p>
          {run.summary && <p className="mt-2">{run.summary}</p>}
          {run.error_code && <p className="mt-2 text-amber-600">Review failed: {label(run.error_code)} (no findings were trusted)</p>}
        </div>
      ))}
      {(report?.findings?.length ?? 0) > 0 && (
        <div>
          <label className="block text-sm font-medium">
            Analyst rationale (required for AI finding review)
            <textarea rows={2} maxLength={1200} value={reason}
              onChange={e => setReason(e.target.value)}
              placeholder="Cite original telemetry and approved change context…"
              className="mt-2 w-full rounded border bg-background p-2" />
          </label>
        </div>
      )}
      {(report?.findings ?? []).map(finding => (
        <div key={finding.id} className="space-y-2 rounded border p-3 text-sm">
          <p className="font-medium">{label(finding.category)} · Suggestion #{finding.id}</p>
          <p>{finding.explanation}</p>
          <p className="text-xs text-muted-foreground">
            AI citation maps to case event #{finding.evidence_event_id} ·
            Advisory run #{finding.run_id} · Not verified compromise.
          </p>
          {finding.review_verdict ? (
            <p className="rounded border p-2 text-xs">Human verdict: <strong>{label(finding.review_verdict)}</strong>.
              {" "}{finding.review_reason}</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" disabled={busy}
                onClick={() => void decide(finding, "supported")}>Supported for review</Button>
              <Button variant="outline" disabled={busy}
                onClick={() => void decide(finding, "refuted")}>Refuted</Button>
              <Button variant="outline" disabled={busy}
                onClick={() => void decide(finding, "needs_more_evidence")}>Needs more evidence</Button>
            </div>
          )}
        </div>
      ))}
      {!report?.runs.length && (
        <p className="text-xs text-muted-foreground">No AI review has been requested. Deterministic investigations continue unchanged.</p>
      )}
    </section>
  );
}
