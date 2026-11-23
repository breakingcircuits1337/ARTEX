"use client";

import * as React from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Activity, BookOpen, GitBranch, RefreshCw, ShieldAlert } from "lucide-react";
import { http } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type Indicator = {
  id: number; type: string; value: string; confidence: number;
  confidence_meaning: string; first_seen: string; last_seen: string;
  first_event_id: number; evidence_count: number;
};
type Observation = {
  event_id: number; link_reason: string; linkage_confidence: number;
  recorded_at: string; source: string; external_id: string; kind: string;
  observed_at: string; src_ip: string; dst_ip: string; host: string;
};
type Relation = {
  id: number; source_indicator_id: number; target_indicator_id: number;
  evidence_event_id: number; relation: string; causal_claim: boolean;
};
type Mapping = {
  id: number; technique_id: string; tactic_id: string; confidence: number;
  mapping_source: string; rationale: string; evidence_event_id: number;
  mapped_at: string; confirmed: boolean;
};
type Intel = {
  case_id: number; mode: string; note: string;
  observations: Observation[]; indicators: Indicator[];
  relations: Relation[]; techniques: Mapping[];
};
type TimelineEvent = {
  kind: string; reference_id: number; occurred_at: string;
  summary: string; provenance: string; confidence: number;
};
type Timeline = { case_id: number; events: TimelineEvent[]; limit: number; note: string };
type ReadGraph = {
  nodes: { id: string; kind: string; label: string; metadata?: Record<string, unknown> }[];
  edges: { source: string; target: string; relation: string }[];
  note: string;
};

const stamp = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
};

export default function ThreatIntelligencePage() {
  const params = useParams<{ id: string }>();
  const id = Number(params.id);
  const validID = Number.isSafeInteger(id) && id > 0;
  const [intel, setIntel] = React.useState<Intel | null>(null);
  const [timeline, setTimeline] = React.useState<Timeline | null>(null);
  const [graph, setGraph] = React.useState<ReadGraph | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const [message, setMessage] = React.useState("");
  const [technique, setTechnique] = React.useState("");
  const [tactic, setTactic] = React.useState("");
  const [evidence, setEvidence] = React.useState("");
  const [confidence, setConfidence] = React.useState(40);
  const [reason, setReason] = React.useState("");

  const reload = React.useCallback(async () => {
    if (!validID) throw new Error("Invalid case identifier");
    const [intelligence, history, links] = await Promise.all([
      http<Intel>(`/defense/cases/${id}/intelligence`),
      http<Timeline>(`/defense/cases/${id}/timeline`),
      http<ReadGraph>(`/defense/cases/${id}/graph`),
    ]);
    setIntel(intelligence);
    setTimeline(history);
    setGraph(links);
    setEvidence(current => current && intelligence.observations.some(e => String(e.event_id) === current)
      ? current : String(intelligence.observations[0]?.event_id ?? ""));
  }, [id, validID]);

  React.useEffect(() => {
    let mounted = true;
    void reload().catch(err => {
      if (mounted) setError(err instanceof Error ? err.message : "Intelligence unavailable");
    }).finally(() => {
      if (mounted) setLoading(false);
    });
    return () => { mounted = false; };
  }, [reload]);

  async function refresh() {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await http(`/defense/cases/${id}/intelligence/refresh`, { method: "POST" });
      await reload();
      setMessage("Evidence correlation refreshed. No external containment or scanning occurred.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to refresh correlation");
    } finally {
      setBusy(false);
    }
  }

  async function submitMapping() {
    if (!technique.trim() || !evidence || reason.trim().length < 12) {
      setError("Provide a technique ID, linked evidence, and 12+ characters of rationale.");
      return;
    }
    if (!window.confirm("Record an unverified ATT&CK hypothesis linked to this case evidence? This does not confirm compromise or initiate response.")) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await http(`/defense/cases/${id}/intelligence/techniques`, {
        method: "POST",
        body: JSON.stringify({
          technique_id: technique.trim(), tactic_id: tactic.trim(),
          event_id: Number(evidence), confidence, reason: reason.trim(),
        }),
      });
      await reload();
      setMessage("Evidence-linked ATT&CK hypothesis recorded. This is not verified attribution.");
      setReason("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not record mapping");
    } finally {
      setBusy(false);
    }
  }

  const indicatorsByID = new Map(intel?.indicators.map(i => [i.id, i]) ?? []);

  return (
    <div className="flex flex-col gap-5 p-5">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold">
            <GitBranch className="size-6" /> Case #{validID ? id : "?"} — Threat Correlation
          </h1>
          <p className="mt-2 max-w-4xl text-sm text-muted-foreground">
            Evidence-linked indicators, MITRE ATT&CK hypotheses and incident timeline.
            Observed connections do not establish hostile intent, identity or causation.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" asChild><Link href="/function/defense/cases">Back to cases</Link></Button>
          <Button disabled={busy || !validID} onClick={() => void refresh()}>
            <RefreshCw className="mr-2 size-4" /> Refresh evidence correlation
          </Button>
        </div>
      </header>

      {loading && <p className="text-muted-foreground">Loading linked evidence…</p>}
      {error && <p role="alert" className="rounded-md border border-destructive p-3 text-sm text-destructive">{error}</p>}
      {message && <p role="status" className="rounded-md border p-3 text-sm">{message}</p>}

      {intel && (
        <>
          <div className="grid gap-3 sm:grid-cols-4">
            {[
              ["Recorded observations", intel.observations.length],
              ["Indicators", intel.indicators.length],
              ["Co-observations", intel.relations.length],
              ["ATT&CK hypotheses", intel.techniques.length],
            ].map(([title, count]) => (
              <Card key={String(title)}>
                <CardHeader><CardTitle className="text-sm">{title}</CardTitle></CardHeader>
                <CardContent className="text-3xl font-semibold">{count}</CardContent>
              </Card>
            ))}
          </div>
          <Card>
            <CardHeader><CardTitle className="flex items-center gap-2">
              <ShieldAlert className="size-5" /> Confidence and provenance
            </CardTitle></CardHeader>
            <CardContent className="space-y-2 text-sm">
              <p>{intel.note}</p>
              <p className="text-muted-foreground">
                Confidence indicates the strength of the *evidence link*, not the
                probability that an indicator is malicious. Correlation requires
                shared source and two matching observations within ±15 minutes.
                Results are bounded; refresh again when new telemetry arrives.
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>Observed indicators</CardTitle></CardHeader>
            <CardContent className="overflow-x-auto">
              <table className="w-full min-w-[650px] text-left text-sm">
                <thead><tr className="border-b text-muted-foreground">
                  <th className="p-2">Type</th><th>Observed value</th><th>Link confidence</th>
                  <th>Evidence</th><th>First → Last</th>
                </tr></thead>
                <tbody>
                  {intel.indicators.map(i => (
                    <tr key={i.id} className="border-b align-top">
                      <td className="p-2">{i.type}</td>
                      <td className="p-2 break-all font-mono text-xs">{i.value}</td>
                      <td className="p-2">{i.confidence}/100 <span className="text-xs text-muted-foreground">(link only)</span></td>
                      <td className="p-2">{i.evidence_count} record(s) · first event #{i.first_event_id}</td>
                      <td className="p-2 text-xs">{stamp(i.first_seen)} → {stamp(i.last_seen)}</td>
                    </tr>
                  ))}
                  {!intel.indicators.length && <tr><td colSpan={5} className="p-3 text-muted-foreground">No observed indicators yet.</td></tr>}
                </tbody>
              </table>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>Co-observation relationships</CardTitle></CardHeader>
            <CardContent className="space-y-2 text-sm">
              <p className="text-muted-foreground">Links are only recorded when two IP indicators occur in the same evidence event. No actor-attribution edges are created.</p>
              {intel.relations.map(rel => (
                <div key={rel.id} className="rounded-md border p-3">
                  <span className="break-all font-mono text-xs">
                    {indicatorsByID.get(rel.source_indicator_id)?.value ?? `Indicator #${rel.source_indicator_id}`}
                    {" ↔ "}
                    {indicatorsByID.get(rel.target_indicator_id)?.value ?? `Indicator #${rel.target_indicator_id}`}
                  </span>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {rel.relation.replaceAll("_", " ")} · Source evidence #{rel.evidence_event_id} · Not a causal claim
                  </p>
                </div>
              ))}
              {!intel.relations.length && <p className="text-muted-foreground">No co-observed indicator pairs.</p>}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>MITRE ATT&CK — hypotheses, not findings</CardTitle></CardHeader>
            <CardContent className="space-y-3 text-sm">
              {intel.techniques.map(m => (
                <div key={m.id} className="rounded-md border p-3">
                  <strong>{m.technique_id}</strong>{m.tactic_id && <span> · {m.tactic_id}</span>}
                  <p className="text-muted-foreground text-xs">
                    {m.mapping_source.replaceAll("_", " ")} · Confidence {m.confidence}/100
                    · Evidence #{m.evidence_event_id} · {stamp(m.mapped_at)}
                  </p>
                  <p className="mt-1">{m.rationale}</p>
                </div>
              ))}
              {!intel.techniques.length && <p className="text-muted-foreground">No ATT&CK mapping has been proposed.</p>}
              <div className="space-y-3 rounded-md border bg-muted/20 p-3">
                <h3 className="font-semibold">Record a reviewed hypothesis</h3>
                <p className="text-xs text-muted-foreground">
                  Identifier format is checked but catalog existence and behavior are not verified.
                  The evidence must already belong to this case. No response is authorized.
                </p>
                <div className="grid gap-3 sm:grid-cols-3">
                  <label>Technique ID
                    <input value={technique} onChange={e => setTechnique(e.target.value.toUpperCase())}
                      placeholder="T1110.003" maxLength={9}
                      className="mt-1 w-full rounded-md border bg-background p-2" />
                  </label>
                  <label>Tactic ID (optional)
                    <input value={tactic} onChange={e => setTactic(e.target.value.toUpperCase())}
                      placeholder="TA0006" maxLength={6}
                      className="mt-1 w-full rounded-md border bg-background p-2" />
                  </label>
                  <label>Supporting event
                    <select value={evidence} onChange={e => setEvidence(e.target.value)}
                      className="mt-1 w-full rounded-md border bg-background p-2">
                      <option value="">Select linked event</option>
                      {intel.observations.map(o =>
                        <option key={o.event_id} value={o.event_id}>#{o.event_id} — {o.source}:{o.external_id}</option>)}
                    </select>
                  </label>
                </div>
                <label className="block">Hypothesis confidence (1–90)
                  <input type="number" min={1} max={90} value={confidence}
                    onChange={e => setConfidence(Number(e.target.value))}
                    className="mt-1 w-full rounded-md border bg-background p-2" />
                </label>
                <label className="block">Rationale
                  <textarea value={reason} maxLength={1200} rows={3}
                    onChange={e => setReason(e.target.value)}
                    placeholder="Describe the observed evidence, alternative explanations, and why this technique may apply…"
                    className="mt-1 w-full rounded-md border bg-background p-2" />
                </label>
                <Button disabled={busy || !evidence || reason.trim().length < 12}
                  onClick={() => void submitMapping()}>
                  <BookOpen className="mr-2 size-4" /> Add evidence-linked ATT&CK hypothesis
                </Button>
              </div>
            </CardContent>
          </Card>
        </>
      )}

      {timeline && (
        <Card>
          <CardHeader><CardTitle className="flex items-center gap-2">
            <Activity className="size-5" /> Incident timeline ({timeline.events.length} entries)
          </CardTitle></CardHeader>
          <CardContent className="space-y-3 text-sm">
            <p className="text-muted-foreground">{timeline.note}</p>
            <ol className="space-y-2 border-l pl-4">
              {timeline.events.map((item, index) => (
                <li key={`${item.kind}:${item.reference_id}:${index}`} className="relative rounded-md border p-3">
                  <div className="font-semibold">{item.kind.replaceAll("_", " ")} · {stamp(item.occurred_at)}</div>
                  <p className="mt-1">{item.summary}</p>
                  <p className="text-xs text-muted-foreground">
                    Provenance: {item.provenance} · Record #{item.reference_id}
                    {item.confidence ? ` · Evidence linkage/hypothesis confidence ${item.confidence}/100` : ""}
                  </p>
                </li>
              ))}
              {timeline.events.length === 0 && <li className="text-muted-foreground">No timeline records yet.</li>}
            </ol>
          </CardContent>
        </Card>
      )}

      {graph && (
        <Card>
          <CardHeader><CardTitle>Case graph inspector</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p className="text-muted-foreground">{graph.note}</p>
            <p>{graph.nodes.length} evidence nodes · {graph.edges.length} recorded edges</p>
            <div className="grid gap-4 lg:grid-cols-2">
              <div className="space-y-2">
                {graph.nodes.map(node => (
                  <div key={node.id} className="rounded-md border p-2">
                    <strong>{node.kind.replaceAll("_", " ")}</strong> · {node.id}
                    <p className="break-all text-xs">{node.label}</p>
                  </div>
                ))}
              </div>
              <div className="space-y-2">
                {graph.edges.map((edge, index) => (
                  <div key={`${edge.source}:${edge.target}:${index}`} className="rounded-md border p-2 text-xs">
                    {edge.source} → <strong>{edge.relation.replaceAll("_", " ")}</strong> → {edge.target}
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
