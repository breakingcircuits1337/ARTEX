"use client";

import * as React from "react";

type StreamState = "connecting" | "live" | "polling";

// Read only, authenticated fetch SSE: native EventSource cannot send ARTEX's
// bearer header. Never put JWTs into URLs, browser history or proxy logs.
function socStreamURL() {
  const override = process.env.NEXT_PUBLIC_SSE_BASE;
  const base = override !== undefined
    ? override
    : process.env.NODE_ENV !== "production"
      ? `${window.location.protocol}//${window.location.hostname}:8787`
      : "";
  return base ? `${base.replace(/\/$/, "")}/api/defense/live` : "/api/defense/live";
}

export function useSOCLive(onRevision: () => void): StreamState {
  const [state, setState] = React.useState<StreamState>("connecting");
  const current = React.useRef(onRevision);
  React.useEffect(() => { current.current = onRevision; }, [onRevision]);

  React.useEffect(() => {
    let stopped = false;
    let active = false;
    let failures = 0;
    let signature = "";
    let generation = 0;
    let controller: AbortController | null = null;
    let retry: number | undefined;
    const decoder = new TextDecoder();

    const fallback = window.setInterval(() => {
      if (!active && !document.hidden) current.current();
    }, 8000);

    async function connect() {
      if (stopped || document.hidden) return;
      const myGeneration = ++generation;
      const connection = new AbortController();
      controller = connection;
      setState("connecting");
      let ready = false;
      const initialWatchdog = window.setTimeout(() => connection.abort(), 10000);
      try {
        const token = window.localStorage.getItem("artex_token");
        const response = await fetch(socStreamURL(), {
          method: "GET",
          headers: {
            Accept: "text/event-stream",
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
          cache: "no-store",
          signal: connection.signal,
        });
        if (!response.ok || !response.body || !response.headers.get("content-type")?.includes("text/event-stream")) {
          throw new Error("SOC live stream unavailable");
        }
        const reader = response.body.getReader();
        let pending = "";
        let eventName = "";
        let data = "";
        while (!stopped && !connection.signal.aborted) {
          const { value, done } = await reader.read();
          if (done) break;
          // Never accumulate unbounded, untrusted stream bytes.
          pending += decoder.decode(value, { stream: true });
          if (pending.length > 16384) throw new Error("Invalid SOC stream frame");
          let lineEnd = pending.indexOf("\n");
          while (lineEnd !== -1) {
            const line = pending.slice(0, lineEnd).replace(/\r$/, "");
            pending = pending.slice(lineEnd + 1);
            if (line === "") {
              if (eventName === "revision" && data) {
                const revision: unknown = JSON.parse(data);
                if (revision && typeof revision === "object" &&
                    "events" in revision && "alerts" in revision && "case_updated_micros" in revision &&
                    typeof revision.events === "number" && typeof revision.alerts === "number" &&
                    typeof revision.case_updated_micros === "number") {
                  const next = `${revision.events}:${revision.alerts}:${revision.case_updated_micros}`;
                  if (signature !== next) {
                    signature = next;
                    current.current();
                  }
                }
                if (!ready) {
                  ready = true;
                  active = true;
                  failures = 0;
                  setState("live");
                  window.clearTimeout(initialWatchdog);
                }
              }
              if (eventName === "unavailable") throw new Error("SOC database temporarily unavailable");
              eventName = "";
              data = "";
            } else if (line.startsWith("event: ")) {
              eventName = line.slice(7);
            } else if (line.startsWith("data: ")) {
              data += line.slice(6);
              if (data.length > 8192) throw new Error("Oversized stream frame");
            }
            lineEnd = pending.indexOf("\n");
          }
        }
      } catch {
        // Polling is a durable fallback for buffering proxies, load limits,
        // server restart, and interrupted network connections.
      } finally {
        window.clearTimeout(initialWatchdog);
        if (myGeneration === generation) active = false;
        if (controller === connection) controller = null;
        connection.abort();
      }
      if (!stopped && !document.hidden && myGeneration === generation) {
        failures += 1;
        setState("polling");
        retry = window.setTimeout(() => { void connect(); }, Math.min(16000, 1500 * 2 ** Math.min(failures, 4)));
      }
    }

    function visibilityChanged() {
      generation += 1;
      if (retry) window.clearTimeout(retry);
      controller?.abort();
      active = false;
      if (document.hidden) return;
      current.current();
      void connect();
    }
    document.addEventListener("visibilitychange", visibilityChanged);
    void connect();

    return () => {
      stopped = true;
      controller?.abort();
      if (retry) window.clearTimeout(retry);
      window.clearInterval(fallback);
      document.removeEventListener("visibilitychange", visibilityChanged);
    };
  }, []);
  return state;
}
