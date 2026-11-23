# ARTEX Emergency Auto-Containment (Phase 3.1 preview)

**Purpose:** A defender cannot wait for a human approval round when a trusted
sensor reports an active, rapid attack. This feature adds a *fast deterministic
response path* alongside the human-controlled incident review from Phase 3.

**Safety boundary:** The only live autonomous action implemented here is adding
an **exact public IPv4 source** to an operator-provisioned **nftables set with a
30–300 second kernel expiry**. Every action is visible on the SOC dashboard;
one click deletes its element, and a **PANIC STOP — pause & undo all** button
pauses new admissions before attempting to remove all outstanding blocks.
Simulation mode records the same decisions without touching the firewall.

This implementation **does not** disable users, isolate endpoints, change
routes or DNS, delete files, stop services, revoke credentials, or change OT
controller state. Those actions are not safely reversible through one click.
Removing a block does **not** restore previously dropped packets, terminated
sessions, lost work, or disrupted control processes.

## Architecture and performance

| Layer | Behavior | Risk boundary |
| --- | --- | --- |
| Suricata/Wazuh ingest | Existing authenticated normalizer | Uses only supported vendor source records, not generic event projections |
| Deterministic fast path | Correlate observations with a SQL index and fixed thresholds | No LLM calls, tool invocation, prompt processing, or human queue in path |
| Policy admission | PostgreSQL transaction, scoped IP check, budgets, pause state | All admissions are durable and tied to an event before any enforcement |
| Execution | Small unprivileged ARTEX client → local Unix socket → host helper → nftables set | Application needs no CAP_NET_ADMIN, shell, TCP management endpoint or remote API |
| Recovery | Kernel expiry, two-second process reconciliation, SQL action history | Kernel timeout still expires after process/DB failure |
| Human-in-loop | Explicit ARM, PAUSE, individual UNDO, global PANIC STOP, audit log | Operator can intervene without waiting for the attacking session to end |

The gateway update is requested immediately after event commit; no polling or
LLM round is needed. **No latency SLA has been established.** Measure p50/p95/p99
sensor-to-kernel-action timing in your actual deployment before relying on it
against machine-speed attackers. SQL ingest, collector delays, helper scheduling
and nftables update time remain part of the end-to-end latency.

### High-confidence activation criteria (version 1)

All automatic responses require **both**:
- A fresh observed event (no older than 30 seconds), a parsed, public IPv4
  **source**, and an explicit IPv4 **destination within the operator's protected
  CIDR allowlist**. Private, reserved, internal and operator-exempt source
  ranges are never blocked.
- The operator must set a non-off mode **and click ARM** in the SOC dashboard.
  ARM is persisted; PAUSE stops new admissions. The first startup is paused.

Only the following vendor-source rules may trigger:

| Rule | Minimum corroboration |
| --- | --- |
| \`repeated_critical_ids_v1\` | Three or more matching critical-severity **Suricata** network alert records with the same source IP, protected destination and signature within 10 seconds |
| \`active_password_spray_v1\` | Twelve or more different failed account names in **Wazuh** authentication events from one public IP to one protected destination within 60 seconds |

The word "critical" here reflects the upstream sensor severity, **not** a
verified compromise or an independently proven attribution. Forged sensor data
can induce false positives; ensure collection/authentication is restricted and
tune your sensor rules carefully. Most native Wazuh authentication events do
not include \`dst_ip\`; those events are **not eligible** for auto-blocking until
a trusted collector supplies a verified destination IP. Do not guess an IP
from untrusted log message text.

Limits: \`ARTEX_AUTO_CONTAIN_MAX_ACTIVE\` defaults to **20** live/pending sources
(maximum 50), \`ARTEX_AUTO_CONTAIN_MAX_PER_HOUR\` defaults to **50** (maximum 200),
and each kernel entry expires after **120 seconds** (configurable 30–300).
A human reversal suppresses the same IP from automatic re-blocking for
**30 minutes**. These are hard admission budgets, not claims of perfect
false-positive protection.

## Safe rollout (three stages)

### A. Simulate on an ordinary ARTEX deployment

In \`.env\` or container environment:

\`\`\`dotenv
ARTEX_MODE=defense
ARTEX_AUTO_CONTAIN_MODE=simulate
# Example documentation-only destination network; replace after review.
ARTEX_AUTO_CONTAIN_PROTECTED_CIDRS=192.0.2.0/24
ARTEX_AUTO_CONTAIN_EXEMPT_CIDRS=
ARTEX_AUTO_CONTAIN_TTL_SECONDS=120
ARTEX_AUTO_CONTAIN_MAX_ACTIVE=20
ARTEX_AUTO_CONTAIN_MAX_PER_HOUR=50
\`\`\`

Restart ARTEX, open **Functions → Emergency Containment**
(\`/function/defense/emergency\`), review the policy, and click **Arm emergency
policy**. Send authorized *test-only* Suricata or Wazuh events that include the
expected destination IP and matching corroboration. In simulation the ledger
records \`simulated\` — **no firewall changes can occur**. Verify the events,
action links, timings, audit log and single-click **Undo now**.

### B. Pre-provision and review a gateway firewall set

A network administrator must deliberately create an isolated nftables
table/set **in the actual firewall network namespace**. The following sample
is documentation-only; it uses TEST-NET-1 addresses and a **forward** hook,
which will not protect local host input or another network namespace.
**Do not deploy verbatim on critical infrastructure.** Customize and review
scope, high-availability behavior, fail-open/fail-safe requirements, OT safety,
management paths, and rollback access.

\`\`\`nft
table inet artex_emergency {
    set blocked_v4 {
        type ipv4_addr
        flags timeout
        gc-interval 5s
        size 50
    }
    chain guarded_forward {
        type filter hook forward priority -50; policy accept;
        ip daddr 192.0.2.0/24 ip saddr @blocked_v4 counter drop
    }
}
\`\`\`

Use \`nft -c -f\` to syntax-check the reviewed ruleset before loading.
The gateway helper only adds/deletes **set elements**; it never installs a
chain, changes priorities, flushes rules, or runs a shell.

### C. Run the minimal privileged **host-local helper**

Build a standalone helper:

\`\`\`bash
go build -o artex-emergency-agent ./cmd/artex-emergency-agent
\`\`\`

Run it as a separately constrained system service in the **gateway's host
network namespace**. Its required environment is:

\`\`\`dotenv
ARTEX_MODE=defense
ARTEX_AUTO_CONTAIN_MODE=nftables
ARTEX_AUTO_CONTAIN_PROTECTED_CIDRS=192.0.2.0/24
ARTEX_AUTO_CONTAIN_TTL_SECONDS=120
ARTEX_AUTO_CONTAIN_MAX_ACTIVE=20
ARTEX_AUTO_CONTAIN_MAX_PER_HOUR=50
ARTEX_AUTO_CONTAIN_SOCKET=/run/artex/emergency.sock
\`\`\`

The helper refuses to start unless the socket path is absolute, its parent
directory has no group/world write permission, and the exclusive nft set
exists with IPv4 timeout support. It binds **only to a Unix socket**, with
file mode \`0660\`. It needs **CAP_NET_ADMIN only in the gateway namespace**;
do **not** grant this capability to the full ARTEX container. Configure the
socket directory as, for example, root-owned \`/run/artex\` with permission
\`0750\` and a dedicated group allowed to connect to the socket. Limit that
group to the ARTEX backend account. The helper revalidates destination scope,
source exclusions, bounded TTL and supported operations independently of
the main application.

Mount the host socket into ARTEX with a deployment-specific Compose override
or native host service configuration. Ensure the ARTEX service identity can
connect to it through its matching group; the main application remains
unprivileged. **Do not publish or reverse-proxy the Unix helper to TCP**.
For initial testing, use a disposable Linux network namespace and nftables
ruleset rather than a real production gateway.

Set the ARTEX application's environment to the same \`ARTEX_MODE=defense\`,
\`ARTEX_AUTO_CONTAIN_MODE=nftables\`, protected/exempt CIDRs and:
\`ARTEX_AUTO_CONTAIN_SOCKET=/run/artex/emergency.sock\`.

Restart and check the SOC Emergency dashboard's backend readiness, then
click **Arm emergency policy**. If the socket, helper or nft set is unavailable,
no live action can be armed or applied.

## Dashboard and API

Every endpoint inherits ARTEX's existing administrator JWT + same-origin
cookie CSRF protection, and is unavailable outside \`ARTEX_MODE=defense\`.

| Method | Path | Result |
| --- | --- | --- |
| GET | \`/api/defense/emergency/status\` | Current mode, operator arming state, readiness, scope size and action count |
| POST | \`/api/defense/emergency/arm\` | Operator preauthorizes the fixed policy; live backend preflight required |
| POST | \`/api/defense/emergency/pause\` | Disables new admissions; leaves existing short-lived actions until undone or TTL |
| GET | \`/api/defense/emergency/actions?limit=100&before_id=N\` | Cursor-paged history of **all** automatic actions and evidence IDs |
| POST | \`/api/defense/emergency/actions/{id}/revert\` | **One-click** exact-IP removal/recorded undo; 30-minute suppress |
| POST | \`/api/defense/emergency/revert-all\` | **Panic stop**: pause, then attempt every outstanding removal |
| GET | \`/api/defense/emergency/audit\` | Operator arming, all admissions, enforcement successes/failures and reversals |

The database stores one ledger record per action with source IP, destination,
original event ID, rule, timestamp, backend, status, kernel latency, expiry
and reason. The associated audit table is append-only at the database trigger
level. A privileged database owner can bypass this restriction, so do not claim
cryptographic tamper resistance.

**Important:** The panic-stop response reports partial failures and remaining
items; it never claims full reversal if the kernel helper is unreachable.
A failed action may reflect an uncertain kernel operation — use **Undo now**
and verify the gateway directly. A browser or ARTEX process failure does not
extend the nftables kernel timeout.

## Release checklist

\`\`\`bash
go test ./defense ./containment ./server
go test -p 1 ./...
./scripts/verify.sh
cd web && npx tsc --noEmit
\`\`\`

Run simulated input and operator-rollback tests, a disposable gateway
smoke test, PostgreSQL migration and fault-injection tests (helper down,
process crash, duplicate messages, timeout expiry). Measure sensor-to-kernel
p99 and alert false-positive rates, verify excluded infrastructure and
OT/network management sources, and confirm the gateway rules really affect
the intended traffic paths before enabling \`nftables\` mode.

The high-speed rules are fixed and deliberately narrow. Further response
types must **not** be added to auto mode until a reliable reversal adapter,
strict target allowlist, operator safety review and availability testing
are implemented.

AGPL-3.0 and upstream attribution are preserved.
