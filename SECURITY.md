# ARTEX-DEFENSE Security Policy

## Supported Versions

This policy covers **Breaking Circuits' ARTEX-DEFENSE fork**, not third-party
ARTEX releases or unrelated downstream builds. At this stage the repository has
**no tagged ARTEX-DEFENSE release**; fixes are developed on `main` on a best-effort
basis. `main` is under active development, is not a stable security-certified
release, and may change without notice. Once this fork publishes a versioned
release, this section should be updated to name supported release lines.

Please provide the exact fork commit SHA or image digest when reporting a problem.
Vulnerabilities that affect an upstream component should also be coordinated
with its maintainers, without disclosing a fork vulnerability publicly.

## Rootless-host deployment and execution safeguards (Phase 20)

When explicitly requested, ARTEX refuses startup unless Linux user
namespace UID 0 maps to a nonzero parent UID and the separate agent
executor UID/GID drop remains active. Compose deployments now require
the executor drop by default. Linux Bash and MCP command shims set
`PR_SET_NO_NEW_PRIVS` after dropping identity. The executor home is
opened without following a symlink before privileged ownership changes.
This strengthens host/agent separation **without changing agent network
connectivity or introducing hidden egress policies**.

A rootless Docker daemon plus the opt-in guard protects the host-root
boundary, but the Go server remains namespace-root inside the container.
Per-task identities, complete filesystem sandboxing and the archive
restore audit remain follow-on security work. Full instructions, tests,
compatibility warnings and limitations are in
[PR #20 security notes](docs/DEFENSE_PHASE20.md).

## Runtime isolation and container hardening (Phase 19)

The authenticated workspace file manager now binds reads, downloads,
uploads, writes, directory creation and recursive deletion to `os.Root`,
including pinned parent directories for atomic file replacement. Docker
Compose runs with no-new-privileges, reduced capabilities, a process budget,
init reaping, ephemeral `/tmp`, and read-only local skill sources.
The release pipeline runs a checksum-verified container image vulnerability
scan and blocks known **fixable** HIGH/CRITICAL vulnerabilities in the
Linux/amd64 runtime image before publication.

This does **not** make the main server non-root or isolate workers as a
complete sandbox. Races involving symlinks **inside** the data root, other
archive/restore server paths, hardlinks/mounts and native runtime caches,
and the unscanned Linux/arm64 image remain explicitly out of scope.
See [Phase 19 limitations and validation](docs/DEFENSE_PHASE19.md).

## Release qualification

Pull requests and tagged releases now have blocking Go and Node dependency
vulnerability gates, plus dedicated CodeQL analysis. Release publication is
gated on the full tagged-SHA CI matrix, SemVer/tag ancestry validation, package
checks, checksums, CycloneDX inventories and build attestations. See
[Phase 18](docs/DEFENSE_PHASE18.md).

These scans do **not** assess all third-party executables, Python packages
or container OS layers; the principal server remains root-owned, and
filesystem/operational gaps are documented below. Production deployment
requires review of vulnerabilities, keys, network boundaries, backups,
rollback and site safety; no automated green check certifies OT readiness.

## Reporting a Vulnerability

**Do not disclose exploit details, credentials, logs containing sensitive data,
or reproduction payloads in a public issue or pull request.**

Use this fork's [GitHub private vulnerability reporting form](https://github.com/breakingcircuits1337/ARTEX-DEFENSE/security/advisories/new)
when it is available. Private vulnerability reporting is a **GitHub repository
setting**, not something this Markdown file can enable: maintainers must enable it
under the repository's security settings and verify the form works for reporters.

If the private reporting form is not available, **do not post vulnerability
details publicly**. Request that the Breaking Circuits maintainer enable a private
reporting channel; a public issue may contain only a generic request for a
private contact method, with no technical details or identifying evidence.
Do not send fork vulnerabilities to the upstream BaaRai advisory form as a
substitute for contacting this fork's maintainers.

Please include privately:
- The affected ARTEX-DEFENSE commit/release and expected impact.
- Deployment mode (`defense` or `pentest`), OS, Docker/runtime and database version.
- Minimal steps to reproduce using assets you own or are authorized to test.
- Redacted logs and evidence, with no secrets or third-party personal data.
- Suggested mitigation or fix, if available.

## Scope and Authorized Testing

ARTEX-DEFENSE includes an opt-in penetration-testing mode alongside defensive
SOC workflows. Test only against deployments and networks you own or for which
you have explicit written authorization. Do not run active assessment against
third-party systems without their permission. Emergency containment must be
separately authorized, reviewed and tested in simulation before use on live
networks; enabling defense mode does **not** enable automatic blocking.

## Trusted Inputs and Scope Enforcement

ARTEX trusts the scanner output file (`output.json`) that `ingest_bbot` reads. The `scope_distance` field carried on scope-relevant events is the scanner's own verdict and is ingested as-is: an event the scanner marks in scope (per its own `-s`/`--no-scope` configuration) is treated as in scope without being re-checked against ARTEX's rule set.

The enforced trust boundary for asset insertion is `insert_assets`, which runs every candidate through `EvaluateAssetGate`: block rules always apply, and a task allow-list is enforced when one is configured. A rejected candidate is returned as an `insertion forbidden` error for that asset and is never inserted, so it cannot reach task execution. `in_scope_not_asset` in the `ingest_bbot` result is a different count: in-scope events that are not asset types (findings and the like).

Accepted gap: when a task has no allow-list, there is no allow rule to apply (block rules still run), and any host carried on an in-scope event that is not blocked enters the graph as an asset. Operators who rely on the scanner's scope rules alone should configure an allow-list per task, or review `output.json` before feeding it to ARTEX. Cross-checking ingested events against ARTEX's own rule set would change what existing scanner configurations mean for those operators, so it is treated as a deliberate design question (see #317), not an accepted vulnerability.

## Outbound Model Listing (`POST /api/llm/models`)

`POST /api/llm/models` fetches model lists from the provider endpoint and optional HTTP proxy supplied in the request. By default, ARTEX allows only `http` and `https` URLs whose hosts resolve exclusively to public IP addresses (blocking loopback, RFC1918 private networks, IPv6 unique-local `fc00::/7`, link-local/cloud metadata such as `169.254.169.254`, unspecified, and multicast addresses, carrier-grade NAT `100.64.0.0/10`, the benchmarking range `198.18.0.0/15`, `192.0.0.0/24` and the reserved block `240.0.0.0/4`; a NAT64 `64:ff9b::/96` or 6to4 `2002::/16` address is judged by the IPv4 address it embeds), and enforces the same checks on redirects and at dial time. A non-200 answer from the endpoint is reported by its status only; its body is not returned. The built-in local Ollama default (`http://127.0.0.1:11434/v1`) is permitted only when the request leaves `base_url` empty for the `ollama` provider.

Operators running self-hosted LLM gateways or Ollama on a LAN or Docker bridge can allow specific endpoints with `ARTEX_LLM_PRIVATE_ENDPOINTS`, a comma-separated list of exact `host:port` entries (for example, `127.0.0.1:11434,host.docker.internal:11434,192.168.1.10:11434`). A URL whose `host:port` matches an entry may resolve to a loopback or private address, or to an address in `100.64.0.0/10` or `198.18.0.0/15` (an overlay network, a fake-IP resolver), while scheme restrictions, link-local/cloud-metadata blocks, the other reserved ranges above, and redirect validation still apply; everything else stays refused. Leaving `ARTEX_LLM_PRIVATE_ENDPOINTS` unset or empty keeps the strict public-only policy.

## Agent Process Isolation

The server runs as root, but the processes an agent starts (Bash, the interactive shell, custom tools and stdio MCP servers) run as the unprivileged uid and gid set by `-exec-uid` and `-exec-gid` (default 10001). Only the run directories and their own home (`<data>/exec-home`) are writable by them. No agent working directory is an ancestor of another: the main agent and the planner work in `tasks/<id>/main`, a worker in `tasks/<id>/i<N>`, a chat in `sessions/<id>`. Their parents (`tasks/`, `sessions/` and `tasks/<id>`) are root:root 0755, so the executor cannot create, rename or remove an entry there, and only the leaves are shared with the executor group (setgid, 0775); with the drop active the server creates each level without following a symlink. Entries that a task already had directly under `tasks/<id>/` before this layout (uploads, files the main agent wrote there) are not moved and are shared with the executor group again, at start-up and on archive restore, so for tasks in progress too, while `tasks/<id>` itself stays root:root 0755: the main agent's new run directory `main/` is empty on its first turn, and the earlier artifacts stay under `tasks/<id>/` and are reached through Bash only. `keys/` (`jwt.key`, `secret.key`), the config file and the MITM CA key are root-only, and the server's environment block no longer carries `ARTEX_PG_DSN`, `ARTEX_SECRET_KEY`, the LLM API keys or the LLM proxy and base URLs (Linux). The agent's file tools (Read, Write, Edit, MultiEdit, LS, Glob, Grep) run inside the server but reach only the run's working directory: paths are opened through `os.Root`, so absolute paths elsewhere, `..` and symlinks leading out are refused, and a working directory reached through any symlink is refused. The executor cannot replace a run directory or one of its parents, so the race that remains is the swap between an `EvalSymlinks` check and the open of a file inside a run directory, which the executor can do only inside a leaf (every executor process has the same identity, so this is any leaf, never a leaf itself or its parents). `ingest_bbot` reads its file through the same confinement. Custom-tool scripts are protected only when the executor privilege drop is active: they are then written to `<data>/exec-scripts`, a root-owned directory the executor can read and cannot change; with the drop disabled they still go to `.tools/` under the run directory. Command-output spills (the full output of a tool call over the size cap, written by Norma inside the server) follow the same rule: with the drop active they go to a root-owned directory per task or chat session outside the run directory, `<data>/spill/tasks/<id>` or `<data>/spill/sessions/<id>` (root with the executor group, 0750, below root:root 0755 parents), which is deleted and archived with the task, or deleted with the conversation. The executor cannot create, rename or remove an entry there. Norma writes a spill file 0600 and the server makes it root with the executor group, 0640, when the tool call returns: the agent reads it with Bash, not with the file tools, which do not reach outside the run directory. With the drop disabled spills still go to `cmd-output/` under the run directory. Residual, not closed here: some other root reads and writes by path remain open, and a symlink the executor places can redirect them, so root may read or write outside the workspace. The scanner ingestion read is confined by `os.Root`; task-archive package source reads and operator image source/destination opens are now likewise rooted and verified. Chat attachment uploads are now opened through `os.Root` anchored at the application data directory with exclusive create, though other workspace upload paths still require review. Remaining paths include workspace uploads, archive staging/restore renames and journal/recovery paths, and the background-task output that Norma writes inside the server under `os.TempDir()/norma` (`<tmp>/norma/<session>/tasks/`), a path ARTEX does not choose: with the drop active the server creates that directory root:root 0755 at start-up, before any agent process runs, and refuses to start when it is a symlink or not a directory, or when a pre-existing `<tmp>/norma` is one the executor can write (this can refuse a start that worked before; the operator remedy is to remove that directory or set `TMPDIR` to a directory the executor cannot write; ARTEX never modifies or deletes the directory), but a directory already there under another owner is used as found, with a warning in the log. `TMPDIR` must be a root-controlled path: the start-up check follows `TMPDIR` and inspects `<tmp>/norma` and its immediate parent only, so a symlink or an ancestor below a directory the executor can write is not detected, and POSIX ACLs are not inspected. The `ask_operator` image staging is narrower than those. It creates `tasks/<id>/uploads` with `Mkdir` and checks it with `Lstat` (a symlink or anything that is not a directory is refused), gives the copy a random name `ask-operator-<unixnano>-<8 hex>.<ext>` created with `O_EXCL` and mode 0640, so it never overwrites a file, and opens the source only when the `Lstat` of the path and the `Stat` of the opened file agree (`os.SameFile`). What remains there: a directory component inside the run directory can be swapped for a symlink between the check and the open, so root can still read a file outside the run directory and stage a copy of it; an `uploads/` directory that existed before start-up or an archive restore is shared with the executor group and stays group-writable, so a staged copy can be replaced after it is written and the operator may see another image; with `fs.protected_hardlinks=0` a hard link to a file the executor cannot read is copied; and a FIFO swapped in after the `Lstat` blocks the call. The Docker image has no setuid programs and `docker-compose.yml` sets `no-new-privileges`. These are a containment layer, not a sandbox: an executor can still read world-readable files under the data directory, reach the loopback API and the database if the network allows it, and use any credential it was given through the platform. Persistence tools (custom tools, MCP servers, skills) need operator approval by default.

## What to Expect

This is an open-source project maintained on a best-effort basis. We aim to acknowledge a report within about a week and keep you updated, but we cannot guarantee specific response or fix timeframes.

## If a Report Is Accepted

- We will open a private **GitHub Security Advisory** for coordination.
- We will identify the release containing the fix when it is published.
- We may request a **CVE** if the vulnerability qualifies.
- We will credit you or your organization in the advisory if you wish.
- Default disclosure timing: **90 days** after a fix is available, or earlier by mutual agreement. If the vulnerability is being exploited in the wild, we may disclose earlier.

## If a Report Is Declined

We will explain the reason, for example:
- It is not a security vulnerability but intended behavior.
- It is outside ARTEX’s scope (e.g., an issue in an LLM provider, PostgreSQL, Docker, or a browser).
- There is insufficient information to reproduce it.
- The report only states that “the tool can be misused” without identifying a specific technical flaw in ARTEX.

Where appropriate, we may convert the report into a public hardening issue or feature request.

## Out of Scope

The following are generally **not** considered ARTEX security vulnerabilities:
- Attacks or scans against systems you do not own or are not authorized to test.
- Self-XSS, spam, or brute-force without real impact.
- Large-scale DoS/DDoS or resource-exhaustion attacks.
- Social engineering targeting maintainers or users.
- Issues that exist only in third-party dependencies and do not affect ARTEX.
- Reports that “ARTEX can be used to attack systems” when the user has valid authorization — this is the nature of a penetration-testing tool, not a vulnerability.
- Missing headers or hardening configuration without a concrete security impact.

## Safe Harbor

We welcome ethical security research. If you follow this policy and test only within authorized scope, we will not pursue legal action against you for good-faith research. This does not exempt you from applicable laws in your jurisdiction.

## Disclosure Policy

- Do not publicly disclose vulnerability details before a fix is available or before the coordinated disclosure period ends.
- Do not publish a public PoC without maintainer consent.
- If you do not receive a response within a reasonable time, please ping the contact channel above before disclosing.

Thank you for helping make ARTEX safer.
