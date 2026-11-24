# PR #20 — Rootless Host Runtime & Executor Privilege Isolation

> **Scope:** opt-in remapped-root deployment plus fail-closed agent executor
> separation and Linux process privilege-locking. This is *not* a conversion of
> ARTEX's principal Go process to a non-root user inside the container, a
> per-task mount namespace, or a complete application sandbox.

## Why this architecture

ARTEX presently runs its control plane as container UID 0 to provision
private files and launch agent commands under a distinct unprivileged
identity (default UID/GID 10001). If we instead set `user: 10001:10001`
on the entire Compose service, the server and its Bash/MCP/custom-tool
children would share an identity and lose a meaningful file-security
boundary. This PR retains separate identities **inside** a Linux user
namespace while making container UID 0 map to a nonzero parent-namespace
UID when an operator opts into rootless-host deployment.

### What PR #20 changes

- `ARTEX_REQUIRE_EXEC_ISOLATION=1` is now the **Compose default**. The
  server stops before creating stores/listeners if the executor credential
  drop was disabled (`-exec-uid=-1`) or could not be enabled. Direct
  binary deployments retain their current default but can set this
  variable to explicitly enforce the same invariant.
- `ARTEX_REQUIRE_USERNS=1` (opt-in, default **0**) makes startup fail
  unless the process is namespace UID 0 and `/proc/self/uid_map` maps
  UID 0 to a nonzero UID in its parent namespace. It cannot be used with
  an unisolated executor. Linux only; unsupported platforms fail closed.
  **This verifies remapped root, not the privilege level of dockerd.**
- Linux Bash and MCP stdio command shims apply kernel
  `PR_SET_NO_NEW_PRIVS` *after* dropping UID and GID and *before*
  exec, then fail closed if the kernel refuses. Child/grandchild
  processes inherit the flag, so setuid binaries and file capabilities
  cannot restore privilege. This does **not** change sockets, DNS,
  destination reachability, packet routing, or available collectors.
- The server opens `exec-home` with `O_NOFOLLOW|O_DIRECTORY` and
  changes ownership and permissions via its open file descriptor,
  not a re-resolvable path.
- `scripts/rootless-preflight.sh` inspects the **active** Docker
  daemon's reported security options, refuses a rootful daemon, and
  validates the chosen Compose definition without creating containers.
  It is a deployment preflight; the binary performs the kernel UID-map
  check **again at each startup**.
- CI checks the rootless preflight with mocked rootful, rootless,
  unavailable, malformed and invalid-Compose engine responses.
  Unit/integration tests cover mapping acceptance/refusal, fail-closed
  startup, executor shim `NoNewPrivs=1` and symlinked-home refusal.

## Opt-in rootless Docker deployment

On an operator-controlled Linux host, install Docker's supported
**rootless daemon** using Docker's official rootless installation
instructions (including `newuidmap`, `newgidmap`, subordinate IDs,
the user's service manager and any cgroup-v2 configuration). Do not
`sudo docker compose` and do not merely add a normal user to the
`docker` group: that usually accesses a rootful daemon.

From the ARTEX-DEFENSE checkout:

```bash
# Ensure Docker CLI talks to your rootless Docker service.
docker context ls
docker context use rootless
# If a DOCKER_HOST variable is set, verify it points to the intended service.

# Copy .env.example to .env and supply a strong POSTGRES_PASSWORD.
# Preserve existing data/ and keys/ and back them up before migrating!
# Add or change:
# ARTEX_REQUIRE_EXEC_ISOLATION=1
# ARTEX_REQUIRE_USERNS=1

bash scripts/rootless-preflight.sh local
docker compose config --quiet
docker compose up -d --build
docker compose logs -f artex
```

For a released GHCR image, run
`bash scripts/rootless-preflight.sh ghcr` and then use
`docker compose -f docker-compose.ghcr.yml up -d`.

**First migration requires operator preparation.** Rootless Docker
changes host-side bind mount permissions and ownership mappings;
`./data`, `./keys`, `./skills` and PostgreSQL's persistent volume
may need to be initialized or migrated under the rootless daemon.
Do not recursively `chown` production key, PostgreSQL, or task trees
based on a guess. Restore from a backup on a disposable host and
verify the effective UID map and write permissions first.
Only the Docker **CLI and daemon used for deployment** change; no
collector targets, network routes, egress deny policies, proxy ports,
or traffic interception behavior are changed by this PR. Rootless
Docker's own networking implementation may have limitations; test
authorized scans and collector connectivity in your specific environment.

### Rollback / compatibility

Existing rootful Docker and direct-binary deployments continue to work
without `ARTEX_REQUIRE_USERNS=1`; Compose still requires the executor
drop, which should be active with the supported image. If the new
guard fails at startup, **investigate** the mapped UID / executor
capability / bind mount configuration. Do not set `-exec-uid=-1` as a
workaround. For a temporary rootful rollback, explicitly set
`ARTEX_REQUIRE_USERNS=0` while preserving the executor boundary.
No production database schema changes occur in this PR.

## What remains out of scope

- The principal Go process is still **namespace-root inside the
  container**, though remapped away from host root when this mode is
  selected. A truly unprivileged application control plane would need a
  separately isolated launcher/broker for privileged file operations.
- All executor processes still run as UID/GID 10001; per-task or
  per-company *Unix identity* isolation, process namespaces and
  writable-cache separation are not implemented. An executor may access
  sibling artifacts permitted by that shared UID; `os.Root` file
  tools are not a Bash syscall-level sandbox.
- Custom Python tools spawned directly with
  `SysProcAttr.Credential` continue using an unprivileged UID/GID;
  `PR_SET_NO_NEW_PRIVS` is enforced by Docker's
  `no-new-privileges:true` when deployed through the supported Compose
  configuration, but not independently added to direct-binary Python
  child creation in this PR.
- Mounts, hard links, internal workspace symlink authorization races,
  archive staging/restore, file ACLs and credential delegation need
  their own audit and follow-on work.
- This PR does **not** block outbound network access. Optional network
  policies would require independent operator opt-in, never a hidden
  default restriction. The user-namespace isolation can still change
  host networking behavior because of the selected Docker engine.

## Test and verification

```bash
go test ./server -run 'TestRuntimeIsolation|TestCheckMappedRootUID|TestValidateRuntimeIsolation|TestExecutorBashShimAsRoot|TestExecutorMCPStdioAsRoot|TestPrepareExecHomeRejectsSymlinkAsRoot' -count=1
go test -race ./server -run 'TestRuntimeIsolation|TestCheckMappedRootUID|TestValidateRuntimeIsolation' -count=1
bash scripts/test-rootless-preflight.sh
python3 scripts/test_container_hardening.py
```

Root-only integration tests skip when not run as root; remapped-UID
deployment must also be validated in a rootless Docker installation.
After merge, verify all required CI checks plus the non-publishing
full image vulnerability audit introduced in PR #19 before cutting a
production release.
