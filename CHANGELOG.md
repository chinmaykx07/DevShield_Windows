# Changelog

All notable changes to DevShield are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Agent Watch: behaviour-first detection of AI agents and rogue agents.
  Any process is classed as an agent by behaviour (LLM traffic, LLM keys
  set for it, AI libraries loaded, shell/tool agent loop), never by name.
  Rogue indicators (undocumented, Temp/Downloads location,
  approvals-disabled flags, recon/persistence tools, auto-start, detached)
  give 🚨 rogue-suspect and ⚠ risky verdicts. Sanction approved agents from
  the tray. Alert-only, no admin needed. Not yet tested on Windows. See
  `docs/RESEARCH_AI_AGENT_MONITORING.md`.

- Linux root daemon (`devshield daemon`) + CLI (`status`, `agents`,
  `events`, `sanction`, `revoke`, `verify-log`). It owns the sanction list,
  agent database and audit log in a root-only directory, and talks to
  clients over a Unix socket whose callers are identified by the kernel
  (SO_PEERCRED). Policy changes require root, so an agent cannot sanction
  itself; attempts are logged as AGENT_TAMPER_ATTEMPT. Hardened systemd
  unit in `packaging/linux/` (not yet tested under systemd).
- Linux sensors (`devshield sensors`) from the kernel's hwmon/thermal zones,
  replacing the need for LibreHardwareMonitor on Linux.
- Linux thermal profiles (`sudo devshield profile silent|gaming|dev|off`)
  via cpufreq, boost, energy-performance preference and ACPI
  platform_profile, with an original-state baseline, all-or-nothing apply,
  read-back verification and exact restore. Root-only, audit-logged.
  Tested on simulated sysfs; not yet on real hardware.
- Linux telemetry sinkhole (`sudo devshield sinkhole on|off`): managed
  /etc/hosts block with a small documented list and a never-block list;
  user entries preserved; re-apply always writes the full list; status
  flags missing entries and resolvers that ignore /etc/hosts. Verified
  live on a real resolver.
- Linux network controls (`internal/egress`), in DevShield's own nftables
  table, enforced in the kernel (fail closed):
  `sudo devshield block|unblock <agent>` cuts one agent and everything it
  spawns off the network (loopback included) through a cgroup v2 group.
  Its pre-existing connections and listeners are dropped by address, and
  it is re-quarantined after a restart.
  `sudo devshield lockdown on --via IFACE | --endpoint IP:PORT/PROTO |
  --user NAME | --tor [--lan] [--strict] [--confirm-within D]` allows
  outbound traffic only through the chosen tunnel/users. This is a Tor
  kill switch and its alternative for networks that block Tor: no DNS or
  IPv6 leaks, DNS never goes to the LAN, and replies to inbound SSH still
  work unless `--strict` is set. There is a dead-man auto-revert. A
  removed or altered rule is detected (the kernel's rules are compared
  with the expected ones) and restored within 10 s, and logged.
  `devshield-egress.service` loads the saved rules at boot before the
  network starts. Agents seen before can be blocked while not running.
  Rules for closed sockets are dropped automatically. Tested live in
  network namespaces (unified and hybrid cgroups); not yet with a real
  VPN/Tor setup or under systemd.
- Tamper-evident, hash-chained audit log: edits, deletions, reordering and
  truncation are detected; unclean daemon stops are reported.

### Changed
- Agent Watch moved to `internal/agentwatch` as a configurable Watcher.
- An LLM key now counts only for the process that introduced it at launch.
  Inherited keys don't count, so a rogue can't launder its key by spawning
  children (a flaw found in live testing of the previous majority rule).
- Built with patched Go 1.27.3: reachable known vulnerabilities went from
  35 to 0. CI now runs vet, race tests and govulncheck on Linux and Windows.

### Fixed
- systemd unit: `ProtectSystem=strict` left `/etc/hosts` read-only, so the
  sinkhole could not have worked under systemd. It is now the one
  `ReadWritePaths` entry. `ProtectControlGroups` is dropped (quarantine
  writes `/sys/fs/cgroup`) and `CAP_NET_ADMIN` added (nftables).
- App froze on Quit (`closeAudit` self-deadlock on `auditMu`).

### Pending before v0.1.0 tag
- Project status: experimental / intermediate development; not yet rigorously tested in real-world environments
- Phase B local build verification (see `docs/SHIP_PLAN.md`)
- Phase C VM-based safety testing — full bricking-risk matrix
- Phase D real hardware compatibility testing
- `docs/INSTALL.md`, `docs/USER_MANUAL.md`, `docs/TROUBLESHOOTING.md` — not yet written
- `go.sum` — must be generated via `go mod tidy` (requires network access to the Go module proxy, not available in this packaging environment)
- WinGet manifest PR submission to `microsoft/winget-pkgs`
- GitHub repository path updated to `chinmaykx07/DevShield_Windows` in the app metadata and packaging files

## [0.1.0] — unreleased

### Added
- Thermal profiles: Silent Summer, Gaming Gear, Dev Mode — each with
  before/after sensor verification and automatic rollback on failure
- Privacy enforcer: telemetry hosts-file sinkhole (51 domains),
  registry hardening, Windows Recall and Copilot Runtime blocking
- Network guardian: per-process background monitor with developer-aware
  allowlist (VS Code, Docker, Node, WSL2, etc.) and Windows Toast alerts
- Tor hardening with dynamic install-path detection and firewall kill-switch
- Full rollback system — undo any single action or everything, with
  `-DryRun` preview mode
- Live hardware dashboard (2s refresh) with bilingual HWiNFO-style display
- Bilingual interface throughout: English + Sanskrit (द्विभाषिक)
- System tray app (Go) with Task Scheduler-based elevation — single UAC
  prompt at first run, never again afterward
- SQLite audit log (WAL mode) of every action taken
- Process-aware auto mode switching (optional, off by default)
- Auto-update checker — notifies via tray, never auto-installs
- Cryptographically verifiable releases: Sigstore signing + GitHub
  Artifact Attestation + SHA256 checksums

### Known limitations (tracked for v0.5)
- GPU power/thermal control not yet implemented (CPU only)
- ARM64 build is best-effort (`continue-on-error` in CI)
- No profile export/import yet
- No Scoop bucket yet

[Unreleased]: https://github.com/chinmaykx07/DevShield_Windows/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/chinmaykx07/DevShield_Windows/releases/tag/v0.1.0
