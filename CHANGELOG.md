# Changelog

All notable changes to DevShield are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Pending before v0.1.0 tag
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
