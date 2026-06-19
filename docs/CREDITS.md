# Credits and Third-Party Acknowledgements

DevShield builds on several existing open-source projects, platform features, and developer tooling. This document records the major upstream components that are used directly by the project and the people or organizations behind them.

## Core runtime and app framework

- Go (Go Authors / Google) — the core programming language and runtime used to build the tray application.
- Fyne and fyne.io/systray (Fyne contributors) — the system-tray UI framework used by the desktop app.
- gopsutil (Shirou and contributors) — process and system monitoring library used for process-awareness features.
- modernc.org/sqlite (modernc project) — pure-Go SQLite implementation used for local audit logging.

## Windows integration and hardware access

- PowerShell 7 (Microsoft) — used for the hardening, monitoring, rollback, and first-run automation scripts.
- LibreHardwareMonitor (LibreHardwareMonitor contributors) — used as the hardware sensor backend for thermal and hardware monitoring.
- Windows Task Scheduler, WMI, and registry APIs — built-in Windows capabilities used by the application and scripts.

## Packaging, distribution, and release verification

- Inno Setup (JRSoftware / Jordan Russell) — used for the Windows installer build.
- Windows Package Manager / WinGet (Microsoft) — packaging metadata and distribution support.
- Sigstore / cosign (Sigstore maintainers) — used for release signing and signature verification.
- GitHub Attestations (GitHub) — used for provenance and release verification support.

## Other tools and resources referenced by the project

- The repository documentation and scripts also reference standard Windows tooling, PowerShell commands, GitHub workflows, and common developer utilities that are part of the broader Windows and open-source ecosystem.
- The current icon and branding assets are project-local placeholders and should be replaced with original artwork before any broader public distribution.

## Notes

- DevShield is an independent project, but it relies on the work of many upstream maintainers and contributors.
- This document is intended to make those dependencies explicit for anyone who forks, redistributes, or builds the project.
- When adding new third-party libraries, SDKs, tools, or assets, please add them here as part of the change.
