# Install DevShield

> ⚠️ Warning
> This project is still experimental and not yet rigorously tested. The installer and PowerShell scripts may change without notice and can make system-level changes. Do not install on mission-critical or production systems unless you understand the risks and have backups or a restore point.

## Credits and dependencies

This project relies on third-party libraries, SDKs, and tools. A summary of those upstream components and their maintainers is documented in [CREDITS.md](CREDITS.md).

## Prerequisites

- Windows 10 17763+ or Windows 11
- PowerShell 7
- A local administrator account for first-run setup

## Recommended install

1. Download the latest installer from the GitHub Releases page.
2. Run the installer.
3. When Windows SmartScreen appears, choose More Info and then Run Anyway.
4. Allow the first-run setup to complete.

## Manual build from source

```powershell
go mod tidy
build.bat dev
```

The built executable will be placed in the dist folder.
