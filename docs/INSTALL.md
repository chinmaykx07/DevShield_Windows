# Install DevShield

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
