# Troubleshooting

## Tray icon does not appear

- Confirm the executable is running.
- Check whether the app was blocked by SmartScreen or antivirus.
- Re-run the installer or build the application again.

## Profile did not apply

- Confirm PowerShell 7 is installed.
- Review the audit log and event files in the .devshield folder.
- Try running the relevant profile script manually.

## Guardian alerts appear unexpectedly

- Check whether the affected process is a trusted developer tool.
- Review the allowlist in the network guardian script.
- Use rollback if you want to remove the applied changes.
