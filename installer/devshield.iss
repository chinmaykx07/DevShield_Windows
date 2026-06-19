; ============================================================
; DevShield — Inno Setup Installer Script
; installer/devshield.iss
;
; Compile with: iscc devshield.iss
; Requires: Inno Setup 6.x from https://jrsoftware.org/isinfo.php
;
; Produces: installer\Output\DevShield-v0.1.0-Setup.exe
; ============================================================

#define AppName      "DevShield"
#define AppVersion   "0.1.0"
#define AppPublisher "DevShield Project"
#define AppURL       "https://github.com/devshield/devshield"
#define AppExeName   "devshield.exe"
#define AppID        "{{8F4A2B1C-3D5E-4F67-A890-B1C2D3E4F5A6}"

; ── [Setup] ──────────────────────────────────────────────────
[Setup]
AppId={#AppID}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} v{#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases

; Install into Program Files — no per-user install to keep scripts accessible
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
AllowNoIcons=yes

; Output installer file
OutputDir=Output
OutputBaseFilename=DevShield-v{#AppVersion}-Setup

; Compression
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes

; Require admin — needed so Task Scheduler setup works
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=

; Minimum OS: Windows 10 (major 10, minor 0, build 17763 = 1809)
MinVersion=10.0.17763

; Uninstall
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName} v{#AppVersion}
CreateUninstallRegKey=yes

; Cosmetics
SetupIconFile=..\assets\devshield.ico
WizardStyle=modern
WizardSizePercent=120

; Signable: sign the installer too if code-signing is available
; SignTool=MicrosoftTrustedSigning $f

; Architectures
ArchitecturesInstallIn64BitMode=x64compatible arm64

; ── [Languages] ──────────────────────────────────────────────
[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

; ── [Tasks] ──────────────────────────────────────────────────
[Tasks]
Name: "desktopicon";   Description: "Create a &Desktop shortcut";   GroupDescription: "Additional shortcuts:"
Name: "startmenuicon"; Description: "Create a &Start Menu shortcut"; GroupDescription: "Additional shortcuts:"; Flags: checked

; ── [Files] ──────────────────────────────────────────────────
[Files]
; Main executable
Source: "..\dist\{#AppExeName}";         DestDir: "{app}";             Flags: ignoreversion

; PowerShell scripts — entire tree, preserving subdirectory structure
Source: "..\scripts\*";                  DestDir: "{app}\scripts";     Flags: ignoreversion recursesubdirs createallsubdirs

; Assets (icon for tray — already embedded in exe but kept for installer use)
Source: "..\assets\devshield.ico";       DestDir: "{app}\assets";      Flags: ignoreversion

; Bundled telemetry blocklist (ships with app so privacy enforcer works offline)
; The guardian uses this as fallback if live update fails
Source: "..\scripts\monitor\blocklist_bundled.json"; DestDir: "{app}\scripts\monitor"; Flags: ignoreversion skipifsourcedoesntexist

; ── [Icons] ──────────────────────────────────────────────────
[Icons]
; Start Menu shortcut
Name: "{group}\{#AppName}";            Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\assets\devshield.ico"; Tasks: startmenuicon; Comment: "Privacy · Thermal · Network Intelligence"
Name: "{group}\Uninstall {#AppName}";  Filename: "{uninstallexe}"

; Desktop shortcut (optional)
Name: "{autodesktop}\{#AppName}";      Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\assets\devshield.ico"; Tasks: desktopicon

; ── [Run] ────────────────────────────────────────────────────
[Run]
; Launch DevShield after install (optional — user can uncheck)
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName} now"; Flags: nowait postinstall skipifsilent

; ── [Registry] ───────────────────────────────────────────────
[Registry]
; Store install path for reference by scripts
Root: HKLM; Subkey: "SOFTWARE\DevShield"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: createvalueifdoesntexist uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\DevShield"; ValueType: string; ValueName: "Version";     ValueData: "{#AppVersion}"; Flags: createvalueifdoesntexist

; ── [UninstallDelete] ────────────────────────────────────────
; Clean up the app folder completely
[UninstallDelete]
Type: filesandordirs; Name: "{app}"

; ── [Code] ───────────────────────────────────────────────────
[Code]

// ── Pre-install: Check PowerShell 7 ──────────────────────────
// DevShield scripts require PS7. Warn the user if it's missing.
function IsPowerShell7Installed(): Boolean;
var
  PwshPath: String;
begin
  // Check standard install path
  PwshPath := ExpandConstant('{commonpf64}\PowerShell\7\pwsh.exe');
  Result := FileExists(PwshPath);
  if not Result then
  begin
    // Also check if pwsh is on PATH via registry
    Result := RegQueryStringValue(HKLM,
      'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\pwsh.exe',
      '', PwshPath);
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not IsPowerShell7Installed() then
  begin
    if MsgBox(
      'PowerShell 7 is required by DevShield scripts.'          + #13#10 +
      'It is not currently installed on this machine.'           + #13#10 + #13#10 +
      'Install PowerShell 7 from:'                               + #13#10 +
      '  winget install Microsoft.PowerShell'                    + #13#10 + #13#10 +
      'Or download from: https://github.com/PowerShell/PowerShell/releases' + #13#10 + #13#10 +
      'Continue installation anyway? (DevShield tray app will work, but'    + #13#10 +
      'thermal profiles and hardware dashboard require PS7.)',
      mbConfirmation, MB_YESNO) = IDNO then
    begin
      Result := False;
    end;
  end;
end;

// ── Uninstall: offer to remove user data ─────────────────────
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DSHomeDir: String;
  MsgResult: Integer;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DSHomeDir := ExpandConstant('{userappdata}') + '\.devshield';
    if DirExists(DSHomeDir) then
    begin
      MsgResult := MsgBox(
        'DevShield has stored data in:'  + #13#10 +
        DSHomeDir                         + #13#10 + #13#10 +
        'This folder contains:'           + #13#10 +
        '  · Your hardware profile'       + #13#10 +
        '  · Audit logs'                  + #13#10 +
        '  · Backup files for rollback'   + #13#10 +
        '  · Downloaded LibreHardwareMonitor' + #13#10 + #13#10 +
        'Do you want to remove this data?',
        mbConfirmation, MB_YESNO);
      if MsgResult = IDYES then
      begin
        DelTree(DSHomeDir, True, True, True);
      end;
    end;
  end;
end;
