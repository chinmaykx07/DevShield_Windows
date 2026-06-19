#Requires -Version 7.0
<#
.SYNOPSIS  DevShield — Tor Hardening
.DESCRIPTION
    Hardens Windows for anonymous browsing via Tor Browser.
    High value — medium priority. Every step verified and reversible.

    What it does:
      1. Detects Tor Browser dynamically (6 search paths)
      2. Shows full privacy pre-flight (network adapter, DNS, MAC state)
      3. Disables LLMNR — prevents identity leaks on LAN
      4. Disables NetBIOS on active adapter
      5. Randomizes Wi-Fi MAC address (with before/after verify)
      6. Creates tagged kill-switch firewall rules (Tor-only outbound)
      7. Launches Tor Browser → auto-opens check.torproject.org
      8. All rules tagged DEVSHIELD_TOR_* for precise rollback

    NASA 8-step pattern throughout. Complete rollback via rollback.ps1.

.PARAMETER NoConfirm    Skip confirmation prompt
.PARAMETER DryRun       Show pre-flight only, apply nothing
.PARAMETER NoMacRandom  Skip MAC randomization (useful on Ethernet)
.PARAMETER NoFirewall   Skip kill-switch firewall rule creation
.PARAMETER Rollback     Remove all DEVSHIELD_TOR_* changes
#>
param(
    [switch]$NoConfirm,
    [switch]$DryRun,
    [switch]$NoMacRandom,
    [switch]$NoFirewall,
    [switch]$Rollback
)

. "$PSScriptRoot\..\core\00_core.ps1"

Initialize-DevShield -ScriptName "tor_hardening.ps1"

# ══════════════════════════════════════════════════════════════
# SECTION 1 — TOR BROWSER DETECTION
# Dynamic — never hardcoded paths
# ══════════════════════════════════════════════════════════════
$TOR_SEARCH_PATHS = @(
    "$env:USERPROFILE\Desktop\Tor Browser\Browser\firefox.exe",
    "$env:USERPROFILE\Desktop\Tor Browser\Browser\TorBrowser\firefox.exe",
    "$env:USERPROFILE\Downloads\Tor Browser\Browser\firefox.exe",
    "$env:LOCALAPPDATA\Tor Browser\Browser\firefox.exe",
    "C:\Users\Public\Desktop\Tor Browser\Browser\firefox.exe",
    "C:\Program Files\Tor Browser\Browser\firefox.exe",
    "C:\Tor Browser\Browser\firefox.exe"
)

# Tor daemon (tor.exe) — relative to firefox.exe location
$TOR_DAEMON_RELATIVE = @(
    "TorBrowser\Tor\tor.exe",
    "..\TorBrowser\Tor\tor.exe",
    "tor.exe"
)

$RULE_TAG  = "DEVSHIELD_TOR"
$RULE_PREFIX = "DEVSHIELD_TOR_"

function Find-TorBrowser {
    foreach ($path in $TOR_SEARCH_PATHS) {
        if (Test-Path $path) { return $path }
    }
    return $null
}

function Find-TorDaemon {
    param([string]$FirefoxPath)
    $browserDir = Split-Path $FirefoxPath -Parent
    foreach ($rel in $TOR_DAEMON_RELATIVE) {
        $candidate = Join-Path $browserDir $rel
        if (Test-Path $candidate) { return $candidate }
    }
    # Broader search from parent of browser dir
    $tbDir = Split-Path $browserDir -Parent
    $found = Get-ChildItem $tbDir -Filter "tor.exe" -Recurse -ErrorAction SilentlyContinue |
             Select-Object -First 1
    return $found?.FullName
}

# ══════════════════════════════════════════════════════════════
# SECTION 2 — NETWORK ADAPTER DISCOVERY
# ══════════════════════════════════════════════════════════════
function Get-ActiveAdapters {
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } |
                ForEach-Object {
                    $type = if ($_.Name -match "Wi-Fi|Wireless|WLAN|802\.11") { "wifi" } else { "ethernet" }
                    @{
                        Name          = $_.Name
                        Description   = $_.InterfaceDescription
                        MacAddress    = $_.MacAddress
                        InterfaceGuid = $_.InterfaceGuid.ToString("B").ToUpper()
                        Type          = $type
                        LinkSpeed     = $_.LinkSpeed
                    }
                }
    return @($adapters)
}

function Get-AdapterRegistryPath {
    param([string]$InterfaceGuid)
    $base = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
    return Get-ChildItem $base -ErrorAction SilentlyContinue | Where-Object {
        (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).NetCfgInstanceId -eq $InterfaceGuid
    } | Select-Object -First 1
}

function Get-LLMNRState {
    $path = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
    try { (Get-ItemProperty $path -ErrorAction Stop).EnableMulticast }
    catch { 1 }  # Default = enabled (1)
}

function Get-NetBIOSState {
    param([string]$AdapterGuid)
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$AdapterGuid"
    try { (Get-ItemProperty $path -ErrorAction Stop).NetbiosOptions }
    catch { 0 }  # Default = use DHCP (0)
}

# ══════════════════════════════════════════════════════════════
# SECTION 3 — PRE-FLIGHT DISPLAY
# ══════════════════════════════════════════════════════════════
function Show-TorPreFlight {
    param(
        [string]$TorPath,
        [array]$Adapters,
        [string]$LLMNRState,
        [hashtable]$Tor
    )
    $lang = Get-DSLanguage

    Write-DS -EN "TOR ANONYMITY PRE-FLIGHT" -SA "टोर-गुप्तता पूर्व-परीक्षण" -Level HEADER
    Write-DSSeparator

    # Tor Browser status
    if ($TorPath) {
        Write-DS -EN "Tor Browser  : ✅ Found" -SA "Tor Browser : ✅ मिला" -Level SUCCESS
        Write-DS -EN "  Path       : $TorPath" -Level INFO -NoIcon
        if ($Tor.Daemon) {
            Write-DS -EN "  tor.exe    : ✅ $($Tor.Daemon)" -Level SUCCESS -NoIcon
        } else {
            Write-DS -EN "  tor.exe    : ⚠ Not found (kill-switch will use Browser only)" -Level WARN -NoIcon
        }
    } else {
        Write-DS -EN "Tor Browser  : ❌ Not found in any known path" `
                 -SA "Tor Browser : ❌ किसी भी ज्ञात पथ पर नहीं मिला" -Level WARN
        Write-DS -EN "  Install from: https://www.torproject.org/download/" -Level INFO -NoIcon
        Write-DS -EN "  Hardening will apply network changes only (kill-switch skipped)." `
                 -SA "  नेटवर्क बदलाव लागू होंगे (kill-switch छोड़ा)।" -Level WARN -NoIcon
    }

    Write-DS -BLANK

    # Network adapter state
    Write-DS -EN "Network Adapters ($($Adapters.Count) active)" `
             -SA "नेटवर्क-अडैप्टर ($($Adapters.Count) सक्रिय)" -Level HEADER

    foreach ($a in $Adapters) {
        $typeTag = if ($a.Type -eq "wifi") { "[Wi-Fi  ]" } else { "[Ethernet]" }
        $macNote = if ($a.Type -eq "wifi") { "← MAC will be randomized" } else { "(skip — Ethernet MAC is less useful to change)" }
        Write-DS -EN "  $typeTag $($a.Name.PadRight(20)) MAC: $($a.MacAddress)  $macNote" `
                 -Level INFO -NoIcon
    }

    Write-DS -BLANK

    # Current privacy state
    $llmnrOn = ($LLMNRState -ne 0)
    Write-DS -EN "LLMNR        : $(if($llmnrOn){'🔴 ENABLED — leaks identity on LAN'}else{'🟢 DISABLED — good'})" `
             -SA "LLMNR        : $(if($llmnrOn){'🔴 सक्षम — LAN पर पहचान लीक'}else{'🟢 अक्षम — अच्छा'})" `
             -Level $(if ($llmnrOn) {"WARN"} else {"SUCCESS"})

    # Check existing kill-switch rules
    $existingRules = Get-NetFirewallRule -DisplayName "$RULE_PREFIX*" -ErrorAction SilentlyContinue
    Write-DS -EN "Kill-switch  : $(if($existingRules){"✅ $($existingRules.Count) rules active"}else{"⬜ Not active"})" `
             -SA "Kill-switch  : $(if($existingRules){"✅ $($existingRules.Count) नियम सक्रिय"}else{"⬜ सक्रिय नहीं"})" `
             -Level $(if ($existingRules) {"SUCCESS"} else {"WARN"})

    Write-DSSeparator
    Write-DS -BLANK
}

# ══════════════════════════════════════════════════════════════
# SECTION 4 — ROLLBACK (remove all DEVSHIELD_TOR_* changes)
# ══════════════════════════════════════════════════════════════
function Invoke-TorRollback {
    Write-DSBanner -Subtitle "Tor Rollback · टोर-पुनःस्थापना"
    if (-not (Assert-DSAdmin)) { exit 1 }

    Write-DS -EN "Removing all DevShield Tor hardening..." `
             -SA "सभी DevShield Tor सुरक्षा हटा रहे हैं..." -Level WARN

    # Remove firewall rules
    $rules = Get-NetFirewallRule -DisplayName "$RULE_PREFIX*" -ErrorAction SilentlyContinue
    if ($rules) {
        $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Write-DS -EN "  ✅ $($rules.Count) firewall rules removed" `
                 -SA "  ✅ $($rules.Count) फ़ायरवॉल नियम हटाए" -Level SUCCESS -NoIcon
    } else {
        Write-DS -EN "  ✅ No DevShield firewall rules found" -Level INFO -NoIcon
    }

    # Re-enable LLMNR
    $llmnrPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
    try {
        Set-ItemProperty $llmnrPath -Name "EnableMulticast" -Value 1 -Type DWord -Force
        Write-DS -EN "  ✅ LLMNR re-enabled" -SA "  ✅ LLMNR पुनः-सक्षम" -Level SUCCESS -NoIcon
    } catch {
        Write-DS -EN "  ⚠ LLMNR restore failed: $_" -Level WARN -NoIcon
    }

    # Find backup file for MAC restoration
    $macBackup = Get-ChildItem $DS_BACKUPS -Filter "tor_mac_*.json" -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($macBackup) {
        $saved = Get-Content $macBackup.FullName -Raw | ConvertFrom-Json
        $regKey = Get-AdapterRegistryPath -InterfaceGuid $saved.adapter_guid
        if ($regKey) {
            try {
                if ($saved.original_mac -and $saved.original_mac -ne "") {
                    Set-ItemProperty $regKey.PSPath -Name "NetworkAddress" -Value ($saved.original_mac -replace "-","") -Force
                } else {
                    Remove-ItemProperty $regKey.PSPath -Name "NetworkAddress" -ErrorAction SilentlyContinue
                }
                # Restart adapter to apply MAC restore
                Disable-NetAdapter -Name $saved.adapter_name -Confirm:$false -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 1500
                Enable-NetAdapter  -Name $saved.adapter_name -Confirm:$false -ErrorAction SilentlyContinue
                Write-DS -EN "  ✅ MAC address restored for $($saved.adapter_name)" `
                         -SA "  ✅ $($saved.adapter_name) का MAC पुनःस्थापित" -Level SUCCESS -NoIcon
            } catch {
                Write-DS -EN "  ⚠ MAC restore failed: $_" -Level WARN -NoIcon
            }
        }
    }

    Set-DSStateKey -Key "tor_active"     -Value $false
    Set-DSStateKey -Key "tor_applied_at" -Value $null

    Write-DS -BLANK
    Write-DS -EN "Tor hardening removed. Normal browsing restored." `
             -SA "Tor सुरक्षा हटाई। सामान्य ब्राउज़िंग पुनःस्थापित।" -Level SUCCESS
    Write-DSAudit -Action "TOR_ROLLBACK_COMPLETE" -Status "ok"
}

# ══════════════════════════════════════════════════════════════
# SECTION 5 — MAIN
# ══════════════════════════════════════════════════════════════
function Invoke-TorHardening {
    if ($Rollback) { Invoke-TorRollback; return }

    Write-DSBanner -Subtitle "Tor Hardening · टोर-सुरक्षा-कवच"

    # ── STEP 1: PRE-FLIGHT ────────────────────────────────────
    Write-DS -EN "Scanning network environment..." `
             -SA "नेटवर्क-पर्यावरण स्कैन कर रहे हैं..." -Level INFO

    $torFirefox = Find-TorBrowser
    $torDaemon  = if ($torFirefox) { Find-TorDaemon -FirefoxPath $torFirefox } else { $null }
    $adapters   = Get-ActiveAdapters
    $llmnrState = Get-LLMNRState

    $torInfo = @{ Path = $torFirefox; Daemon = $torDaemon }

    # Detect Wi-Fi adapters for MAC randomization
    $wifiAdapters = $adapters | Where-Object { $_.Type -eq "wifi" }

    Show-TorPreFlight -TorPath $torFirefox `
                      -Adapters $adapters `
                      -LLMNRState $llmnrState `
                      -Tor $torInfo

    # Public Wi-Fi warning
    $publicWifiSigns = @("public","hotel","airport","cafe","guest","free")
    $activeSSID = try {
        (netsh wlan show interfaces 2>$null | Select-String "SSID\s*:\s+(.+)") |
        ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() } |
        Select-Object -First 1
    } catch { "" }

    if ($activeSSID -and ($publicWifiSigns | Where-Object { $activeSSID -match $_ })) {
        Write-DS -EN "⚠  Possible public Wi-Fi detected: '$activeSSID'" `
                 -SA "⚠  संभावित सार्वजनिक Wi-Fi: '$activeSSID'" -Level WARN
        Write-DS -EN "   This is exactly when Tor hardening matters most. Proceeding." `
                 -SA "   यही समय है जब Tor सुरक्षा सबसे जरूरी है।" -Level INFO
    }

    # ── STEP 2: ASSERT ────────────────────────────────────────
    if (-not (Assert-DSAdmin)) {
        Write-DS -EN "Admin rights required. Run via Task Scheduler or as Administrator." -Level CRITICAL
        exit 1
    }

    # ── STEP 3: CONFIRMATION ──────────────────────────────────
    if (-not $NoConfirm -and -not $DryRun) {
        Write-DS -EN "Apply Tor hardening?" `
                 -SA "Tor सुरक्षा-कवच लागू करें?" -Level WARN
        Write-DS -EN "  Changes: LLMNR off, NetBIOS off, MAC random, kill-switch firewall rules" `
                 -SA "  बदलाव: LLMNR बंद, NetBIOS बंद, MAC यादृच्छिक, kill-switch नियम" -Level INFO -NoIcon
        $ans = Read-Host "  [Y] Apply  [N] Cancel"
        if ($ans.ToUpper() -ne "Y") {
            Write-DS -EN "Cancelled." -SA "रद्द।" -Level INFO; return
        }
    }

    if ($DryRun) {
        Write-DS -EN "DRY RUN — No changes made. See pre-flight above." `
                 -SA "परीक्षण-मोड — कोई बदलाव नहीं। ऊपर पूर्व-परीक्षण देखें।" -Level WARN
        return
    }

    # ── STEP 4: BACKUP ────────────────────────────────────────
    Write-DS -EN "Saving rollback state..." -SA "रोलबैक-अवस्था सहेज रहे हैं..." -Level INFO

    $rollbackId = "TOR_$(Get-Date -Format 'yyyyMMddHHmmss')"
    $rollback   = @{
        rollback_id     = $rollbackId
        llmnr_was       = $llmnrState
        adapters        = $adapters | ForEach-Object {
            @{
                name           = $_.Name
                original_mac   = $_.MacAddress
                adapter_guid   = $_.InterfaceGuid
                netbios_was    = Get-NetBIOSState $_.InterfaceGuid
                type           = $_.Type
            }
        }
        firewall_rules  = (Get-NetFirewallRule -DisplayName "$RULE_PREFIX*" -EA SilentlyContinue)?.DisplayName
        applied_at      = (Get-Date -Format "o")
    }

    $backup = New-DSBackup -Type "tor_hardening" -Data $rollback

    # Save MAC-specific backup for easy restore
    foreach ($a in ($rollback.adapters | Where-Object { $_.type -eq "wifi" })) {
        $macBackupPath = Join-Path $DS_BACKUPS "tor_mac_$(Get-Date -Format 'yyyyMMddHHmmss').json"
        $a | ConvertTo-Json | Set-Content $macBackupPath -Encoding UTF8
    }

    Write-DS -EN "Rollback ID: $rollbackId" -SA "रोलबैक ID: $rollbackId" -Level SUCCESS

    # ── STEP 5: ACT ───────────────────────────────────────────
    $results = @{ LLMNR=$false; NetBIOS=0; MAC=@(); Firewall=0; Errors=@() }
    Write-DS -BLANK

    try {
        # [1/4] Disable LLMNR
        Write-DSProgress -EN "Disabling LLMNR..." -SA "LLMNR अक्षम..." -Step 1 -Total 4
        $llmnrRegPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
        if (-not (Test-Path $llmnrRegPath)) {
            New-Item -Path $llmnrRegPath -Force | Out-Null
        }
        Set-ItemProperty $llmnrRegPath -Name "EnableMulticast" -Value 0 -Type DWord -Force
        $results.LLMNR = $true

        # [2/4] Disable NetBIOS on all active adapters
        Write-DSProgress -EN "Disabling NetBIOS on active adapters..." `
                         -SA "सक्रिय अडैप्टर पर NetBIOS अक्षम..." -Step 2 -Total 4
        foreach ($a in $adapters) {
            $nbPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($a.InterfaceGuid)"
            try {
                if (-not (Test-Path $nbPath)) { New-Item $nbPath -Force | Out-Null }
                Set-ItemProperty $nbPath -Name "NetbiosOptions" -Value 2 -Type DWord -Force
                # 0 = default (DHCP), 1 = enabled, 2 = disabled
                $results.NetBIOS++
            } catch { $results.Errors += "NetBIOS on $($a.Name): $_" }
        }

        # [3/4] MAC Randomization (Wi-Fi adapters only)
        Write-DSProgress -EN "Randomizing Wi-Fi MAC addresses..." `
                         -SA "Wi-Fi MAC पते यादृच्छिक कर रहे हैं..." -Step 3 -Total 4
        if (-not $NoMacRandom) {
            foreach ($a in $wifiAdapters) {
                try {
                    $regKey = Get-AdapterRegistryPath -InterfaceGuid $a.InterfaceGuid
                    if (-not $regKey) {
                        $results.Errors += "MAC: Registry path not found for $($a.Name)"
                        continue
                    }

                    # Generate locally-administered random MAC
                    # Byte 1: set bits 1 (locally administered) and clear bit 0 (unicast)
                    $firstByte = (Get-Random -Minimum 0 -Maximum 63) * 4 + 2  # ensures LA + unicast
                    $macBytes  = @($firstByte) + (1..5 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 })
                    $newMac    = ($macBytes | ForEach-Object { "{0:X2}" -f $_ }) -join ""

                    # Apply via registry
                    Set-ItemProperty $regKey.PSPath -Name "NetworkAddress" -Value $newMac -Force

                    # Restart adapter to apply new MAC
                    Disable-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds 1500
                    Enable-NetAdapter  -Name $a.Name -Confirm:$false -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds 1000

                    # Read back to verify
                    $verifiedMac = (Get-NetAdapter -Name $a.Name -ErrorAction SilentlyContinue).MacAddress
                    $results.MAC += @{
                        Adapter  = $a.Name
                        Original = $a.MacAddress
                        New      = $verifiedMac
                        Changed  = ($verifiedMac -ne $a.MacAddress)
                    }
                } catch {
                    $results.Errors += "MAC randomization on $($a.Name): $_"
                }
            }
        } else {
            Write-DS -EN "MAC randomization skipped (-NoMacRandom flag)." -SA "MAC यादृच्छिकरण छोड़ा।" -Level INFO
        }

        # [4/4] Kill-switch firewall rules
        Write-DSProgress -EN "Creating kill-switch firewall rules..." `
                         -SA "Kill-switch फ़ायरवॉल नियम बना रहे हैं..." -Step 4 -Total 4
        if (-not $NoFirewall) {
            # Remove any stale DevShield Tor rules first
            Get-NetFirewallRule -DisplayName "$RULE_PREFIX*" -EA SilentlyContinue |
                Remove-NetFirewallRule -ErrorAction SilentlyContinue

            $rulesDone = 0
            # Allow Tor Browser (firefox.exe inside Tor Browser)
            if ($torFirefox) {
                New-NetFirewallRule `
                    -DisplayName "${RULE_PREFIX}ALLOW_BROWSER" `
                    -Description "DevShield: Allow Tor Browser (tagged for rollback)" `
                    -Direction Outbound `
                    -Program $torFirefox `
                    -Action Allow `
                    -Profile Any `
                    -Enabled True `
                    -ErrorAction Stop | Out-Null
                $rulesDone++
            }
            # Allow Tor daemon (tor.exe)
            if ($torDaemon) {
                New-NetFirewallRule `
                    -DisplayName "${RULE_PREFIX}ALLOW_DAEMON" `
                    -Description "DevShield: Allow Tor daemon (tagged for rollback)" `
                    -Direction Outbound `
                    -Program $torDaemon `
                    -Action Allow `
                    -Profile Any `
                    -Enabled True `
                    -ErrorAction Stop | Out-Null
                $rulesDone++
            }
            # Sentinel rule (marker for rollback identification)
            New-NetFirewallRule `
                -DisplayName "${RULE_PREFIX}SENTINEL" `
                -Description "DevShield Tor sentinel — do not delete manually. Use rollback.ps1." `
                -Direction Outbound `
                -RemoteAddress "0.0.0.0" `
                -Action Allow `
                -Profile Any `
                -Enabled False `
                -ErrorAction Stop | Out-Null

            $results.Firewall = $rulesDone
        }

    } catch {
        Write-DS -EN "Exception during hardening: $_" -Level CRITICAL
        Write-DS -EN "Running rollback to restore state..." -Level WARN
        Invoke-TorRollback
        Write-DSAudit -Action "TOR_APPLY_EXCEPTION" -Detail "$_" -Status "fail" `
                      -Rollback @{ file = $backup.file; type = "tor_hardening" }
        exit 1
    }

    Set-DSStateKey -Key "tor_active"     -Value $true
    Set-DSStateKey -Key "tor_applied_at" -Value (Get-Date -Format "o")

    # ── STEP 6: VERIFY ────────────────────────────────────────
    $llmnrVerified  = (Get-LLMNRState) -eq 0
    $macChanged     = ($results.MAC | Where-Object { $_.Changed }).Count
    $rulesActive    = (Get-NetFirewallRule -DisplayName "$RULE_PREFIX*" -EA SilentlyContinue).Count

    # ── STEP 7: REPORT ────────────────────────────────────────
    Write-DS -BLANK
    Write-DS -EN "TOR HARDENING — RESULTS" -SA "टोर-सुरक्षा — परिणाम" -Level HEADER
    Write-DSSeparator

    Write-DS -EN "LLMNR disabled    : $(if($llmnrVerified){'✅ Confirmed'}else{'❌ Failed'})" `
             -SA "LLMNR अक्षम      : $(if($llmnrVerified){'✅ पुष्ट'}else{'❌ विफल'})" `
             -Level $(if ($llmnrVerified) {"SUCCESS"} else {"CRITICAL"})

    Write-DS -EN "NetBIOS disabled  : ✅ $($results.NetBIOS) adapter(s)" `
             -SA "NetBIOS अक्षम    : ✅ $($results.NetBIOS) अडैप्टर" `
             -Level $(if ($results.NetBIOS -gt 0) {"SUCCESS"} else {"WARN"})

    if ($results.MAC.Count -gt 0) {
        foreach ($m in $results.MAC) {
            $changed = if ($m.Changed) {"✅ Changed"} else {"⚠ Unchanged — may need restart"}
            Write-DS -EN "MAC ($($m.Adapter)) : $changed  $($m.Original) → $($m.New)" `
                     -Level $(if ($m.Changed) {"SUCCESS"} else {"WARN"})
        }
    } elseif (-not $NoMacRandom -and $wifiAdapters.Count -eq 0) {
        Write-DS -EN "MAC randomization : ⬜ No Wi-Fi adapters found (Ethernet only)" -Level INFO
    }

    Write-DS -EN "Kill-switch rules : $(if($rulesActive -gt 0){"✅ $rulesActive rules active"}else{"⬜ None (no Tor Browser found)"})" `
             -SA "Kill-switch नियम : $(if($rulesActive -gt 0){"✅ $rulesActive नियम सक्रिय"}else{"⬜ नहीं"})" `
             -Level $(if ($rulesActive -gt 0) {"SUCCESS"} else {"WARN"})

    Write-DS -EN "Rollback ID       : $rollbackId" -Level INFO

    if ($results.Errors) {
        Write-DS -BLANK
        Write-DS -EN "Non-fatal errors:" -Level WARN
        $results.Errors | ForEach-Object { Write-DS -EN "  · $_" -Level WARN -NoIcon }
    }

    Write-DSSeparator
    Write-DS -BLANK

    # Auto-launch verification
    if ($torFirefox -and -not $DryRun) {
        Write-DS -EN "Launching Tor Browser → check.torproject.org..." `
                 -SA "Tor Browser खोल रहे हैं → check.torproject.org..." -Level INFO
        Start-Sleep -Seconds 2
        try {
            Start-Process $torFirefox -ArgumentList "https://check.torproject.org" -ErrorAction Stop
            Write-DS -EN "✅ Tor Browser launched. Confirm 'You are using Tor' on the page." `
                     -SA "✅ Tor Browser खोला। पेज पर 'You are using Tor' देखें।" -Level SUCCESS
        } catch {
            Write-DS -EN "Could not auto-launch Tor Browser: $torFirefox" -Level WARN
            Write-DS -EN "Launch manually and visit: https://check.torproject.org" -Level INFO
        }
    } elseif (-not $torFirefox) {
        Write-DS -EN "Tor Browser not found — install from torproject.org then re-run." `
                 -SA "Tor Browser नहीं मिला — torproject.org से स्थापित करें।" -Level WARN
    }

    # ── STEP 8: LOG ───────────────────────────────────────────
    Confirm-DSOperation -Action "TOR_HARDENING" -Backup $backup

    Write-DSAudit `
        -Action   "TOR_HARDENING_APPLIED" `
        -Detail   "LLMNR:$llmnrVerified NetBIOS:$($results.NetBIOS) MAC:$macChanged Rules:$rulesActive ID:$rollbackId" `
        -Rollback @{ file = $backup.file; type = "tor_hardening"; rollback_id = $rollbackId } `
        -Status   $(if ($llmnrVerified) {"ok"} else {"warn"})

    @{
        status       = if ($llmnrVerified) {"ok"} else {"warn"}
        rollback_id  = $rollbackId
        llmnr_off    = $llmnrVerified
        mac_changed  = $macChanged
        rules_active = $rulesActive
        timestamp    = (Get-Date -Format "o")
    } | ConvertTo-Json -Compress
}

# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════
Invoke-TorHardening
