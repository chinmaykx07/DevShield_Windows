// tray.go — System tray UI
//
// Builds the full menu, wires every callback, updates labels
// live when language/mode/alerts change without restarting.
//
// fyne-io/systray rules we follow:
//   · All menu item creation happens inside onTrayReady()
//   · Dynamic updates use SetTitle() on stored item refs
//   · Submenus created via parent.AddSubMenuItem()
//   · systray.Run() blocks — called last in main.go

package main

import (
	"fmt"
	"log"

	"fyne.io/systray"
)

// ── STORED ITEM REFERENCES ────────────────────────────────────
// We keep refs so any goroutine can call SetTitle() to update
// labels without rebuilding the entire menu.

type trayRefs struct {
	// Header
	status *systray.MenuItem // greyed status line

	// Thermal profiles
	mSilent *systray.MenuItem
	mGaming *systray.MenuItem
	mDev    *systray.MenuItem

	// Privacy
	mPrivacyApply *systray.MenuItem

	// Guardian
	mGuardianStart  *systray.MenuItem
	mGuardianStop   *systray.MenuItem
	mGuardianAlerts *systray.MenuItem

	// Tools
	mDashboard *systray.MenuItem
	mRollback  *systray.MenuItem

	// Language submenu items
	mLangBOTH *systray.MenuItem
	mLangEN   *systray.MenuItem
	mLangSA   *systray.MenuItem

	// Settings
	mAutoSwitch *systray.MenuItem

	// Update notification (hidden until an update is available)
	mUpdate *systray.MenuItem

	// Quit
	mQuit *systray.MenuItem
}

var tr trayRefs

// ── ENTRY POINTS ─────────────────────────────────────────────

func onTrayReady() {
	systray.SetIcon(trayIconData)
	systray.SetTitle(T(LblAppTitle))
	systray.SetTooltip(CurrentModeStatus())

	buildMenu()
	wireCallbacks()
	startClickRouter()
}

func onTrayExit() {
	log.Println("tray: exiting")
	WriteGoEvent("TRAY_EXIT", "user quit", "ok")

	shutdownWatchdog()
	shutdownThermal()
	shutdownContextWatcher()
	shutdownUpdater()
	closeAudit()
}

// ── MENU BUILDER ──────────────────────────────────────────────

func buildMenu() {
	// ── Status (greyed — updates dynamically) ────────────────
	tr.status = systray.AddMenuItem(CurrentModeStatus(), "")
	tr.status.Disable()
	systray.AddSeparator()

	// ── Thermal profiles ─────────────────────────────────────
	tr.mSilent = systray.AddMenuItem(T(LblModeSilent), "Quiet, cool — ideal for writing and calls")
	tr.mGaming = systray.AddMenuItem(T(LblModeGaming), "Full performance — enables CPU boost")
	tr.mDev = systray.AddMenuItem(T(LblModeDev), "Balanced — optimised for coding and builds")
	systray.AddSeparator()

	// ── Privacy ──────────────────────────────────────────────
	mPrivacy := systray.AddMenuItem(T(LblPrivacy), "")
	tr.mPrivacyApply = mPrivacy.AddSubMenuItem(
		bilingual("Apply Telemetry Sinkhole", "टेलीमेट्री सिंकहोल लागू करें"), "")
	mPrivacyRollback := mPrivacy.AddSubMenuItem(
		bilingual("Remove Sinkhole (Rollback)", "सिंकहोल हटाएं (पुनःस्थापना)"), "")

	_ = mPrivacyRollback // wired below

	// ── Network Guardian ─────────────────────────────────────
	mGuardian := systray.AddMenuItem(T(LblNetwork), "")
	tr.mGuardianStart = mGuardian.AddSubMenuItem(
		bilingual("Start Guardian", "रक्षक आरंभ करें"), "")
	tr.mGuardianStop = mGuardian.AddSubMenuItem(
		bilingual("Stop Guardian", "रक्षक बंद करें"), "")
	mGuardian.AddSubMenuItem("──────────────", "").Disable()
	tr.mGuardianAlerts = mGuardian.AddSubMenuItem(FormatAlertBadge(), "")
	tr.mGuardianAlerts.Disable()

	// Sync initial guardian state
	updateGuardianItems()

	systray.AddSeparator()

	// ── Tools ─────────────────────────────────────────────────
	tr.mDashboard = systray.AddMenuItem(
		bilingual("📋 Open Dashboard", "📋 निरीक्षण-पट खोलें"), "Live hardware monitor")
	tr.mRollback = systray.AddMenuItem(
		bilingual("↩  Rollback…", "↩  पुनःस्थापना…"), "Undo any DevShield change")
	systray.AddSeparator()

	// ── Language submenu ──────────────────────────────────────
	mLang := systray.AddMenuItem(T(LblLanguage), "")
	tr.mLangBOTH = mLang.AddSubMenuItem(T(LblLangBOTH), "")
	tr.mLangEN = mLang.AddSubMenuItem(T(LblLangEN), "")
	tr.mLangSA = mLang.AddSubMenuItem(T(LblLangSA), "")
	refreshLangChecks()

	// ── Auto-switch ───────────────────────────────────────────
	tr.mAutoSwitch = systray.AddMenuItem(formatAutoSwitchLabel(), "")

	// ── Update notification (hidden — shown only when an update exists) ──
	tr.mUpdate = systray.AddMenuItem("", "A newer version of DevShield is available")
	tr.mUpdate.Hide()

	systray.AddSeparator()

	// ── Quit ─────────────────────────────────────────────────
	tr.mQuit = systray.AddMenuItem(T(LblQuit), "")

	// Store sub-items we need later for click routing
	traySubItems.privacyRollback = mPrivacyRollback
}

// ── EXTRA SUB-ITEM REFS ───────────────────────────────────────
// Items that don't need SetTitle but do need click handling

var traySubItems struct {
	privacyRollback *systray.MenuItem
}

// ── CALLBACK WIRING ───────────────────────────────────────────

func wireCallbacks() {
	// Thermal mode change → update status line + tooltip
	thermal.OnModeChange(func(m ThermalMode) {
		label := CurrentModeStatus()
		tr.status.SetTitle(label)
		systray.SetTooltip(label)
		refreshProfileChecks(m)
		log.Printf("tray: mode label updated → %s", m)
	})

	// Alert count change → update badge
	OnNewAlert(func(n int) {
		tr.mGuardianAlerts.SetTitle(FormatAlertBadge())
		updateGuardianItems()
		// Update tooltip to surface alert count
		systray.SetTooltip(fmt.Sprintf("%s\n%s",
			CurrentModeStatus(), GetTodayAlertSummary()))
	})

	// Language change → refresh all labels
	lang.OnChange(func(m LangMode) {
		updateMenuLabels()
	})

	// Update available → reveal the update menu item with version label
	OnUpdateAvailable(func(version string) {
		tr.mUpdate.SetTitle(bilingual(
			"⬆  Update available: "+version,
			"⬆  अद्यतन उपलब्ध: "+version))
		tr.mUpdate.Show()
		log.Printf("tray: update notification shown → %s", version)
	})
}

// ── CLICK ROUTER ─────────────────────────────────────────────

func startClickRouter() {
	go func() {
		for {
			select {
			// ── Thermal profiles ──────────────────────────────
			case <-tr.mSilent.ClickedCh:
				SuppressAutoSwitch()
				applyAndUpdate(ModeSilent)

			case <-tr.mGaming.ClickedCh:
				SuppressAutoSwitch()
				applyAndUpdate(ModeGaming)

			case <-tr.mDev.ClickedCh:
				SuppressAutoSwitch()
				applyAndUpdate(ModeDev)

			// ── Privacy ───────────────────────────────────────
			case <-tr.mPrivacyApply.ClickedCh:
				go func() {
					tr.mPrivacyApply.Disable()
					tr.mPrivacyApply.SetTitle(bilingual("Applying…", "लागू हो रहा है…"))
					_ = RunTask(TaskPrivacy)
					tr.mPrivacyApply.SetTitle(
						bilingual("Apply Telemetry Sinkhole", "टेलीमेट्री सिंकहोल लागू करें"))
					tr.mPrivacyApply.Enable()
				}()

			case <-traySubItems.privacyRollback.ClickedCh:
				go func() {
					_ = OpenScriptWindow("hardening/rollback.ps1", "-Type", "privacy")
				}()

			// ── Guardian ──────────────────────────────────────
			case <-tr.mGuardianStart.ClickedCh:
				go func() {
					_ = RunTask(TaskGuardian)
					updateGuardianItems()
				}()

			case <-tr.mGuardianStop.ClickedCh:
				go func() {
					_, _ = RunScriptDirect("monitor/network_guardian.ps1", "-Stop")
					updateGuardianItems()
				}()

			case <-tr.mGuardianAlerts.ClickedCh:
				// alerts item is disabled (display only) — no action

			// ── Tools ─────────────────────────────────────────
			case <-tr.mDashboard.ClickedCh:
				go func() {
					_ = OpenScriptWindow("monitor/hardware_dashboard.ps1")
				}()

			case <-tr.mRollback.ClickedCh:
				go func() {
					_ = OpenScriptWindow("hardening/rollback.ps1")
				}()

			// ── Language ──────────────────────────────────────
			case <-tr.mLangBOTH.ClickedCh:
				lang.Set(LangBOTH)
				refreshLangChecks()

			case <-tr.mLangEN.ClickedCh:
				lang.Set(LangEN)
				refreshLangChecks()

			case <-tr.mLangSA.ClickedCh:
				lang.Set(LangSA)
				refreshLangChecks()

			// ── Auto-switch toggle ─────────────────────────────
			case <-tr.mAutoSwitch.ClickedCh:
				EnableAutoSwitch(!IsAutoSwitchEnabled())
				tr.mAutoSwitch.SetTitle(formatAutoSwitchLabel())

			// ── Update notification ─────────────────────────────
			case <-tr.mUpdate.ClickedCh:
				go func() {
					v := IsUpdateAvailable()
					OpenReleasePage()
					if v != "" {
						DismissUpdate(v)
					}
					tr.mUpdate.Hide()
				}()

			// ── Quit ──────────────────────────────────────────
			case <-tr.mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

// ── APPLY + UPDATE ────────────────────────────────────────────

func applyAndUpdate(mode ThermalMode) {
	// Disable all profile items while applying
	tr.mSilent.Disable()
	tr.mGaming.Disable()
	tr.mDev.Disable()
	tr.status.SetTitle(ApplyingStatus())

	go func() {
		if err := ApplyProfile(mode); err != nil {
			log.Printf("tray: apply %s failed: %v", mode, err)
		}
		// Re-enable — mode change callback updates the actual label
		tr.mSilent.Enable()
		tr.mGaming.Enable()
		tr.mDev.Enable()
	}()
}

// ── DYNAMIC LABEL UPDATERS ────────────────────────────────────

// updateMenuLabels re-titles every item in the new language.
// Called by lang.OnChange callback.
func updateMenuLabels() {
	systray.SetTitle(T(LblAppTitle))
	systray.SetTooltip(CurrentModeStatus())
	tr.status.SetTitle(CurrentModeStatus())

	tr.mSilent.SetTitle(T(LblModeSilent))
	tr.mGaming.SetTitle(T(LblModeGaming))
	tr.mDev.SetTitle(T(LblModeDev))

	tr.mDashboard.SetTitle(bilingual("📋 Open Dashboard", "📋 निरीक्षण-पट खोलें"))
	tr.mRollback.SetTitle(bilingual("↩  Rollback…", "↩  पुनःस्थापना…"))

	tr.mGuardianAlerts.SetTitle(FormatAlertBadge())
	tr.mAutoSwitch.SetTitle(formatAutoSwitchLabel())
	tr.mQuit.SetTitle(T(LblQuit))

	if v := IsUpdateAvailable(); v != "" {
		tr.mUpdate.SetTitle(bilingual("⬆  Update available: "+v, "⬆  अद्यतन उपलब्ध: "+v))
	}

	refreshLangChecks()
	refreshProfileChecks(thermal.getMode())
}

// refreshProfileChecks puts "● " prefix on the active mode.
func refreshProfileChecks(active ThermalMode) {
	items := map[ThermalMode]*systray.MenuItem{
		ModeSilent: tr.mSilent,
		ModeGaming: tr.mGaming,
		ModeDev:    tr.mDev,
	}
	for mode, item := range items {
		base := T(map[ThermalMode]LabelKey{
			ModeSilent: LblModeSilent,
			ModeGaming: LblModeGaming,
			ModeDev:    LblModeDev,
		}[mode])
		if mode == active {
			item.SetTitle("● " + base)
		} else {
			item.SetTitle("  " + base)
		}
	}
}

// refreshLangChecks marks the current language with "● ".
func refreshLangChecks() {
	cur := lang.Get()
	tr.mLangBOTH.SetTitle(langCheckLabel(LangBOTH, T(LblLangBOTH), cur))
	tr.mLangEN.SetTitle(langCheckLabel(LangEN, T(LblLangEN), cur))
	tr.mLangSA.SetTitle(langCheckLabel(LangSA, T(LblLangSA), cur))
}

func langCheckLabel(m LangMode, label string, cur LangMode) string {
	if m == cur {
		return "● " + label
	}
	return "  " + label
}

// updateGuardianItems enables/disables Start/Stop based on state.
func updateGuardianItems() {
	if IsGuardianRunning() {
		tr.mGuardianStart.Disable()
		tr.mGuardianStop.Enable()
	} else {
		tr.mGuardianStart.Enable()
		tr.mGuardianStop.Disable()
	}
}

func formatAutoSwitchLabel() string {
	if IsAutoSwitchEnabled() {
		return bilingual("⚙  Auto-switch: ON", "⚙  स्वत:-स्विच: चालू")
	}
	return bilingual("⚙  Auto-switch: OFF", "⚙  स्वत:-स्विच: बंद")
}
