// tray_agents.go — "AI Agents" tray submenu (Agent Watch UI)
//
// fyne-io/systray cannot add menu items after onTrayReady, so a fixed
// number of slots is created up front and shown/hidden as agents come
// and go. Each slot has two children: "Sanction" and "Open location".

package main

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"fyne.io/systray"
)

const maxAgentSlots = 10

type agentSlot struct {
	item     *systray.MenuItem
	sanction *systray.MenuItem
	open     *systray.MenuItem
}

// slotAgents maps slot index → agent currently shown in it.
var (
	slotMu     sync.Mutex
	slotAgents [maxAgentSlots]RunningAgent
)

func buildAgentMenu() {
	tr.mAgents = systray.AddMenuItem(formatAgentsLabel(nil), "AI agents running on this PC")
	tr.mAgentsNone = tr.mAgents.AddSubMenuItem(
		bilingual("No AI agents running", "कोई AI-प्रतिनिधि सक्रिय नहीं"), "")
	tr.mAgentsNone.Disable()

	for i := 0; i < maxAgentSlots; i++ {
		s := agentSlot{item: tr.mAgents.AddSubMenuItem("", "")}
		s.sanction = s.item.AddSubMenuItem(
			bilingual("✅ Sanction this agent", "✅ इस प्रतिनिधि को स्वीकृत करें"),
			"Approve this agent — no more alerts unless its program file changes")
		s.open = s.item.AddSubMenuItem(
			bilingual("📂 Open file location", "📂 संचिका-स्थान खोलें"), "")
		s.item.Hide()
		tr.agentSlots = append(tr.agentSlots, s)
	}
}

// startAgentSlotRouters gives each slot its own click goroutine, since the
// main router's select statement cannot range over a slice of channels.
func startAgentSlotRouters() {
	for i := range tr.agentSlots {
		i, s := i, tr.agentSlots[i]
		go func() {
			for {
				select {
				case <-s.sanction.ClickedCh:
					slotMu.Lock()
					a := slotAgents[i]
					slotMu.Unlock()
					if a.Fingerprint == "" {
						continue
					}
					if err := SanctionAgent(a.Fingerprint); err != nil {
						log.Printf("tray: sanction %s failed: %v", a.Name, err)
					}
				case <-s.open.ClickedCh:
					slotMu.Lock()
					exe := slotAgents[i].Exe
					slotMu.Unlock()
					openFileLocation(exe)
				}
			}
		}()
	}
}

// refreshAgentMenu re-renders the submenu from the latest scan.
func refreshAgentMenu() {
	if tr.mAgents == nil {
		return
	}
	agents := RunningAgents()
	tr.mAgents.SetTitle(formatAgentsLabel(agents))

	if len(agents) == 0 {
		tr.mAgentsNone.Show()
	} else {
		tr.mAgentsNone.Hide()
	}

	slotMu.Lock()
	defer slotMu.Unlock()
	for i, s := range tr.agentSlots {
		if i >= len(agents) {
			slotAgents[i] = RunningAgent{}
			s.item.Hide()
			continue
		}
		a := agents[i]
		slotAgents[i] = a

		s.item.SetTitle(formatAgentSlot(a))
		s.item.SetTooltip(strings.Join(a.Reasons, "; ") + "\n" + a.Exe)
		if a.Status == AgentSanctioned {
			s.sanction.SetTitle(bilingual("✅ Sanctioned", "✅ स्वीकृत"))
			s.sanction.Disable()
		} else {
			s.sanction.SetTitle(bilingual("✅ Sanction this agent", "✅ इस प्रतिनिधि को स्वीकृत करें"))
			s.sanction.Enable()
		}
		if a.Exe == "" {
			s.open.Disable()
		} else {
			s.open.Enable()
		}
		s.item.Show()
	}
}

func formatAgentsLabel(agents []RunningAgent) string {
	unsanctioned := 0
	for _, a := range agents {
		if a.Status != AgentSanctioned {
			unsanctioned++
		}
	}
	more := ""
	if len(agents) > maxAgentSlots {
		more = fmt.Sprintf(" (+%d)", len(agents)-maxAgentSlots)
	}
	if unsanctioned == 0 {
		return bilingual(
			fmt.Sprintf("🤖 AI Agents: %d running%s", len(agents), more),
			fmt.Sprintf("🤖 AI-प्रतिनिधि: %d सक्रिय%s", len(agents), more))
	}
	return bilingual(
		fmt.Sprintf("🤖 AI Agents: %d running · %d unsanctioned ⚠%s", len(agents), unsanctioned, more),
		fmt.Sprintf("🤖 AI-प्रतिनिधि: %d सक्रिय · %d अस्वीकृत ⚠%s", len(agents), unsanctioned, more))
}

func formatAgentSlot(a RunningAgent) string {
	icon := "⚠"
	switch {
	case !a.Known:
		icon = "❓"
	case a.Status == AgentSanctioned:
		icon = "✅"
	}
	procs := ""
	if a.Processes > 1 {
		procs = fmt.Sprintf(" ×%d", a.Processes)
	}
	return fmt.Sprintf("%s %s%s", icon, a.Name, procs)
}

func openFileLocation(path string) {
	if path == "" || runtime.GOOS != "windows" {
		return
	}
	// explorer.exe returns a non-zero exit code even on success — ignore it
	_ = exec.Command("explorer", "/select,"+path).Start()
}
