// Package thermal applies DevShield's thermal profiles on Linux through the
// kernel's own interfaces — no vendor tools:
//
//	CPU boost          /sys/devices/system/cpu/cpufreq/boost   (1 = on)
//	                   /sys/devices/system/cpu/intel_pstate/no_turbo (1 = OFF)
//	                   …/cpufreq/policyN/boost                 (newer amd-pstate)
//	max frequency      …/cpufreq/policyN/scaling_max_freq      (kHz)
//	energy preference  …/cpufreq/policyN/energy_performance_preference
//	fan/power profile  /sys/firmware/acpi/platform_profile     (laptops)
//
// Safety model:
//   - Baseline: before DevShield first writes a file, that file's original
//     value is saved (files that only appear later, e.g. a CPU brought
//     online, are added before their first write). Off() writes them back
//     and reads each one back to confirm.
//   - Atomic apply: if a required write fails, everything already written in
//     that apply is put back, so the machine is never left half-changed.
//   - Optional writes (EPP, platform profile) may be refused by the
//     hardware/governor; that is reported, not fatal.
//   - Verify: every value is read back afterwards; drivers can round or
//     silently refuse.
//
// Root is a filesystem prefix ("" = the real system) for testing.
package thermal

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Profile names, matching the Windows build.
const (
	Silent = "silent"
	Gaming = "gaming"
	Dev    = "dev"
)

// Profiles lists the valid profile names.
var Profiles = []string{Silent, Gaming, Dev}

const silentCapKHz = 2_800_000

// Write is one sysfs change.
type Write struct {
	Path     string `json:"path"`
	Value    string `json:"value"`
	Optional bool   `json:"optional,omitempty"`
	What     string `json:"what"`
}

// Policy is one cpufreq policy (a group of CPUs sharing a clock).
type Policy struct {
	Dir      string
	MinKHz   int
	MaxKHz   int
	EPPs     []string // available energy_performance_preference values
	HasEPP   bool
	HasBoost bool // per-policy boost file
}

// Caps is what this machine lets us control.
type Caps struct {
	Root            string
	Policies        []Policy
	BoostPath       string // global boost control, "" if none
	BoostInverted   bool   // intel_pstate no_turbo: 1 means boost OFF
	PlatformProfile bool
	PlatformChoices []string
}

func (c Caps) path(rel string) string { return filepath.Join(c.Root, rel) }

// Detect inspects sysfs under root.
func Detect(root string) Caps {
	c := Caps{Root: root}
	pols, _ := filepath.Glob(filepath.Join(root, "/sys/devices/system/cpu/cpufreq/policy*"))
	sort.Strings(pols)
	for _, dir := range pols {
		p := Policy{Dir: dir}
		p.MinKHz, _ = readInt(filepath.Join(dir, "cpuinfo_min_freq"))
		p.MaxKHz, _ = readInt(filepath.Join(dir, "cpuinfo_max_freq"))
		if p.MaxKHz == 0 || !exists(filepath.Join(dir, "scaling_max_freq")) {
			continue
		}
		if exists(filepath.Join(dir, "energy_performance_preference")) {
			p.HasEPP = true
			p.EPPs = strings.Fields(readString(filepath.Join(dir, "energy_performance_available_preferences")))
		}
		p.HasBoost = exists(filepath.Join(dir, "boost"))
		c.Policies = append(c.Policies, p)
	}
	switch {
	case exists(c.path("/sys/devices/system/cpu/intel_pstate/no_turbo")):
		c.BoostPath, c.BoostInverted = c.path("/sys/devices/system/cpu/intel_pstate/no_turbo"), true
	case exists(c.path("/sys/devices/system/cpu/cpufreq/boost")):
		c.BoostPath = c.path("/sys/devices/system/cpu/cpufreq/boost")
	}
	if exists(c.path("/sys/firmware/acpi/platform_profile")) {
		c.PlatformProfile = true
		c.PlatformChoices = strings.Fields(readString(c.path("/sys/firmware/acpi/platform_profile_choices")))
	}
	return c
}

// Supported reports whether there is anything to control at all.
func (c Caps) Supported() bool { return len(c.Policies) > 0 || c.BoostPath != "" || c.PlatformProfile }

// candidatePaths is every file any profile might write — the baseline.
func (c Caps) candidatePaths() []string {
	var out []string
	for _, p := range c.Policies {
		out = append(out, filepath.Join(p.Dir, "scaling_max_freq"))
		if p.HasEPP {
			out = append(out, filepath.Join(p.Dir, "energy_performance_preference"))
		}
		if p.HasBoost {
			out = append(out, filepath.Join(p.Dir, "boost"))
		}
	}
	if c.BoostPath != "" {
		out = append(out, c.BoostPath)
	}
	if c.PlatformProfile {
		out = append(out, c.path("/sys/firmware/acpi/platform_profile"))
	}
	return out
}

// Plan returns the writes for a profile, plus notes about what this
// machine can't do.
func (c Caps) Plan(profile string) ([]Write, []string, error) {
	var boostOn bool
	var epp []string
	var platform []string
	freq := func(p Policy) int { return p.MaxKHz }
	switch profile {
	case Silent:
		boostOn, epp, platform = false, []string{"power", "balance_power"}, []string{"quiet", "low-power", "cool"}
		freq = func(p Policy) int { return clamp(silentCapKHz, p.MinKHz, p.MaxKHz) }
	case Gaming:
		boostOn, epp, platform = true, []string{"performance"}, []string{"performance"}
	case Dev:
		boostOn, epp, platform = true, []string{"balance_performance"}, []string{"balanced"}
		freq = func(p Policy) int { return clamp(p.MaxKHz*9/10, p.MinKHz, p.MaxKHz) }
	default:
		return nil, nil, fmt.Errorf("unknown profile %q (want %s)", profile, strings.Join(Profiles, ", "))
	}
	if !c.Supported() {
		return nil, nil, errors.New("this machine exposes no CPU frequency, boost or platform-profile controls")
	}

	var ws []Write
	var notes []string
	bool01 := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}
	if c.BoostPath != "" {
		v := bool01(boostOn)
		if c.BoostInverted {
			v = bool01(!boostOn)
		}
		ws = append(ws, Write{Path: c.BoostPath, Value: v, What: "CPU boost " + onOff(boostOn)})
	}
	for _, p := range c.Policies {
		name := filepath.Base(p.Dir)
		if c.BoostPath == "" && p.HasBoost {
			ws = append(ws, Write{Path: filepath.Join(p.Dir, "boost"), Value: bool01(boostOn), What: name + " boost " + onOff(boostOn)})
		}
		ws = append(ws, Write{Path: filepath.Join(p.Dir, "scaling_max_freq"), Value: strconv.Itoa(freq(p)),
			What: fmt.Sprintf("%s max %d MHz", name, freq(p)/1000)})
		if p.HasEPP {
			if v := firstAvailable(epp, p.EPPs); v != "" {
				ws = append(ws, Write{Path: filepath.Join(p.Dir, "energy_performance_preference"), Value: v, Optional: true, What: name + " energy preference " + v})
			}
		}
	}
	if c.BoostPath == "" && !anyPolicyBoost(c.Policies) {
		notes = append(notes, "no CPU boost control on this machine")
	}
	if c.PlatformProfile {
		if v := firstAvailable(platform, c.PlatformChoices); v != "" {
			ws = append(ws, Write{Path: c.path("/sys/firmware/acpi/platform_profile"), Value: v, Optional: true, What: "platform profile " + v})
		} else {
			notes = append(notes, fmt.Sprintf("platform profile has no %s option (choices: %s)", strings.Join(platform, "/"), strings.Join(c.PlatformChoices, " ")))
		}
	} else {
		notes = append(notes, "no platform_profile (fan/power mode) on this machine")
	}
	return ws, notes, nil
}

// ── Baseline / apply / restore ─────────────────────────────────────

// Baseline is the original state before DevShield changed anything.
type Baseline struct {
	Taken  string            `json:"taken"`
	Values map[string]string `json:"values"` // path → original content
}

// Result reports what an apply did.
type Result struct {
	Profile  string   `json:"profile"`
	Applied  []string `json:"applied"`
	Skipped  []string `json:"skipped,omitempty"`  // optional writes the system refused
	Mismatch []string `json:"mismatch,omitempty"` // read back differently
	Notes    []string `json:"notes,omitempty"`
}

// Apply switches to profile. stateDir must be root-only: it holds the
// baseline that Off() restores.
func Apply(c Caps, profile, stateDir string) (Result, error) {
	writes, notes, err := c.Plan(profile)
	if err != nil {
		return Result{}, err
	}
	if err := ensureBaseline(c, stateDir); err != nil {
		return Result{}, fmt.Errorf("could not save original settings, nothing changed: %w", err)
	}

	res := Result{Profile: profile, Notes: notes}
	type undo struct{ path, old string }
	var done []undo
	for _, w := range writes {
		old := readString(w.Path)
		if err := os.WriteFile(w.Path, []byte(w.Value), 0); err != nil {
			if w.Optional {
				res.Skipped = append(res.Skipped, fmt.Sprintf("%s: %v", w.What, rootErr(err)))
				continue
			}
			// Required write failed → put back everything written so far,
			// and say exactly what could not be put back.
			var stuck []string
			for i := len(done) - 1; i >= 0; i-- {
				if done[i].old == "" {
					continue // was unreadable: nothing known to restore
				}
				if werr := os.WriteFile(done[i].path, []byte(done[i].old), 0); werr != nil || readString(done[i].path) != done[i].old {
					stuck = append(stuck, done[i].path)
				}
			}
			if len(stuck) > 0 {
				return Result{}, fmt.Errorf("%s failed (%v); these earlier changes could NOT be undone: %s — run 'sudo devshield profile off'", w.What, rootErr(err), strings.Join(stuck, ", "))
			}
			return Result{}, fmt.Errorf("%s failed (%v); all changes from this apply were undone", w.What, rootErr(err))
		}
		done = append(done, undo{w.Path, old})
		res.Applied = append(res.Applied, w.What)
	}

	for _, w := range writes {
		if contains(res.Skipped, w.What) {
			continue
		}
		if got := readString(w.Path); got != w.Value && !sameSelection(got, w.Value) {
			res.Mismatch = append(res.Mismatch, fmt.Sprintf("%s: wrote %s, reads back %s", w.What, w.Value, got))
		}
	}
	if err := saveActive(stateDir, profile); err != nil {
		res.Notes = append(res.Notes, "could not record active profile: "+err.Error())
	}
	return res, nil
}

// Off restores every original value and forgets the baseline.
// With no baseline (DevShield never changed anything) it does nothing.
func Off(stateDir string) ([]string, error) {
	if !exists(filepath.Join(stateDir, "thermal-baseline.json")) {
		return nil, nil
	}
	b, err := loadBaseline(stateDir)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(b.Values))
	for p := range b.Values {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var failed []string
	// Write twice: some values are only accepted once others are restored
	// (e.g. scaling_max_freq while boost is still off).
	for pass := 0; pass < 2; pass++ {
		failed = failed[:0]
		for _, p := range paths {
			if b.Values[p] == "" || readString(p) == b.Values[p] {
				continue // unreadable at baseline time, or already original
			}
			if err := os.WriteFile(p, []byte(b.Values[p]), 0); err != nil {
				failed = append(failed, fmt.Sprintf("%s: %v", p, rootErr(err)))
			} else if got := readString(p); got != b.Values[p] && !sameSelection(got, b.Values[p]) {
				failed = append(failed, fmt.Sprintf("%s: wrote %s, reads back %s", p, b.Values[p], got))
			}
		}
		if len(failed) == 0 {
			break
		}
	}
	if len(failed) > 0 {
		return failed, fmt.Errorf("could not restore %d setting(s); baseline kept for another try", len(failed))
	}
	_ = os.Remove(filepath.Join(stateDir, "thermal-baseline.json"))
	_ = os.Remove(filepath.Join(stateDir, "thermal-active"))
	return nil, nil
}

// Active returns the profile DevShield last applied ("" = none / restored).
func Active(stateDir string) string {
	return readString(filepath.Join(stateDir, "thermal-active"))
}

func ensureBaseline(c Caps, stateDir string) error {
	path := filepath.Join(stateDir, "thermal-baseline.json")
	b := Baseline{Taken: time.Now().UTC().Format(time.RFC3339), Values: map[string]string{}}
	if exists(path) {
		old, err := loadBaseline(stateDir)
		if err != nil {
			return err
		}
		b = old
	}
	// Existing entries are the ORIGINAL pre-DevShield values: never
	// overwritten. A file not in the baseline has never been written by
	// DevShield, so its current value is its original one.
	added := 0
	for _, p := range c.candidatePaths() {
		if _, ok := b.Values[p]; !ok {
			b.Values[p] = readString(p)
			added++
		}
	}
	if added == 0 && exists(path) {
		return nil
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadBaseline(stateDir string) (Baseline, error) {
	var b Baseline
	data, err := os.ReadFile(filepath.Join(stateDir, "thermal-baseline.json"))
	if os.IsNotExist(err) {
		return b, errors.New("DevShield has not changed any thermal settings — nothing to restore")
	}
	if err != nil {
		return b, err
	}
	return b, json.Unmarshal(data, &b)
}

func saveActive(stateDir, profile string) error {
	return os.WriteFile(filepath.Join(stateDir, "thermal-active"), []byte(profile+"\n"), 0o600)
}

// ── helpers ──────────────────────────────────────────────────────────

func clamp(v, lo, hi int) int {
	if lo > 0 && v < lo {
		return lo
	}
	if hi > 0 && v > hi {
		return hi
	}
	return v
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func firstAvailable(want, have []string) string {
	for _, w := range want {
		if contains(have, w) {
			return w
		}
	}
	return ""
}

func anyPolicyBoost(ps []Policy) bool {
	for _, p := range ps {
		if p.HasBoost {
			return true
		}
	}
	return false
}

// sameSelection handles files that read back as a list with the active
// choice in brackets, e.g. "low-power [balanced] performance".
func sameSelection(got, want string) bool {
	return strings.Contains(got, "["+want+"]")
}

func rootErr(err error) error {
	if errors.Is(err, os.ErrPermission) {
		return errors.New("permission denied (needs root)")
	}
	return err
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func readString(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readInt(p string) (int, bool) {
	v, err := strconv.Atoi(readString(p))
	return v, err == nil
}
