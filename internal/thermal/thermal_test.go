package thermal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, content := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func read(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

const cpu = "sys/devices/system/cpu"

// Intel laptop: intel_pstate (no_turbo), EPP, ACPI platform profile.
func intelMachine(t *testing.T) string {
	root := t.TempDir()
	files := map[string]string{
		cpu + "/intel_pstate/no_turbo":               "0",
		"sys/firmware/acpi/platform_profile":         "balanced",
		"sys/firmware/acpi/platform_profile_choices": "low-power balanced performance",
	}
	for _, p := range []string{"policy0", "policy1", "policy2", "policy3"} {
		d := cpu + "/cpufreq/" + p + "/"
		files[d+"cpuinfo_min_freq"] = "400000"
		files[d+"cpuinfo_max_freq"] = "4800000"
		files[d+"scaling_max_freq"] = "4800000"
		files[d+"energy_performance_preference"] = "balance_performance"
		files[d+"energy_performance_available_preferences"] = "default performance balance_performance balance_power power"
	}
	writeTree(t, root, files)
	return root
}

func TestSilentThenGamingThenOffRestoresOriginal(t *testing.T) {
	root, state := intelMachine(t), t.TempDir()
	c := Detect(root)
	if len(c.Policies) != 4 || !c.BoostInverted || !c.PlatformProfile {
		t.Fatalf("detect: %+v", c)
	}

	res, err := Apply(c, Silent, state)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 0 || len(res.Mismatch) != 0 {
		t.Fatalf("unexpected result %+v", res)
	}
	for rel, want := range map[string]string{
		cpu + "/intel_pstate/no_turbo":                         "1", // boost OFF
		cpu + "/cpufreq/policy2/scaling_max_freq":              "2800000",
		cpu + "/cpufreq/policy2/energy_performance_preference": "power",
		"sys/firmware/acpi/platform_profile":                   "low-power", // no "quiet" offered
	} {
		if got := read(t, root, rel); got != want {
			t.Errorf("silent: %s = %s, want %s", rel, got, want)
		}
	}

	if _, err := Apply(c, Gaming, state); err != nil {
		t.Fatal(err)
	}
	if read(t, root, cpu+"/intel_pstate/no_turbo") != "0" || read(t, root, cpu+"/cpufreq/policy0/scaling_max_freq") != "4800000" ||
		read(t, root, "sys/firmware/acpi/platform_profile") != "performance" {
		t.Fatal("gaming not applied")
	}
	if Active(state) != Gaming {
		t.Fatalf("active = %q", Active(state))
	}

	// Off returns to the state BEFORE the first DevShield change (not silent's).
	if failed, err := Off(state); err != nil {
		t.Fatalf("off: %v %v", err, failed)
	}
	for rel, want := range map[string]string{
		cpu + "/intel_pstate/no_turbo":                         "0",
		cpu + "/cpufreq/policy1/scaling_max_freq":              "4800000",
		cpu + "/cpufreq/policy1/energy_performance_preference": "balance_performance",
		"sys/firmware/acpi/platform_profile":                   "balanced",
	} {
		if got := read(t, root, rel); got != want {
			t.Errorf("after off: %s = %s, want %s", rel, got, want)
		}
	}
	if Active(state) != "" {
		t.Error("active profile not cleared")
	}
	if _, err := Off(state); err == nil {
		t.Error("second Off should say there is nothing to restore")
	}
}

func TestBaselineFileIsRootOnly(t *testing.T) {
	root, state := intelMachine(t), t.TempDir()
	if _, err := Apply(Detect(root), Dev, state); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(state, "thermal-baseline.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("baseline mode %v err %v", fi.Mode().Perm(), err)
	}
}

// A required write failing halfway must leave the machine exactly as before.
func TestFailedApplyUndoesEverything(t *testing.T) {
	root, state := intelMachine(t), t.TempDir()
	c := Detect(root)
	// Make policy2's max-freq unwritable (a directory cannot be written to,
	// even by root — permission bits wouldn't stop a root test run).
	bad := filepath.Join(root, cpu, "cpufreq/policy2/scaling_max_freq")
	os.Remove(bad)
	os.Mkdir(bad, 0o755)

	_, err := Apply(c, Silent, state)
	if err == nil || !strings.Contains(err.Error(), "undone") {
		t.Fatalf("expected an undone failure, got %v", err)
	}
	if read(t, root, cpu+"/intel_pstate/no_turbo") != "0" || read(t, root, cpu+"/cpufreq/policy0/scaling_max_freq") != "4800000" {
		t.Fatal("earlier writes were not undone")
	}
	if Active(state) != "" {
		t.Fatal("failed apply recorded as active")
	}
}

// An optional write the governor refuses is reported, not fatal.
func TestRefusedOptionalWriteIsSkipped(t *testing.T) {
	root, state := intelMachine(t), t.TempDir()
	epp := filepath.Join(root, cpu, "cpufreq/policy3/energy_performance_preference")
	os.Remove(epp)
	os.Mkdir(epp, 0o755)

	res, err := Apply(Detect(root), Gaming, state)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0], "policy3 energy preference") {
		t.Fatalf("skipped = %v", res.Skipped)
	}
}

// AMD desktop: global cpufreq/boost (1 = on), no EPP, no platform profile.
func TestAMDDevProfile(t *testing.T) {
	root, state := t.TempDir(), t.TempDir()
	writeTree(t, root, map[string]string{
		cpu + "/cpufreq/boost":                    "0",
		cpu + "/cpufreq/policy0/cpuinfo_min_freq": "550000",
		cpu + "/cpufreq/policy0/cpuinfo_max_freq": "5000000",
		cpu + "/cpufreq/policy0/scaling_max_freq": "3000000",
	})
	res, err := Apply(Detect(root), Dev, state)
	if err != nil {
		t.Fatal(err)
	}
	if read(t, root, cpu+"/cpufreq/boost") != "1" || read(t, root, cpu+"/cpufreq/policy0/scaling_max_freq") != "4500000" {
		t.Fatal("dev profile: want boost on and 90% max frequency")
	}
	if len(res.Notes) == 0 || !strings.Contains(strings.Join(res.Notes, ";"), "platform_profile") {
		t.Fatalf("missing note about absent platform profile: %v", res.Notes)
	}
	Off(state)
	if read(t, root, cpu+"/cpufreq/boost") != "0" || read(t, root, cpu+"/cpufreq/policy0/scaling_max_freq") != "3000000" {
		t.Fatal("off did not restore the original values")
	}
}

func TestUnsupportedMachineAndUnknownProfile(t *testing.T) {
	c := Detect(t.TempDir())
	if _, err := Apply(c, Silent, t.TempDir()); err == nil {
		t.Fatal("expected an error on a machine with no controls")
	}
	if _, _, err := Detect(intelMachine(t)).Plan("turbo-max"); err == nil {
		t.Fatal("expected an error for an unknown profile")
	}
}
