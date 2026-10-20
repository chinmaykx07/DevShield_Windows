package sensors

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTree creates files under root from a path → content map.
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

// Layout recorded from a typical Intel laptop with an NVMe drive and fan.
func TestIntelLaptopLayout(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"sys/class/hwmon/hwmon0/name":        "acpitz",
		"sys/class/hwmon/hwmon0/temp1_input": "27800",
		"sys/class/hwmon/hwmon1/name":        "nvme",
		"sys/class/hwmon/hwmon1/temp1_input": "38850",
		"sys/class/hwmon/hwmon1/temp1_label": "Composite",
		"sys/class/hwmon/hwmon1/temp1_crit":  "84850",
		"sys/class/hwmon/hwmon2/name":        "coretemp",
		"sys/class/hwmon/hwmon2/temp1_input": "55000",
		"sys/class/hwmon/hwmon2/temp1_label": "Package id 0",
		"sys/class/hwmon/hwmon2/temp1_crit":  "100000",
		"sys/class/hwmon/hwmon2/temp2_input": "61000",
		"sys/class/hwmon/hwmon2/temp2_label": "Core 0",
		"sys/class/hwmon/hwmon3/name":        "thinkpad",
		"sys/class/hwmon/hwmon3/fan1_input":  "2150",
		"sys/class/hwmon/hwmon3/temp1_input": "garbage", // unreadable sensor is skipped
	})
	s := Read(root)
	if s.Summary.Source != "hwmon" {
		t.Fatalf("source %q", s.Summary.Source)
	}
	// Package sensor preferred over the hotter single core
	if s.Summary.CPUTempC != 55 || s.Summary.NVMeTempC != 38.85 || s.Summary.MaxFanRPM != 2150 {
		t.Fatalf("summary %+v", s.Summary)
	}
	for _, r := range s.Readings {
		if r.Chip == "coretemp" && r.Label == "Package id 0" && r.Crit != 100 {
			t.Errorf("crit not read: %+v", r)
		}
		if r.Chip == "thinkpad" && r.Kind == "temp" {
			t.Errorf("unreadable sensor reported: %+v", r)
		}
	}
}

// AMD desktop: k10temp Tctl, amdgpu edge/junction, GPU power in µW.
func TestAMDDesktopLayout(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"sys/class/hwmon/hwmon0/name":           "k10temp",
		"sys/class/hwmon/hwmon0/temp1_input":    "48250",
		"sys/class/hwmon/hwmon0/temp1_label":    "Tctl",
		"sys/class/hwmon/hwmon0/temp3_input":    "41000",
		"sys/class/hwmon/hwmon0/temp3_label":    "Tccd1",
		"sys/class/hwmon/hwmon1/name":           "amdgpu",
		"sys/class/hwmon/hwmon1/temp1_input":    "52000",
		"sys/class/hwmon/hwmon1/temp1_label":    "edge",
		"sys/class/hwmon/hwmon1/temp2_input":    "66000",
		"sys/class/hwmon/hwmon1/temp2_label":    "junction",
		"sys/class/hwmon/hwmon1/power1_average": "45000000",
		"sys/class/hwmon/hwmon1/fan1_input":     "0",
	})
	s := Read(root)
	if s.Summary.CPUTempC != 48.25 || s.Summary.GPUTempC != 66 {
		t.Fatalf("summary %+v", s.Summary)
	}
	found := false
	for _, r := range s.Readings {
		if r.Kind == "power" && r.Chip == "amdgpu" {
			found = r.Value == 45
		}
	}
	if !found {
		t.Fatal("GPU power (µW → W) not read")
	}
}

func TestThermalZoneFallback(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"sys/class/thermal/thermal_zone0/type": "acpitz",
		"sys/class/thermal/thermal_zone0/temp": "30000",
		"sys/class/thermal/thermal_zone1/type": "x86_pkg_temp",
		"sys/class/thermal/thermal_zone1/temp": "47000",
	})
	s := Read(root)
	if s.Summary.Source != "thermal_zone" || s.Summary.CPUTempC != 47 {
		t.Fatalf("summary %+v", s.Summary)
	}
}

func TestNoSensorsAtAll(t *testing.T) {
	s := Read(t.TempDir())
	if s.Summary.Source != "none" || len(s.Readings) != 0 {
		t.Fatalf("expected nothing, got %+v", s)
	}
}
