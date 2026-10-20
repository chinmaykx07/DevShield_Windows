// Package sensors reads hardware sensors on Linux straight from the kernel
// (hwmon in /sys/class/hwmon, with /sys/class/thermal as a fallback).
// No download and no root needed: these files are world-readable. This
// replaces the Windows build's dependency on LibreHardwareMonitor.
//
// Root is a filesystem prefix ("" = the real system) so the parser can be
// tested against recorded sysfs layouts.
package sensors

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Reading is one sensor value.
type Reading struct {
	Chip  string  `json:"chip"`  // hwmon driver name, e.g. coretemp, k10temp, amdgpu, nvme
	Label string  `json:"label"` // e.g. "Package id 0", "Tctl", "edge", "fan1"
	Kind  string  `json:"kind"`  // temp | fan | power
	Value float64 `json:"value"` // °C, RPM or W
	Unit  string  `json:"unit"`
	Crit  float64 `json:"crit,omitempty"` // critical threshold if the chip reports one
}

// Summary picks the numbers people care about. 0 means unknown.
type Summary struct {
	CPUTempC  float64 `json:"cpu_temp_c"`
	GPUTempC  float64 `json:"gpu_temp_c"`
	NVMeTempC float64 `json:"nvme_temp_c"`
	MaxFanRPM float64 `json:"max_fan_rpm"`
	Source    string  `json:"source"` // hwmon | thermal_zone | none
}

// Snapshot is one full read.
type Snapshot struct {
	Readings []Reading `json:"readings"`
	Summary  Summary   `json:"summary"`
}

var cpuChips = map[string]bool{"coretemp": true, "k10temp": true, "zenpower": true, "cpu_thermal": true, "cpu-thermal": true}
var gpuChips = map[string]bool{"amdgpu": true, "nouveau": true, "radeon": true, "xe": true, "i915": true}

// Read collects every hwmon reading under root, falling back to thermal
// zones when no hwmon chip exposes temperatures.
func Read(root string) Snapshot {
	var s Snapshot
	chips, _ := filepath.Glob(filepath.Join(root, "/sys/class/hwmon/hwmon*"))
	sort.Strings(chips)
	for _, dir := range chips {
		s.Readings = append(s.Readings, readChip(dir)...)
	}
	if hasKind(s.Readings, "temp") {
		s.Summary.Source = "hwmon"
	} else if zones := readThermalZones(root); len(zones) > 0 {
		s.Readings = append(s.Readings, zones...)
		s.Summary.Source = "thermal_zone"
	} else {
		s.Summary.Source = "none"
	}
	s.Summary = summarize(s.Readings, s.Summary.Source)
	return s
}

func readChip(dir string) []Reading {
	chip := readString(filepath.Join(dir, "name"))
	if chip == "" {
		chip = filepath.Base(dir)
	}
	var out []Reading
	add := func(kind, prefix, unit string, scale float64) {
		inputs, _ := filepath.Glob(filepath.Join(dir, prefix+"*_input"))
		if kind == "power" {
			avg, _ := filepath.Glob(filepath.Join(dir, prefix+"*_average"))
			inputs = append(inputs, avg...)
		}
		sort.Strings(inputs)
		seen := map[string]bool{}
		for _, in := range inputs {
			base := filepath.Base(in)
			id := base[:strings.LastIndexByte(base, '_')] // "temp1"
			if seen[id] {
				continue // power1_input and power1_average: keep one
			}
			raw, ok := readNumber(in)
			if !ok {
				continue // sensor present but not readable right now
			}
			seen[id] = true
			label := readString(filepath.Join(dir, id+"_label"))
			if label == "" {
				label = id
			}
			r := Reading{Chip: chip, Label: label, Kind: kind, Value: raw / scale, Unit: unit}
			if c, ok := readNumber(filepath.Join(dir, id+"_crit")); ok {
				r.Crit = c / scale
			}
			out = append(out, r)
		}
	}
	add("temp", "temp", "°C", 1000) // millidegrees
	add("fan", "fan", "RPM", 1)     // RPM
	add("power", "power", "W", 1e6) // microwatts
	return out
}

func readThermalZones(root string) []Reading {
	zones, _ := filepath.Glob(filepath.Join(root, "/sys/class/thermal/thermal_zone*"))
	sort.Strings(zones)
	var out []Reading
	for _, z := range zones {
		v, ok := readNumber(filepath.Join(z, "temp"))
		if !ok {
			continue
		}
		typ := readString(filepath.Join(z, "type"))
		out = append(out, Reading{Chip: "thermal_zone", Label: typ, Kind: "temp", Value: v / 1000, Unit: "°C"})
	}
	return out
}

// summarize picks CPU/GPU/NVMe temperatures. For CPUs the package-level
// sensor is preferred (coretemp "Package id N", k10temp "Tctl"/"Tdie");
// otherwise the hottest sensor of that chip. Multi-socket → the hottest.
func summarize(rs []Reading, source string) Summary {
	s := Summary{Source: source}
	pkgCPU, anyCPU := 0.0, 0.0
	for _, r := range rs {
		switch r.Kind {
		case "fan":
			s.MaxFanRPM = max(s.MaxFanRPM, r.Value)
		case "temp":
			l := strings.ToLower(r.Label)
			switch {
			case cpuChips[r.Chip]:
				if strings.HasPrefix(l, "package id") || l == "tctl" || l == "tdie" {
					pkgCPU = max(pkgCPU, r.Value)
				}
				anyCPU = max(anyCPU, r.Value)
			case r.Chip == "thermal_zone" && (l == "x86_pkg_temp" || strings.Contains(l, "cpu")):
				pkgCPU = max(pkgCPU, r.Value)
			case gpuChips[r.Chip]:
				s.GPUTempC = max(s.GPUTempC, r.Value)
			case r.Chip == "nvme" && (l == "composite" || strings.HasPrefix(l, "temp")):
				s.NVMeTempC = max(s.NVMeTempC, r.Value)
			}
		}
	}
	s.CPUTempC = pkgCPU
	if s.CPUTempC == 0 {
		s.CPUTempC = anyCPU
	}
	return s
}

func hasKind(rs []Reading, kind string) bool {
	for _, r := range rs {
		if r.Kind == kind {
			return true
		}
	}
	return false
}

func readString(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readNumber(path string) (float64, bool) {
	v, err := strconv.ParseFloat(readString(path), 64)
	return v, err == nil
}
