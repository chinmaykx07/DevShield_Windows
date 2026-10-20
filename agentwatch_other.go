//go:build !windows

// agentwatch_other.go — Non-Windows collectors for Agent Watch.
//
// DevShield ships for Windows only. These implementations exist so the
// project builds and Agent Watch's logic can be exercised on Linux/macOS
// development machines and CI.

package main

import "github.com/shirou/gopsutil/v3/process"

func fastProcList() ([]fastProc, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}
	out := make([]fastProc, 0, len(procs))
	for _, p := range procs {
		name, _ := p.Name()
		ppid, _ := p.Ppid()
		out = append(out, fastProc{PID: p.Pid, PPID: ppid, Name: name})
	}
	return out, nil
}

// processModules is not implemented outside Windows.
func processModules(pid int32) []string { return nil }

// autostartEntries is not implemented outside Windows.
func autostartEntries() map[string]string { return map[string]string{} }
