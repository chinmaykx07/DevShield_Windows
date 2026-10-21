//go:build !windows && !linux

// agentwatch_other.go — Fallback collectors (macOS, BSD) for Agent Watch.
//
// DevShield targets Windows and Linux (see agentwatch_windows.go and
// agentwatch_linux.go). These portable fallbacks only keep other
// platforms compiling; they are slower and collect less.

package agentwatch

import (
	"errors"

	"github.com/shirou/gopsutil/v3/process"
)

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

// startExecEvents: kernel exec events are Linux-only so far.
func (w *Watcher) startExecEvents() error {
	return errors.New("exec events are only implemented on Linux")
}

func readFastProc(int32) (fastProc, bool) { return fastProc{}, false }
