//go:build linux

// agentwatch_linux.go — Linux collectors for Agent Watch.
//
// Efficiency matters here: the fast tick runs twice a second. Reading
// every process's details each tick cost ~14 ms per tick on 78 processes
// (≈3% of a core). Instead, /proc is listed (one getdents) and a
// process's stat file is read only the first time its PID is seen.

package agentwatch

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// procNameCache: PID → (ppid, name) for PIDs already read. Only the fast
// tick goroutine touches it, so it needs no lock.
var procNameCache = map[int32]fastProc{}

func fastProcList() ([]fastProc, error) {
	d, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	names, err := d.Readdirnames(-1)
	d.Close()
	if err != nil {
		return nil, err
	}

	alive := make(map[int32]bool, len(names))
	out := make([]fastProc, 0, len(names))
	for _, n := range names {
		pid64, err := strconv.ParseInt(n, 10, 32)
		if err != nil {
			continue // not a PID directory
		}
		pid := int32(pid64)
		alive[pid] = true
		if p, ok := procNameCache[pid]; ok {
			out = append(out, p)
			continue
		}
		p, ok := readProcStat(pid)
		if !ok {
			continue // exited between listing and reading
		}
		procNameCache[pid] = p
		out = append(out, p)
	}
	for pid := range procNameCache {
		if !alive[pid] {
			delete(procNameCache, pid)
		}
	}
	return out, nil
}

// readProcStat parses "pid (comm) state ppid ..." from /proc/<pid>/stat.
// comm may contain spaces and parentheses, so split on the LAST ')'.
func readProcStat(pid int32) (fastProc, bool) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(int(pid)) + "/stat")
	if err != nil {
		return fastProc{}, false
	}
	open, close := bytes.IndexByte(data, '('), bytes.LastIndexByte(data, ')')
	if open < 0 || close < open {
		return fastProc{}, false
	}
	fields := strings.Fields(string(data[close+1:]))
	if len(fields) < 2 {
		return fastProc{}, false
	}
	ppid, _ := strconv.ParseInt(fields[1], 10, 32)
	return fastProc{PID: pid, PPID: int32(ppid), Name: string(data[open+1 : close])}, true
}

// processModules lists the shared libraries mapped into pid (lower-case
// file names), from /proc/<pid>/maps. Unreadable for other users' processes.
func processModules(pid int32) []string {
	f, err := os.Open("/proc/" + strconv.Itoa(int(pid)) + "/maps")
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, '/')
		if i < 0 || !strings.Contains(line[i:], ".so") {
			continue
		}
		name := strings.ToLower(filepath.Base(line[i:]))
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// autostartEntries maps executable paths to where they are registered to
// start automatically: systemd units (user + system) and XDG autostart.
// (cron @reboot needs root to read other users' crontabs — Phase 2.)
func autostartEntries() map[string]string {
	out := map[string]string{}
	home, _ := os.UserHomeDir()

	scan := func(dir, glob, key, where string) {
		files, _ := filepath.Glob(filepath.Join(dir, glob))
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, key) {
					continue
				}
				cmd := strings.TrimLeft(strings.TrimPrefix(line, key), "-@!+:") // systemd prefixes
				if f := strings.Fields(cmd); len(f) > 0 {
					out[strings.ToLower(f[0])] = where + " (" + filepath.Base(file) + ")"
				}
			}
		}
	}

	if home != "" {
		scan(filepath.Join(home, ".config/systemd/user"), "*.service", "ExecStart=", "systemd user unit")
		scan(filepath.Join(home, ".config/autostart"), "*.desktop", "Exec=", "XDG autostart")
	}
	scan("/etc/systemd/system", "*.service", "ExecStart=", "systemd unit")
	scan("/etc/xdg/autostart", "*.desktop", "Exec=", "XDG autostart")
	return out
}
