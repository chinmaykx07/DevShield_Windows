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
	"sync"
)

// procNameCache: PID → (ppid, name) for PIDs already read. Shared by
// every Watcher in the process (it mirrors /proc), so procCacheMu guards it
// and procRecheck.
var (
	procCacheMu   sync.Mutex
	procNameCache = map[int32]fastProc{}
)

// procRecheck: young processes still carrying their parent's name (forked
// but maybe not yet exec'd) are re-read for a few ticks, so a tool started
// as fork → pause → exec is not hidden behind its parent's name.
var procRecheck = map[int32]int{}

const forkRechecks = 6 // × 0.5 s

func fastProcList() ([]fastProc, error) {
	procCacheMu.Lock()
	defer procCacheMu.Unlock()
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
		if p, ok := procNameCache[pid]; ok && procRecheck[pid] == 0 {
			out = append(out, p)
			continue
		}
		p, ok := readProcStat(pid)
		if !ok {
			continue // exited between listing and reading
		}
		if left, rechecking := procRecheck[pid]; rechecking {
			if left <= 1 || p.Name != procNameCache[pid].Name {
				delete(procRecheck, pid)
			} else {
				procRecheck[pid] = left - 1
			}
		} else if parent, ok := procNameCache[p.PPID]; ok && parent.Name == p.Name {
			procRecheck[pid] = forkRechecks
		}
		procNameCache[pid] = p
		out = append(out, p)
	}
	for pid := range procNameCache {
		if !alive[pid] {
			delete(procNameCache, pid)
			delete(procRecheck, pid)
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
	tty := len(fields) > 4 && fields[4] != "0" // field 7 of stat: tty_nr
	return fastProc{PID: pid, PPID: int32(ppid), Name: string(data[open+1 : close]), Interactive: tty}, true
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
// start automatically or on a schedule: systemd units (system, every
// user's, and drop-in overrides; timers start a .service, which is what is
// read), XDG autostart, and cron jobs (user crontabs, /etc/crontab,
// /etc/cron.d).
func autostartEntries() map[string]string { return autostartEntriesIn("/") }

func autostartEntriesIn(root string) map[string]string {
	out := map[string]string{}
	add := func(cmd, where, file string) {
		if f := strings.Fields(cmd); len(f) > 0 {
			out[autostartKey(f[0], cmd)] = where + " (" + filepath.Base(file) + ")"
		}
	}
	scan := func(dir, glob, key, where string) {
		files, _ := filepath.Glob(filepath.Join(root, dir, glob))
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, key) {
					add(strings.TrimLeft(strings.TrimPrefix(line, key), "-@!+:"), where, file) // systemd prefixes
				}
			}
		}
	}
	units := func(dir, where string) {
		scan(dir, "*.service", "ExecStart=", where)
		scan(dir, "*.service.d/*.conf", "ExecStart=", where+" override")
	}
	// Every account's entries, not just the daemon's own (it runs as root).
	for _, home := range homeDirs(root) {
		units(filepath.Join(home, ".config/systemd/user"), "systemd user unit")
		scan(filepath.Join(home, ".config/autostart"), "*.desktop", "Exec=", "XDG autostart")
	}
	units("/etc/systemd/system", "systemd unit")
	units("/etc/systemd/user", "systemd user unit (all users)")
	scan("/etc/xdg/autostart", "*.desktop", "Exec=", "XDG autostart")

	// cron: user crontabs have no user field, system ones do.
	cron := func(file string, userField bool) {
		data, err := os.ReadFile(file)
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 || strings.HasPrefix(f[0], "#") || (strings.Contains(f[0], "=") && !strings.HasPrefix(f[0], "@")) {
				continue // blank, comment or VAR=value
			}
			skip := 5 // minute hour day month weekday
			if strings.HasPrefix(f[0], "@") {
				skip = 1 // @reboot, @daily, …
			}
			if userField {
				skip++
			}
			if len(f) > skip {
				add(strings.Join(f[skip:], " "), "cron job", file)
			}
		}
	}
	for _, glob := range []string{"var/spool/cron/crontabs/*", "var/spool/cron/*"} {
		files, _ := filepath.Glob(filepath.Join(root, glob))
		for _, file := range files {
			if st, err := os.Stat(file); err == nil && st.Mode().IsRegular() {
				cron(file, false)
			}
		}
	}
	cron(filepath.Join(root, "etc/crontab"), true)
	files, _ := filepath.Glob(filepath.Join(root, "etc/cron.d/*"))
	for _, file := range files {
		cron(file, true)
	}
	return out
}

// homeDirs lists every account's home from /etc/passwd (homes need not be
// under /home), plus /home/* and /root, relative to root.
func homeDirs(root string) []string {
	seen := map[string]bool{}
	var out []string
	addHome := func(h string) {
		h = filepath.Clean("/" + h)
		if h != "/" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	if data, err := os.ReadFile(filepath.Join(root, "etc/passwd")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if f := strings.Split(line, ":"); len(f) >= 6 {
				addHome(f[5])
			}
		}
	}
	homes, _ := filepath.Glob(filepath.Join(root, "home/*"))
	for _, h := range homes {
		addHome(strings.TrimPrefix(h, filepath.Clean(root)))
	}
	addHome("/root")
	return out
}
