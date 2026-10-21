//go:build windows

// agentwatch_windows.go — Windows collectors for Agent Watch.
//
// All of these work without admin rights for the current user's own
// processes. Other users' / elevated processes are simply skipped.

package agentwatch

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// fastProcList returns PID, parent PID and image name for every process
// using one Toolhelp snapshot — cheap enough to run every two seconds.
func fastProcList() ([]fastProc, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var out []fastProc
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		out = append(out, fastProc{
			PID:  int32(e.ProcessID),
			PPID: int32(e.ParentProcessID),
			Name: windows.UTF16ToString(e.ExeFile[:]),
		})
	}
	return out, nil
}

// processModules lists the DLL names loaded by pid (lower case).
// Returns nil if the process cannot be opened (another user, protected).
func processModules(pid int32) []string {
	snap, err := windows.CreateToolhelp32Snapshot(
		windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, uint32(pid))
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)

	var m windows.ModuleEntry32
	m.Size = uint32(unsafe.Sizeof(m))
	var out []string
	for err = windows.Module32First(snap, &m); err == nil; err = windows.Module32Next(snap, &m) {
		out = append(out, strings.ToLower(windows.UTF16ToString(m.Module[:])))
	}
	return out
}

// autostartEntries maps lower-case exe paths to where they are registered
// to start at logon: Run/RunOnce registry keys and the Startup folders.
// (Scheduled tasks and services are Phase 2 — they need admin to enumerate.)
func autostartEntries() map[string]string {
	out := map[string]string{}

	keys := []struct {
		root registry.Key
		path string
		name string
	}{
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, `HKCU\...\Run`},
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, `HKCU\...\RunOnce`},
		{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, `HKLM\...\Run`},
		{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, `HKLM\...\RunOnce`},
		{registry.LOCAL_MACHINE, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, `HKLM\...\WOW6432Node\Run`},
	}
	for _, k := range keys {
		key, err := registry.OpenKey(k.root, k.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, _ := key.ReadValueNames(-1)
		for _, n := range names {
			if v, _, err := key.GetStringValue(n); err == nil {
				// REG_EXPAND_SZ values hold %VAR% paths; os.ExpandEnv only knows $VAR.
				if x, err := registry.ExpandString(v); err == nil {
					v = x
				}
				if exe := exeFromCommand(v); exe != "" {
					out[autostartKey(exe, v)] = k.name + ` "` + n + `"`
				}
			}
		}
		key.Close()
	}

	startupDirs := []string{
		filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`),
		filepath.Join(os.Getenv("PROGRAMDATA"), `Microsoft\Windows\Start Menu\Programs\StartUp`),
	}
	for _, dir := range startupDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			full := filepath.Join(dir, e.Name())
			if strings.EqualFold(filepath.Ext(e.Name()), ".lnk") {
				// Shortcut targets are stored as plain paths inside the .lnk
				data, err := os.ReadFile(full)
				if err != nil {
					continue
				}
				for _, exe := range exePathsInBytes(data) {
					out[strings.ToLower(exe)] = "Startup folder (" + e.Name() + ")"
				}
				continue
			}
			out[strings.ToLower(full)] = "Startup folder"
		}
	}
	return out
}

// startExecEvents: kernel exec events are Linux-only so far.
func (w *Watcher) startExecEvents() error {
	return errors.New("exec events are only implemented on Linux")
}

func readFastProc(int32) (fastProc, bool) { return fastProc{}, false }

// execChanged: Windows has no exec-in-place; a new program is a new
// process (new PID or start time), which the cache already handles.
func execChanged(*process.Process, ProcInfo) bool { return false }
