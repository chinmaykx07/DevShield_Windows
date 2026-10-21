//go:build linux

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lockState makes sure only one daemon uses a state directory: two would
// append to the same audit log and break its hash chain. The kernel drops
// the lock when the process exits, however it exits.
func lockState(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, "daemon.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if err == syscall.EWOULDBLOCK {
			return nil, fmt.Errorf("another DevShield daemon is already running with state in %s (only one may run; stop it first)", dir)
		}
		return nil, fmt.Errorf("lock %s: %w", dir, err)
	}
	return f, nil
}
