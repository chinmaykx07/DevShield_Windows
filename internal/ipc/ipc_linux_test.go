//go:build linux

package ipc

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
)

// A socket a running daemon answers on must not be taken over; a stale
// one left by a crash must be replaced.
func TestListenRefusesLiveSocketReplacesStale(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "d.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if _, err := Listen(sock); err == nil || !strings.Contains(err.Error(), "already listening") {
		t.Fatalf("live socket replaced: %v", err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false) // leave a stale socket file, as a crash would
	l.Close()
	l2, err := Listen(sock)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	l2.Close()
}
