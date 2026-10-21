//go:build linux

package ipc

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// A request whose work takes longer than the I/O deadline (a slow service
// reload) must still be answered: the client used to be told "no answer"
// while the change went through.
func TestSlowHandlerIsStillAnswered(t *testing.T) {
	old := ioTimeout
	ioTimeout = 200 * time.Millisecond
	t.Cleanup(func() { ioTimeout = old })
	sock := filepath.Join(t.TempDir(), "d.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go Serve(l, func(Peer, Request) Response {
		time.Sleep(600 * time.Millisecond)
		return Response{OK: true}
	})
	resp, err := Call(sock, Request{Op: "status"})
	if err != nil || !resp.OK {
		t.Fatalf("slow answer lost: %+v %v", resp, err)
	}
}
