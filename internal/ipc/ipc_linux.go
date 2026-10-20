//go:build linux

package ipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// Listen creates the daemon socket. The socket is connectable by any local
// user (mode 0666) on purpose: every request is then authorized by the
// kernel-reported peer uid, which a caller cannot fake. A stale socket
// from a previous run is replaced.
func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket file %s", path)
		}
		_ = os.Remove(path)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// peerOf asks the kernel who is on the other end of a Unix socket.
func peerOf(conn net.Conn) (Peer, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Peer{}, fmt.Errorf("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Peer{}, err
	}
	if credErr != nil {
		return Peer{}, credErr
	}
	p := Peer{UID: int(cred.Uid), PID: int(cred.Pid)}
	p.Exe, _ = os.Readlink("/proc/" + strconv.Itoa(p.PID) + "/exe")
	return p, nil
}
