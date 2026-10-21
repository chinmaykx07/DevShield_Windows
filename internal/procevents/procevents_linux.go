//go:build linux

// Package procevents delivers the kernel's process events (the netlink
// "proc connector"): every exec as it happens, instead of what a /proc
// scan happens to catch. It needs CAP_NET_ADMIN and a kernel built with
// CONFIG_PROC_EVENTS (standard on mainstream distributions); callers keep
// their /proc scan as the fallback.
package procevents

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Values from linux/connector.h and linux/cn_proc.h.
const (
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1
	procCnMcastIgnore = 2
	procEventExec     = 0x00000002
	cnMsgLen          = 20 // struct cn_msg without data
)

// Listener is an open subscription.
type Listener struct {
	fd int
	// Lost counts receive-buffer overflows: events were dropped by the
	// kernel (exec storms). The /proc scan still covers them, later.
	Lost int
}

// Open subscribes to process events.
func Open() (*Listener, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
	if err != nil {
		return nil, fmt.Errorf("proc connector socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: cnIdxProc}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("proc connector bind: %w", err)
	}
	// Bursts of execs (builds) must not overflow the default buffer.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 4<<20)
	// Wake up regularly so Run notices it should stop.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 200000})
	l := &Listener{fd: fd}
	if err := l.control(procCnMcastListen); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("proc connector subscribe: %w", err)
	}
	return l, nil
}

func (l *Listener) control(op uint32) error {
	msg := make([]byte, unix.NLMSG_HDRLEN+cnMsgLen+4)
	ne := binary.NativeEndian
	ne.PutUint32(msg[0:], uint32(len(msg)))
	ne.PutUint16(msg[4:], unix.NLMSG_DONE)
	ne.PutUint32(msg[12:], uint32(os.Getpid()))
	cn := msg[unix.NLMSG_HDRLEN:]
	ne.PutUint32(cn[0:], cnIdxProc)
	ne.PutUint32(cn[4:], cnValProc)
	ne.PutUint16(cn[16:], 4)
	ne.PutUint32(cn[cnMsgLen:], op)
	return unix.Sendto(l.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

// Run calls onExec with the PID of every process that starts a new
// program, until stop is closed. It then unsubscribes and closes.
func (l *Listener) Run(stop <-chan struct{}, onExec func(pid int32)) error {
	defer func() {
		_ = l.control(procCnMcastIgnore)
		unix.Close(l.fd)
	}()
	buf := make([]byte, 64<<10)
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		n, from, err := unix.Recvfrom(l.fd, buf, 0)
		switch {
		case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.ENOBUFS):
			l.Lost++
			continue
		case err != nil:
			return fmt.Errorf("proc connector: %w", err)
		}
		if !fromKernel(from) {
			continue // only the kernel speaks for process events
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			continue
		}
		for _, m := range msgs {
			if pid, ok := execPID(m.Data); ok {
				onExec(pid)
			}
		}
	}
}

// fromKernel: another local program can send to this socket; only
// messages from the kernel (netlink port 0) are process events.
func fromKernel(from unix.Sockaddr) bool {
	nl, ok := from.(*unix.SockaddrNetlink)
	return ok && nl.Pid == 0
}

// execPID reads a cn_msg carrying a proc_event: what (u32), cpu (u32),
// timestamp (u64), then for exec: process_pid, process_tgid.
func execPID(data []byte) (int32, bool) {
	ev := cnMsgLen
	if len(data) < ev+24 {
		return 0, false
	}
	ne := binary.NativeEndian
	if ne.Uint32(data[0:]) != cnIdxProc || ne.Uint32(data[ev:]) != procEventExec {
		return 0, false
	}
	return int32(ne.Uint32(data[ev+20:])), true // the thread group: the process
}
