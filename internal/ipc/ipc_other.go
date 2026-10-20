//go:build !linux

package ipc

import "net"

// Listen is not implemented yet outside Linux (Windows uses a named pipe
// with an ACL in roadmap Phase W; macOS comes later).
func Listen(path string) (net.Listener, error) { return nil, ErrUnsupported }

func peerOf(conn net.Conn) (Peer, error) { return Peer{}, ErrUnsupported }
