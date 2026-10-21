//go:build !linux

package daemon

import "os"

// lockState: the daemon runs on Linux only so far.
func lockState(string) (*os.File, error) { return nil, nil }
