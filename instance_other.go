//go:build !windows

// instance_other.go — Non-Windows stub for single-instance enforcement.
//
// This stub exists only so that go build / go vet / gopls can succeed on
// Linux and macOS development machines and CI containers. It provides no
// real single-instance protection because the actual DevShield runtime is
// Windows-only.

package main

import "log"

func checkSingleInstance() {
	log.Println("main: checkSingleInstance is a no-op stub on this platform " +
		"(non-Windows build — for compile verification only, not a real DevShield run)")
}
