//go:build !linux

// Package procevents delivers process start events; Linux only so far.
package procevents

import "errors"

// Listener is an open subscription.
type Listener struct{ Lost int }

// Open reports that process events are not available here.
func Open() (*Listener, error) {
	return nil, errors.New("process events are only implemented on Linux")
}

// Run never runs.
func (l *Listener) Run(stop <-chan struct{}, onExec func(pid int32)) error { return nil }
