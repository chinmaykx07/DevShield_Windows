//go:build linux

package procevents

import (
	"os/exec"
	"sync"
	"testing"
	"time"
)

// Every program start is delivered, including ones that exit at once
// (what /proc sampling misses).
func TestEveryExecIsDelivered(t *testing.T) {
	l, err := Open()
	if err != nil {
		t.Skipf("proc connector unavailable here (needs CAP_NET_ADMIN and CONFIG_PROC_EVENTS): %v", err)
	}
	var mu sync.Mutex
	seen := map[int32]bool{}
	stop, done := make(chan struct{}), make(chan error)
	go func() {
		done <- l.Run(stop, func(pid int32) { mu.Lock(); seen[pid] = true; mu.Unlock() })
	}()
	var pids []int32
	for i := 0; i < 20; i++ {
		c := exec.Command("/bin/true")
		if err := c.Run(); err != nil {
			t.Fatal(err)
		}
		pids = append(pids, int32(c.Process.Pid))
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		missing := 0
		for _, p := range pids {
			if !seen[p] {
				missing++
			}
		}
		mu.Unlock()
		if missing == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d execs not delivered", missing, len(pids))
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(stop)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
