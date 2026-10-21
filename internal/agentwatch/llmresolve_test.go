package agentwatch

import (
	"context"
	"sync"
	"testing"
	"time"
)

// During a lockdown DNS outside the tunnel is dropped, so a lookup hangs.
// A scan must not wait for it, a second refresh must not pile up, and
// every lookup must have a deadline.
func TestLLMHostLookupNeverBlocksScan(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	calls, noDeadline := 0, 0
	w, err := New(Config{Lookup: func(ctx context.Context, host string) ([]string, error) {
		mu.Lock()
		calls++
		if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > llmLookupTimeout {
			noDeadline++
		}
		mu.Unlock()
		select {
		case <-release:
			return []string{"192.0.2.7"}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	w.refreshLLMIPs(w.Catalog())
	w.refreshLLMIPs(w.Catalog()) // while the first is still running
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("refresh blocked the scan for %v", d)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		w.mu.RLock()
		done, n := !w.resolving, len(w.llmIPs)
		w.mu.RUnlock()
		if done {
			if n == 0 {
				t.Fatal("resolved addresses not stored")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("refresh never finished")
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := len(w.Catalog().LLMAPIHosts); calls != want {
		t.Errorf("%d lookups, want %d (one refresh at a time)", calls, want)
	}
	if noDeadline > 0 {
		t.Errorf("%d lookups had no deadline (or a longer one)", noDeadline)
	}
}
