package netwatch

import (
	"errors"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	conns := []Conn{
		{Name: "code", Remote: "13.69.239.72:443"},
		{Name: "claude", Remote: "160.79.104.10:443"},
		{Name: "firefox", Remote: "93.184.215.14:443"},
		{Name: "cups", Remote: "192.168.1.20:631"},
		{Name: "postgres", Remote: "127.0.0.1:5432"},
		{Name: "ssh", Remote: "[fe80::1]:22"},
		{Name: "odd", Remote: "garbage"},
		{PID: 7, Name: "claude", Remote: "160.79.104.10:443"},
		{PID: 7, Name: "claude", Remote: "160.79.104.10:443"},
	}
	llm := func(ip string) string {
		if ip == "160.79.104.10" {
			return "api.anthropic.com"
		}
		return ""
	}
	got := Classify(conns, llm, map[string]string{"13.69.239.72": "dc.services.visualstudio.com"})
	want := map[string]string{"code": "telemetry", "claude": "llm", "firefox": "other", "cups": "lan", "postgres": "loopback", "ssh": "lan", "odd": "other"}
	for _, e := range got {
		if e.Category != want[e.Program] {
			t.Errorf("%s → %s, want %s", e.Program, e.Category, want[e.Program])
		}
	}
	if len(got) != 8 {
		t.Fatalf("parallel connections of one process not merged: %d entries", len(got))
	}
	for _, e := range got {
		if e.PID == 7 && e.Count != 2 {
			t.Errorf("merged count = %d, want 2", e.Count)
		}
	}
	if got[0].Program != "code" || got[0].Host != "dc.services.visualstudio.com" {
		t.Errorf("telemetry must be listed first with its host: %+v", got[0])
	}
}

func TestResolverKeepsLastGoodSetAndIgnoresSinkhole(t *testing.T) {
	online := true
	r := &Resolver{Interval: 0, Lookup: func(h string) ([]string, error) {
		if !online {
			return nil, errors.New("offline")
		}
		if h == "sinkholed.example" {
			return []string{"0.0.0.0"}, nil
		}
		return []string{"203.0.113.9"}, nil
	}}
	r.Refresh([]string{"telemetry.example", "sinkholed.example"})
	ips := r.IPs(nil)
	if ips["203.0.113.9"] != "telemetry.example" || len(ips) != 1 {
		t.Fatalf("ips = %v", ips)
	}
	online = false
	r.Refresh([]string{"telemetry.example"})
	if ips := r.IPs(nil); ips["203.0.113.9"] == "" {
		t.Fatal("offline refresh dropped the last good set")
	}
}

// A request must never wait for DNS (found in review: during a lockdown
// "devshield net" could exceed the 10 s IPC deadline).
func TestResolverNeverBlocksCaller(t *testing.T) {
	release := make(chan struct{})
	r := &Resolver{Interval: time.Hour, Lookup: func(string) ([]string, error) {
		<-release
		return []string{"203.0.113.9"}, nil
	}}
	answered := make(chan map[string]string, 2)
	go func() {
		answered <- r.IPs([]string{"a.example", "b.example"})
		answered <- r.IPs([]string{"a.example"}) // a second caller must not wait either
	}()
	for i := 0; i < 2; i++ {
		select {
		case ips := <-answered:
			if len(ips) != 0 {
				t.Fatalf("got %v before any lookup finished", ips)
			}
		case <-time.After(time.Second):
			close(release)
			t.Fatal("caller waited for DNS")
		}
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for len(r.IPs(nil)) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(r.IPs(nil)) == 0 {
		t.Fatal("background refresh never landed")
	}
}

func TestDedupe(t *testing.T) {
	d := &Dedupe{Window: time.Hour}
	now := time.Now()
	if !d.First("code|x", now) || d.First("code|x", now.Add(time.Minute)) || !d.First("code|x", now.Add(2*time.Hour)) {
		t.Fatal("dedupe window wrong")
	}
}
