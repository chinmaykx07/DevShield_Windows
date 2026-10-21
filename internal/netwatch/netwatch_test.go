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
	ips := r.IPs([]string{"telemetry.example", "sinkholed.example"})
	if ips["203.0.113.9"] != "telemetry.example" || len(ips) != 1 {
		t.Fatalf("ips = %v", ips)
	}
	online = false
	if ips := r.IPs([]string{"telemetry.example"}); ips["203.0.113.9"] == "" {
		t.Fatal("offline refresh dropped the last good set")
	}
}

func TestDedupe(t *testing.T) {
	d := &Dedupe{Window: time.Hour}
	now := time.Now()
	if !d.First("code|x", now) || d.First("code|x", now.Add(time.Minute)) || !d.First("code|x", now.Add(2*time.Hour)) {
		t.Fatal("dedupe window wrong")
	}
}
