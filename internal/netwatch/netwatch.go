// Package netwatch shows which program talks to whom (Linux counterpart of
// the Windows Network Guardian). It does no scanning of its own: it
// classifies the connections Agent Watch already collected each scan.
//
// Categories:
//
//	llm        an LLM API (from Agent Watch's resolved API hosts)
//	telemetry  a domain on the sinkhole's telemetry list
//	lan        private, link-local or multicast address
//	loopback   this machine
//	other      everything else
//
// Matching is by IP. Shared CDN addresses mean a label can be wrong in
// both directions, so it is shown as "likely", never as proof.
package netwatch

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Conn is one connection to classify.
type Conn struct {
	PID    int32
	Name   string
	Exe    string
	User   string
	Remote string // "ip:port"
}

// Entry is a classified connection.
type Entry struct {
	PID      int32  `json:"pid"`
	Program  string `json:"program"`
	Exe      string `json:"exe,omitempty"`
	User     string `json:"user,omitempty"`
	Remote   string `json:"remote"`
	Category string `json:"category"`
	Host     string `json:"host,omitempty"` // the known name behind the IP
	Count    int    `json:"count"`          // connections from this process to this endpoint
}

// Classify labels conns. llmHost and telemetry map an IP to a host name.
func Classify(conns []Conn, llmHost func(ip string) string, telemetry map[string]string) []Entry {
	out := make([]Entry, 0, len(conns))
	index := map[string]int{} // pid|remote → position, to merge parallel connections
	for _, c := range conns {
		key := fmt.Sprint(c.PID, "|", c.Remote)
		if i, ok := index[key]; ok {
			out[i].Count++
			continue
		}
		index[key] = len(out)
		e := Entry{PID: c.PID, Program: c.Name, Exe: c.Exe, User: c.User, Remote: c.Remote, Category: "other", Count: 1}
		host, _, err := net.SplitHostPort(c.Remote)
		ip := net.ParseIP(host)
		switch {
		case err != nil || ip == nil:
		case ip.IsLoopback():
			e.Category = "loopback"
		case telemetry[ip.String()] != "":
			e.Category, e.Host = "telemetry", telemetry[ip.String()]
		case llmHost != nil && llmHost(ip.String()) != "":
			e.Category, e.Host = "llm", llmHost(ip.String())
		case ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast():
			e.Category = "lan"
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return rank[out[i].Category] < rank[out[j].Category]
		}
		return out[i].Program < out[j].Program
	})
	return out
}

var rank = map[string]int{"telemetry": 0, "llm": 1, "other": 2, "lan": 3, "loopback": 4}

// Resolver keeps telemetry domains resolved to IPs. Lookups never run on
// the caller's path: IPs answers from the cache at once and, when the
// cache is stale, starts one background refresh (DNS can be slow or, under
// a lockdown, unreachable). Lookup is injectable for tests.
type Resolver struct {
	Interval time.Duration
	Lookup   func(host string) ([]string, error)

	mu         sync.Mutex
	at         time.Time
	ips        map[string]string
	refreshing bool
}

// IPs returns the cached ip → domain map (empty until the first refresh
// finishes) and refreshes it in the background when it is stale.
func (r *Resolver) IPs(domains []string) map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if (r.ips == nil || time.Since(r.at) >= r.Interval) && !r.refreshing {
		r.refreshing = true
		go r.Refresh(domains)
	}
	return r.ips
}

// Refresh resolves domains now. On failure (offline) the last good set is
// kept. A name answered with 0.0.0.0 or loopback (sinkholed) teaches nothing.
func (r *Resolver) Refresh(domains []string) {
	lookup := r.Lookup
	if lookup == nil {
		lookup = func(h string) ([]string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			return net.DefaultResolver.LookupHost(ctx, h)
		}
	}
	fresh := map[string]string{}
	for _, d := range domains {
		addrs, err := lookup(d)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() {
				fresh[ip.String()] = d
			}
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.at, r.refreshing = time.Now(), false
	if len(fresh) > 0 || r.ips == nil {
		r.ips = fresh
	}
}

// Dedupe reports each (program, host) pair at most once per window, so
// the audit log records that telemetry happened without filling up.
type Dedupe struct {
	Window time.Duration
	mu     sync.Mutex
	seen   map[string]time.Time
}

// First reports whether key has not been seen within the window.
func (d *Dedupe) First(key string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen == nil {
		d.seen = map[string]time.Time{}
	}
	for k, t := range d.seen { // keep the map small
		if now.Sub(t) > d.Window {
			delete(d.seen, k)
		}
	}
	if _, ok := d.seen[key]; ok {
		return false
	}
	d.seen[key] = now
	return true
}
