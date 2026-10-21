//go:build !linux

package egress

import (
	"errors"
	"time"
)

var errUnsupported = errors.New("network controls are only implemented on Linux so far")

// Config for a Manager.
type Config struct {
	StateDir   string
	ProcRoot   string
	CgroupRoot string
	Nft        func(script string, check bool) error
	NftList    func() (string, error)
	Emit       func(action, detail, status string)
}

// Status is what the egress controls look like right now.
type Status struct {
	CgroupV2         bool        `json:"cgroup_v2"`
	RulesLoaded      bool        `json:"rules_loaded"`
	Blocked          []BlockInfo `json:"blocked,omitempty"`
	Lockdown         *Lockdown   `json:"lockdown,omitempty"`
	ConfirmBy        time.Time   `json:"confirm_by,omitempty"`
	QuarantinedProcs int         `json:"quarantined_processes"`
	Allowed          []BlockInfo `json:"allowed,omitempty"`
	AllowedProcs     int         `json:"allowed_processes"`
}

// BlockInfo is the client view of one blocked agent.
type BlockInfo struct {
	ID    string    `json:"id"`
	Name  string    `json:"name"`
	Since time.Time `json:"since"`
	Flows int       `json:"flows_cut"`
}

// Manager is a stub outside Linux.
type Manager struct{}

func New(Config) (*Manager, error)                                     { return nil, errUnsupported }
func (*Manager) Block(string, string, string, []int) (int, int, error) { return 0, 0, errUnsupported }
func (*Manager) Unblock(string) error                                  { return errUnsupported }
func (*Manager) Reconcile(map[string][]int) []string                   { return nil }
func (*Manager) IsBlocked(string) bool                                 { return false }
func (*Manager) ResolveBlocked(string) (string, bool)                  { return "", false }
func (*Manager) Allow(string, string, string, []int) (int, error)      { return 0, errUnsupported }
func (*Manager) Disallow(string) error                                 { return errUnsupported }
func (*Manager) IsAllowed(string) bool                                 { return false }
func (*Manager) AllowedFingerprints() []string                         { return nil }
func (*Manager) ResolveAllowed(string) (string, bool)                  { return "", false }
func (*Manager) LockdownOn(Lockdown, time.Duration) error              { return errUnsupported }
func (*Manager) Confirm() error                                        { return errUnsupported }
func (*Manager) LockdownOff() error                                    { return errUnsupported }
func (*Manager) Status() Status                                        { return Status{} }
func (*Manager) EnsureLoaded() (bool, error)                           { return false, errUnsupported }
