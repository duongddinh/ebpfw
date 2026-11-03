//go:build !linux

package firewall

import (
	"errors"
	"github.com/duongddinh/ebpfw/internal/config"
)

type Manager struct{ Root, Object string }
type Status struct {
	AgentAlive       bool              `json:"agent_alive"`
	AgentPID         int               `json:"agent_pid,omitempty"`
	EarlyActive      bool              `json:"early_active"`
	EarlyInterfaces  []string          `json:"early_interfaces,omitempty"`
	Enabled          bool              `json:"enabled"`
	Hooks            int               `json:"hooks"`
	Generation       uint32            `json:"generation"`
	Rules            uint32            `json:"rules"`
	Counters         map[string]uint64 `json:"counters"`
	RuleCounters     []uint64          `json:"rule_counters"`
	ConntrackEntries int               `json:"conntrack_entries"`
	PinRoot          string            `json:"pin_root"`
}

func DefaultRoot() string                     { return "/sys/fs/bpf/ebpfw" }
func NewManager(root, object string) *Manager { return &Manager{root, object} }
func (m *Manager) Apply(config.Config) error {
	return errors.New("enforcement requires Linux 6.6+ with BTF and Netfilter eBPF")
}
func (m *Manager) Status() (Status, error) { return Status{}, errors.New("live status requires Linux") }
func (m *Manager) Doctor() error           { return errors.New("enforcement requires Linux 6.6+") }
func (m *Manager) Run(string, interface{ Write([]byte) (int, error) }) error {
	return errors.New("enforcement requires Linux")
}
func (m *Manager) Logs(interface{ Write([]byte) (int, error) }) error {
	return errors.New("packet events require Linux")
}
func (m *Manager) Accelerate(string, string) error {
	return errors.New("XDP acceleration requires Linux")
}
func (m *Manager) Deaccelerate(string) error { return errors.New("XDP acceleration requires Linux") }
