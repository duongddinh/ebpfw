// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/duongddinh/ebpfw/internal/config"
	"github.com/duongddinh/ebpfw/internal/firewall"
)

const help = `ebpfw: stateful eBPF host firewall (Linux 6.6+)

Usage: ebpfw [--config PATH] [--pin-root BPFFS_PATH] [--object ELF] [--dry-run] COMMAND
  allow|deny|reject|limit [in|out] [on IFACE] [PORT[/PROTO]|APP]
      [proto PROTO] [from IP/CIDR [port PORT]] [to IP/CIDR [port PORT]]
      [log] [comment TEXT] [rate N/minute] [burst N]
  route ACTION [in on IFACE] [out on IFACE] ...
  block from IP/CIDR             Absolute source block, including existing flows
  insert NUMBER ACTION ...      Insert rules before NUMBER
  prepend ACTION ...            Insert rules at the beginning
  delete NUMBER|ACTION ...      Delete a numbered or matching rule
  default allow|deny|reject [incoming|outgoing|routed]
  logging on|off                 Enable bounded packet-event logging
  status [numbered|verbose|json] Show desired configuration and live enforcement
  stats                         Show live counters and state-table usage as JSON
  check                         Validate the saved policy without applying it
  enable|disable|reload|restore  Reconcile persistent eBPF enforcement
  run                           Watch policy, expire flow state, log/reply to events
  reset                         Disable and reset to installation defaults
  app list|info NAME            Inspect built-in and custom profiles
  app set NAME PORT/PROTO...     Define or override an application profile
  app update NAME               Refresh expanded rules using a profile
  app delete NAME               Remove a custom definition (keeps existing rules)
  accelerate IFACE [native|generic]  Add optional absolute-block acceleration
  deaccelerate IFACE             Remove only this firewall's XDP link
  doctor                        Check the kernel/bpffs prerequisites

All firewall decisions run in eBPF. Accepted local traffic uses Linux TCP/IP.
Pinned kernel links keep enforcing when the management/event process exits.
`

func main() {
	if e := run(os.Args[1:], os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, "ebpfw:", e)
		os.Exit(1)
	}
}
func systemd(operation string, out io.Writer) error {
	if _, e := os.Stat("/usr/lib/systemd/system/ebpfw.service"); os.IsNotExist(e) {
		return nil
	}
	c := exec.Command("systemctl", operation, "--now", "ebpfw.service")
	c.Stdout = out
	c.Stderr = out
	return c.Run()
}
func run(args []string, out io.Writer) error {
	f := flag.NewFlagSet("ebpfw", flag.ContinueOnError)
	f.SetOutput(out)
	path := f.String("config", "/etc/ebpfw/rules.json", "configuration path")
	root := f.String("pin-root", "", "bpffs pin root (default: per network namespace)")
	object := f.String("object", "/usr/local/lib/ebpfw/stateful.o", "compiled eBPF object")
	dry := f.Bool("dry-run", false, "print planned configuration without changing disk or kernel")
	if e := f.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			fmt.Fprint(out, help)
			return nil
		}
		return e
	}
	args = f.Args()
	if len(args) == 0 || args[0] == "help" {
		fmt.Fprint(out, help)
		return nil
	}
	command, args := args[0], args[1:]
	manager := firewall.NewManager(*root, *object)
	load := func() (config.Config, error) { return config.Load(*path) }
	switch command {
	case "accelerate":
		if len(args) < 1 || len(args) > 2 {
			return errors.New("usage: accelerate IFACE [native|generic]")
		}
		mode := "native"
		if len(args) == 2 {
			mode = args[1]
		}
		if *dry {
			return errors.New("dry-run supports policy changes, not attachment")
		}
		return manager.Accelerate(args[0], mode)
	case "deaccelerate":
		if len(args) != 1 {
			return errors.New("usage: deaccelerate IFACE")
		}
		if *dry {
			return errors.New("dry-run supports policy changes, not attachment")
		}
		return manager.Deaccelerate(args[0])
	case "app":
		c, e := load()
		if os.IsNotExist(e) {
			c = config.New()
		} else if e != nil {
			return e
		}
		profiles := config.AvailableProfiles(c.Applications)
		if len(args) > 0 && (args[0] == "set" || args[0] == "delete" || args[0] == "update") {
			command = "app-" + args[0]
			args = args[1:]
			break
		}
		if len(args) == 1 && args[0] == "list" {
			names := make([]string, 0, len(profiles))
			for n := range profiles {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				fmt.Fprintln(out, n)
			}
			return nil
		}
		if len(args) == 2 && args[0] == "info" {
			p, ok := profiles[args[1]]
			if !ok {
				return errors.New("unknown application profile")
			}
			return json.NewEncoder(out).Encode(p)
		}
		return errors.New("usage: app list | app info NAME")
	case "help":
		fmt.Fprint(out, help)
		return nil
	case "doctor":
		if len(args) != 0 {
			return errors.New("unexpected arguments")
		}
		if e := manager.Doctor(); e != nil {
			return e
		}
		fmt.Fprintln(out, "Kernel BTF and bpffs are available; enable performs the definitive helper/verifier/hook checks.")
		return nil
	case "check", "status":
		c, e := load()
		if e != nil {
			return e
		}
		p, e := firewall.Compile(c, binary.NativeEndian)
		if e != nil {
			return e
		}
		if command == "check" {
			if len(args) != 0 {
				return errors.New("unexpected arguments")
			}
			fmt.Fprintln(out, "Policy is valid:", p.Summary())
			return nil
		}
		if len(args) > 1 || len(args) == 1 && (args[0] != "numbered" && args[0] != "verbose" && args[0] != "json") {
			return errors.New("usage: status [numbered|verbose|json]")
		}
		live, liveErr := manager.Status()
		if len(args) == 1 && args[0] == "json" {
			return json.NewEncoder(out).Encode(struct {
				Desired config.Config   `json:"desired"`
				Live    firewall.Status `json:"live"`
				Error   string          `json:"live_error,omitempty"`
			}{c, live, errorString(liveErr)})
		}
		fmt.Fprintln(out, p.Summary())
		fmt.Fprintf(out, "Saved enabled: %t; kernel enforcement: %t; hooks: %d/6; event agent: %t\n", c.Enabled, live.Enabled, live.Hooks, live.AgentAlive)
		if liveErr != nil {
			fmt.Fprintln(out, "Live status unavailable:", liveErr)
		} else if live.Enabled && live.Generation != p.Generation {
			fmt.Fprintln(out, "WARNING: saved configuration and active policy differ; run reload.")
		}
		for i, r := range c.Rules {
			b, _ := json.Marshal(r)
			fmt.Fprintf(out, "[%d] %s\n", i+1, b)
		}
		return nil
	case "stats":
		if len(args) != 0 {
			return errors.New("usage: stats")
		}
		s, e := manager.Status()
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(s)
	case "reload", "restore":
		if len(args) != 0 {
			return errors.New("unexpected arguments")
		}
		c, e := load()
		if e != nil {
			return e
		}
		if !c.Enabled {
			fmt.Fprintln(out, "Saved firewall is disabled.")
			return nil
		}
		if *dry {
			p, e := firewall.Compile(c, binary.NativeEndian)
			if e != nil {
				return e
			}
			return json.NewEncoder(out).Encode(p)
		}
		return manager.Apply(c)
	case "run":
		if len(args) != 0 {
			return errors.New("usage: run")
		}
		if *dry {
			return errors.New("dry-run is for policy changes and restore")
		}
		return manager.Run(*path, out)
	case "logs":
		if len(args) != 0 {
			return errors.New("usage: logs")
		}
		return manager.Logs(out)
	}
	parseRules := func(action, direction string, args []string) ([]config.Rule, error) {
		c, e := load()
		if os.IsNotExist(e) {
			c = config.New()
		} else if e != nil {
			return nil, e
		}
		return config.ParseWithProfiles(action, direction, args, config.AvailableProfiles(c.Applications))
	}
	forceApply := command == "enable" || command == "disable" || command == "reset"
	var change func(*config.Config) error
	switch command {
	case "app-set":
		if len(args) < 2 {
			return errors.New("usage: app set NAME PORT/PROTO...")
		}
		p := config.Profile{Description: "User-defined profile", Ports: args[1:]}
		if e := config.ValidateProfile(args[0], p); e != nil {
			return e
		}
		change = func(c *config.Config) error {
			if c.Applications == nil {
				c.Applications = map[string]config.Profile{}
			}
			c.Applications[args[0]] = p
			return nil
		}
	case "app-delete":
		if len(args) != 1 {
			return errors.New("usage: app delete NAME")
		}
		change = func(c *config.Config) error {
			if _, ok := c.Applications[args[0]]; !ok {
				return errors.New("custom application profile not found")
			}
			delete(c.Applications, args[0])
			return nil
		}
	case "app-update":
		if len(args) != 1 {
			return errors.New("usage: app update NAME")
		}
		change = func(c *config.Config) error {
			p, ok := config.AvailableProfiles(c.Applications)[args[0]]
			if !ok {
				return errors.New("profile not found")
			}
			var next []config.Rule
			var previous *config.Rule
			for _, r := range c.Rules {
				if r.Application != args[0] {
					next = append(next, r)
					previous = nil
					continue
				}
				base := r
				base.Protocol = "any"
				base.Port = ""
				if previous != nil && *previous == base {
					continue
				}
				for _, v := range p.Ports {
					parts := strings.Split(v, "/")
					rule := r
					rule.Protocol = parts[1]
					rule.Port = parts[0]
					next = append(next, rule)
				}
				copy := base
				previous = &copy
			}
			c.Rules = next
			return nil
		}
	case "enable", "disable":
		if len(args) != 0 {
			return errors.New("usage: enable | disable (host-wide; no interface argument)")
		}
		change = func(c *config.Config) error { c.Enabled = command == "enable"; return nil }
	case "reset":
		if len(args) != 0 {
			return errors.New("usage: reset")
		}
		change = func(c *config.Config) error { *c = config.New(); return nil }
	case "default":
		if len(args) < 1 || len(args) > 2 {
			return errors.New("usage: default allow|deny|reject [incoming|outgoing|routed]")
		}
		direction := "incoming"
		if len(args) == 2 {
			direction = args[1]
		}
		change = func(c *config.Config) error {
			switch direction {
			case "in", "incoming":
				c.Default = args[0]
			case "out", "outgoing":
				c.DefaultOut = args[0]
			case "route", "routed":
				c.DefaultRoute = args[0]
			default:
				return errors.New("invalid default direction")
			}
			return nil
		}
	case "logging":
		if len(args) != 1 || (args[0] != "on" && args[0] != "off") {
			return errors.New("usage: logging on|off")
		}
		change = func(c *config.Config) error { c.Logging = args[0] == "on"; return nil }
	case "allow", "deny", "reject", "limit", "block", "route", "insert", "prepend":
		action, direction, position := command, "", -1
		if command == "insert" {
			if len(args) < 2 {
				return errors.New("usage: insert NUMBER ACTION ...")
			}
			n, e := strconv.Atoi(args[0])
			if e != nil || n < 1 {
				return errors.New("invalid insertion index")
			}
			position = n - 1
			action, args = args[1], args[2:]
		}
		if command == "prepend" {
			if len(args) == 0 {
				return errors.New("usage: prepend ACTION ...")
			}
			position = 0
			action, args = args[0], args[1:]
		}
		if action == "route" {
			if len(args) == 0 {
				return errors.New("usage: route ACTION ...")
			}
			direction = "route"
			action, args = args[0], args[1:]
		}
		rules, e := parseRules(action, direction, args)
		if e != nil {
			return e
		}
		change = func(c *config.Config) error {
			n := position
			if n < 0 {
				n = len(c.Rules)
			}
			if n > len(c.Rules) {
				return errors.New("insertion index out of range")
			}
			next := append([]config.Rule{}, c.Rules[:n]...)
			next = append(next, rules...)
			c.Rules = append(next, c.Rules[n:]...)
			return nil
		}
	case "delete":
		if len(args) == 0 {
			return errors.New("usage: delete NUMBER | delete ACTION ...")
		}
		if n, e := strconv.Atoi(args[0]); e == nil {
			if len(args) != 1 {
				return errors.New("unexpected arguments")
			}
			change = func(c *config.Config) error {
				if n < 1 || n > len(c.Rules) {
					return errors.New("rule number out of range")
				}
				c.Rules = append(c.Rules[:n-1], c.Rules[n:]...)
				return nil
			}
		} else {
			action, rest := args[0], args[1:]
			direction := ""
			if action == "route" {
				if len(rest) == 0 {
					return errors.New("missing action")
				}
				direction = "route"
				action, rest = rest[0], rest[1:]
			}
			rules, e := parseRules(action, direction, rest)
			if e != nil {
				return e
			}
			change = func(c *config.Config) error {
				for _, r := range rules {
					found := -1
					for i, v := range c.Rules {
						if r == v {
							found = i
							break
						}
					}
					if found < 0 {
						return errors.New("matching rule not found")
					}
					c.Rules = append(c.Rules[:found], c.Rules[found+1:]...)
				}
				return nil
			}
		}
	default:
		return fmt.Errorf("unknown command %q; see help", command)
	}
	if *dry {
		c, e := load()
		if os.IsNotExist(e) {
			c = config.New()
		} else if e != nil {
			return e
		}
		if e = change(&c); e != nil {
			return e
		}
		p, e := firewall.Compile(c, binary.NativeEndian)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(p)
	}
	apply := func(c config.Config) error {
		if c.Enabled || forceApply {
			return manager.Apply(c)
		}
		return nil
	}
	if e := config.Update(*path, change, apply); e != nil {
		return e
	}
	if *path == "/etc/ebpfw/rules.json" {
		if command == "enable" {
			if e := systemd("enable", out); e != nil {
				return fmt.Errorf("kernel enforcement is active; starting the event service failed: %w", e)
			}
		}
		if command == "disable" || command == "reset" {
			if e := systemd("disable", out); e != nil {
				return e
			}
		}
	}
	fmt.Fprintln(out, "Configuration saved. Enabled policies were applied atomically to persistent eBPF maps.")
	return nil
}
func errorString(e error) string {
	if e == nil {
		return ""
	}
	return strings.TrimSpace(e.Error())
}
