// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/duongddinh/ebpfw/internal/policy"
	engine "github.com/duongddinh/ebpfw/internal/runtime"
)

const help = `ebpfw: an ingress-only, stateless XDP firewall (Linux)

Usage: ebpfw [--config PATH] COMMAND
  allow|deny [PORT[/tcp|udp]] [from CIDR] [proto tcp|udp|icmp|icmpv6|any]
  delete NUMBER                 Remove a numbered rule
  default allow|deny            Set the policy for unmatched IP packets
  status                        Show the saved policy in match order
  check                         Validate the saved policy
  enable INTERFACE              Enable and start the installed systemd unit
  disable INTERFACE             Stop and disable that unit
  stats INTERFACE               Read counters from a running instance
  run --interface IFACE [--mode native|generic] [--object PATH]

Rules use first-match order. Edits apply within one second to running instances
using this config. There is no connection tracking or outbound filtering.
Default deny also blocks replies to outbound connections unless allowed.
`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "ebpfw:", err)
		os.Exit(1)
	}
}
func validInterface(s string) bool {
	if len(s) == 0 || len(s) > 15 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}
func parseRule(action string, args []string) (policy.Rule, error) {
	r := policy.Rule{Action: action, Protocol: "any"}
	seenFrom, seenProto := false, false
	if len(args) > 0 && args[0] != "from" && args[0] != "proto" {
		p := strings.Split(args[0], "/")
		if len(p) > 2 {
			return r, errors.New("use PORT/tcp or PORT/udp")
		}
		r.Port = p[0]
		r.Protocol = "tcp"
		if len(p) == 2 {
			r.Protocol = p[1]
		}
		seenProto = len(p) == 2
		args = args[1:]
	}
	for len(args) > 0 {
		if len(args) < 2 {
			return r, errors.New("expected from CIDR or proto PROTOCOL")
		}
		switch args[0] {
		case "from":
			if seenFrom {
				return r, errors.New("duplicate source")
			}
			seenFrom = true
			r.Source = args[1]
		case "proto":
			if seenProto {
				return r, errors.New("duplicate protocol")
			}
			seenProto = true
			r.Protocol = args[1]
		default:
			return r, fmt.Errorf("unexpected argument %q", args[0])
		}
		args = args[2:]
	}
	c := policy.New()
	c.Rules = append(c.Rules, r)
	_, err := c.Encode(binary.LittleEndian)
	return r, err
}
func run(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("ebpfw", flag.ContinueOnError)
	flags.SetOutput(out)
	config := flags.String("config", "/etc/ebpfw/rules.json", "configuration path")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(out, help)
			return nil
		}
		return err
	}
	args = flags.Args()
	if len(args) == 0 || args[0] == "help" {
		fmt.Fprint(out, help)
		return nil
	}
	command, args := args[0], args[1:]
	var err error
	switch command {
	case "allow", "deny":
		r, e := parseRule(command, args)
		if e != nil {
			return e
		}
		err = policy.Edit(*config, func(c *policy.Config) error { c.Rules = append(c.Rules, r); return nil })
	case "default":
		if len(args) != 1 {
			return errors.New("usage: default allow|deny")
		}
		err = policy.Edit(*config, func(c *policy.Config) error { c.Default = args[0]; return nil })
	case "delete":
		if len(args) != 1 {
			return errors.New("usage: delete NUMBER")
		}
		n, e := strconv.Atoi(args[0])
		if e != nil {
			return e
		}
		err = policy.Edit(*config, func(c *policy.Config) error {
			if n < 1 || n > len(c.Rules) {
				return errors.New("rule number out of range")
			}
			c.Rules = append(c.Rules[:n-1], c.Rules[n:]...)
			return nil
		})
	case "status", "check":
		if len(args) != 0 {
			return errors.New("unexpected arguments")
		}
		c, e := policy.Load(*config)
		if e != nil {
			return e
		}
		if command == "check" {
			fmt.Fprintln(out, "Policy is valid.")
			return nil
		}
		fmt.Fprintf(out, "Saved policy: default %s (ingress, stateless)\n", c.Default)
		for i, r := range c.Rules {
			source := r.Source
			if source == "" {
				source = "any"
			}
			port := r.Port
			if port == "" {
				port = "any"
			}
			fmt.Fprintf(out, "[%d] %-5s %-6s port %-11s from %s\n", i+1, r.Action, r.Protocol, port, source)
		}
		fmt.Fprintln(out, "Use systemctl status ebpfw@INTERFACE to check enforcement.")
		return nil
	case "run":
		return engine.Run(*config, args)
	case "stats":
		if len(args) != 1 || !validInterface(args[0]) {
			return errors.New("usage: stats INTERFACE")
		}
		return engine.Stats(args[0], out)
	case "enable", "disable":
		if len(args) != 1 || !validInterface(args[0]) {
			return errors.New("usage: enable|disable INTERFACE")
		}
		if *config != "/etc/ebpfw/rules.json" {
			return errors.New("systemd units use /etc/ebpfw/rules.json; use run for a custom config")
		}
		if command == "enable" {
			if _, e := policy.Load(*config); e != nil {
				return e
			}
			if _, e := net.InterfaceByName(args[0]); e != nil {
				return e
			}
		}
		operation := "enable"
		if command == "disable" {
			operation = "disable"
		}
		cmd := exec.Command("systemctl", operation, "--now", "ebpfw@"+args[0]+".service")
		cmd.Stdout = out
		cmd.Stderr = out
		return cmd.Run()
	default:
		return fmt.Errorf("unknown command %q; see ebpfw help", command)
	}
	if err == nil {
		fmt.Fprintln(out, "Policy saved. Running instances reload it within one second; check service logs for reload errors.")
	}
	return err
}
