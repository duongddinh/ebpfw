// SPDX-License-Identifier: Apache-2.0
package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Profile struct {
	Description string   `json:"description"`
	Ports       []string `json:"ports"`
}

var Profiles = map[string]Profile{
	"OpenSSH":    {"Secure shell", []string{"22/tcp"}},
	"WWW":        {"HTTP", []string{"80/tcp"}},
	"WWW Secure": {"HTTPS", []string{"443/tcp"}},
	"WWW Full":   {"HTTP and HTTPS", []string{"80/tcp", "443/tcp"}},
	"DNS":        {"DNS over TCP and UDP", []string{"53/tcp", "53/udp"}},
}

// Parse supports the UFW-style endpoint syntax, but requires an explicit
// transport protocol when a port is supplied through a from/to clause.
func Parse(action, direction string, args []string) ([]Rule, error) {
	return ParseWithProfiles(action, direction, args, Profiles)
}

func ParseWithProfiles(action, direction string, args []string, profiles map[string]Profile) ([]Rule, error) {
	r := Rule{Action: action, Protocol: "any", Direction: direction}
	seen := map[string]bool{}
	endpoint := ""
	ifaceDirection := ""
	profile := ""
	next := func(i *int) (string, error) {
		*i++
		if *i >= len(args) {
			return "", errors.New("missing argument")
		}
		return args[*i], nil
	}
	for i := 0; i < len(args); i++ {
		token := args[i]
		switch token {
		case "in", "out":
			if r.Direction != "route" {
				if seen["direction"] {
					return nil, errors.New("duplicate direction")
				}
				r.Direction = token
				seen["direction"] = true
			}
			ifaceDirection = token
		case "on":
			if ifaceDirection == "" {
				ifaceDirection = r.Direction
			}
			v, e := next(&i)
			if e != nil {
				return nil, e
			}
			key := ifaceDirection + "if"
			if seen[key] {
				return nil, errors.New("duplicate interface")
			}
			seen[key] = true
			if ifaceDirection == "out" {
				r.OutInterface = v
			} else if ifaceDirection == "in" {
				r.InInterface = v
			} else {
				return nil, errors.New("specify in on or out on")
			}
		case "from", "to":
			if seen[token] {
				return nil, errors.New("duplicate endpoint")
			}
			seen[token] = true
			v, e := next(&i)
			if e != nil {
				return nil, e
			}
			endpoint = token
			if token == "from" {
				r.Source = v
			} else {
				r.Destination = v
			}
		case "port":
			if endpoint == "" || seen[endpoint+"port"] {
				return nil, errors.New("port must follow one from/to endpoint")
			}
			seen[endpoint+"port"] = true
			v, e := next(&i)
			if e != nil {
				return nil, e
			}
			if endpoint == "from" {
				r.SourcePort = v
			} else {
				r.Port = v
			}
		case "proto":
			if seen["proto"] {
				return nil, errors.New("duplicate protocol")
			}
			seen["proto"] = true
			v, e := next(&i)
			if e != nil {
				return nil, e
			}
			r.Protocol = v
		case "log":
			if seen["log"] {
				return nil, errors.New("duplicate log")
			}
			seen["log"] = true
			r.Log = true
		case "comment":
			if seen["comment"] {
				return nil, errors.New("duplicate comment")
			}
			seen["comment"] = true
			v, e := next(&i)
			if e != nil {
				return nil, e
			}
			r.Comment = v
		case "rate", "burst":
			if seen[token] {
				return nil, errors.New("duplicate limit parameter")
			}
			seen[token] = true
			v, e := next(&i)
			if e != nil {
				return nil, e
			}
			if token == "rate" {
				v = strings.TrimSuffix(v, "/minute")
				n, e := strconv.ParseUint(v, 10, 64)
				if e != nil || n == 0 {
					return nil, errors.New("rate must be a positive connections/minute value")
				}
				r.Rate = n
			} else {
				n, e := strconv.ParseUint(v, 10, 32)
				if e != nil || n == 0 {
					return nil, errors.New("burst must be positive")
				}
				r.Burst = uint32(n)
			}
		default:
			if seen["port"] || seen["toport"] || profile != "" {
				return nil, fmt.Errorf("unexpected argument %q", token)
			}
			if _, ok := profiles[token]; ok {
				profile = token
				continue
			}
			parts := strings.Split(token, "/")
			if len(parts) > 2 {
				return nil, errors.New("use PORT/protocol")
			}
			r.Port = parts[0]
			seen["port"] = true
			if len(parts) == 2 {
				if seen["proto"] {
					return nil, errors.New("duplicate protocol")
				}
				r.Protocol = parts[1]
				seen["proto"] = true
			} else if !seen["proto"] {
				r.Protocol = "tcp"
			}
		}
	}
	if action == "block" && r.Direction == "" {
		r.Direction = "any"
	}
	if r.Direction == "" {
		r.Direction = "in"
	}
	if action == "limit" && r.Protocol == "any" && profile == "" {
		r.Protocol = "tcp"
	}
	if profile != "" {
		if seen["proto"] || r.Port != "" || r.SourcePort != "" {
			return nil, errors.New("profile cannot be combined with explicit ports/protocol")
		}
		var rules []Rule
		for _, p := range profiles[profile].Ports {
			parts := strings.Split(p, "/")
			v := r
			v.Application = profile
			v.Port = parts[0]
			v.Protocol = parts[1]
			if v.Comment == "" {
				v.Comment = "app " + profile
			}
			if e := v.Validate(); e != nil {
				return nil, e
			}
			rules = append(rules, v)
		}
		return rules, nil
	}
	if e := r.Validate(); e != nil {
		return nil, e
	}
	return []Rule{r}, nil
}

func AvailableProfiles(user map[string]Profile) map[string]Profile {
	out := make(map[string]Profile)
	for n, p := range Profiles {
		out[n] = p
	}
	for n, p := range user {
		out[n] = p
	}
	return out
}
func ValidateProfile(name string, p Profile) error {
	if len(name) == 0 || len(name) > 64 || strings.ContainsAny(name, "\x00\r\n") {
		return errors.New("invalid application profile name")
	}
	if len(p.Description) > 256 || strings.ContainsAny(p.Description, "\x00\r\n") {
		return errors.New("profile description must be one line of at most 256 bytes")
	}
	if len(p.Ports) == 0 || len(p.Ports) > 64 {
		return errors.New("an application profile needs 1..64 ports")
	}
	for _, v := range p.Ports {
		parts := strings.Split(v, "/")
		if len(parts) != 2 {
			return errors.New("application ports require /tcp, /udp, or /sctp")
		}
		r := Rule{Action: "allow", Protocol: parts[1], Port: parts[0]}
		if e := r.Validate(); e != nil {
			return e
		}
	}
	return nil
}
