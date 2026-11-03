// SPDX-License-Identifier: Apache-2.0
package firewall

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/duongddinh/ebpfw/internal/config"
)

const EntrySize = 96
const StatDefault = config.MaxRules
const StatState = config.MaxRules + 3
const StatInvalid = config.MaxRules + 4
const StatCTFull = config.MaxRules + 5
const StatEventLost = config.MaxRules + 6
const StatRate = config.MaxRules + 7
const StatPass = config.MaxRules + 8
const StatDrop = config.MaxRules + 9
const StatReject = config.MaxRules + 10

var actionCode = map[string]byte{"allow": 1, "deny": 2, "reject": 3, "limit": 4, "block": 5}
var directionCode = map[string]byte{"any": 0, "in": 1, "out": 2, "route": 3}
var protocolCode = map[string]byte{"any": 0, "icmp": 1, "igmp": 2, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "ah": 51, "icmpv6": 58, "sctp": 132}

type Plan struct {
	Config     config.Config `json:"config"`
	SHA256     string        `json:"sha256"`
	Generation uint32        `json:"generation"`
	Entries    [][]byte      `json:"-"`
}

func Compile(c config.Config, order binary.ByteOrder) (Plan, error) {
	if e := c.Validate(); e != nil {
		return Plan{}, e
	}
	c = c.Normalized()
	serialized, e := json.Marshal(c)
	if e != nil {
		return Plan{}, e
	}
	sum := sha256.Sum256(serialized)
	generation := binary.LittleEndian.Uint32(sum[:4])
	if generation == 0 {
		generation = 1
	}
	plan := Plan{Config: c, SHA256: hex.EncodeToString(sum[:]), Generation: generation}
	header := make([]byte, EntrySize)
	order.PutUint32(header, uint32(len(c.Rules)))
	order.PutUint32(header[8:], uint32(actionCode[c.Default]))
	order.PutUint32(header[12:], uint32(actionCode[c.DefaultOut]))
	order.PutUint32(header[16:], uint32(actionCode[c.DefaultRoute]))
	if c.Logging {
		order.PutUint32(header[20:], 1)
	}
	order.PutUint32(header[24:], generation)
	order.PutUint32(header[28:], 1)
	order.PutUint32(header[32:], 2)
	plan.Entries = append(plan.Entries, header)
	var blocks, normal [][]byte
	for i, r := range c.Rules {
		b := make([]byte, EntrySize)
		b[0] = actionCode[r.Action]
		b[1] = directionCode[r.Direction]
		b[3] = protocolCode[r.Protocol]
		if r.Log {
			b[6] = 1
		}
		src, _ := config.Prefix(r.Source)
		dst, _ := config.Prefix(r.Destination)
		if src.IsValid() {
			if src.Addr().Is4() {
				b[2] = 4
				a := src.Addr().As4()
				copy(b[24:], a[:])
			} else {
				b[2] = 6
				a := src.Addr().As16()
				copy(b[24:], a[:])
			}
			b[4] = byte(src.Bits())
		}
		if dst.IsValid() {
			if dst.Addr().Is4() {
				b[2] = 4
				a := dst.Addr().As4()
				copy(b[40:], a[:])
			} else {
				b[2] = 6
				a := dst.Addr().As16()
				copy(b[40:], a[:])
			}
			b[5] = byte(dst.Bits())
		}
		lo, hi, _ := config.PortsFor(r.Protocol, r.SourcePort)
		order.PutUint16(b[8:], lo)
		order.PutUint16(b[10:], hi)
		lo, hi, _ = config.PortsFor(r.Protocol, r.Port)
		order.PutUint16(b[12:], lo)
		order.PutUint16(b[14:], hi)
		if r.Action == "limit" {
			rate, burst := r.Rate, r.Burst
			if rate == 0 {
				rate = 12
			}
			if burst == 0 {
				burst = 6
			}
			order.PutUint32(b[16:], uint32(rate))
			order.PutUint32(b[20:], burst)
		}
		copy(b[56:], r.InInterface)
		copy(b[72:], r.OutInterface)
		order.PutUint32(b[88:], uint32(i))
		if b[0] == 5 {
			blocks = append(blocks, b)
		} else {
			normal = append(normal, b)
		}
	}
	order.PutUint32(header[4:], uint32(len(blocks)))
	plan.Entries = append(plan.Entries, blocks...)
	plan.Entries = append(plan.Entries, normal...)
	return plan, nil
}
func (p Plan) Summary() string {
	return fmt.Sprintf("%d rules; incoming %s, outgoing %s, routed %s; eBPF-only enforcement", len(p.Config.Rules), p.Config.Default, p.Config.DefaultOut, p.Config.DefaultRoute)
}
