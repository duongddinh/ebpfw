package firewall

import (
	"encoding/binary"
	"testing"
)

func TestRejectChecksumsAndSuppression(t *testing.T) {
	for _, family := range []byte{4, 6} {
		for _, protocol := range []byte{6, 17} {
			src, dst := "192.0.2.2", "192.0.2.1"
			if family == 6 {
				src, dst = "2001:db8::2", "2001:db8::1"
			}
			wire := udpWire(int(family), src, dst, 41234, 81, []byte("test"), false)
			at := 20
			if family == 6 {
				at = 40
				wire[6] = protocol
			} else {
				wire[9] = protocol
			}
			if protocol == 6 {
				wire = append(wire[:at], make([]byte, 20)...)
				binary.BigEndian.PutUint16(wire[at:], 41234)
				binary.BigEndian.PutUint16(wire[at+2:], 81)
				wire[at+12] = 0x50
				wire[at+13] = 2
				binary.BigEndian.PutUint32(wire[at+4:], 1234)
			}
			event := Event{Family: family, Protocol: protocol, SourcePort: 41234, DestinationPort: 81, Length: uint32(len(wire)), Captured: uint32(len(wire))}
			if family == 4 {
				copy(event.Source[:], wire[12:16])
				copy(event.Destination[:], wire[16:20])
			} else {
				copy(event.Source[:], wire[8:24])
				copy(event.Destination[:], wire[24:40])
			}
			copy(event.Packet[:], wire)
			packet, err := rejectPacket(event)
			if err != nil || len(packet) == 0 {
				t.Fatal(family, protocol, err)
			}
			var pseudo []byte
			replyProto := packet[9]
			if family == 4 {
				if checksum(packet[:20]) != 0 {
					t.Fatal("IPv4 checksum")
				}
				if protocol == 6 {
					pseudo = make([]byte, 12)
					copy(pseudo, packet[12:20])
					pseudo[9] = 6
					binary.BigEndian.PutUint16(pseudo[10:], uint16(len(packet)-at))
				}
			} else {
				replyProto = packet[6]
				pseudo = make([]byte, 40)
				copy(pseudo, packet[8:40])
				binary.BigEndian.PutUint32(pseudo[32:], uint32(len(packet)-at))
				pseudo[39] = replyProto
			}
			if checksum(pseudo, packet[at:]) != 0 {
				t.Fatal("reply checksum", family, protocol)
			}
			if protocol == 6 {
				if packet[at+13] != 0x14 || binary.BigEndian.Uint32(packet[at+8:]) != 1235 {
					t.Fatal("RST acknowledgment")
				}
				event.Packet[at+13] = 4
				packet, err = rejectPacket(event)
				if err != nil || packet != nil {
					t.Fatal("answered a TCP reset")
				}
			}
			event.Source[0] = 255
			packet, err = rejectPacket(event)
			if err != nil || packet != nil {
				t.Fatal("answered multicast source")
			}
		}
	}
}

func FuzzRejectPacket(f *testing.F) {
	f.Add([]byte{0x45, 0, 0, 20}, byte(4))
	f.Add([]byte{0x60, 0, 0, 0}, byte(6))
	f.Fuzz(func(t *testing.T, packet []byte, family byte) {
		e := Event{Family: family, Length: uint32(len(packet))}
		e.Captured = uint32(copy(e.Packet[:], packet))
		e.Source[0] = 1
		e.Destination[0] = 2
		_, _ = rejectPacket(e)
	})
}
