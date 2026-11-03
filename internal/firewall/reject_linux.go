// SPDX-License-Identifier: Apache-2.0
package firewall

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func checksum(parts ...[]byte) uint16 {
	var n uint32
	odd := false
	var last byte
	for _, b := range parts {
		for _, v := range b {
			if !odd {
				last = v
				odd = true
			} else {
				n += uint32(last)<<8 | uint32(v)
				odd = false
			}
		}
	}
	if odd {
		n += uint32(last) << 8
	}
	for n>>16 != 0 {
		n = (n & 65535) + (n >> 16)
	}
	return ^uint16(n)
}
func transportOffset(packet []byte) (int, byte, error) {
	if len(packet) < 1 {
		return 0, 0, errors.New("empty reject quote")
	}
	if packet[0]>>4 == 4 {
		if len(packet) < 20 {
			return 0, 0, errors.New("truncated IPv4")
		}
		n := int(packet[0]&15) * 4
		if n < 20 || n > len(packet) {
			return 0, 0, errors.New("bad IPv4 header")
		}
		return n, packet[9], nil
	}
	if packet[0]>>4 != 6 || len(packet) < 40 {
		return 0, 0, errors.New("bad IPv6 header")
	}
	at, proto := 40, packet[6]
	for i := 0; i < 32; i++ {
		if proto != 0 && proto != 43 && proto != 44 && proto != 51 && proto != 60 && proto != 135 {
			return at, proto, nil
		}
		if at+8 > len(packet) {
			return 0, 0, errors.New("truncated extension")
		}
		n := int(packet[at+1]+1) * 8
		if proto == 44 {
			n = 8
		} else if proto == 51 {
			n = (int(packet[at+1]) + 2) * 4
		}
		proto = packet[at]
		at += n
		if at > len(packet) {
			return 0, 0, errors.New("truncated extension")
		}
	}
	return 0, 0, errors.New("too many extension headers")
}
func rejectPacket(e Event) ([]byte, error) {
	if e.Captured < 20 || e.Captured > uint32(len(e.Packet)) {
		return nil, errors.New("invalid reject quote")
	}
	original := e.Packet[:e.Captured]
	if original[0]>>4 != e.Family {
		return nil, errors.New("reject family mismatch")
	}
	if e.Family == 4 && (e.Source[0] == 0 || e.Source[0] >= 224 || e.Destination[0] >= 224) {
		return nil, nil
	}
	if e.Family == 6 && (e.Source == [16]byte{} || e.Source[0] == 255 || e.Destination[0] == 255) {
		return nil, nil
	}
	at, proto, err := transportOffset(original)
	if err != nil {
		return nil, err
	}
	var payload []byte
	outProto := byte(1)
	if proto == 6 {
		if at+20 > len(original) {
			return nil, errors.New("truncated TCP")
		}
		t := original[at:]
		header := uint32(t[12]>>4) * 4
		if header < 20 || e.Length < uint32(at)+header {
			return nil, errors.New("bad TCP reject header")
		}
		if t[13]&4 != 0 {
			return nil, nil
		}
		payload = make([]byte, 20)
		binary.BigEndian.PutUint16(payload, e.DestinationPort)
		binary.BigEndian.PutUint16(payload[2:], e.SourcePort)
		payload[12] = 0x50
		if t[13]&16 != 0 {
			binary.BigEndian.PutUint32(payload[4:], binary.BigEndian.Uint32(t[8:]))
			payload[13] = 4
		} else {
			n := e.Length - uint32(at) - uint32(t[12]>>4)*4
			if t[13]&2 != 0 {
				n++
			}
			if t[13]&1 != 0 {
				n++
			}
			binary.BigEndian.PutUint32(payload[8:], binary.BigEndian.Uint32(t[4:])+n)
			payload[13] = 0x14
		}
		outProto = 6
	} else {
		// Never answer multicast/broadcast, an ICMP error, or unsupported families.
		if e.Family == 4 && (e.Source[0] >= 224 || e.Destination[0] >= 224 || e.Source[0] == 0) || e.Family == 6 && (e.Source[0] == 255 || e.Destination[0] == 255) {
			return nil, nil
		}
		if proto == 1 && at < len(original) && (original[at] == 3 || original[at] == 4 || original[at] == 5 || original[at] == 11 || original[at] == 12) {
			return nil, nil
		}
		if proto == 58 && at < len(original) && original[at] < 128 {
			return nil, nil
		}
		quote := len(original)
		if e.Family == 4 && quote > 548 {
			quote = 548
		}
		if e.Family == 6 && quote > 1232 {
			quote = 1232
		}
		payload = make([]byte, 8+quote)
		copy(payload[8:], original[:quote])
		if e.Family == 4 {
			payload[0] = 3
			payload[1] = 13
		} else {
			payload[0] = 1
			payload[1] = 1
			outProto = 58
		}
	}
	if e.Family == 4 {
		if e.Source[0] >= 224 || e.Destination[0] >= 224 {
			return nil, nil
		}
		ip := make([]byte, 20+len(payload))
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
		ip[8] = 64
		ip[9] = outProto
		copy(ip[12:], e.Destination[:4])
		copy(ip[16:], e.Source[:4])
		if outProto == 6 {
			pseudo := make([]byte, 12)
			copy(pseudo, ip[12:20])
			pseudo[9] = 6
			binary.BigEndian.PutUint16(pseudo[10:], uint16(len(payload)))
			binary.BigEndian.PutUint16(payload[16:], checksum(pseudo, payload))
		} else {
			binary.BigEndian.PutUint16(payload[2:], checksum(payload))
		}
		copy(ip[20:], payload)
		binary.BigEndian.PutUint16(ip[10:], checksum(ip[:20]))
		return ip, nil
	}
	if e.Family != 6 {
		return nil, fmt.Errorf("bad address family %d", e.Family)
	}
	if e.Source[0] == 255 || e.Destination[0] == 255 {
		return nil, nil
	}
	ip := make([]byte, 40+len(payload))
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(payload)))
	ip[6] = outProto
	ip[7] = 64
	copy(ip[8:], e.Destination[:])
	copy(ip[24:], e.Source[:])
	pseudo := make([]byte, 40)
	copy(pseudo, ip[8:40])
	binary.BigEndian.PutUint32(pseudo[32:], uint32(len(payload)))
	pseudo[39] = outProto
	sum := checksum(pseudo, payload)
	if outProto == 6 {
		binary.BigEndian.PutUint16(payload[16:], sum)
	} else {
		binary.BigEndian.PutUint16(payload[2:], sum)
	}
	copy(ip[40:], payload)
	return ip, nil
}
func (m *Manager) reject(e Event) error {
	packet, err := rejectPacket(e)
	if err != nil || len(packet) == 0 {
		return err
	}
	family := unix.AF_INET
	if e.Family == 6 {
		family = unix.AF_INET6
	}
	fd, err := unix.Socket(family, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if family == unix.AF_INET {
		var a [4]byte
		copy(a[:], e.Source[:4])
		if err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
			return err
		}
		return unix.Sendto(fd, packet, 0, &unix.SockaddrInet4{Addr: a})
	}
	if err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1); err != nil {
		return err
	}
	zone := uint32(0)
	if e.Source[0] == 0xfe && e.Source[1]&0xc0 == 0x80 {
		name := e.InInterface[:]
		if name[0] == 0 {
			name = e.OutInterface[:]
		}
		if n := bytes.IndexByte(name, 0); n >= 0 {
			name = name[:n]
		}
		nic, err := net.InterfaceByName(string(name))
		if err != nil {
			return err
		}
		zone = uint32(nic.Index)
	}
	return unix.Sendto(fd, packet, 0, &unix.SockaddrInet6{Addr: e.Source, ZoneId: zone})
}
