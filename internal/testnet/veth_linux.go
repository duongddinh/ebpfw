// Package testnet creates disposable interfaces for privileged tests and benchmarks.
// It is never imported by the firewall daemon.
package testnet

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func attr(kind uint16, data []byte) []byte {
	n := 4 + len(data)
	b := make([]byte, (n+3)&^3)
	binary.NativeEndian.PutUint16(b, uint16(n))
	binary.NativeEndian.PutUint16(b[2:], kind)
	copy(b[4:], data)
	return b
}
func info(index int) []byte {
	b := make([]byte, 16)
	binary.NativeEndian.PutUint32(b[4:], uint32(index))
	return b
}
func request(kind uint16, flags uint16, payload []byte) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 3})
	b := make([]byte, 16+len(payload))
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], kind)
	binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK|flags)
	binary.NativeEndian.PutUint32(b[8:], 1)
	copy(b[16:], payload)
	if err = unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	response := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, response, 0)
	if err != nil {
		return err
	}
	if n < 20 || binary.NativeEndian.Uint16(response[4:]) != unix.NLMSG_ERROR {
		return fmt.Errorf("unexpected netlink response")
	}
	code := int32(binary.NativeEndian.Uint32(response[16:]))
	if code != 0 {
		return unix.Errno(-code)
	}
	return nil
}

type Pair struct {
	Left, Right *net.Interface
	FD          int
}

func New() (*Pair, error) {
	left, right := fmt.Sprintf("ew%da", os.Getpid()), fmt.Sprintf("ew%db", os.Getpid())
	peer := append(info(0), attr(unix.IFLA_IFNAME, append([]byte(right), 0))...)
	data := attr(1, peer) // VETH_INFO_PEER
	linkInfo := append(attr(1, []byte("veth\x00")), attr(2|unix.NLA_F_NESTED, data)...)
	payload := append(info(0), attr(unix.IFLA_IFNAME, append([]byte(left), 0))...)
	payload = append(payload, attr(unix.IFLA_LINKINFO|unix.NLA_F_NESTED, linkInfo)...)
	if err := request(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, payload); err != nil {
		return nil, fmt.Errorf("create veth: %w", err)
	}
	p := &Pair{FD: -1}
	var err error
	p.Left, err = net.InterfaceByName(left)
	if err != nil {
		return nil, err
	}
	p.Right, err = net.InterfaceByName(right)
	if err != nil {
		p.Close()
		return nil, err
	}
	for _, nic := range []*net.Interface{p.Left, p.Right} {
		payload := info(nic.Index)
		binary.NativeEndian.PutUint32(payload[8:], unix.IFF_UP)
		binary.NativeEndian.PutUint32(payload[12:], unix.IFF_UP)
		if err = request(unix.RTM_NEWLINK, 0, payload); err != nil {
			p.Close()
			return nil, err
		}
	}
	p.FD, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(binary.NativeEndian.Uint16([]byte{0, 3})))
	if err != nil {
		p.Close()
		return nil, err
	}
	if err = unix.Bind(p.FD, &unix.SockaddrLinklayer{Ifindex: p.Left.Index, Protocol: binary.NativeEndian.Uint16([]byte{0, 3})}); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}
func (p *Pair) Close() {
	if p.FD >= 0 {
		unix.Close(p.FD)
	}
	if p.Left != nil {
		request(unix.RTM_DELLINK, 0, info(p.Left.Index))
	}
}
func (p *Pair) Packet(port uint16) []byte {
	b := make([]byte, 64)
	copy(b, p.Right.HardwareAddr)
	copy(b[6:], p.Left.HardwareAddr)
	binary.BigEndian.PutUint16(b[12:], 0x0800)
	ip := b[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], 50)
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:], []byte{192, 0, 2, 1, 192, 0, 2, 2})
	sum := uint32(0)
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i:]))
	}
	sum = (sum & 65535) + (sum >> 16)
	binary.BigEndian.PutUint16(ip[10:], ^uint16(sum))
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp, 12345)
	binary.BigEndian.PutUint16(udp[2:], port)
	binary.BigEndian.PutUint16(udp[4:], 30)
	return b
}
func (p *Pair) Send(packet []byte) error {
	return unix.Sendto(p.FD, packet, 0, &unix.SockaddrLinklayer{Ifindex: p.Left.Index})
}
