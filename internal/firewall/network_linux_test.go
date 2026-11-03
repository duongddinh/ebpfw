// Disposable network fixtures for the live tests and benchmark.
package firewall

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

func netlinkAttr(kind uint16, data []byte) []byte {
	n := 4 + len(data)
	b := make([]byte, (n+3)&^3)
	binary.NativeEndian.PutUint16(b, uint16(n))
	binary.NativeEndian.PutUint16(b[2:], kind)
	copy(b[4:], data)
	return b
}
func linkInfoMessage(index int) []byte {
	b := make([]byte, 16)
	binary.NativeEndian.PutUint32(b[4:], uint32(index))
	return b
}
func netlinkRequest(kind uint16, flags uint16, payload []byte) error {
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

var pairNumber atomic.Uint32

type testPair struct {
	Left, Right *net.Interface
}

func newTestPair() (*testPair, error) {
	id := pairNumber.Add(1)
	left, right := fmt.Sprintf("ew%x%xa", os.Getpid(), id), fmt.Sprintf("ew%x%xb", os.Getpid(), id)
	peer := append(linkInfoMessage(0), netlinkAttr(unix.IFLA_IFNAME, append([]byte(right), 0))...)
	data := netlinkAttr(1, peer) // VETH_INFO_PEER
	linkInfo := append(netlinkAttr(1, []byte("veth\x00")), netlinkAttr(2|unix.NLA_F_NESTED, data)...)
	payload := append(linkInfoMessage(0), netlinkAttr(unix.IFLA_IFNAME, append([]byte(left), 0))...)
	payload = append(payload, netlinkAttr(unix.IFLA_LINKINFO|unix.NLA_F_NESTED, linkInfo)...)
	if err := netlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, payload); err != nil {
		return nil, fmt.Errorf("create veth: %w", err)
	}
	p := &testPair{}
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
		payload := linkInfoMessage(nic.Index)
		binary.NativeEndian.PutUint32(payload[8:], unix.IFF_UP)
		binary.NativeEndian.PutUint32(payload[12:], unix.IFF_UP)
		if err = netlinkRequest(unix.RTM_NEWLINK, 0, payload); err != nil {
			p.Close()
			return nil, err
		}
	}
	return p, nil
}
func (p *testPair) Close() {
	if p.Right != nil {
		netlinkRequest(unix.RTM_DELLINK, 0, linkInfoMessage(p.Right.Index))
	}
}

// moveTestInterface places an interface in an already-created network namespace.
func moveTestInterface(index, namespaceFD int) error {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, uint32(namespaceFD))
	return netlinkRequest(unix.RTM_NEWLINK, 0, append(linkInfoMessage(index), netlinkAttr(unix.IFLA_NET_NS_FD, b)...))
}
func upTestInterface(name string) error {
	nic, e := net.InterfaceByName(name)
	if e != nil {
		return e
	}
	b := linkInfoMessage(nic.Index)
	binary.NativeEndian.PutUint32(b[8:], unix.IFF_UP)
	binary.NativeEndian.PutUint32(b[12:], unix.IFF_UP)
	return netlinkRequest(unix.RTM_NEWLINK, 0, b)
}
func addTestAddress(index int, address string) error {
	p, e := netip.ParsePrefix(address)
	if e != nil {
		return e
	}
	b := make([]byte, 8)
	b[1] = byte(p.Bits())
	b[2] = unix.IFA_F_NODAD
	binary.NativeEndian.PutUint32(b[4:], uint32(index))
	if p.Addr().Is4() {
		b[0] = unix.AF_INET
		a := p.Addr().As4()
		b = append(b, netlinkAttr(unix.IFA_ADDRESS, a[:])...)
		b = append(b, netlinkAttr(unix.IFA_LOCAL, a[:])...)
	} else {
		b[0] = unix.AF_INET6
		a := p.Addr().As16()
		b = append(b, netlinkAttr(unix.IFA_ADDRESS, a[:])...)
	}
	return netlinkRequest(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL, b)
}
func addTestRoute(destination, gateway string, index int) error {
	p, e := netip.ParsePrefix(destination)
	if e != nil {
		return e
	}
	g, e := netip.ParseAddr(gateway)
	if e != nil {
		return e
	}
	b := make([]byte, 12)
	b[1] = byte(p.Bits())
	b[4] = unix.RT_TABLE_MAIN
	b[5] = unix.RTPROT_STATIC
	b[7] = unix.RTN_UNICAST
	if p.Addr().Is4() {
		b[0] = unix.AF_INET
		a := p.Masked().Addr().As4()
		v := g.As4()
		b = append(b, netlinkAttr(unix.RTA_DST, a[:])...)
		b = append(b, netlinkAttr(unix.RTA_GATEWAY, v[:])...)
	} else {
		b[0] = unix.AF_INET6
		a := p.Masked().Addr().As16()
		v := g.As16()
		b = append(b, netlinkAttr(unix.RTA_DST, a[:])...)
		b = append(b, netlinkAttr(unix.RTA_GATEWAY, v[:])...)
	}
	dev := make([]byte, 4)
	binary.NativeEndian.PutUint32(dev, uint32(index))
	b = append(b, netlinkAttr(unix.RTA_OIF, dev)...)
	return netlinkRequest(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, b)
}
