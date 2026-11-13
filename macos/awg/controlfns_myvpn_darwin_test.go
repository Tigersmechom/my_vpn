//go:build darwin

package conn

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMyVPNTransportIsBoundToRequestedInterface(t *testing.T) {
	iface, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MYVPN_OUTBOUND_INTERFACE", "lo0")
	for _, network := range []string{"udp4", "udp6"} {
		conn, _, err := listenNet(network, 0)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := conn.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		bound := 0
		var optionErr error
		err = raw.Control(func(fd uintptr) {
			level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
			if network == "udp6" {
				level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
			}
			bound, optionErr = unix.GetsockoptInt(int(fd), level, option)
		})
		conn.Close()
		if err != nil || optionErr != nil || bound != iface.Index {
			t.Fatalf("%s socket interface=%d, want=%d, errors=%v/%v", network, bound, iface.Index, err, optionErr)
		}
	}
}

func TestMyVPNInvalidTransportInterfaceFailsClosed(t *testing.T) {
	t.Setenv("MYVPN_OUTBOUND_INTERFACE", "nonexistent999")
	conn, _, err := listenNet("udp4", 0)
	if err == nil {
		conn.Close()
		t.Fatal("invalid interface silently opened an unbound transport")
	}
}
