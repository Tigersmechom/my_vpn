//go:build darwin

// My VPN integration; upstream protocol and cryptography remain unchanged.
// Only the encrypted UDP socket bypasses TUN. Ordinary SSH/web requests to the
// same server must still use the VPN, without a host-wide /32 bypass route.
package conn

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func init() {
	controlFns = append(controlFns, func(network, address string, c syscall.RawConn) error {
		name := os.Getenv("MYVPN_OUTBOUND_INTERFACE")
		if name == "" {
			return nil
		}
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return fmt.Errorf("outbound interface: %w", err)
		}
		var bindErr error
		err = c.Control(func(fd uintptr) {
			if network == "udp6" {
				bindErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, iface.Index)
			} else {
				bindErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, iface.Index)
			}
		})
		if err != nil {
			return err
		}
		return bindErr // Never silently fall back to unbound transport.
	})
}
