package health

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	hy "github.com/apernet/hysteria/core/v2/client"
	hyerrors "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/extras/v2/obfs"
)

func (p *probe) dialer(ctx context.Context) (func(context.Context, string, string) (net.Conn, error), func(), error) {
	if p.route.Protocol == "AWG" {
		return p.amnezia(ctx)
	}
	return p.hysteria(ctx)
}

type packetFactory struct {
	p        *probe
	password string
	ctx      context.Context
}

func (f packetFactory) New(_ net.Addr) (net.PacketConn, error) {
	f.p.mu.Lock()
	defer f.p.mu.Unlock()
	if f.p.ctx.Err() != nil || f.ctx.Err() != nil {
		return nil, context.Canceled
	}
	c, e := net.ListenUDP("udp", nil)
	if e != nil {
		return nil, e
	}
	var pc net.PacketConn = c
	if f.password != "" {
		pc, e = obfs.WrapPacketConnSalamander(c, []byte(f.password))
		if e != nil {
			c.Close()
			return nil, e
		}
	}
	f.p.pending = pc
	return pc, nil
}
func (p *probe) hysteria(ctx context.Context) (func(context.Context, string, string) (net.Conn, error), func(), error) {
	h := p.route.Profile.HY2
	port := h.Port
	password := ""
	if p.route.Protocol == "HY2_OBFS" {
		port = h.ObfsPort
		password = h.ObfsPassword
	}
	addr, e := net.ResolveUDPAddr("udp", net.JoinHostPort(p.route.Profile.Host, strconv.Itoa(port)))
	if e != nil {
		return nil, nil, e
	}
	pin, _ := hex.DecodeString(h.Pin)
	config := &hy.Config{ServerAddr: addr, Auth: h.Auth, ConnFactory: packetFactory{p, password, ctx}, TLSConfig: hy.TLSConfig{ServerName: h.SNI, InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errPin
			}
			actual := sha256.Sum256(raw[0])
			if subtle.ConstantTimeCompare(actual[:], pin) != 1 {
				return errPin
			}
			return nil
		}},
		QUICConfig: hy.QUICConfig{InitialStreamReceiveWindow: 65536, MaxStreamReceiveWindow: 131072, InitialConnectionReceiveWindow: 131072, MaxConnectionReceiveWindow: 262144, MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 15 * time.Second, DisablePathMTUDiscovery: true}}
	c, _, e := hy.NewClient(config)
	if e != nil {
		return nil, nil, e
	}
	if ctx.Err() != nil || p.ctx.Err() != nil {
		c.Close()
		return nil, nil, context.Canceled
	}
	var once sync.Once
	closeFn := func() { once.Do(func() { c.Close() }) }
	return func(ctx context.Context, _ string, address string) (net.Conn, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return c.TCP(address)
	}, closeFn, nil
}
func (p *probe) amnezia(ctx context.Context) (func(context.Context, string, string) (net.Conn, error), func(), error) {
	profile := p.route.Profile
	o := profile.Probe
	if o == nil {
		return nil, nil, errDedicatedKey
	}
	prefix, e := netip.ParsePrefix(o.Address)
	if e != nil {
		return nil, nil, errConfig
	}
	var dns []netip.Addr
	for _, s := range strings.FieldsFunc(profile.DNS, func(c rune) bool { return c == ',' || c == ' ' }) {
		a, e := netip.ParseAddr(s)
		if e != nil {
			return nil, nil, errConfig
		}
		dns = append(dns, a)
	}
	tun, network, e := netstack.CreateNetTUN([]netip.Addr{prefix.Addr()}, dns, integer(profile.AWG["mtu"]))
	if e != nil {
		return nil, nil, e
	}
	logger := &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}}
	wg := device.NewDevice(tun, conn.NewDefaultBind(), logger)
	var once sync.Once
	closeFn := func() { once.Do(wg.Close) }
	hexkey := func(s string) string { b, _ := base64.StdEncoding.DecodeString(s); return hex.EncodeToString(b) }
	text := "private_key=" + hexkey(o.PrivateKey) + "\n"
	for _, k := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"} {
		v, ok := profile.AWG[k]
		if !ok {
			continue
		}
		s, isString := v.(string)
		if !isString {
			s = strconv.Itoa(integer(v))
		}
		if s == "" {
			continue
		}
		if !safe(s) {
			closeFn()
			return nil, nil, errConfig
		}
		if s != "" {
			text += k + "=" + s + "\n"
		}
	}
	text += "public_key=" + hexkey(str(profile.AWG["serverPublicKey"])) + "\npreshared_key=" + hexkey(o.PresharedKey) + "\nallowed_ip=0.0.0.0/0\nendpoint=" + net.JoinHostPort(profile.Host, strconv.Itoa(integer(profile.AWG["port"]))) + "\npersistent_keepalive_interval=0\n"
	if e = wg.IpcSet(text); e != nil {
		closeFn()
		return nil, nil, errConfig
	}
	if ctx.Err() != nil || p.ctx.Err() != nil {
		closeFn()
		return nil, nil, context.Canceled
	}
	if e = wg.Up(); e != nil {
		closeFn()
		return nil, nil, e
	}
	return network.DialContext, closeFn, nil
}
func protocolErrorCode(err error) string {
	var auth hyerrors.AuthError
	if errors.As(err, &auth) {
		return "auth"
	}
	if strings.Contains(err.Error(), "certificate") {
		return "certificate"
	}
	return "unreachable"
}
