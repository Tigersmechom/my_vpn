// Safe AmneziaWG data check: userspace netstack, no TUN, routes or DNS changes.
// Run from macos/vendor/src-awg-go: go run /absolute/path/tools/awgcheck.go --profile FILE
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "AmneziaWG check failed:", err)
		os.Exit(1)
	}
}

func run() error {
	source := flag.String("profile", "", "Private JSON profile")
	flag.Parse()
	data, err := os.ReadFile(*source)
	if err != nil || len(data) > 1024*1024 {
		return fmt.Errorf("cannot read bounded profile")
	}
	var p struct {
		Host     string
		ExitHost string
		DNS      string
		AWG      map[string]any
	}
	if json.Unmarshal(data, &p) != nil {
		return fmt.Errorf("invalid profile JSON")
	}
	str := func(name string) string { return fmt.Sprint(p.AWG[name]) }
	key := func(name string) (string, error) {
		v, err := base64.StdEncoding.DecodeString(str(name))
		if err != nil || len(v) != 32 {
			return "", fmt.Errorf("invalid key")
		}
		return hex.EncodeToString(v), nil
	}
	prefix, err := netip.ParsePrefix(str("address"))
	if err != nil || !prefix.Addr().Is4() {
		return fmt.Errorf("invalid client address")
	}
	var dns []netip.Addr
	for _, raw := range strings.Split(p.DNS, ",") {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("invalid DNS")
		}
		dns = append(dns, addr)
	}
	mtuf, ok := p.AWG["mtu"].(float64)
	if !ok || mtuf < 1280 || mtuf > 9000 {
		return fmt.Errorf("invalid MTU")
	}
	tun, network, err := netstack.CreateNetTUN([]netip.Addr{prefix.Addr()}, dns, int(mtuf))
	if err != nil {
		return fmt.Errorf("cannot initialize userspace network")
	}
	logger := &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}}
	wg := device.NewDevice(tun, conn.NewDefaultBind(), logger)
	defer wg.Close()
	private, err := key("privateKey")
	if err != nil {
		return err
	}
	public, err := key("serverPublicKey")
	if err != nil {
		return err
	}
	psk, err := key("presharedKey")
	if err != nil {
		return err
	}
	config := "private_key=" + private + "\n"
	for _, name := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"} {
		if raw, ok := p.AWG[name]; ok {
			value := fmt.Sprint(raw)
			if strings.ContainsAny(value, "\r\n\x00") {
				return fmt.Errorf("invalid parameter")
			}
			if value != "" {
				config += name + "=" + value + "\n"
			}
		}
	}
	addr, err := netip.ParseAddr(p.Host)
	if err != nil || !addr.Is4() {
		return fmt.Errorf("server must be IPv4")
	}
	port, ok := p.AWG["port"].(float64)
	if !ok || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port")
	}
	config += "public_key=" + public + "\npreshared_key=" + psk + "\nallowed_ip=0.0.0.0/0\nendpoint=" + fmt.Sprintf("%s:%d", addr, int(port)) + "\npersistent_keepalive_interval=25\n"
	if wg.IpcSet(config) != nil {
		return fmt.Errorf("native core rejected settings")
	}
	if wg.Up() != nil {
		return fmt.Errorf("native core did not start")
	}
	transport := &http.Transport{DialContext: network.DialContext, Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 8 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 18 * time.Second}
	checks := []struct {
		Name, URL     string
		Status, Bytes int
	}{
		{"exit_ip", "https://api.ipify.org", 200, -1},
		{"google", "https://www.google.com/generate_204", 204, 0},
		{"download64k", "https://speed.cloudflare.com/__down?bytes=65536", 200, 65536},
	}
	results := map[string]any{"network_changed": false, "protocol": "AmneziaWG"}
	failed := false
	for _, check := range checks {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", check.URL, nil)
		resp, err := client.Do(req)
		record := map[string]any{"ok": false}
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 65537))
			resp.Body.Close()
			record["status"] = resp.StatusCode
			record["bytes"] = len(body)
			valid := readErr == nil && resp.StatusCode == check.Status && (check.Bytes < 0 || len(body) == check.Bytes)
			if check.Name == "exit_ip" {
				exit := strings.TrimSpace(string(body))
				record["ip"] = exit
				expected := p.ExitHost
				if expected == "" {
					expected = p.Host
				}
				valid = valid && exit == expected
			}
			record["ok"] = valid
		}
		cancel()
		record["ms"] = time.Since(start).Milliseconds()
		results[check.Name] = record
		if record["ok"] != true {
			failed = true
		}
	}
	json.NewEncoder(os.Stdout).Encode(results)
	if failed {
		return fmt.Errorf("one or more bounded data checks failed")
	}
	return nil
}
