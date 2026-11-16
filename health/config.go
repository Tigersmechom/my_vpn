// Package health checks existing VPN transports without creating a system TUN.
package health

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

const MaxRoutes = 27
const IntervalMS = 5000
const TargetURL = "https://www.google.com/generate_204"

var errConfig = errors.New("invalid_config")
var errDedicatedKey = errors.New("requires_probe_key")
var errPin = errors.New("certificate")
var validID = regexp.MustCompile(`^[A-Za-z0-9_/-]{1,96}$`)

type Overrides struct {
	PrivateKey   string `json:"privateKey"`
	PresharedKey string `json:"presharedKey"`
	Address      string `json:"address"`
}
type Hysteria struct {
	Port         int    `json:"port"`
	ObfsPort     int    `json:"obfsPort"`
	Auth         string `json:"auth"`
	SNI          string `json:"sni"`
	Pin          string `json:"pinSha256"`
	ObfsPassword string `json:"obfsPassword"`
}
type Profile struct {
	Host  string         `json:"host"`
	DNS   string         `json:"dns"`
	HY2   Hysteria       `json:"hy2"`
	AWG   map[string]any `json:"awg"`
	Probe *Overrides     `json:"probeAwg"`
}
type Route struct {
	ID       string  `json:"id"`
	Protocol string  `json:"protocol"`
	Profile  Profile `json:"profile"`
}
type Request struct {
	Routes []Route `json:"routes"`
}

func key(s string) bool  { b, e := base64.StdEncoding.DecodeString(s); return e == nil && len(b) == 32 }
func port(p int) bool    { return p > 0 && p <= 65535 }
func safe(s string) bool { return !strings.ContainsAny(s, "\r\n\x00") && len(s) <= 8192 }
func (r Route) validate() error {
	if !validID.MatchString(r.ID) || r.Profile.Host == "" || len(r.Profile.Host) > 253 || !safe(r.Profile.Host) || strings.ContainsAny(r.Profile.Host, " /\\@?#") {
		return errConfig
	}
	switch r.Protocol {
	case "HY2", "HY2_OBFS":
		h := r.Profile.HY2
		pin, e := hex.DecodeString(h.Pin)
		if e != nil || len(pin) != 32 || !port(h.Port) || !port(h.ObfsPort) || !safe(h.Auth) || h.Auth == "" || !safe(h.SNI) || h.SNI == "" || !safe(h.ObfsPassword) {
			return errConfig
		}
		if r.Protocol == "HY2_OBFS" && len(h.ObfsPassword) < 4 {
			return errConfig
		}
	case "AWG":
		if r.Profile.Probe == nil {
			return nil
		} // Caller shows yellow until a dedicated key arrives.
		o := r.Profile.Probe
		a := r.Profile.AWG
		if !key(o.PrivateKey) || !key(o.PresharedKey) || !key(str(a["serverPublicKey"])) || o.PrivateKey == str(a["privateKey"]) || strings.Split(o.Address, "/")[0] == strings.Split(str(a["address"]), "/")[0] {
			return errConfig
		}
		p, e := netip.ParsePrefix(o.Address)
		if e != nil || !p.Addr().Is4() || p.Bits() != 32 {
			return errConfig
		}
		for _, s := range strings.FieldsFunc(r.Profile.DNS, func(c rune) bool { return c == ',' || c == ' ' }) {
			if net.ParseIP(s) == nil {
				return errConfig
			}
		}
		if r.Profile.DNS == "" || !port(integer(a["port"])) || integer(a["mtu"]) < 1280 || integer(a["mtu"]) > 9000 {
			return errConfig
		}
		for _, v := range a {
			if s, ok := v.(string); ok && !safe(s) {
				return errConfig
			}
		}
	default:
		return errConfig
	}
	return nil
}
func parse(data []byte) ([]Route, error) {
	if len(data) > 1048576 {
		return nil, errConfig
	}
	var req Request
	if json.Unmarshal(data, &req) != nil || len(req.Routes) == 0 || len(req.Routes) > MaxRoutes {
		return nil, errConfig
	}
	ids := map[string]bool{}
	for _, r := range req.Routes {
		if ids[r.ID] {
			return nil, errConfig
		}
		ids[r.ID] = true
		if e := r.validate(); e != nil {
			return nil, e
		}
	}
	return req.Routes, nil
}
func fingerprint(r Route) [32]byte { b, _ := json.Marshal(r); return sha256.Sum256(b) }
func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
func integer(v any) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	if i, ok := v.(int); ok {
		return i
	}
	return 0
}
