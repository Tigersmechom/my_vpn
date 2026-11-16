package health

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(id string) Route {
	return Route{ID: id, Protocol: "HY2", Profile: Profile{Host: "vpn.example", HY2: Hysteria{Port: 443, ObfsPort: 444, Auth: "test", SNI: "vpn.example", Pin: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", ObfsPassword: "test"}}}
}
func request(routes ...Route) []byte { b, _ := json.Marshal(Request{Routes: routes}); return b }
func reply(t *testing.T, e *Engine, routes ...Route) Reply {
	t.Helper()
	var out Reply
	if err := json.Unmarshal(e.Check(request(routes...)), &out); err != nil {
		t.Fatal(err)
	}
	if out.Error != "" {
		t.Fatal(out.Error)
	}
	return out
}
func TestRealTLSBoundedReuseAndCatalog(t *testing.T) {
	var requests, conns, closes, active, peak atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" || r.URL.Path != "/generate_204" {
			t.Error("unexpected request")
		}
		n := active.Add(1)
		defer active.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		requests.Add(1)
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(204)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	// Fixed production URL is retained; test transport maps only its socket to localhost.
	e := New(roots)
	defer e.Stop()
	e.factory = func(Route) (func(context.Context, string, string) (net.Conn, error), func(), error) {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "www.google.com:443" {
				t.Error("non-fixed destination")
			}
			conns.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}, func() { closes.Add(1) }, nil
	}
	// The loopback certificate has a different SAN; production must reject it.
	got := reply(t, e, fixture("one"))
	if got.Results[0].Code != "certificate" {
		t.Fatalf("TLS validation bypassed: %+v", got)
	}
	if requests.Load() != 0 {
		t.Fatal("untrusted HTTP reached server")
	}
	if closes.Load() != 1 {
		t.Fatal("failed TLS transport wasn't closed")
	}
}

func TestMissingKeyValidationAndRetirement(t *testing.T) {
	e := New(nil)
	defer e.Stop()
	r := fixture("awg")
	r.Protocol = "AWG"
	got := reply(t, e, r).Results[0]
	if got.Code != "requires_probe_key" || got.Grade != "yellow" || got.Samples != 0 {
		t.Fatal(got)
	}
	for _, bad := range [][]byte{[]byte(`{"routes":[]}`), request(r, r), request(fixture("bad id")), []byte(`{"routes":null}`)} {
		var out Reply
		json.Unmarshal(e.Check(bad), &out)
		if out.Error != "invalid_config" {
			t.Fatal("accepted invalid config")
		}
	}
	e.factory = func(Route) (func(context.Context, string, string) (net.Conn, error), func(), error) {
		return nil, nil, errors.New("unreachable")
	}
	reply(t, e, fixture("new"))
	e.mu.Lock()
	_, old := e.routes["awg"]
	e.mu.Unlock()
	if old {
		t.Fatal("removed route retained")
	}
}
func TestStopCancelsAndNoMoreNetwork(t *testing.T) {
	e := New(nil)
	var dials atomic.Int32
	entered := make(chan struct{}, 1)
	e.factory = func(Route) (func(context.Context, string, string) (net.Conn, error), func(), error) {
		return func(ctx context.Context, _, _ string) (net.Conn, error) {
			dials.Add(1)
			entered <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		}, func() {}, nil
	}
	done := make(chan struct{})
	go func() { e.Check(request(fixture("one"))); close(done) }()
	<-entered
	e.Stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stop did not interrupt")
	}
	before := dials.Load()
	e.Check(request(fixture("one")))
	if dials.Load() != before {
		t.Fatal("network after Stop")
	}
}
func TestTimeoutRecoveryFingerprintAndHistory(t *testing.T) {
	e := New(nil)
	defer e.Stop()
	e.timeout = 25 * time.Millisecond
	var created, closed atomic.Int32
	e.factory = func(Route) (func(context.Context, string, string) (net.Conn, error), func(), error) {
		created.Add(1)
		return nil, func() { closed.Add(1) }, errors.New("unreachable")
	}
	r := fixture("one")
	first := reply(t, e, r).Results[0]
	second := reply(t, e, r).Results[0]
	if first.Grade != "yellow" || second.Grade != "red" || second.Samples != 2 {
		t.Fatal(first, second)
	}
	r.Profile.HY2.Auth = "changed"
	third := reply(t, e, r).Results[0]
	if third.Samples != 1 || third.Grade != "yellow" {
		t.Fatal("history leaked across credentials")
	}
}

func TestSuccessfulPoolReuseBoundedParallelismAndCatalogChange(t *testing.T) {
	var requests, connections, active, peak, closed atomic.Int32
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"www.google.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" || r.URL.Path != "/generate_204" || r.ContentLength > 0 {
			t.Error("unexpected data transfer")
		}
		n := active.Add(1)
		defer active.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		requests.Add(1)
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(204)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	e := New(roots)
	defer e.Stop()
	e.factory = func(Route) (func(context.Context, string, string) (net.Conn, error), func(), error) {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "www.google.com:443" {
				t.Error("unexpected destination")
			}
			connections.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}, func() { closed.Add(1) }, nil
	}
	routes := []Route{}
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"} {
		routes = append(routes, fixture(id))
	}
	for i := 0; i < 3; i++ {
		for _, r := range reply(t, e, routes...).Results {
			if r.Code != "ok" || r.Samples != i+1 || r.Successes != i+1 {
				t.Fatal(r)
			}
		}
	}
	if connections.Load() != 9 || requests.Load() != 27 || peak.Load() > 3 {
		t.Fatalf("connections=%d requests=%d concurrency=%d", connections.Load(), requests.Load(), peak.Load())
	}
	routes = append(routes[:8], fixture("new-route"))
	got := reply(t, e, routes...)
	if got.Results[8].Samples != 1 || got.Results[0].Samples != 4 || closed.Load() != 1 {
		t.Fatal("catalog replacement retained old state")
	}
	e.Stop()
	if closed.Load() != 10 {
		t.Fatal("network sessions not all closed")
	}
}
