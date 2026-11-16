package health

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

type Result struct {
	ID        string `json:"id"`
	Grade     string `json:"grade"`
	Code      string `json:"code"`
	RTT       int64  `json:"rttMs"`
	Average   int64  `json:"averageMs"`
	Jitter    int64  `json:"jitterMs"`
	Samples   int    `json:"samples"`
	Successes int    `json:"successes"`
	CheckedAt int64  `json:"checkedAt"`
}
type Reply struct {
	Results []Result `json:"results"`
	Error   string   `json:"error,omitempty"`
}
type sample struct {
	ok bool
	ms int64
}

type Engine struct {
	checkMu sync.Mutex
	mu      sync.Mutex
	routes  map[string]*probe
	ctx     context.Context
	cancel  context.CancelFunc
	timeout time.Duration
	roots   *x509.CertPool
	// Replaced only in tests; production always creates actual protocol clients.
	factory func(Route) (func(context.Context, string, string) (net.Conn, error), func(), error)
}

func New(roots *x509.CertPool) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{routes: map[string]*probe{}, ctx: ctx, cancel: cancel, timeout: 2500 * time.Millisecond, roots: roots}
}
func (e *Engine) Stop() {
	e.mu.Lock()
	e.cancel()
	all := e.routes
	e.routes = map[string]*probe{}
	e.mu.Unlock()
	for _, p := range all {
		p.close()
	}
}

// Check has at most three network requests in flight and one fixed HEAD per route.
// Clients and TLS sessions are reused across rounds, avoiding repeated handshakes.
func (e *Engine) Check(data []byte) []byte {
	e.checkMu.Lock()
	defer e.checkMu.Unlock()
	routes, err := parse(data)
	if err != nil {
		b, _ := json.Marshal(Reply{Error: "invalid_config"})
		return b
	}
	e.mu.Lock()
	if e.ctx.Err() != nil {
		e.mu.Unlock()
		return []byte(`{"error":"cancelled","results":[]}`)
	}
	keep := map[string]bool{}
	jobs := make([]*probe, len(routes))
	stale := []*probe{}
	for i, r := range routes {
		keep[r.ID] = true
		p := e.routes[r.ID]
		if p == nil || p.fingerprint != fingerprint(r) {
			if p != nil {
				stale = append(stale, p)
			}
			ctx, cancel := context.WithCancel(e.ctx)
			p = &probe{route: r, fingerprint: fingerprint(r), ctx: ctx, cancel: cancel, roots: e.roots, factory: e.factory}
			e.routes[r.ID] = p
		}
		jobs[i] = p
	}
	for id, p := range e.routes {
		if !keep[id] {
			stale = append(stale, p)
			delete(e.routes, id)
		}
	}
	e.mu.Unlock()
	for _, p := range stale {
		p.close()
	}
	result := make([]Result, len(jobs))
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup
	for i, p := range jobs {
		wg.Add(1)
		go func(i int, p *probe) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-p.ctx.Done():
				result[i] = Result{ID: p.route.ID, Grade: "yellow", Code: "cancelled"}
				return
			}
			defer func() { <-sem }()
			timeout := e.timeout
			if len(p.history) == 0 && e.factory == nil {
				timeout = 5 * time.Second
			}
			ctx, cancel := context.WithTimeout(p.ctx, timeout)
			defer cancel()
			result[i] = p.check(ctx)
		}(i, p)
	}
	wg.Wait()
	b, _ := json.Marshal(Reply{Results: result})
	return b
}

type probe struct {
	route        Route
	fingerprint  [32]byte
	ctx          context.Context
	cancel       context.CancelFunc
	roots        *x509.CertPool
	checkMu      sync.Mutex
	mu           sync.Mutex
	http         *http.Client
	transport    *http.Transport
	closeNetwork func()
	pending      net.PacketConn
	connections  map[*trackedConn]bool
	generation   uint64
	history      []sample
	factory      func(Route) (func(context.Context, string, string) (net.Conn, error), func(), error)
}

func (p *probe) abort() {
	p.mu.Lock()
	closeFn, packet, tr := p.closeNetwork, p.pending, p.transport
	conns := p.connections
	p.generation++
	p.closeNetwork = nil
	p.pending = nil
	p.http = nil
	p.transport = nil
	p.connections = nil
	p.mu.Unlock()
	if tr != nil {
		tr.CloseIdleConnections()
	}
	for c := range conns {
		_ = c.Conn.Close()
	}
	if packet != nil {
		_ = packet.Close()
	}
	if closeFn != nil {
		closeFn()
	}
}
func (p *probe) close() { p.cancel(); p.abort() }
func (p *probe) client(ctx context.Context) (*http.Client, error) {
	p.mu.Lock()
	c := p.http
	generation := p.generation
	p.mu.Unlock()
	if c != nil {
		return c, nil
	}
	if p.ctx.Err() != nil || ctx.Err() != nil {
		return nil, context.Canceled
	}
	var dial func(context.Context, string, string) (net.Conn, error)
	var closeFn func()
	var err error
	if p.factory != nil {
		dial, closeFn, err = p.factory(p.route)
	} else {
		dial, closeFn, err = p.dialer(ctx)
	}
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || p.ctx.Err() != nil {
		closeFn()
		return nil, context.Canceled
	}
	tr := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, MaxIdleConns: 1, MaxIdleConnsPerHost: 1, MaxConnsPerHost: 1, MaxResponseHeaderBytes: 4096, IdleConnTimeout: 20 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: p.roots, ClientSessionCache: tls.NewLRUClientSessionCache(1)}, TLSHandshakeTimeout: 2 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			c, err := dial(ctx, network, address)
			if err != nil {
				return nil, err
			}
			p.mu.Lock()
			if ctx.Err() != nil || p.ctx.Err() != nil || p.generation != generation {
				p.mu.Unlock()
				c.Close()
				return nil, context.Canceled
			}
			t := &trackedConn{Conn: c, owner: p}
			if p.connections == nil {
				p.connections = map[*trackedConn]bool{}
			}
			p.connections[t] = true
			p.mu.Unlock()
			return t, nil
		}}
	c = &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	p.mu.Lock()
	if p.ctx.Err() != nil || ctx.Err() != nil || p.generation != generation {
		p.mu.Unlock()
		tr.CloseIdleConnections()
		closeFn()
		return nil, context.Canceled
	}
	p.http = c
	p.transport = tr
	p.closeNetwork = closeFn
	p.mu.Unlock()
	return c, nil
}

type trackedConn struct {
	net.Conn
	owner *probe
}

func (c *trackedConn) Close() error {
	c.owner.mu.Lock()
	delete(c.owner.connections, c)
	c.owner.mu.Unlock()
	return c.Conn.Close()
}
func (p *probe) check(ctx context.Context) Result {
	p.checkMu.Lock()
	defer p.checkMu.Unlock()
	started := time.Now()
	abortDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { p.abort(); close(abortDone) })
	c, err := p.client(ctx)
	code := "ok"
	if err == nil {
		var req *http.Request
		req, err = http.NewRequestWithContext(ctx, http.MethodHead, TargetURL, nil)
		if err == nil {
			req.Header.Set("User-Agent", "MyVPN-availability/1")
			var response *http.Response
			response, err = c.Do(req)
			if err == nil {
				response.Body.Close()
				if response.StatusCode != 204 {
					code = "http_status"
				}
			}
		}
	}
	elapsed := time.Since(started).Milliseconds()
	stopped := stop()
	if !stopped {
		<-abortDone
	}
	if ctx.Err() != nil {
		code = "timeout"
	} else if err != nil {
		code = errorCode(err)
	}
	if p.ctx.Err() != nil {
		code = "cancelled"
	}
	if err != nil || !stopped {
		p.abort()
	}
	ok := code == "ok"
	if code != "cancelled" && code != "requires_probe_key" {
		p.history = append(p.history, sample{ok, elapsed})
		if len(p.history) > 5 {
			p.history = p.history[len(p.history)-5:]
		}
	}
	r := Result{ID: p.route.ID, Code: code, RTT: elapsed, Grade: "yellow", Samples: len(p.history), CheckedAt: time.Now().UnixMilli()}
	var sum, min, max int64
	for _, s := range p.history {
		if s.ok {
			r.Successes++
			sum += s.ms
			if min == 0 || s.ms < min {
				min = s.ms
			}
			if s.ms > max {
				max = s.ms
			}
		}
	}
	if r.Successes > 0 {
		r.Average = sum / int64(r.Successes)
		r.Jitter = max - min
	}
	if ok && r.Successes == r.Samples && elapsed < 250 {
		r.Grade = "green"
	} else if !ok && code != "cancelled" && code != "requires_probe_key" && code != "http_status" {
		if code == "certificate" || code == "auth" || (len(p.history) >= 2 && !p.history[len(p.history)-2].ok) {
			r.Grade = "red"
		}
	}
	return r
}
func errorCode(err error) string {
	if errors.Is(err, errDedicatedKey) {
		return "requires_probe_key"
	}
	if errors.Is(err, errPin) {
		return "certificate"
	}
	var verify *tls.CertificateVerificationError
	if errors.As(err, &verify) {
		return "certificate"
	}
	var n net.Error
	if errors.As(err, &n) && n.Timeout() {
		return "timeout"
	}
	return protocolErrorCode(err)
}
