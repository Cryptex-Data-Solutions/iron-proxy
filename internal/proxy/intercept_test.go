package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/allowlist"
)

// Selective interception: with tls.intercept / tls.intercept_exclude set,
// only matching SNIs are decrypted; every other host is tunnelled
// undecrypted, as in sni-only mode.

type selectiveProxy struct {
	p          *Proxy
	tunnelAddr string
	caCert     *x509.Certificate
	results    func() []transform.PipelineResult
}

// startSelectiveProxy starts a mitm-mode proxy with the given intercept
// lists. Both paths reach the echo server: the MITM path through p.transport,
// the tunnel path through sniUpstreamPort.
func startSelectiveProxy(t *testing.T, intercept, exclude []string, upstream string) *selectiveProxy {
	t.Helper()
	_, upstreamPort, err := net.SplitHostPort(upstream)
	require.NoError(t, err)

	caCert, caKey := generateTestCA(t)
	cache, err := certcache.NewFromCA(caCert, caKey, 100, 72*time.Hour)
	require.NoError(t, err)

	al, err := allowlist.New([]string{"localhost", "allowed.example"}, nil)
	require.NoError(t, err)
	pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, testLogger())
	var mu sync.Mutex
	var results []transform.PipelineResult
	pipeline.SetAuditFunc(func(r *transform.PipelineResult) {
		mu.Lock()
		defer mu.Unlock()
		results = append(results, *r)
	})

	p := New(Options{
		HTTPAddr:         "127.0.0.1:0",
		HTTPSAddr:        "127.0.0.1:0",
		TunnelAddr:       "127.0.0.1:0",
		CertCache:        cache,
		Pipeline:         transform.NewPipelineHolder(pipeline),
		Logger:           testLogger(),
		InterceptHosts:   intercept,
		InterceptExclude: exclude,
	})
	p.sniUpstreamPort = upstreamPort
	p.transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstream)
		},
	}

	return &selectiveProxy{
		p:          p,
		tunnelAddr: startTunnelListener(t, p),
		caCert:     caCert,
		results: func() []transform.PipelineResult {
			mu.Lock()
			defer mu.Unlock()
			return append([]transform.PipelineResult(nil), results...)
		},
	}
}

// get CONNECTs to connectTarget, handshakes with ServerName sni, sends one
// GET and returns whether the proxy decrypted the connection (the leaf was
// signed by the proxy CA) and the response body.
func (s *selectiveProxy) get(t *testing.T, connectTarget, sni, path string) (intercepted bool, body string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", s.tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", connectTarget, connectTarget)
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Verification is checked by hand below: the point is which cert we got.
	tlsConn := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	require.NoError(t, tlsConn.Handshake())
	leaf := tlsConn.ConnectionState().PeerCertificates[0]
	intercepted = leaf.CheckSignatureFrom(s.caCert) == nil

	_, err = fmt.Fprintf(tlsConn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, sni)
	require.NoError(t, err)
	resp, err = http.ReadResponse(bufio.NewReader(tlsConn), nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return intercepted, string(data)
}

func TestSelectiveIntercept_DecryptsOnlyListedHosts(t *testing.T) {
	upstream, _ := startEchoTLSServer(t)
	_, port, _ := net.SplitHostPort(upstream)

	// Tunnelled cases use "localhost": the tunnel path dials the SNI host by
	// name, and only localhost resolves here. The MITM path dials through
	// p.transport, so any name works there.
	tests := []struct {
		name          string
		intercept     []string
		exclude       []string
		sni           string
		wantIntercept bool
	}{
		{"listed host is decrypted", []string{"allowed.example"}, nil, "allowed.example", true},
		{"unlisted host is tunnelled", []string{"allowed.example"}, nil, "localhost", false},
		{"glob covers subdomain and apex", []string{"*.example"}, nil, "allowed.example", true},
		{"exclude wins over intercept", []string{"localhost", "allowed.example"}, []string{"localhost"}, "localhost", false},
		{"exclude only: everything else decrypted", nil, []string{"localhost"}, "allowed.example", true},
		{"exclude only: excluded host tunnelled", nil, []string{"localhost"}, "localhost", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := startSelectiveProxy(t, tc.intercept, tc.exclude, upstream)
			intercepted, body := s.get(t, tc.sni+":"+port, tc.sni, "/x")
			require.Equal(t, tc.wantIntercept, intercepted)
			require.Equal(t, "echo /x\n", body, "both paths must reach the upstream")
		})
	}
}

// The decision follows the SNI, not the CONNECT target: CONNECTing to a
// tunnelled host and then sending a ClientHello for an intercepted one must
// still be decrypted, or a client could skip the transforms that host needs.
func TestSelectiveIntercept_DecidesOnSNINotCONNECTTarget(t *testing.T) {
	upstream, _ := startEchoTLSServer(t)
	_, port, _ := net.SplitHostPort(upstream)
	s := startSelectiveProxy(t, []string{"allowed.example"}, nil, upstream)

	intercepted, _ := s.get(t, "localhost:"+port, "allowed.example", "/sni")
	require.True(t, intercepted, "SNI is intercepted, so the connection is decrypted")

	intercepted, _ = s.get(t, "allowed.example:"+port, "localhost", "/sni")
	require.False(t, intercepted, "SNI is not intercepted, so the connection is tunnelled")
}

// A tunnelled connection still goes through the allowlist, on its SNI.
func TestSelectiveIntercept_TunnelledHostIsStillAllowlisted(t *testing.T) {
	upstream, _ := startEchoTLSServer(t)
	_, port, _ := net.SplitHostPort(upstream)
	s := startSelectiveProxy(t, []string{"allowed.example"}, nil, upstream)

	conn, err := net.DialTimeout("tcp", s.tunnelAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	// CONNECT to an allowed host, then present an SNI the allowlist denies.
	_, err = fmt.Fprintf(conn, "CONNECT localhost:%s HTTP/1.1\r\nHost: localhost:%s\r\n\r\n", port, port)
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	tlsConn := tls.Client(conn, &tls.Config{ServerName: "blocked.example", InsecureSkipVerify: true})
	require.Error(t, tlsConn.Handshake(), "a denied SNI must not reach the upstream")

	require.Eventually(t, func() bool {
		for _, r := range s.results() {
			if r.Mode == transform.ModeSNIOnly && r.SNI == "blocked.example" && r.Action == transform.ActionReject {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond)
}

func TestSelectiveIntercept_OffByDefault(t *testing.T) {
	upstream, _ := startEchoTLSServer(t)
	_, port, _ := net.SplitHostPort(upstream)
	s := startSelectiveProxy(t, nil, nil, upstream)
	require.False(t, s.p.selectiveIntercept())

	intercepted, body := s.get(t, "localhost:"+port, "localhost", "/all")
	require.True(t, intercepted, "with no lists every host is decrypted, as before")
	require.Equal(t, "echo /all\n", body)
}

// startSelectiveHTTPSListener builds a selective proxy (no tunnel listener)
// and serves its direct HTTPS listener on 127.0.0.1:0. upstreamHandler
// answers decrypted requests; tunnelled ones go to the echo server.
func startSelectiveHTTPSListener(t *testing.T, intercept []string, upstreamHandler http.Handler, echo string) (*Proxy, string, *x509.Certificate) {
	t.Helper()
	_, echoPort, err := net.SplitHostPort(echo)
	require.NoError(t, err)

	caCert, caKey := generateTestCA(t)
	cache, err := certcache.NewFromCA(caCert, caKey, 100, 72*time.Hour)
	require.NoError(t, err)
	al, err := allowlist.New([]string{"localhost", "allowed.example"}, nil)
	require.NoError(t, err)

	p := New(Options{
		HTTPAddr:       "127.0.0.1:0",
		HTTPSAddr:      "127.0.0.1:0",
		CertCache:      cache,
		Pipeline:       transform.NewPipelineHolder(transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, testLogger())),
		Logger:         testLogger(),
		InterceptHosts: intercept,
	})
	p.sniUpstreamPort = echoPort

	mitmUpstream := httptest.NewTLSServer(upstreamHandler)
	t.Cleanup(mitmUpstream.Close)
	upstreamAddr := mitmUpstream.Listener.Addr().String()
	p.transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.serveHTTPSSelectiveOn(ln) }() // returns http.ErrServerClosed on Shutdown
	return p, ln.Addr().String(), caCert
}

// dialDirect handshakes with the direct HTTPS listener as sni and reports
// whether the proxy decrypted (leaf signed by the proxy CA).
func dialDirect(t *testing.T, addr, sni string, caCert *x509.Certificate) (*tls.Conn, bool) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	leaf := conn.ConnectionState().PeerCertificates[0]
	return conn, leaf.CheckSignatureFrom(caCert) == nil
}

func TestSelectiveIntercept_DirectHTTPSListener(t *testing.T) {
	echo, _ := startEchoTLSServer(t)
	_, addr, caCert := startSelectiveHTTPSListener(t, []string{"allowed.example"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "decrypted")
	}), echo)

	conn, intercepted := dialDirect(t, addr, "allowed.example", caCert)
	require.True(t, intercepted)
	_, err := fmt.Fprint(conn, "GET /a HTTP/1.1\r\nHost: allowed.example\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "decrypted", string(body))

	conn, intercepted = dialDirect(t, addr, "localhost", caCert)
	require.False(t, intercepted, "unlisted host is tunnelled to the echo server")
	_, err = fmt.Fprint(conn, "GET /b HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)
	resp, err = http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "echo /b\n", string(body))
}

// Shutdown drains a decrypted request that is in flight on the direct
// HTTPS listener, as plain mitm mode does, instead of cutting it off.
func TestSelectiveIntercept_ShutdownDrainsInFlightRequest(t *testing.T) {
	echo, _ := startEchoTLSServer(t)
	started := make(chan struct{})
	release := make(chan struct{})
	p, addr, caCert := startSelectiveHTTPSListener(t, []string{"allowed.example"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_, _ = fmt.Fprint(w, "finished")
	}), echo)

	conn, intercepted := dialDirect(t, addr, "allowed.example", caCert)
	require.True(t, intercepted)
	_, err := fmt.Fprint(conn, "GET /slow HTTP/1.1\r\nHost: allowed.example\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)
	<-started

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownDone <- p.Shutdown(ctx)
	}()

	select {
	case <-shutdownDone:
		t.Fatal("Shutdown returned while a decrypted request was still in flight")
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "finished", string(body), "the in-flight request completes")

	select {
	case err := <-shutdownDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return after the request finished")
	}
}

// temporaryErr is an accept error marked temporary, like EMFILE.
type temporaryErr struct{}

func (temporaryErr) Error() string   { return "too many open files" }
func (temporaryErr) Timeout() bool   { return false }
func (temporaryErr) Temporary() bool { return true }

// flakyListener fails its first Accept with a temporary error, then
// behaves like the real listener it wraps.
type flakyListener struct {
	net.Listener
	failed atomic.Bool
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if !l.failed.Swap(true) {
		return nil, temporaryErr{}
	}
	return l.Listener.Accept()
}

// A temporary accept error must not stop the listener: the next connection
// is still routed.
func TestSelectiveListener_RetriesTemporaryAcceptErrors(t *testing.T) {
	p := New(Options{Logger: testLogger(), InterceptHosts: []string{"localhost"}})
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	l := p.newSelectiveListener(&flakyListener{Listener: raw})
	t.Cleanup(func() { _ = l.Close() })

	// The handshake never completes (nobody answers), so the client goroutine
	// just ends when the test closes the connection; its error is irrelevant.
	go func() {
		conn, err := tls.Dial("tcp", raw.Addr().String(), &tls.Config{ServerName: "localhost", InsecureSkipVerify: true})
		if err == nil {
			_ = conn.Close()
		}
	}()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := l.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("no connection accepted after a temporary accept error")
	}
}

func TestSelectiveListener_PermanentErrorEndsAccept(t *testing.T) {
	p := New(Options{Logger: testLogger(), InterceptHosts: []string{"localhost"}})
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	l := p.newSelectiveListener(raw)
	require.NoError(t, raw.Close()) // the raw listener fails for good

	_, err = l.Accept()
	require.Error(t, err)
}
