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
	"sync"
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
