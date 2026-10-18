package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
)

// Selective interception (tls.intercept / tls.intercept_exclude).
//
// In mitm mode the proxy normally decrypts every TLS connection. With an
// intercept list it decrypts only the hosts that need a transform to see
// inside them, and tunnels the rest exactly as sni-only mode does: the
// pipeline runs on the SNI alone (so the allowlist still applies) and the
// bytes are passed through undecrypted.

// selectiveIntercept reports whether an intercept list is configured.
func (p *Proxy) selectiveIntercept() bool {
	return p.interceptHosts != nil || p.interceptExclude != nil
}

// shouldIntercept reports whether a TLS connection for sni is decrypted.
// An exclude match always wins; with no intercept list every other host is
// intercepted.
func (p *Proxy) shouldIntercept(sni string) bool {
	if p.interceptExclude != nil && p.interceptExclude.Matches(sni) {
		return false
	}
	if p.interceptHosts == nil {
		return true
	}
	return p.interceptHosts.Matches(sni)
}

// serveSelectiveTLS handles one client TLS connection when interception is
// selective: it reads the ClientHello SNI, then either terminates TLS and
// serves the requests through handler, or tunnels the connection
// undecrypted.
//
// The decision is made on the SNI, never on the CONNECT target. The tunnel
// path dials the SNI host, so deciding on the target would let a client
// CONNECT to a tunnelled host and then send a ClientHello for an
// intercepted one, skipping every transform that host needs.
func (p *Proxy) serveSelectiveTLS(clientConn net.Conn, handler http.Handler) error {
	sni, peeked, err := peekSNI(clientConn, sniPeekTimeout)
	if err != nil {
		_ = clientConn.Close()
		return fmt.Errorf("peek sni: %w", err)
	}

	if !p.shouldIntercept(sni) {
		return p.servePeekedSNIPassthrough(clientConn, sni, peeked)
	}

	// Replay the ClientHello bytes the peek consumed, then hand the
	// connection to crypto/tls as if nothing had been read.
	replay := newPeekedConn(clientConn, bufio.NewReader(io.MultiReader(bytes.NewReader(peeked), clientConn)))
	tlsConn := tls.Server(replay, &tls.Config{
		GetCertificate: p.getCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	})
	defer func() { _ = tlsConn.Close() }()

	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		return fmt.Errorf("TLS handshake for %s: %w", sni, err)
	}
	return serveOneHTTPConn(tlsConn, handler)
}

// serveHTTPSSelective runs the HTTPS listener in mitm mode with an intercept
// list: each connection goes through serveSelectiveTLS.
func (p *Proxy) serveHTTPSSelective() error {
	ln, err := net.Listen("tcp", p.httpsAddr)
	if err != nil {
		return fmt.Errorf("https listen: %w", err)
	}
	p.tlsListener = ln
	p.logger.Info("https proxy starting (selective intercept)", slog.String("addr", ln.Addr().String()))
	handler := http.HandlerFunc(p.handleDirectHTTP)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if p.shutdownCtx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			p.logger.Warn("https accept error", slog.String("error", err.Error()))
			continue
		}
		go func() {
			defer func() { _ = conn.Close() }()
			if err := p.serveSelectiveTLS(conn, handler); err != nil {
				p.logger.Debug("https selective intercept error", slog.String("error", err.Error()))
			}
		}()
	}
}
