package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// Selective interception (tls.intercept / tls.intercept_exclude).
//
// In mitm mode the proxy normally decrypts every TLS connection. With an
// intercept list it decrypts only the hosts that need a transform to see
// inside them, and tunnels the rest exactly as sni-only mode does: the
// pipeline runs on the SNI alone (so the allowlist still applies) and the
// bytes are passed through undecrypted.
//
// The decision is always made on the ClientHello SNI, never on the CONNECT
// target. The tunnel path dials the SNI host, so deciding on the target
// would let a client CONNECT to a tunnelled host and then send a
// ClientHello for an intercepted one, skipping every transform that host
// needs.
//
// Lifecycles: decrypted connections on the HTTPS listener are served by
// httpsServer, so Shutdown drains them like plain mitm mode. Tunnelled
// connections close when shutdownCtx is cancelled, like sni-only mode.

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

// replayConn returns conn with the already-peeked ClientHello bytes put back
// in front, so crypto/tls can read the handshake as if nothing was consumed.
func replayConn(conn net.Conn, peeked []byte) net.Conn {
	return newPeekedConn(conn, bufio.NewReader(io.MultiReader(bytes.NewReader(peeked), conn)))
}

// serveSelectiveTLS handles one tunnelled (CONNECT/SOCKS5) TLS connection
// when interception is selective: it reads the SNI, then either terminates
// TLS and serves the requests through handler, or tunnels the connection
// undecrypted.
func (p *Proxy) serveSelectiveTLS(clientConn net.Conn, handler http.Handler) error {
	sni, peeked, err := peekSNI(clientConn, sniPeekTimeout)
	if err != nil {
		_ = clientConn.Close()
		return fmt.Errorf("peek sni: %w", err)
	}

	if !p.shouldIntercept(sni) {
		return p.servePeekedSNIPassthrough(clientConn, sni, peeked)
	}

	tlsConn := tls.Server(replayConn(clientConn, peeked), &tls.Config{
		GetCertificate: p.getCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	})
	defer func() { _ = tlsConn.Close() }()

	// shutdownCtx so a handshake in progress stops when the proxy shuts down.
	if err := tlsConn.HandshakeContext(p.shutdownCtx); err != nil {
		return fmt.Errorf("TLS handshake for %s: %w", sni, err)
	}
	return serveOneHTTPConn(tlsConn, handler)
}

// serveHTTPSSelective runs the HTTPS listener in mitm mode with an intercept
// list. httpsServer serves the decrypted connections (so its Shutdown drains
// them); selectiveListener routes the others to the tunnel path.
func (p *Proxy) serveHTTPSSelective() error {
	ln, err := net.Listen("tcp", p.httpsAddr)
	if err != nil {
		return fmt.Errorf("https listen: %w", err)
	}
	return p.serveHTTPSSelectiveOn(ln)
}

// serveHTTPSSelectiveOn is serveHTTPSSelective on an existing listener.
func (p *Proxy) serveHTTPSSelectiveOn(ln net.Listener) error {
	tlsLn := tls.NewListener(p.newSelectiveListener(ln), p.httpsServer.TLSConfig)
	p.tlsListener = tlsLn
	p.logger.Info("https proxy starting (selective intercept)", slog.String("addr", ln.Addr().String()))
	return fmt.Errorf("https: %w", p.httpsServer.Serve(tlsLn))
}

// selectiveListener wraps the raw HTTPS listener. Each accepted connection
// has its SNI peeked in its own goroutine (so a slow client cannot stall
// Accept): intercepted connections are handed to Accept's caller with the
// peeked bytes replayed; the rest are tunnelled undecrypted right there.
//
// Goroutine lifecycles: the accept loop ends when the raw listener closes
// (Close, or httpsServer.Shutdown closing it). A routing goroutine ends
// after the peek (bounded by sniPeekTimeout) once its connection is handed
// over, dropped because the listener closed, or tunnelled; a tunnel ends
// when either side closes or shutdownCtx is cancelled.
type selectiveListener struct {
	net.Listener
	p *Proxy

	conns     chan net.Conn
	acceptErr chan error
	done      chan struct{}
	closeOnce sync.Once
}

func (p *Proxy) newSelectiveListener(ln net.Listener) *selectiveListener {
	l := &selectiveListener{
		Listener:  ln,
		p:         p,
		conns:     make(chan net.Conn),
		acceptErr: make(chan error, 1),
		done:      make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

// acceptLoop mirrors http.Server's accept loop: a temporary error (for
// example EMFILE, out of file descriptors) is retried with a growing delay
// instead of ending the loop, because http.Server would keep calling
// Accept and nothing would ever arrive. A closed listener or a permanent
// error is passed to Accept's caller once, and the loop ends.
func (l *selectiveListener) acceptLoop() {
	var delay time.Duration
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			if isTemporaryAcceptError(err) {
				select {
				case <-l.done:
					l.acceptErr <- net.ErrClosed // buffered: the loop ends here, so at most one send
					return
				default:
				}
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else {
					delay *= 2
				}
				if delay > time.Second {
					delay = time.Second
				}
				l.p.logger.Warn("https accept error; retrying", slog.String("error", err.Error()), slog.Duration("delay", delay))
				time.Sleep(delay)
				continue
			}
			l.acceptErr <- err // buffered: the loop ends here, so at most one send
			return
		}
		delay = 0
		go l.route(conn)
	}
}

// isTemporaryAcceptError reports whether an Accept error is worth retrying,
// by the same test http.Server uses. Temporary() is deprecated on net.Error
// in general but is still how accept errors like EMFILE are marked.
func isTemporaryAcceptError(err error) bool {
	var t interface{ Temporary() bool }
	return !errors.Is(err, net.ErrClosed) && errors.As(err, &t) && t.Temporary()
}

func (l *selectiveListener) route(conn net.Conn) {
	sni, peeked, err := peekSNI(conn, sniPeekTimeout)
	if err != nil {
		_ = conn.Close()
		l.p.logger.Debug("https selective intercept: peek sni", slog.String("error", err.Error()))
		return
	}
	if !l.p.shouldIntercept(sni) {
		if err := l.p.servePeekedSNIPassthrough(conn, sni, peeked); err != nil {
			l.p.logger.Debug("https selective intercept: passthrough", slog.String("error", err.Error()))
		}
		return
	}
	select {
	case l.conns <- replayConn(conn, peeked):
	case <-l.done:
		_ = conn.Close()
	}
}

// Accept returns the next connection to decrypt.
func (l *selectiveListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case err := <-l.acceptErr:
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops Accept and closes the raw listener, which ends the accept loop.
func (l *selectiveListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}
