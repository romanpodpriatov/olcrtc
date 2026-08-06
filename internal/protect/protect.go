// Package protect provides functions to protect sockets from VPN routing.
package protect

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

const (
	defaultDialTimeout       = 10 * time.Second
	defaultKeepAlive         = 30 * time.Second
	defaultIdleConnTimeout   = 30 * time.Second
	defaultTLSHandshake      = 10 * time.Second
	defaultResponseHeader    = 10 * time.Second
	defaultWebSocketTimeout  = 10 * time.Second
	defaultHTTPClientTimeout = 30 * time.Second
	defaultStatusBodyLimit   = 1024
)

var (
	sensitiveFieldRE = regexp.MustCompile(
		`(?i)((?:access[_-]?token|room[_-]?token|token|credentials)"?\s*[:=]\s*"?)` +
			`[^",\s}]+`,
	)
	sensitiveBearerRE = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+`)
)

// Protector is called with a socket file descriptor before connect.
// On Android, this calls VpnService.protect(fd) to bypass VPN routing.
var Protector func(fd int) bool //nolint:gochecknoglobals // package-level state intentional

// ErrProtectorRejected reports that the host protector refused a socket.
//
// This used to surface as net.ErrClosed, which prints "use of closed network
// connection" - a protector that fails only for AF_INET6 then reads as an
// unrelated bug in whatever was dialing. The network is in the OpError, so the
// message now names both the cause and the family it happened on.
var ErrProtectorRejected = errors.New("socket protector rejected the socket")

func controlFunc(network, _ string, c syscall.RawConn) error {
	if Protector == nil {
		return nil
	}
	var err error
	controlErr := c.Control(func(fd uintptr) {
		if !Protector(int(fd)) {
			err = &net.OpError{Op: "protect", Net: network, Err: ErrProtectorRejected}
		}
	})
	if controlErr != nil {
		return fmt.Errorf("control failed: %w", controlErr)
	}
	return err
}

// NewDialer returns a net.Dialer that calls Protector on each new socket and
// resolves through the configured DNS servers.
func NewDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   defaultDialTimeout,
		KeepAlive: defaultKeepAlive,
		Control:   controlFunc,
		Resolver:  activeResolver(),
	}
}

// NewTLSConfig returns the shared TLS policy for provider HTTP/WebSocket clients.
func NewTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

// NewHTTPTransport returns an HTTP transport using protected sockets and sane timeouts.
func NewHTTPTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           DialContext,
		TLSClientConfig:       NewTLSConfig(),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       defaultIdleConnTimeout,
		TLSHandshakeTimeout:   defaultTLSHandshake,
		ResponseHeaderTimeout: defaultResponseHeader,
	}
}

// NewHTTPClient returns an http.Client using protected sockets with DNS retry.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Transport: &retryTransport{base: NewHTTPTransport()},
		Timeout:   defaultHTTPClientTimeout,
	}
}

// retryTransport retries requests on transient DNS/dial errors.
type retryTransport struct {
	base http.RoundTripper
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	const maxRetries = 3
	var resp *http.Response
	var err error
	for i := range maxRetries {
		if i > 0 {
			time.Sleep(time.Duration(i) * 500 * time.Millisecond)
		}
		resp, err = t.base.RoundTrip(req)
		if err == nil || !isRetriableError(err) {
			if err != nil {
				return resp, fmt.Errorf("round trip: %w", err)
			}
			return resp, nil
		}
	}
	return resp, fmt.Errorf("round trip after %d retries: %w", maxRetries, err)
}

func isRetriableError(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Timeout() || strings.Contains(opErr.Error(), "connection refused")
	}
	s := err.Error()
	return strings.Contains(s, "no such host") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "i/o timeout")
}

// NewWebSocketDialer returns a WebSocket dialer using protected sockets and shared TLS policy.
func NewWebSocketDialer(handshakeTimeout time.Duration) websocket.Dialer {
	if handshakeTimeout <= 0 {
		handshakeTimeout = defaultWebSocketTimeout
	}
	return websocket.Dialer{
		NetDialContext:   DialContext,
		Proxy:            http.ProxyFromEnvironment,
		TLSClientConfig:  NewTLSConfig(),
		HandshakeTimeout: handshakeTimeout,
	}
}

// StatusError formats an upstream HTTP error while bounding and redacting the body.
func StatusError(base error, resp *http.Response, limit int64) error {
	if limit <= 0 {
		limit = defaultStatusBodyLimit
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	bodyText := RedactSensitive(strings.TrimSpace(string(body)))
	if bodyText == "" {
		return fmt.Errorf("%w: status %d", base, resp.StatusCode)
	}
	return fmt.Errorf("%w: status %d: %s", base, resp.StatusCode, bodyText)
}

// RedactSensitive removes common token-like values from provider error text.
func RedactSensitive(text string) string {
	text = sensitiveBearerRE.ReplaceAllString(text, "${1}<redacted>")
	return sensitiveFieldRE.ReplaceAllString(text, "${1}<redacted>")
}

// DialContext dials using a protected socket.
//
// For "tcp" against a host name it resolves both address families and tries
// both. A plain net.Dialer races them only when both families reach it, and a
// single dropped AAAA is enough for them not to - which on a link with no IPv4
// leaves an immediate ENETUNREACH as the only outcome (#1).
func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network == "tcp" && !isIPLiteral(address) {
		conn, err := dialDualStack(ctx, address)
		if err != nil {
			return nil, fmt.Errorf("dial failed: %w", err)
		}
		return conn, nil
	}
	conn, err := NewDialer().DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}
	return conn, nil
}

// isIPLiteral reports whether address is a host:port whose host is an IP.
func isIPLiteral(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	return net.ParseIP(host) != nil
}

// ProxyDialer implements golang.org/x/net/proxy.Dialer for pion ICE.
type ProxyDialer struct{}

// Dial connects to the address on the named network using a protected socket.
func (d *ProxyDialer) Dial(network, addr string) (net.Conn, error) {
	return DialContext(context.Background(), network, addr)
}

// NewProxyDialer returns a proxy.Dialer that protects ICE sockets.
func NewProxyDialer() *ProxyDialer {
	return &ProxyDialer{}
}
