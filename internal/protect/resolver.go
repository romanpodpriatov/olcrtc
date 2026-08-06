package protect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ErrDNSUnreachable reports that no configured DNS server could be reached.
var ErrDNSUnreachable = errors.New("no configured dns server could be reached")

const (
	defaultDNSPort    = "53"
	defaultDNSTimeout = 3 * time.Second
)

// ai-generated: whole file, part of the IPv6-only carrier-auth fix (#1).

// dnsIPv6Peer maps a public IPv4 resolver to the same operator's IPv6 address.
//
// Clients are configured with a single IPv4 literal - "1.1.1.1:53" on iOS,
// "8.8.8.8:53" by default here. On a link with no IPv4 that address cannot be
// reached at all, so resolution fails before anything dials, which is every
// session on an IPv6-only carrier and on the IPv6-only NAT64 network Apple runs
// App Review from. Falling back to the operator's own IPv6 address keeps the
// queries with the resolver that was already chosen, so no new party sees them.
var dnsIPv6Peer = map[string]string{ //nolint:gochecknoglobals // static lookup table, no state
	"1.1.1.1":         "2606:4700:4700::1111",
	"1.0.0.1":         "2606:4700:4700::1001",
	"8.8.8.8":         "2001:4860:4860::8888",
	"8.8.4.4":         "2001:4860:4860::8844",
	"9.9.9.9":         "2620:fe::fe",
	"149.112.112.112": "2620:fe::9",
}

// configured is the resolver protected dials look names up through.
var configured struct { //nolint:gochecknoglobals // package-level state, same shape as Protector
	mu       sync.RWMutex
	resolver *net.Resolver
}

// SetDNSServers sets the DNS servers protected dialers resolve through. Entries
// may be "host", "host:port" or "[v6]:port". Passing none restores the system
// resolver.
func SetDNSServers(servers ...string) {
	var r *net.Resolver
	if len(servers) > 0 {
		r = NewResolver(servers...)
	}
	configured.mu.Lock()
	defer configured.mu.Unlock()
	configured.resolver = r
}

// NewResolver returns a resolver querying the given servers over protected
// sockets. Servers are tried in turn, so one that this link cannot reach does
// not end resolution.
func NewResolver(servers ...string) *net.Resolver {
	list := expandDNSServers(servers)
	if len(list) == 0 {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialDNS(ctx, network, list)
		},
	}
}

// activeResolver returns the resolver configured for this process.
func activeResolver() *net.Resolver {
	configured.mu.RLock()
	defer configured.mu.RUnlock()
	if configured.resolver == nil {
		return net.DefaultResolver
	}
	return configured.resolver
}

func dialDNS(ctx context.Context, network string, servers []string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: defaultDNSTimeout, Control: controlFunc}
	var firstErr error
	for _, server := range servers {
		conn, err := dialer.DialContext(ctx, network, server)
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	if firstErr == nil {
		return nil, ErrDNSUnreachable
	}
	return nil, fmt.Errorf("%w: %w", ErrDNSUnreachable, firstErr)
}

// expandDNSServers normalizes each server and appends the IPv6 address of every
// known IPv4 public resolver, dropping duplicates and keeping the given order.
func expandDNSServers(servers []string) []string {
	out := make([]string, 0, len(servers)*2)
	seen := make(map[string]struct{}, len(servers)*2)
	for _, server := range servers {
		for _, addr := range withIPv6Peer(server) {
			if _, dup := seen[addr]; dup {
				continue
			}
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}
	return out
}

func withIPv6Peer(server string) []string {
	addr := normalizeDNSServer(server)
	if addr == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return []string{addr}
	}
	peer, ok := dnsIPv6Peer[host]
	if !ok {
		return []string{addr}
	}
	return []string{addr, net.JoinHostPort(peer, port)}
}

// normalizeDNSServer accepts "host", "host:port" and "[v6]:port".
func normalizeDNSServer(server string) string {
	trimmed := strings.TrimSpace(server)
	if trimmed == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(trimmed); err == nil {
		return trimmed
	}
	return net.JoinHostPort(strings.Trim(trimmed, "[]"), defaultDNSPort)
}
