package protect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ErrDNSUnreachable reports that no configured DNS server could be reached.
var ErrDNSUnreachable = errors.New("no configured dns server could be reached")

const (
	defaultDNSPort    = "53"
	defaultDNSTimeout = 3 * time.Second
	// dnsQueryTimeout bounds how long one query waits for one server. Go gives
	// each exchange five seconds and then asks the same server again, so a
	// resolver a network has blackholed used to consume the whole lookup
	// budget in silence. Two seconds without an answer is already the answer,
	// and the ring moves on to the next server for the retry.
	dnsQueryTimeout = 2 * time.Second
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

// publicOperators is the fallback order when the configured resolver is one of
// the public operators above and stays silent: a carrier that blocks 1.1.1.1
// outright is not a carrier with no resolvers, only one where that address is
// dead. Each entry is an operator's IPv4 anycast and its IPv6 twin. The list is
// consulted only when the configured server is itself a public operator -
// someone who chose a private resolver chose where their queries go, and a
// fallback would hand them to a party they never picked.
var publicOperators = [][2]string{ //nolint:gochecknoglobals // static lookup table, no state
	{"1.1.1.1", "2606:4700:4700::1111"},
	{"8.8.8.8", "2001:4860:4860::8888"},
	{"9.9.9.9", "2620:fe::fe"},
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
	ring := &serverRing{servers: list}
	return &net.Resolver{
		PreferGo: true,
		Dial:     ring.dial,
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

// serverRing is the configured servers in preference order, with a cursor that
// moves past a server only once it has stayed silent on a query.
//
// It is not a rotation. While the configured server answers, every query goes
// to it - the AAAA beside the A, the second lookup after the first - because a
// fallback exists for failure, not for sharing every name with a second party.
type serverRing struct {
	servers   []string
	preferred atomic.Int32
}

// dial opens a query socket to the preferred server, or the next one that can
// be reached. Go's resolver passes the address from its own configuration and
// it is ignored: the servers here are the ones this process was told to use.
func (r *serverRing) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: defaultDNSTimeout, Control: controlFunc}
	count := len(r.servers)
	start := int(r.preferred.Load()) % count
	var firstErr error
	for i := range count {
		idx := (start + i) % count
		conn, err := dialer.DialContext(ctx, network, r.servers[idx])
		if err == nil {
			return wrapQuery(conn, r, idx), nil
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

// demote moves the cursor past a server that stayed silent - once. Two queries
// timing out on the same server together must not skip the one after it.
func (r *serverRing) demote(idx int) {
	r.preferred.CompareAndSwap(int32(idx), int32((idx+1)%len(r.servers)))
}

// queryConn gives the server a bounded time to answer each read, and tells the
// ring when it did not. Go's resolver sets its own, longer deadline on the
// socket; the shorter one here is what turns silence into the next server.
type queryConn struct {
	net.Conn
	ring *serverRing
	idx  int
}

func (c *queryConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(dnsQueryTimeout))
	n, err := c.Conn.Read(p)
	c.noteSilence(err)
	return n, err
}

func (c *queryConn) noteSilence(err error) {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		c.ring.demote(c.idx)
	}
}

// packetQueryConn keeps a UDP query socket a net.PacketConn: Go's resolver
// checks for that interface and would otherwise frame the query for a stream.
type packetQueryConn struct {
	*queryConn
	packet net.PacketConn
}

func (c *packetQueryConn) ReadFrom(p []byte) (int, net.Addr, error) {
	_ = c.packet.SetReadDeadline(time.Now().Add(dnsQueryTimeout))
	n, addr, err := c.packet.ReadFrom(p)
	c.noteSilence(err)
	return n, addr, err
}

func (c *packetQueryConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.packet.WriteTo(p, addr)
}

func wrapQuery(conn net.Conn, ring *serverRing, idx int) net.Conn {
	q := &queryConn{Conn: conn, ring: ring, idx: idx}
	if packet, ok := conn.(net.PacketConn); ok {
		return &packetQueryConn{queryConn: q, packet: packet}
	}
	return q
}

// expandDNSServers normalizes each server and appends the IPv6 address of every
// known IPv4 public resolver, dropping duplicates and keeping the given order.
func expandDNSServers(servers []string) []string {
	out := make([]string, 0, len(servers)*2)
	seen := make(map[string]struct{}, len(servers)*2)
	add := func(addr string) {
		if _, dup := seen[addr]; dup {
			return
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	publicPort := ""
	for _, server := range servers {
		for _, addr := range withIPv6Peer(server) {
			add(addr)
		}
		if host, port, err := net.SplitHostPort(normalizeDNSServer(server)); err == nil {
			if _, public := dnsIPv6Peer[host]; public && publicPort == "" {
				publicPort = port
			}
		}
	}
	// The other operators, in their fixed order, behind whatever was
	// configured - and only when what was configured is one of them.
	if publicPort != "" {
		for _, operator := range publicOperators {
			add(net.JoinHostPort(operator[0], publicPort))
			add(net.JoinHostPort(operator[1], publicPort))
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
