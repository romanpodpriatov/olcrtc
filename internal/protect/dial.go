package protect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ai-generated: whole file, part of the IPv6-only carrier-auth fix (#1).

// ErrNoAddresses reports that a host resolved to no usable address.
var ErrNoAddresses = errors.New("host resolved to no address")

const (
	// familyFallbackDelay is how long the second address family waits before
	// racing the first, matching the stdlib Happy Eyeballs delay.
	familyFallbackDelay = 300 * time.Millisecond
	// routeProbeTimeout bounds the source-address probe, which sends nothing.
	routeProbeTimeout = time.Second
)

// familyDialError reports the failure of every address family that was tried.
//
// The stdlib returns only the primary family's error, so a v6 leg that died on
// its own - a protector that cannot pin an IPv6 socket, say - vanishes and
// leaves an unrelated "network is unreachable" from the v4 leg as the whole
// account of the failure. That cost a day of looking at the wrong half.
type familyDialError struct {
	address string
	ipv6    error
	ipv4    error
}

func (e *familyDialError) Error() string {
	parts := make([]string, 0, 2)
	if e.ipv6 != nil {
		parts = append(parts, "ipv6: "+e.ipv6.Error())
	}
	if e.ipv4 != nil {
		parts = append(parts, "ipv4: "+e.ipv4.Error())
	}
	return "dial " + e.address + ": " + strings.Join(parts, "; ")
}

func (e *familyDialError) Unwrap() []error {
	errs := make([]error, 0, 2)
	if e.ipv6 != nil {
		errs = append(errs, e.ipv6)
	}
	if e.ipv4 != nil {
		errs = append(errs, e.ipv4)
	}
	return errs
}

// familyResult carries one family's outcome back to the racer.
type familyResult struct {
	conn  net.Conn
	err   error
	first bool
}

// dialDualStack resolves a host to both address families and tries both, so a
// destination reachable over only one of them still connects on a link that
// carries only the other.
func dialDualStack(ctx context.Context, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("split address: %w", err)
	}
	v6, v4, err := lookupFamilies(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(v6) == 0 {
		return dialAddrs(ctx, port, v4)
	}
	if len(v4) == 0 {
		return dialAddrs(ctx, port, v6)
	}
	return raceFamilies(ctx, address, port, v6, v4)
}

func raceFamilies(ctx context.Context, address, port string, v6, v4 []net.IP) (net.Conn, error) {
	first, second, firstIsV6 := orderFamilies(v6, v4)

	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan familyResult, 2)
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		conn, err := dialAddrs(dialCtx, port, first)
		results <- familyResult{conn: conn, err: err, first: true}
	}()
	go func() {
		timer := time.NewTimer(familyFallbackDelay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-firstDone:
		case <-dialCtx.Done():
		}
		conn, err := dialAddrs(dialCtx, port, second)
		results <- familyResult{conn: conn, err: err, first: false}
	}()

	return collectRace(results, address, firstIsV6)
}

func collectRace(results chan familyResult, address string, firstIsV6 bool) (net.Conn, error) {
	var firstErr, secondErr error
	for received := range 2 {
		res := <-results
		if res.err == nil {
			go closeLate(results, 1-received)
			return res.conn, nil
		}
		if res.first {
			firstErr = res.err
		} else {
			secondErr = res.err
		}
	}
	if firstIsV6 {
		return nil, &familyDialError{address: address, ipv6: firstErr, ipv4: secondErr}
	}
	return nil, &familyDialError{address: address, ipv6: secondErr, ipv4: firstErr}
}

// closeLate drains the losing racer so a connection that lands after a winner
// was picked does not leak a socket.
func closeLate(results chan familyResult, count int) {
	for range count {
		if res := <-results; res.conn != nil {
			_ = res.conn.Close()
		}
	}
}

// orderFamilies puts the family that has a usable source address first.
//
// The probe runs on a protected socket, so it sees the interface the dial will
// really leave through rather than the process default route. Inside a VPN
// extension those are different interfaces, and the stdlib's own RFC 6724 probe
// only ever sees the latter - which is how a dial ends up preferring an A
// record on a link whose physical interface has no IPv4 at all.
// It returns the family to try first, the family to fall back to, and whether
// the first one is IPv6.
func orderFamilies(v6, v4 []net.IP) ([]net.IP, []net.IP, bool) {
	if !hasRoute(v6[0]) && hasRoute(v4[0]) {
		return v4, v6, false
	}
	return v6, v4, true
}

// hasRoute reports whether a protected socket can pick a source address for ip.
// Connecting a UDP socket assigns a route without sending anything.
func hasRoute(ip net.IP) bool {
	dialer := net.Dialer{Timeout: routeProbeTimeout, Control: controlFunc}
	conn, err := dialer.Dial("udp", net.JoinHostPort(ip.String(), defaultDNSPort))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func dialAddrs(ctx context.Context, port string, ips []net.IP) (net.Conn, error) {
	dialer := NewDialer()
	var firstErr error
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
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
		return nil, ErrNoAddresses
	}
	return nil, firstErr
}

// lookupError is what a lookup nobody answered says: which resolver was asked
// and what each one said. "8.8.8.8 timed out" and "the carrier's resolver knows
// no such host" look the same in a log and mean different things (olcbox#16).
type lookupError struct {
	host       string
	configured error
	system     error
}

func (e *lookupError) Error() string {
	parts := make([]string, 0, 2)
	if e.configured != nil {
		parts = append(parts, "configured servers: "+e.configured.Error())
	}
	if e.system != nil {
		parts = append(parts, "host resolver: "+e.system.Error())
	}
	return "lookup " + e.host + ": " + strings.Join(parts, "; ")
}

func (e *lookupError) Unwrap() []error {
	errs := make([]error, 0, 2)
	if e.configured != nil {
		errs = append(errs, e.configured)
	}
	if e.system != nil {
		errs = append(errs, e.system)
	}
	return errs
}

// lookupFamilies resolves both address families and returns the IPv6
// addresses, the IPv4 addresses, and an error only when nothing answered.
//
// The configured servers are asked first and on a budget; if they produce no
// address at all the host's own resolver is asked, on a budget of its own. See
// [systemResolver] for why that order and not the other - and [serverRing] for
// the exception: servers that have just proven dark are asked last, since
// paying their silence again on every lookup buys nothing.
func lookupFamilies(ctx context.Context, host string) ([]net.IP, []net.IP, error) {
	configured := activeResolver()
	fallback := systemResolver
	if fallback == configured {
		fallback = nil
	}
	dark := false
	if ring := configuredRing(); ring != nil && fallback != nil {
		dark = ring.dark(ringNow())
	}

	var configuredErr, systemErr error
	if !dark {
		v6, v4, err := lookupBounded(ctx, configured, host, configuredLookupBudget)
		if len(v6) > 0 || len(v4) > 0 {
			return v6, v4, nil
		}
		if fallback == nil {
			return nil, nil, err
		}
		configuredErr = err
	}
	v6, v4, err := lookupBounded(ctx, fallback, host, systemLookupBudget)
	if len(v6) > 0 || len(v4) > 0 {
		return v6, v4, nil
	}
	systemErr = err
	if dark {
		// The host's resolver had nothing either, so the configured servers
		// get their turn after all, on the usual budget.
		v6, v4, err = lookupBounded(ctx, configured, host, configuredLookupBudget)
		if len(v6) > 0 || len(v4) > 0 {
			return v6, v4, nil
		}
		configuredErr = err
	}
	return nil, nil, &lookupError{host: host, configured: configuredErr, system: systemErr}
}

// lookupBounded is lookupBoth on a budget of its own within ctx.
func lookupBounded(
	ctx context.Context, r *net.Resolver, host string, budget time.Duration,
) ([]net.IP, []net.IP, error) {
	bounded, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	return lookupBoth(bounded, r, host)
}

// lookupBoth resolves both address families through one resolver, concurrently.
func lookupBoth(ctx context.Context, r *net.Resolver, host string) ([]net.IP, []net.IP, error) {
	type answer struct {
		ips []net.IP
		err error
	}
	ch6, ch4 := make(chan answer, 1), make(chan answer, 1)
	go func() {
		ips, lookupErr := lookupFamily(ctx, r, "ip6", host)
		ch6 <- answer{ips: ips, err: lookupErr}
	}()
	go func() {
		ips, lookupErr := lookupFamily(ctx, r, "ip4", host)
		ch4 <- answer{ips: ips, err: lookupErr}
	}()
	got6, got4 := <-ch6, <-ch4

	if len(got6.ips) == 0 && len(got4.ips) == 0 {
		return nil, nil, firstNonNil(got6.err, got4.err)
	}
	return got6.ips, got4.ips, nil
}

// lookupFamily resolves one address family on its own.
//
// Asking per family rather than for "ip" is what keeps one family's failure off
// the other: the combined lookup returns whichever family answered as if it
// were the whole answer, so the caller cannot tell a host that has no AAAA from
// one whose AAAA query failed, and either way is handed a list with nothing to
// fall back to.
func lookupFamily(ctx context.Context, r *net.Resolver, network, host string) ([]net.IP, error) {
	ips, err := r.LookupIP(ctx, network, host)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", network, err)
	}
	return ips, nil
}

func firstNonNil(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return ErrNoAddresses
}

// resolveAddress resolves "host:port" to "ip:port" for one dial, through the
// configured servers and the host's resolver like every other name here.
func resolveAddress(ctx context.Context, network, address string) (string, error) {
	ip, port, zone, err := resolveHostPort(ctx, network, address)
	if err != nil {
		return "", err
	}
	host := ip.String()
	if zone != "" {
		host += "%" + zone
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// resolveHostPort resolves "host:port" to the one address the network wants:
// the family a "udp4" or "tcp6" names, else the family with a route out. A
// literal is returned as it is, zone included.
func resolveHostPort(ctx context.Context, network, address string) (net.IP, int, string, error) {
	host, portName, err := net.SplitHostPort(address)
	if err != nil {
		return nil, 0, "", fmt.Errorf("split address: %w", err)
	}
	port, err := net.DefaultResolver.LookupPort(ctx, network, portName)
	if err != nil {
		return nil, 0, "", fmt.Errorf("port %q: %w", portName, err)
	}
	ip, zone, err := resolveHost(ctx, network, host)
	if err != nil {
		return nil, 0, "", err
	}
	return ip, port, zone, nil
}

// resolveHost resolves a bare host the same way, for the pion lookups that
// carry no port.
func resolveHost(ctx context.Context, network, host string) (net.IP, string, error) {
	zone := ""
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host, zone = host[:i], host[i+1:]
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip, zone, nil
	}
	v6, v4, err := lookupFamilies(ctx, host)
	if err != nil {
		return nil, "", err
	}
	ip, err := pickAddress(network, v6, v4)
	if err != nil {
		return nil, "", fmt.Errorf("resolve %s: %w", host, err)
	}
	return ip, "", nil
}

// pickAddress chooses one address for a network that takes one: the family the
// network names, else the family that has a route out, as the dialers order
// them.
func pickAddress(network string, v6, v4 []net.IP) (net.IP, error) {
	switch {
	case strings.HasSuffix(network, "4"):
		if len(v4) == 0 {
			return nil, fmt.Errorf("%w: no IPv4 address for %s", ErrNoAddresses, network)
		}
		return v4[0], nil
	case strings.HasSuffix(network, "6"):
		if len(v6) == 0 {
			return nil, fmt.Errorf("%w: no IPv6 address for %s", ErrNoAddresses, network)
		}
		return v6[0], nil
	case len(v6) == 0:
		return v4[0], nil
	case len(v4) == 0:
		return v6[0], nil
	}
	first, _, _ := orderFamilies(v6, v4)
	return first[0], nil
}
