package protect

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/fakedns"
)

// ai-generated: whole file, unit cover for the DNS server list built by the
// IPv6-only carrier-auth fix (#1).

// cloudflareV4 is the literal every iOS build is configured with.
const cloudflareV4 = "1.1.1.1:53"

func TestExpandDNSServersAddsTheOperatorsIPv6Address(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			// The iOS client configures exactly this, and on a link without
			// IPv4 it is unreachable on its own.
			name: "cloudflare ipv4 literal gains its ipv6 address",
			in:   []string{cloudflareV4},
			want: []string{
				cloudflareV4, "[2606:4700:4700::1111]:53",
				"8.8.8.8:53", "[2001:4860:4860::8888]:53",
				"9.9.9.9:53", "[2620:fe::fe]:53",
			},
		},
		{
			name: "bare address gets the default port",
			in:   []string{"8.8.8.8"},
			want: []string{
				"8.8.8.8:53", "[2001:4860:4860::8888]:53",
				"1.1.1.1:53", "[2606:4700:4700::1111]:53",
				"9.9.9.9:53", "[2620:fe::fe]:53",
			},
		},
		{
			name: "ipv6 literal is bracketed and left alone",
			in:   []string{"2620:fe::fe"},
			want: []string{"[2620:fe::fe]:53"},
		},
		{
			name: "unknown resolver keeps whatever was configured",
			in:   []string{"resolver.example:5353"},
			want: []string{"resolver.example:5353"},
		},
		{
			name: "duplicates collapse and order is kept",
			in:   []string{"1.1.1.1", cloudflareV4, "9.9.9.9"},
			want: []string{
				cloudflareV4, "[2606:4700:4700::1111]:53", "9.9.9.9:53", "[2620:fe::fe]:53",
				"8.8.8.8:53", "[2001:4860:4860::8888]:53",
			},
		},
		{
			name: "blank entries are dropped",
			in:   []string{"", "   ", "1.0.0.1:53"},
			want: []string{
				"1.0.0.1:53", "[2606:4700:4700::1001]:53",
				"1.1.1.1:53", "[2606:4700:4700::1111]:53",
				"8.8.8.8:53", "[2001:4860:4860::8888]:53",
				"9.9.9.9:53", "[2620:fe::fe]:53",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := expandDNSServers(tc.in)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("expandDNSServers(%q) = %q, want %q", tc.in, got, tc.want)
			}
			for _, addr := range got {
				if _, _, err := net.SplitHostPort(addr); err != nil {
					t.Fatalf("%q is not dialable: %v", addr, err)
				}
			}
		})
	}
}

func TestNewResolverWithoutServersUsesTheSystemResolver(t *testing.T) {
	if got := NewResolver(); got != net.DefaultResolver {
		t.Fatalf("NewResolver() = %p, want the system resolver %p", got, net.DefaultResolver)
	}
	if got := NewResolver("", "  "); got != net.DefaultResolver {
		t.Fatalf("NewResolver(blank) = %p, want the system resolver %p", got, net.DefaultResolver)
	}
}

func TestSetDNSServersResetsToTheSystemResolver(t *testing.T) {
	t.Cleanup(func() { SetDNSServers() })

	SetDNSServers(cloudflareV4)
	if activeResolver() == net.DefaultResolver {
		t.Fatal("configured servers were ignored")
	}
	SetDNSServers()
	if activeResolver() != net.DefaultResolver {
		t.Fatal("clearing the servers did not restore the system resolver")
	}
}

// A resolver that a carrier has blackholed is routable: the UDP connect that
// picks a server "succeeds" against it every time, so the ring never moved on
// and every attempt Go made went to the same silence. The next server is asked
// once the first has had a bounded time to answer and has not.
func TestResolverMovesOnWhenTheConfiguredServerIsSilent(t *testing.T) {
	silent, err := fakedns.StartSilent()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()
	answering, err := fakedns.Start(map[string]string{"carrier.test": "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = answering.Close() }()

	r := NewResolver(silent.Addr, answering.Addr)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	started := time.Now()
	ips, err := r.LookupIP(ctx, "ip4", "carrier.test")
	if err != nil {
		t.Fatalf("LookupIP() = %v after %v, want the answer from the second server", err, time.Since(started))
	}
	if len(ips) != 1 || ips[0].String() != "192.0.2.10" {
		t.Fatalf("LookupIP() = %v, want [192.0.2.10]", ips)
	}
	if silent.Queries() == 0 {
		t.Fatal("the configured server was never asked; it must come first")
	}
	if elapsed := time.Since(started); elapsed > 6*time.Second {
		t.Fatalf("took %v; a silent server should cost about one query timeout, not Go's whole retry budget", elapsed)
	}
}

// The other side of moving on: while the configured server answers, nobody
// else is asked - not for AAAA beside A, not on the second lookup. Fallback
// is for failure, not a rotation that shares every name with a second party.
func TestResolverStaysWithTheConfiguredServerWhileItAnswers(t *testing.T) {
	first, err := fakedns.Start(map[string]string{"carrier.test": "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	second, err := fakedns.Start(map[string]string{"carrier.test": "192.0.2.20"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()

	r := NewResolver(first.Addr, second.Addr)
	for range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := r.LookupIPAddr(ctx, "carrier.test")
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if len(ips) != 1 || ips[0].IP.String() != "192.0.2.10" {
			t.Fatalf("LookupIPAddr() = %v, want the first server's answer", ips)
		}
	}
	if n := second.Queries(); n != 0 {
		t.Fatalf("second server was asked %d times while the first answered", n)
	}
}

// A public resolver that a network blocks needs another public resolver behind
// it, so the operators the engine already knows are appended - in a fixed
// order, each with its IPv6 twin. A private resolver gets none of them: whoever
// configured it chose where their queries go.
func TestExpandDNSServersAppendsTheOtherPublicOperators(t *testing.T) {
	cases := map[string]struct {
		in   []string
		want []string
	}{
		"cloudflare first": {
			in: []string{"1.1.1.1:53"},
			want: []string{
				"1.1.1.1:53", "[2606:4700:4700::1111]:53",
				"8.8.8.8:53", "[2001:4860:4860::8888]:53",
				"9.9.9.9:53", "[2620:fe::fe]:53",
			},
		},
		"google first": {
			in: []string{"8.8.8.8:53"},
			want: []string{
				"8.8.8.8:53", "[2001:4860:4860::8888]:53",
				"1.1.1.1:53", "[2606:4700:4700::1111]:53",
				"9.9.9.9:53", "[2620:fe::fe]:53",
			},
		},
		"a private resolver stays alone": {
			in:   []string{"10.0.0.1:53"},
			want: []string{"10.0.0.1:53"},
		},
		"the platform's list stays ahead of the operators": {
			in: []string{"10.0.0.1:53, fe80::1%pdp_ip0 1.1.1.1:53"},
			want: []string{
				"10.0.0.1:53", "[fe80::1%pdp_ip0]:53",
				"1.1.1.1:53", "[2606:4700:4700::1111]:53",
				"8.8.8.8:53", "[2001:4860:4860::8888]:53",
				"9.9.9.9:53", "[2620:fe::fe]:53",
			},
		},
	}
	for name, tc := range cases {
		got := expandDNSServers(tc.in)
		if strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("%s: expandDNSServers(%v)\n got  %v\n want %v", name, tc.in, got, tc.want)
		}
	}
}

// The host's own resolver is the last resort, and it has to be, because the
// configured one is a public operator and some networks blackhole every public
// operator there is. Answering nothing then is worse than asking the carrier:
// before olcRTC resolved names itself the carrier's resolver was all there was,
// and on the networks that permit it, it works (olcbox#15).
func TestResolverFallsBackToTheSystemWhenNoConfiguredServerAnswers(t *testing.T) {
	silent, err := fakedns.StartSilent()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()
	system, err := fakedns.Start(map[string]string{"carrier.test": "192.0.2.30"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = system.Close() }()

	SetDNSServers(silent.Addr)
	swapSystemResolver(t, NewResolver(system.Addr))
	t.Cleanup(func() { SetDNSServers() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	started := time.Now()
	v6, v4, err := lookupFamilies(ctx, "carrier.test")
	if err != nil {
		t.Fatalf("lookupFamilies() = %v after %v, want the system resolver's answer", err, time.Since(started))
	}
	if len(v4) != 1 || v4[0].String() != "192.0.2.30" {
		t.Fatalf("lookupFamilies() v4 = %v (v6 %v), want [192.0.2.30]", v4, v6)
	}
	if silent.Queries() == 0 {
		t.Fatal("the configured server was never asked; it must come first")
	}
}

// And the configured server keeps its priority: while it answers, the host's
// resolver is never consulted, because the whole point of resolving names
// ourselves is not to ask a carrier that may lie about them.
func TestConfiguredServerIsPreferredOverTheSystemResolver(t *testing.T) {
	configured, err := fakedns.Start(map[string]string{"carrier.test": "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = configured.Close() }()
	system, err := fakedns.Start(map[string]string{"carrier.test": "192.0.2.30"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = system.Close() }()

	SetDNSServers(configured.Addr)
	swapSystemResolver(t, NewResolver(system.Addr))
	t.Cleanup(func() { SetDNSServers() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, v4, err := lookupFamilies(ctx, "carrier.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(v4) != 1 || v4[0].String() != "192.0.2.10" {
		t.Fatalf("lookupFamilies() v4 = %v, want the configured server's [192.0.2.10]", v4)
	}
	if n := system.Queries(); n != 0 {
		t.Fatalf("the host's resolver was asked %d times while the configured one answered", n)
	}
}

func swapSystemResolver(t *testing.T, r *net.Resolver) {
	t.Helper()
	previous := systemResolver
	systemResolver = r
	t.Cleanup(func() { systemResolver = previous })
}

// A carrier that blackholes every public operator does not change its mind
// between one lookup and the next, so paying the configured servers' silence
// on every lookup is paying for what is already known - and a tunnel start
// makes several lookups in a row, each of which used to cost the whole
// budget. The first lookup learns it; the ones that follow go to the host's
// resolver at once (olcbox#16).
func TestLookupSkipsTheConfiguredServersWhileTheyAllStaySilent(t *testing.T) {
	silent, err := fakedns.StartSilent()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()
	system, err := fakedns.Start(map[string]string{"carrier.test": "192.0.2.30"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = system.Close() }()

	SetDNSServers(silent.Addr)
	swapSystemResolver(t, NewResolver(system.Addr))
	t.Cleanup(func() { SetDNSServers() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, _, err := lookupFamilies(ctx, "carrier.test"); err != nil {
		t.Fatalf("first lookupFamilies() = %v, want the host's answer", err)
	}
	asked := silent.Queries()
	if asked == 0 {
		t.Fatal("the configured server was never asked on the first lookup; it must come first")
	}

	started := time.Now()
	_, v4, err := lookupFamilies(ctx, "carrier.test")
	if err != nil {
		t.Fatalf("second lookupFamilies() = %v, want the host's answer", err)
	}
	if len(v4) != 1 || v4[0].String() != "192.0.2.30" {
		t.Fatalf("second lookupFamilies() v4 = %v, want [192.0.2.30]", v4)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("second lookup took %v; the configured servers' silence was already known", elapsed)
	}
	if n := silent.Queries(); n != asked {
		t.Fatalf("the silent server was asked %d more times on the second lookup", n-asked)
	}
}

// When the host's resolver fails as well, the error used to name only the
// configured servers' timeout, so a log read as "8.8.8.8 is blocked" when the
// carrier's own resolver had refused the name too - the two look the same and
// mean different things. Both halves are named.
func TestLookupErrorNamesBothResolvers(t *testing.T) {
	silent, err := fakedns.StartSilent()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()
	// Answers, but knows no names: the "no such host" a filtering resolver gives.
	system, err := fakedns.Start(map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = system.Close() }()

	SetDNSServers(silent.Addr)
	swapSystemResolver(t, NewResolver(system.Addr))
	t.Cleanup(func() { SetDNSServers() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, _, err = lookupFamilies(ctx, "carrier.test")
	if err == nil {
		t.Fatal("lookupFamilies() succeeded with nobody knowing the name")
	}
	msg := err.Error()
	for _, want := range []string{"configured", "i/o timeout", "host", "no such host"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}
}

func TestSplitDNSServersAcceptsWhatPlatformsHandOver(t *testing.T) {
	got := SplitDNSServers(" 10.0.0.1:53, fe80::1%pdp_ip0 ;1.1.1.1 ")
	want := []string{"10.0.0.1:53", "fe80::1%pdp_ip0", "1.1.1.1"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("SplitDNSServers() = %q, want %q", got, want)
	}
	if got := SplitDNSServers(" , ; "); len(got) != 0 {
		t.Fatalf("SplitDNSServers() of separators alone = %q, want nothing", got)
	}
}

// Dark is not forever: a network that blocked every public operator may stop,
// and a phone moves between networks under a running tunnel. Once the window
// has passed the configured servers are asked first again.
func TestLookupAsksTheConfiguredServersAgainAfterTheDarkWindow(t *testing.T) {
	silent, err := fakedns.StartSilent()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()
	system, err := fakedns.Start(map[string]string{"carrier.test": "192.0.2.30"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = system.Close() }()

	SetDNSServers(silent.Addr)
	swapSystemResolver(t, NewResolver(system.Addr))
	t.Cleanup(func() { SetDNSServers() })
	// The ring's clock, held still: the window is measured on it, not on
	// how long the machine took to run the lookups.
	now := time.Now()
	ringNow = func() time.Time { return now }
	t.Cleanup(func() { ringNow = time.Now })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, _, err := lookupFamilies(ctx, "carrier.test"); err != nil {
		t.Fatalf("first lookupFamilies() = %v", err)
	}
	asked := silent.Queries()
	if _, _, err := lookupFamilies(ctx, "carrier.test"); err != nil {
		t.Fatalf("second lookupFamilies() = %v", err)
	}
	if n := silent.Queries(); n != asked {
		t.Fatalf("the dark servers were asked %d times within the window", n-asked)
	}

	now = now.Add(ringDarkWindow + time.Second)
	_, v4, err := lookupFamilies(ctx, "carrier.test")
	if err != nil {
		t.Fatalf("lookupFamilies() after the window = %v", err)
	}
	if len(v4) != 1 || v4[0].String() != "192.0.2.30" {
		t.Fatalf("lookupFamilies() after the window v4 = %v, want the host's [192.0.2.30]", v4)
	}
	if n := silent.Queries(); n == asked {
		t.Fatal("the configured servers were not asked again after the window")
	}
}
