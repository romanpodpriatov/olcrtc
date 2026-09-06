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
	}
	for name, tc := range cases {
		got := expandDNSServers(tc.in)
		if strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("%s: expandDNSServers(%v)\n got  %v\n want %v", name, tc.in, got, tc.want)
		}
	}
}
