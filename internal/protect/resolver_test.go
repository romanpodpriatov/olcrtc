package protect

import (
	"net"
	"slices"
	"testing"
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
			want: []string{cloudflareV4, "[2606:4700:4700::1111]:53"},
		},
		{
			name: "bare address gets the default port",
			in:   []string{"8.8.8.8"},
			want: []string{"8.8.8.8:53", "[2001:4860:4860::8888]:53"},
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
			want: []string{cloudflareV4, "[2606:4700:4700::1111]:53", "9.9.9.9:53", "[2620:fe::fe]:53"},
		},
		{
			name: "blank entries are dropped",
			in:   []string{"", "   ", "1.0.0.1:53"},
			want: []string{"1.0.0.1:53", "[2606:4700:4700::1001]:53"},
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
