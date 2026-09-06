package protect

import (
	"net"
	"testing"

	"github.com/openlibrecommunity/olcrtc/internal/fakedns"
)

// The pion dialers used to be plain net.Dialers with a Control hook and nothing
// else, so their name lookups went to the system resolver. Inside an iOS packet
// tunnel that resolver is the tunnel's own, which nothing is serving yet when
// the carrier is being dialed - a self-hosted Jitsi host, never in the phone's
// DNS cache, failed with "lookup meet.example: no such host" (olcbox#13).
func TestProtectedNetDialResolvesThroughTheConfiguredServer(t *testing.T) {
	carrier, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = carrier.Close() }()
	go func() {
		for {
			c, acceptErr := carrier.Accept()
			if acceptErr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	dns, err := fakedns.Start(map[string]string{"carrier.test": "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dns.Close() }()
	SetDNSServers(dns.Addr)
	t.Cleanup(func() { SetDNSServers() })

	pnet, err := NewProtectedNet()
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(carrier.Addr().String())
	conn, err := pnet.Dial("tcp", net.JoinHostPort("carrier.test", port))
	if err != nil {
		t.Fatalf("Dial() = %v, want a connection resolved through %s", err, dns.Addr)
	}
	_ = conn.Close()
}
