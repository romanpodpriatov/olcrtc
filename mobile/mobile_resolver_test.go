package mobile

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/client"
	"github.com/openlibrecommunity/olcrtc/internal/fakedns"
	"github.com/openlibrecommunity/olcrtc/internal/protect"
)

// SetDNS used to reach the client config and nothing else: the resolver the
// protected dialers use was never told, so on a phone every carrier lookup
// went to the system resolver. Inside an iOS packet tunnel that resolver is the
// tunnel's own, unserved until the cores are up - so a name not already in the
// phone's DNS cache could not be resolved at all (olcbox#13).
func TestStartInstallsTheConfiguredResolverForProtectedDials(t *testing.T) {
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

	original := runClientWithReady
	t.Cleanup(func() {
		Stop()
		runClientWithReady = original
		SetDNS(defaultDNSServer)
		protect.SetDNSServers()
	})

	_, port, _ := net.SplitHostPort(carrier.Addr().String())
	dialed := make(chan error, 1)
	runClientWithReady = func(ctx context.Context, _ client.Config, _ func()) error {
		// What the client does first: dial the carrier by name.
		conn, dialErr := protect.DialContext(ctx, "tcp", net.JoinHostPort("carrier.test", port))
		if dialErr == nil {
			_ = conn.Close()
		}
		dialed <- dialErr
		return nil
	}

	SetDNS(dns.Addr)
	if err := Start("telemost", "https://telemost.example/j/1", "device", "00", 10808, "", ""); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	select {
	case dialErr := <-dialed:
		if dialErr != nil {
			t.Fatalf("carrier dial after Start = %v, want it resolved through %s", dialErr, dns.Addr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the client never dialed")
	}
}
