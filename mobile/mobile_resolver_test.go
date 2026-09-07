package mobile

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
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

// The Jitsi carrier's signalling goes through a library that dials with
// http.DefaultClient and offers no way to hand it a dialer, so on a phone
// those sockets were neither protected nor resolved through the configured
// server: an XMPP host not in the carrier's DNS came back "no such host",
// and on iOS a reconnect from inside the running tunnel had nowhere to go
// but the tunnel itself. Start now points the default transport at the
// protected dialer, which carries both.
func TestStartRoutesTheDefaultHTTPTransportThroughTheProtectedDialer(t *testing.T) {
	carrier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer carrier.Close()
	dns, err := fakedns.Start(map[string]string{"carrier.test": "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dns.Close() }()

	original := runClientWithReady
	originalTransport := http.DefaultTransport
	t.Cleanup(func() {
		Stop()
		runClientWithReady = original
		http.DefaultTransport = originalTransport
		SetDNS(defaultDNSServer)
		protect.SetDNSServers()
	})

	_, port, _ := net.SplitHostPort(carrier.Listener.Addr().String())
	fetched := make(chan error, 1)
	runClientWithReady = func(ctx context.Context, _ client.Config, _ func()) error {
		// What the Jitsi library does first: an HTTP request with the default client.
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://carrier.test:"+port+"/config.js", nil)
		resp, getErr := http.DefaultClient.Do(req)
		if getErr == nil {
			_ = resp.Body.Close()
		}
		fetched <- getErr
		return nil
	}

	SetDNS(dns.Addr)
	if err := Start("jitsi", "olcrtc-room", "device", "00", 10808, "", ""); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	select {
	case getErr := <-fetched:
		if getErr != nil {
			t.Fatalf("default-client request after Start = %v, want it resolved through %s", getErr, dns.Addr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the client never made its request")
	}
}
