package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/client"
	"github.com/openlibrecommunity/olcrtc/internal/crypto"
	"github.com/openlibrecommunity/olcrtc/internal/server"
)

// mustEchoLocal drives one SOCKS echo round-trip against the in-memory echo
// server, failing the test on any error. Uses the shared connectViaSOCKS
// helper (tunnel_test.go).
func mustEchoLocal(_ context.Context, t *testing.T, socksAddr, echoAddr, tag string) {
	t.Helper()
	conn := connectViaSOCKS(t, socksAddr, echoAddr)
	defer func() { _ = conn.Close() }()
	payload := []byte("olcrtc-multikey-" + tag + "\n")
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("[%s] set deadline: %v", tag, err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("[%s] write: %v", tag, err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("[%s] read echo: %v", tag, err)
	}
	if !bytes.Equal(line, payload) {
		t.Fatalf("[%s] echo mismatch: got %q want %q", tag, line, payload)
	}
}

// altKeyHex is a second valid 32-byte key, distinct from testKeyHex, used to
// prove the srv pairs a client holding a NON-FIRST ring entry.
const altKeyHex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

// badKeyHex is a valid-format key that is NOT in the srv ring.
const badKeyHex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

func keyID(t *testing.T, keyHex string) string {
	t.Helper()
	id, err := crypto.KeyIDFromHex(keyHex)
	if err != nil {
		t.Fatalf("KeyIDFromHex: %v", err)
	}
	return id
}

func fetchStats(t *testing.T, addr string) server.StatsBody {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/stats", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /stats: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body server.StatsBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode /stats: %v", err)
	}
	return body
}

// TestMultiKeySecondRingKeyMetersFullStack proves — through the real
// smux + datachannel + memory-carrier stack — that a srv holding a two-key
// ring pairs a client presenting the SECOND key (trial-decrypt reaches
// entry 1) and attributes its traffic to that key's id on /stats. This is
// the end-to-end complement to the muxconn/meter unit tests.
func TestMultiKeySecondRingKeyMetersFullStack(t *testing.T) {
	if _, err := hex.DecodeString(altKeyHex); err != nil {
		t.Fatalf("bad altKeyHex: %v", err)
	}
	echoAddr := startEchoServer(t)
	carrierName, room := registerMemoryCarrier(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	statsAddr := freeLocalAddr(ctx, t)
	socksAddr := freeLocalAddr(ctx, t)
	const transportName = "datachannel"
	opts := e2eTransportOptions(transportName)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Run(ctx, server.Config{
			Transport:        transportName,
			TransportOptions: opts,
			Carrier:          carrierName,
			RoomURL:          testRoom,
			// Ring: the client's key (altKeyHex) is the SECOND entry, so a
			// correct pairing requires trial-decrypt past entry 0.
			Keys:        []string{testKeyHex, altKeyHex},
			StatsListen: statsAddr,
			DNSServer:   localDNSServer,
		})
	}()
	room.waitConnected(t, 1)

	ready := make(chan struct{})
	clientErr := make(chan error, 1)
	go func() {
		clientErr <- client.RunWithReady(ctx, client.Config{
			Transport:        transportName,
			TransportOptions: opts,
			Carrier:          carrierName,
			RoomURL:          testRoom,
			KeyHex:           altKeyHex,
			DeviceID:         "multikey-client",
			LocalAddr:        socksAddr,
			DNSServer:        localDNSServer,
		}, func() { close(ready) })
	}()
	waitForReadyWithin(t, ready, 30*time.Second)

	// Drive a known number of echo round-trips.
	const rounds = 4
	for i := 0; i < rounds; i++ {
		mustEchoLocal(ctx, t, socksAddr, echoAddr, "k2")
	}

	// The traffic hook fires once a stream's copy loops finish (on close),
	// so poll /stats until the paired key's bucket is populated.
	wantID := keyID(t, altKeyHex)
	otherID := keyID(t, testKeyHex)
	deadline := time.Now().Add(15 * time.Second)
	var stats server.StatsBody
	for time.Now().Before(deadline) {
		stats = fetchStats(t, statsAddr)
		if d, ok := stats.Keys[wantID]; ok && d.Up > 0 && d.Down > 0 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	d, ok := stats.Keys[wantID]
	if !ok || d.Up == 0 || d.Down == 0 {
		t.Fatalf("paired key %s not metered: stats=%+v", wantID, stats)
	}
	if _, leaked := stats.Keys[otherID]; leaked {
		t.Fatalf("unpaired ring key %s got a bucket: %+v", otherID, stats)
	}
	if stats.Total.Up < d.Up || stats.Total.Down < d.Down {
		t.Fatalf("total < per-key: %+v", stats)
	}
	t.Logf("metered second-ring-key %s: up=%d down=%d", wantID, d.Up, d.Down)
}

// TestMultiKeyUnknownKeyNeverPairsFullStack proves a client whose key is
// NOT in the srv ring never establishes a tunnel: its SOCKS listener never
// becomes ready and /stats records no traffic.
func TestMultiKeyUnknownKeyNeverPairsFullStack(t *testing.T) {
	_ = startEchoServer(t)
	carrierName, room := registerMemoryCarrier(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	statsAddr := freeLocalAddr(ctx, t)
	socksAddr := freeLocalAddr(ctx, t)
	const transportName = "datachannel"
	opts := e2eTransportOptions(transportName)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Run(ctx, server.Config{
			Transport:        transportName,
			TransportOptions: opts,
			Carrier:          carrierName,
			RoomURL:          testRoom,
			Keys:             []string{testKeyHex}, // ring does NOT contain badKeyHex
			StatsListen:      statsAddr,
			DNSServer:        localDNSServer,
		})
	}()
	room.waitConnected(t, 1)

	ready := make(chan struct{})
	clientErr := make(chan error, 1)
	go func() {
		clientErr <- client.RunWithReady(ctx, client.Config{
			Transport:        transportName,
			TransportOptions: opts,
			Carrier:          carrierName,
			RoomURL:          testRoom,
			KeyHex:           badKeyHex, // outsider key
			DeviceID:         "outsider-client",
			LocalAddr:        socksAddr,
			DNSServer:        localDNSServer,
		}, func() { close(ready) })
	}()

	// The outsider must NOT become ready: its frames never open under the
	// ring's only key, so the server never pins and the handshake never
	// completes. Give it a generous window to (fail to) connect.
	select {
	case <-ready:
		t.Fatal("outsider client with an out-of-ring key reached READY")
	case err := <-clientErr:
		t.Logf("outsider client exited without pairing (expected): %v", err)
	case <-time.After(8 * time.Second):
		// Also acceptable: still hung in handshake, never ready.
	}

	stats := fetchStats(t, statsAddr)
	if len(stats.Keys) != 0 || stats.Total.Up != 0 || stats.Total.Down != 0 {
		t.Fatalf("outsider traffic was metered: %+v", stats)
	}
}
