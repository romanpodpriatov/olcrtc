package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/crypto"
	"github.com/openlibrecommunity/olcrtc/internal/server"
)

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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/stats", http.NoBody)
	if err != nil {
		t.Fatalf("build /stats request: %v", err)
	}
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

// TestMultiKeySecondRingKeyMetersFullStack proves, through the real smux and
// datachannel stack over the memory provider, that a server holding a two-key
// ring pairs a client presenting the second key and attributes its traffic to
// that key's id on /stats, and to nothing else.
func TestMultiKeySecondRingKeyMetersFullStack(t *testing.T) {
	echoAddr := startEchoServer(t)
	tunnel := startRingTunnel(t, []string{testKeyHex, altKeyHex}, altKeyHex, true, 30*time.Second)
	if !tunnel.ready {
		t.Fatal("client holding the second ring key never became ready")
	}
	sent := 0
	for range 4 {
		sent += echoOnce(t, tunnel.socksAddr, echoAddr, "olcrtc-metered")
	}

	// The meter counts a stream once its copy loops finish, so poll.
	wantID := keyID(t, altKeyHex)
	otherID := keyID(t, testKeyHex)
	deadline := time.Now().Add(15 * time.Second)
	var stats server.StatsBody
	for time.Now().Before(deadline) {
		stats = fetchStats(t, tunnel.statsAddr)
		if d := stats.Keys[wantID]; d.Up >= uint64(sent) && d.Down >= uint64(sent) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	d := stats.Keys[wantID]
	if d.Up < uint64(sent) || d.Down < uint64(sent) {
		t.Fatalf("paired key %s metered %+v, want at least %d each way: %+v", wantID, d, sent, stats)
	}
	if leaked, ok := stats.Keys[otherID]; ok && (leaked.Up > 0 || leaked.Down > 0) {
		t.Fatalf("unpaired ring key %s got traffic: %+v", otherID, stats)
	}
	if stats.Total.Up < d.Up || stats.Total.Down < d.Down {
		t.Fatalf("total below the per-key count: %+v", stats)
	}
}
