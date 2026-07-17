// ProofKit fork: per-key traffic metering.
//
// The srv pairs each peer to one ring key (see muxconn pinning). This meter
// attributes per-stream byte counts (from the OnTraffic hook) to the paired
// key's stable id, and exposes the totals on a loopback /stats endpoint the
// agent polls. Only key ids (hex(sha256(key))[:16]) are ever exposed — never
// the key material.
package server

import (
	"encoding/json"
	"net/http"
	"sync"
)

// keyCounters holds one key's cumulative byte totals since srv start.
// up = client→internet, down = internet→client.
type keyCounters struct {
	up   uint64
	down uint64
}

// meter accumulates per-key traffic and maps sessions to their paired key.
// Safe for concurrent use: OnTraffic fires from many stream goroutines while
// the stats handler reads snapshots.
type meter struct {
	mu         sync.Mutex
	perKey     map[string]*keyCounters
	sessionKey map[string]string // sessionID -> keyID
}

func newMeter() *meter {
	return &meter{
		perKey:     make(map[string]*keyCounters),
		sessionKey: make(map[string]string),
	}
}

// bind records which key a session was paired to. keyID "" (legacy/unpaired)
// is ignored — such traffic stays uncounted rather than polluting a bucket.
func (m *meter) bind(sessionID, keyID string) {
	if keyID == "" || sessionID == "" {
		return
	}
	m.mu.Lock()
	m.sessionKey[sessionID] = keyID
	if _, ok := m.perKey[keyID]; !ok {
		m.perKey[keyID] = &keyCounters{}
	}
	m.mu.Unlock()
}

// add attributes a finished stream's byte counts to the session's key. A
// session with no bound key (unpaired legacy peer) is silently skipped.
func (m *meter) add(sessionID string, up, down uint64) {
	m.mu.Lock()
	keyID, ok := m.sessionKey[sessionID]
	if ok {
		c := m.perKey[keyID]
		if c == nil {
			c = &keyCounters{}
			m.perKey[keyID] = c
		}
		c.up += up
		c.down += down
	}
	m.mu.Unlock()
}

// statsDirection is one {up,down} pair in the /stats JSON.
type statsDirection struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

// statsResponse is the /stats body: per-key totals plus a grand total.
type statsResponse struct {
	Keys  map[string]statsDirection `json:"keys"`
	Total statsDirection            `json:"total"`
}

// snapshot copies the current counters for serialization.
func (m *meter) snapshot() statsResponse {
	m.mu.Lock()
	defer m.mu.Unlock()
	resp := statsResponse{Keys: make(map[string]statsDirection, len(m.perKey))}
	for keyID, c := range m.perKey {
		resp.Keys[keyID] = statsDirection{Up: c.up, Down: c.down}
		resp.Total.Up += c.up
		resp.Total.Down += c.down
	}
	return resp
}

// serveStats runs a minimal loopback HTTP server exposing GET /stats. It
// returns after ctx-independent listener setup; the caller owns shutdown by
// closing the returned server. Binds only the given (loopback) address.
func (m *meter) statsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m.snapshot())
	})
	return mux
}
