package server

import (
	"sync"
	"testing"
)

// ai-generated: reproduce a delayed teardown removing a replacement session.
func TestStalePeerTeardownPreservesReplacement(t *testing.T) {
	stale := &peerSession{peerID: "00000042"}
	live := &peerSession{peerID: stale.peerID}
	s := &Server{peerSessions: map[string]*peerSession{live.peerID: live}}
	s.removePeerSession(stale, "closed")
	if s.peerSessions[live.peerID] != live {
		t.Fatal("a stale session callback deleted its replacement")
	}
}

// ai-generated: record the two teardown phases without requiring a media provider.
type lifecycleStub struct {
	peerRoutingStub
	retired map[string]bool
	closed  int
}

// ai-generated: retirement runs under the server's session lock in these tests.
func (p *lifecycleStub) RetirePeer(peerID string) func() {
	p.retired[peerID] = true
	return sync.OnceFunc(func() { p.closed++ })
}

// ai-generated: reject a queued callback after its session has been removed.
func (p *lifecycleStub) PeerRetired(peerID string) bool {
	return p.retired[peerID]
}

// ai-generated: release exactly once, after closing the owning session.
func TestPeerSessionReleaseOrdering(t *testing.T) {
	ln := &lifecycleStub{retired: make(map[string]bool)}
	ps := &peerSession{peerID: "00000042"}
	s := &Server{ln: ln, peerLn: ln, peerSessions: map[string]*peerSession{ps.peerID: ps}}
	ps.controlStop = func() {
		if !ln.PeerRetired(ps.peerID) || ln.closed != 0 {
			t.Error("transport must be fenced but still available for final CLOSE")
		}
		if s.getPeerSession(ps.peerID) != nil || s.getOrCreatePeerControlSession(ps.peerID) != nil {
			t.Error("queued callback recreated a retired server session")
		}
	}
	s.removePeerSession(ps, "closed")
	s.removePeerSession(ps, "liveness")
	if ln.closed != 1 || len(s.peerSessions) != 0 {
		t.Fatalf("cleanup count=%d sessions=%d", ln.closed, len(s.peerSessions))
	}
}
