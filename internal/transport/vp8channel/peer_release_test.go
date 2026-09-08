package vp8channel

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// ai-generated: create real KCP pairs without an external media provider.
func releaseTestTransport(t *testing.T) *streamTransport {
	t.Helper()
	p := &streamTransport{
		stream: &fakeVideoStream{}, closeCh: make(chan struct{}),
		frameInterval: time.Hour, localEpoch: 1,
		peers: make(map[uint32]*kcpRuntime), peerOut: make(map[uint32]chan []byte),
		ctrlPeers: make(map[uint32]*peerControlKCP), controlOutbound: make(chan []byte, 4096),
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// ai-generated: retiring one peer must preserve real KCP delivery to its neighbor.
func TestRetirePeerPreservesNeighborAndRejectsLateFrames(t *testing.T) {
	p := releaseTestTransport(t)
	retired := p.getOrCreatePeerKCP(2)
	p.getOrCreatePeerControlKCP(2)
	live := p.getOrCreatePeerKCP(3)
	ctrl := p.getOrCreatePeerControlKCP(3)
	cleanup := p.RetirePeer(formatPeerID(2))
	cleanup()
	cleanup()
	select {
	case <-retired.conn.closed:
	default:
		t.Fatal("retired data KCP is still open")
	}
	for range 10 {
		p.handlePeerFrame(2, nil)
		p.handlePeerFrame(2, []byte("late data"))
		p.handleControlFrame(2|controlEpochFlag, 0, []byte("late control"))
	}
	if p.getOrCreatePeerKCP(2) != nil || p.getOrCreatePeerControlKCP(2) != nil {
		t.Fatal("late frame recreated a retired runtime")
	}
	if p.getOrCreatePeerKCP(3) != live || p.getOrCreatePeerControlKCP(3) != ctrl {
		t.Fatal("neighbor runtime was replaced")
	}
	assertReleaseNeighborTraffic(t, p, live)
}

// ai-generated: transfer an actual application message over the surviving KCP.
func assertReleaseNeighborTraffic(t *testing.T, p *streamTransport, live *kcpRuntime) {
	t.Helper()
	received := make(chan []byte, 1)
	out := make(chan []byte, 64)
	client, err := startKCP(out, func(b []byte) { received <- b }, testEpochHdr(3))
	if err != nil {
		t.Fatal(err)
	}
	defer client.abortPeer()
	stop := make(chan struct{})
	defer close(stop)
	go pumpPackets(stop, p.peerOut[3], client)
	go pumpPackets(stop, out, live)
	want := []byte("neighbor survives another session closing")
	if err := live.send(want); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if !bytes.Equal(got, want) {
			t.Fatal("neighbor payload changed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("neighbor traffic stalled")
	}
}

// ai-generated: a full queue must not deadlock retirement or whole-room shutdown.
func TestPeerRetirementUnblocksFullQueue(t *testing.T) {
	p := releaseTestTransport(t)
	rt := p.getOrCreatePeerKCP(2)
	for range cap(p.peerOut[2]) {
		p.peerOut[2] <- []byte{1}
	}
	wrote := make(chan struct{})
	go func() {
		_, _ = rt.conn.WriteTo([]byte("blocked"), fakeUDPAddr())
		close(wrote)
	}()
	finished := make(chan struct{})
	go func() {
		p.RetirePeer(formatPeerID(2))()
		_ = p.Close()
		close(finished)
	}()
	for _, done := range []<-chan struct{}{wrote, finished} {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("full outbound queue blocked peer shutdown")
		}
	}
}

// ai-generated: concurrent data/control creation cannot escape a retirement fence.
func TestPeerRetirementConcurrentCreation(t *testing.T) {
	p := releaseTestTransport(t)
	var work sync.WaitGroup
	for range 8 {
		work.Go(func() {
			for range 100 {
				p.getOrCreatePeerKCP(2)
				p.getOrCreatePeerControlKCP(2)
			}
		})
	}
	p.RetirePeer(formatPeerID(2))()
	work.Wait()
	if len(p.peers) != 0 || len(p.ctrlPeers) != 0 {
		t.Fatal("concurrent callback recreated a retired epoch")
	}
}

// ai-generated: a delayed cleanup must not close an epoch reused after eviction.
func TestRetirementFenceBoundedAndCleanupOwnsRuntime(t *testing.T) {
	p := releaseTestTransport(t)
	old := p.getOrCreatePeerKCP(2)
	cleanup := p.RetirePeer(formatPeerID(2))
	for epoch := uint32(3); epoch < retiredPeerLimit+3; epoch++ {
		p.RetirePeer(formatPeerID(epoch))()
	}
	if len(p.retiredPeers) != retiredPeerLimit || p.PeerRetired(formatPeerID(2)) {
		t.Fatal("retirement replay fence is not bounded")
	}
	// Model an epoch reused after the finite replay fence evicts it.
	p.peersMu.Lock()
	delete(p.peers, 2)
	delete(p.peerOut, 2)
	p.peersMu.Unlock()
	live := p.getOrCreatePeerKCP(2)
	cleanup()
	if p.peers[2] != live {
		t.Fatal("delayed cleanup removed a replacement runtime")
	}
	select {
	case <-old.conn.closed:
	default:
		t.Fatal("old runtime was not closed")
	}
	select {
	case <-live.conn.closed:
		t.Fatal("replacement runtime was closed")
	default:
	}
}

// ai-generated: expose the missing transport release contract on the baseline.
func TestRepeatedSessionReleaseBoundsKCPObjects(t *testing.T) {
	p := releaseTestTransport(t)
	for epoch := uint32(2); epoch < 102; epoch++ {
		p.getOrCreatePeerKCP(epoch)
		p.getOrCreatePeerControlKCP(epoch)
		if releaser, ok := any(p).(interface{ RetirePeer(peerID string) func() }); ok {
			releaser.RetirePeer(formatPeerID(epoch))()
		}
	}
	if len(p.peers) != 0 || len(p.ctrlPeers) != 0 || len(p.peerOut) != 0 {
		t.Fatalf("after 100 departures: data=%d control=%d writers=%d", len(p.peers), len(p.ctrlPeers), len(p.peerOut))
	}
}
