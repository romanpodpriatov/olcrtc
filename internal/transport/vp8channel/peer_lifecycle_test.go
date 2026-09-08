// Package vp8channel provides byte transport over VP8 video frames using KCP.
package vp8channel

import (
	"sync"
	"testing"
	"time"
)

// ai-generated: isolated server transport with no external carrier or credentials.
func newLifecycleTransport(tb testing.TB) *streamTransport {
	tb.Helper()
	p := &streamTransport{
		stream:          &fakeVideoStream{canSend: true},
		onPeerData:      func(string, []byte) {},
		closeCh:         make(chan struct{}),
		controlOutbound: make(chan []byte, controlOutboundQueueSize),
		peers:           make(map[uint32]*kcpRuntime),
		peerOut:         make(map[uint32]chan []byte),
		ctrlPeers:       make(map[uint32]*peerControlKCP),
		frameInterval:   time.Hour,
		batchSize:       1,
	}
	tb.Cleanup(func() {
		if err := p.Close(); err != nil {
			tb.Errorf("close transport: %v", err)
		}
	})
	return p
}

// ai-generated: assert that expiry stops KCP readers, not just map accounting.
func requireRuntimeClosed(t *testing.T, rt *kcpRuntime) {
	t.Helper()
	select {
	case <-rt.readDone:
	case <-time.After(time.Second):
		t.Fatal("expired KCP reader is still running")
	}
}

// ai-generated: expire both paths, including a peer that never sent bulk data.
func TestIdlePeerExpiryPreservesActivePeer(t *testing.T) {
	p := newLifecycleTransport(t)
	data := p.getOrCreatePeerKCP(1)
	control := p.getOrCreatePeerControlKCP(1, true)
	onlyControl := p.getOrCreatePeerControlKCP(2, true)
	active := p.getOrCreatePeerKCP(3)
	activeControl := p.getOrCreatePeerControlKCP(3, true)
	now := time.Now()
	p.peersMu.Lock()
	p.peerActivity[1] = now.Add(-peerIdleTimeout)
	p.peerActivity[2] = now.Add(-peerIdleTimeout)
	p.peersMu.Unlock()
	// A local retry must not extend the lease of an absent client.
	if p.getOrCreatePeerControlKCP(1, false) != control {
		t.Fatal("outbound lookup replaced the live control runtime")
	}
	p.expireIdlePeers(now)
	if len(p.peers) != 1 || len(p.ctrlPeers) != 1 || len(p.peerOut) != 1 || len(p.peerActivity) != 1 {
		t.Fatal("expiry retained stale peer resources or removed the active peer")
	}
	if p.peers[3] != active || p.ctrlPeers[3] != activeControl {
		t.Fatal("expiry replaced an active peer")
	}
	requireRuntimeClosed(t, data)
	requireRuntimeClosed(t, control.kcp)
	requireRuntimeClosed(t, onlyControl.kcp)
}

// ai-generated: repeated reconnect epochs must return to an empty resource set.
func TestRepeatedPeerEpochsAreReclaimed(t *testing.T) {
	p := newLifecycleTransport(t)
	for epoch := uint32(1); epoch <= 100; epoch++ {
		data := p.getOrCreatePeerKCP(epoch)
		control := p.getOrCreatePeerControlKCP(epoch, true)
		p.expireIdlePeers(time.Now().Add(peerIdleTimeout))
		requireRuntimeClosed(t, data)
		requireRuntimeClosed(t, control.kcp)
		if len(p.peers)+len(p.ctrlPeers)+len(p.peerOut)+len(p.peerActivity) != 0 {
			t.Fatalf("resources retained after epoch %d", epoch)
		}
	}
}

// ai-generated: keep an idle-but-connected peer when only control frames arrive.
func TestInboundControlRenewsPeerActivity(t *testing.T) {
	p := newLifecycleTransport(t)
	data := p.getOrCreatePeerKCP(1)
	p.peersMu.Lock()
	p.peerActivity[1] = time.Now().Add(-2 * peerIdleTimeout)
	p.peersMu.Unlock()
	p.getOrCreatePeerControlKCP(1, true)
	p.expireIdlePeers(time.Now())
	if p.peers[1] != data {
		t.Fatal("control activity did not protect the idle data path")
	}
	p.expireIdlePeers(time.Now().Add(peerIdleTimeout))
	if replacement := p.getOrCreatePeerKCP(1); replacement == nil || replacement == data {
		t.Fatal("a returning epoch could not create a fresh transport runtime")
	}
}

// ai-generated: cleanup must finish even if nobody drains a peer's outbound queue.
func TestKCPPeerCloseUnblocksOutboundWrite(t *testing.T) {
	rt, err := startKCP(make(chan []byte), nil, [epochHdrLen]byte{})
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan struct{})
	go func() {
		_, _ = rt.conn.WriteTo([]byte("pending"), nil)
		close(writeDone)
	}()
	closeDone := make(chan struct{})
	go func() {
		rt.close()
		close(closeDone)
	}()
	for _, done := range []<-chan struct{}{writeDone, closeDone, rt.readDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("peer cleanup blocked on a full outbound queue")
		}
	}
}

// ai-generated: closing one peer must stop its ticker while the room stays open.
func TestPeerWriterStopsWithoutClosingTransport(t *testing.T) {
	p := newLifecycleTransport(t)
	closed := make(chan struct{})
	done := make(chan struct{})
	go func() {
		p.peerWriterPump(closed, make(chan []byte))
		close(done)
	}()
	close(closed)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("peer writer waited for the whole transport to close")
	}
}

// ai-generated: exercise late frames, expiry, and transport shutdown under -race.
func TestPeerExpiryConcurrentWithCreationAndClose(t *testing.T) {
	p := newLifecycleTransport(t)
	var workers sync.WaitGroup
	for range 3 {
		workers.Go(func() {
			for epoch := uint32(1); epoch <= 30; epoch++ {
				p.getOrCreatePeerKCP(epoch)
				p.getOrCreatePeerControlKCP(epoch, true)
				p.expireIdlePeers(time.Now().Add(peerIdleTimeout))
			}
		})
	}
	workers.Go(func() {
		if err := p.Close(); err != nil {
			t.Errorf("close transport: %v", err)
		}
	})
	workers.Wait()
	if p.getOrCreatePeerKCP(999) != nil || p.getOrCreatePeerControlKCP(999, true) != nil {
		t.Fatal("late frames recreated resources after transport close")
	}
}

// ai-generated: measure resource churn without relying on a live SFU or room.
func BenchmarkPeerEpochReclaim(b *testing.B) {
	p := newLifecycleTransport(b)
	b.ReportAllocs()
	for b.Loop() {
		p.getOrCreatePeerKCP(1)
		p.getOrCreatePeerControlKCP(1, true)
		p.expireIdlePeers(time.Now().Add(peerIdleTimeout))
	}
}
