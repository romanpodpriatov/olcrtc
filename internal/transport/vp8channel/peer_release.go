package vp8channel

import "sync"

// ai-generated: retain only a bounded replay fence, never a timer for live peers.
const retiredPeerLimit = 4096

// ai-generated: reject late application callbacks before recreating a session.
func (p *streamTransport) PeerRetired(peerID string) bool {
	epoch, err := parsePeerID(peerID)
	if err != nil {
		return true
	}
	return p.peers.retired(epoch) || p.closed.Load()
}

// ai-generated: fence a completed epoch; defer closing KCP until CLOSE is sent.
func (p *streamTransport) RetirePeer(peerID string) func() {
	epoch, err := parsePeerID(peerID)
	if err != nil {
		return func() {}
	}
	sess := p.peers.retire(epoch)
	return sync.OnceFunc(func() {
		p.peers.release(epoch, sess)
	})
}

// ai-generated: fence epoch against re-creation and capture the session it owned.
func (t *peerTable) retire(epoch uint32) *peerSession {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rememberRetiredLocked(epoch)
	return t.sessions[epoch]
}

// ai-generated: report whether epoch is inside the bounded retirement fence.
func (t *peerTable) retired(epoch uint32) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.retiredPeers[epoch]
	return ok
}

// ai-generated: bound stale-epoch bookkeeping independently of connection count.
// Caller holds mu. Evicted epochs may bootstrap again if frames arrive.
func (t *peerTable) rememberRetiredLocked(epoch uint32) {
	if t.retiredPeers == nil {
		t.retiredPeers = make(map[uint32]struct{})
	}
	if _, exists := t.retiredPeers[epoch]; exists {
		return
	}
	if len(t.retiredOrder) < retiredPeerLimit {
		t.retiredOrder = append(t.retiredOrder, epoch)
	} else {
		delete(t.retiredPeers, t.retiredOrder[t.retiredNext])
		t.retiredOrder[t.retiredNext] = epoch
		t.retiredNext = (t.retiredNext + 1) % retiredPeerLimit
	}
	t.retiredPeers[epoch] = struct{}{}
}

// ai-generated: detach only the captured session, then close outside the lock.
func (t *peerTable) release(epoch uint32, sess *peerSession) {
	if sess == nil {
		return
	}
	t.mu.Lock()
	if t.sessions[epoch] == sess {
		delete(t.sessions, epoch)
	}
	t.mu.Unlock()
	sess.close()
}

// ai-generated: unblock queued peer output before KCP flushes on close.
// The singleton/client close path is deliberately unchanged.
func (r *kcpRuntime) abortPeer() {
	_ = r.conn.Close()
	r.close()
}
