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
	p.peersMu.RLock()
	_, retired := p.retiredPeers[epoch]
	p.peersMu.RUnlock()
	return retired || p.closed.Load()
}

// ai-generated: fence a completed epoch; defer closing KCP until CLOSE is sent.
func (p *streamTransport) RetirePeer(peerID string) func() {
	epoch, err := parsePeerID(peerID)
	if err != nil {
		return func() {}
	}
	p.peersMu.Lock()
	p.rememberRetiredPeer(epoch)
	rt := p.peers[epoch]
	p.ctrlPeersMu.RLock()
	control := p.ctrlPeers[epoch]
	p.ctrlPeersMu.RUnlock()
	p.peersMu.Unlock()
	return sync.OnceFunc(func() {
		p.releaseRetiredPeer(epoch, rt, control)
	})
}

// ai-generated: bound stale-epoch bookkeeping independently of connection count.
// Caller holds peersMu. Evicted epochs may bootstrap again if frames arrive.
func (p *streamTransport) rememberRetiredPeer(epoch uint32) {
	if p.retiredPeers == nil {
		p.retiredPeers = make(map[uint32]struct{})
	}
	if _, exists := p.retiredPeers[epoch]; exists {
		return
	}
	if len(p.retiredOrder) < retiredPeerLimit {
		p.retiredOrder = append(p.retiredOrder, epoch)
	} else {
		delete(p.retiredPeers, p.retiredOrder[p.retiredNext])
		p.retiredOrder[p.retiredNext] = epoch
		p.retiredNext = (p.retiredNext + 1) % retiredPeerLimit
	}
	p.retiredPeers[epoch] = struct{}{}
}

// ai-generated: detach only captured runtimes, then close outside map locks.
func (p *streamTransport) releaseRetiredPeer(epoch uint32, rt *kcpRuntime, control *peerControlKCP) {
	p.peersMu.Lock()
	if p.peers[epoch] == rt {
		delete(p.peers, epoch)
		delete(p.peerOut, epoch)
	}
	p.ctrlPeersMu.Lock()
	if p.ctrlPeers[epoch] == control {
		delete(p.ctrlPeers, epoch)
	}
	p.ctrlPeersMu.Unlock()
	p.peersMu.Unlock()
	if rt != nil {
		rt.abortPeer()
	}
	if control != nil {
		control.kcp.abortPeer()
	}
}

// ai-generated: unblock queued peer output before KCP flushes on close.
// The singleton/client close path is deliberately unchanged.
func (r *kcpRuntime) abortPeer() {
	_ = r.conn.Close()
	r.close()
}

// ai-generated: shutdown shares retirement's nonblocking per-peer close order.
func (p *streamTransport) closePeerRuntimes() {
	p.peersMu.Lock()
	peers := p.peers
	p.peers = make(map[uint32]*kcpRuntime)
	p.peerOut = make(map[uint32]chan []byte)
	p.ctrlPeersMu.Lock()
	controls := p.ctrlPeers
	p.ctrlPeers = make(map[uint32]*peerControlKCP)
	p.ctrlPeersMu.Unlock()
	p.peersMu.Unlock()
	for _, rt := range peers {
		rt.abortPeer()
	}
	for _, control := range controls {
		control.kcp.abortPeer()
	}
}
