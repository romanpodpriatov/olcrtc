// Package vp8channel provides byte transport over VP8 video frames using KCP.
package vp8channel

import "time"

// ai-generated: allow several liveness windows before reclaiming a silent epoch.
const peerIdleTimeout = 5 * time.Minute

// ai-generated: track received frames using time.Time's monotonic clock.
// peersMu must be held. Outbound retries only initialize a new entry.
func (p *streamTransport) touchPeerLocked(epoch uint32, received bool) {
	if p.peerActivity == nil {
		p.peerActivity = make(map[uint32]time.Time)
	}
	if _, exists := p.peerActivity[epoch]; received || !exists {
		p.peerActivity[epoch] = time.Now()
	}
}

// ai-generated: reap abandoned data and control epochs without restarting the room.
func (p *streamTransport) reapIdlePeers() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-p.closeCh:
			return
		case now := <-ticker.C:
			p.expireIdlePeers(now)
		}
	}
}

// ai-generated: close both KCPs and stop each writer through kcpConn.closed.
// Never close outbound queues: KCP may still be finishing a concurrent write.
func (p *streamTransport) expireIdlePeers(now time.Time) {
	p.peersMu.Lock()
	defer p.peersMu.Unlock()
	p.ctrlPeersMu.Lock()
	defer p.ctrlPeersMu.Unlock()
	for epoch, last := range p.peerActivity {
		if now.Sub(last) < peerIdleTimeout {
			continue
		}
		if rt := p.peers[epoch]; rt != nil {
			rt.close()
			delete(p.peers, epoch)
		}
		if control := p.ctrlPeers[epoch]; control != nil {
			control.kcp.close()
			delete(p.ctrlPeers, epoch)
		}
		delete(p.peerOut, epoch)
		delete(p.peerActivity, epoch)
	}
}
