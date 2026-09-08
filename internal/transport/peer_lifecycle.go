package transport

// PeerLifecycle optionally releases transport state after a server session ends.
// RetirePeer fences new inbound callbacks before returning. Its idempotent
// cleanup must run after the server has sent its best-effort close notification.
// Peer IDs identify transport epochs; reconnecting clients must use a new epoch.
// ai-generated: define explicit session-owned transport teardown.
type PeerLifecycle interface {
	RetirePeer(peerID string) func()
	PeerRetired(peerID string) bool
}

// ai-generated: preserve optional lifecycle support through traffic wrapping.
func (t *trafficTransport) RetirePeer(peerID string) func() {
	if lifecycle, ok := t.inner.(PeerLifecycle); ok {
		return lifecycle.RetirePeer(peerID)
	}
	return func() {}
}

// ai-generated: reject delayed callbacks from retired transport epochs.
func (t *trafficTransport) PeerRetired(peerID string) bool {
	lifecycle, ok := t.inner.(PeerLifecycle)
	return ok && lifecycle.PeerRetired(peerID)
}
