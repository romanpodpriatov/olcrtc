package server

import "github.com/openlibrecommunity/olcrtc/internal/transport"

// ai-generated: fence callbacks under sessMu, close resources after unlocking.
func (s *Server) retirePeer(peerID string) func() {
	if lifecycle, ok := s.ln.(transport.PeerLifecycle); ok {
		return lifecycle.RetirePeer(peerID)
	}
	return func() {}
}

// ai-generated: a queued callback cannot resurrect a retired transport epoch.
func (s *Server) peerRetired(peerID string) bool {
	lifecycle, ok := s.ln.(transport.PeerLifecycle)
	return ok && lifecycle.PeerRetired(peerID)
}
