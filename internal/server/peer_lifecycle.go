package server

import "github.com/openlibrecommunity/olcrtc/internal/transport"

// retirePeer tells the transport that the server's session on peerID has
// ended, so it can release what it keeps for that peer.
// ai-generated: single call after teardown, replacing the fence and cleanup pair.
func (s *Server) retirePeer(peerID string) {
	if lifecycle, ok := s.ln.(transport.PeerLifecycle); ok {
		lifecycle.RetirePeer(peerID)
	}
}
