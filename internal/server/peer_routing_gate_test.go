package server

import (
	"testing"

	"github.com/openlibrecommunity/olcrtc/internal/transport"
)

// olcbox#22: jitsi + datachannel came up, moved SCTP in both directions, and
// never opened a session.
//
// datachannel routes peers when its engine can (only jitsi can), but it has no
// per-peer control plane. With only the first half the server took its peer
// branch, found nothing to build a control session on, installed nothing, and
// then sat in serve's peer branch accepting nothing. Every symptom was an
// absence, which is why it read as a misconfigured room.
func TestPeerRoutingNeedsAPerPeerControlPlane(t *testing.T) {
	if got := peerRoutingLink(&peerRoutingStub{}, "datachannel"); got != nil {
		t.Fatalf("a transport with no per-peer control plane must not be served as peer-routing, got %#v", got)
	}
}

// The third shape, and the one that made the first cut of this gate too wide:
// a transport that routes peers and has a plain control channel but no
// per-peer one. installControlSession builds a single shared control session
// on it, which works for one client, so peer routing stays.
func TestPeerRoutingIsKeptWithOnlyASharedControlChannel(t *testing.T) {
	link := &legacyControlRoutingStub{}
	var _ transport.ControlPlane = link
	if _, perPeer := interface{}(link).(transport.PeerControlPlane); perPeer {
		t.Fatal("this stub must not have a per-peer control plane, or it tests the wrong shape")
	}
	if peerRoutingLink(link, "legacy") == nil {
		t.Fatal("a shared control channel is enough to run the handshake; peer routing must be kept")
	}
}

// vp8channel has both halves and must keep the peer path it has always used.
func TestPeerRoutingIsKeptWhenBothHalvesArePresent(t *testing.T) {
	link := &peerControlRoutingStub{}
	// The stub stands in for vp8channel, so it must really satisfy the
	// interface the real one does; otherwise this proves nothing.
	var _ transport.PeerControlPlane = link

	got := peerRoutingLink(link, "vp8channel")
	if got == nil {
		t.Fatal("a transport with both halves must still be served as peer-routing")
	}
	if got != transport.PeerTransport(link) {
		t.Fatalf("peerRoutingLink returned a different link: %#v", got)
	}
}

// A plain transport was never peer-routing and is unaffected.
func TestAPlainTransportIsNotPeerRouting(t *testing.T) {
	if got := peerRoutingLink(&serverLinkStub{}, "datachannel"); got != nil {
		t.Fatalf("a transport that does not route peers must not be served as peer-routing, got %#v", got)
	}
}
