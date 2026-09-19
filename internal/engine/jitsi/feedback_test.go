package jitsi

// ai-generated: the whole file (issue #12: the conference PeerConnection
// gives JVB the transport-cc feedback its bandwidth estimator runs on).

import (
	"context"
	"errors"
	"testing"
	"time"

	pioninterceptor "github.com/pion/interceptor"
	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

// TestConferenceReceiverSendsTransportCCFeedback plays JVB: it offers video
// with transport-cc, tags every packet it forwards and waits for the
// feedback. JVB's estimator for an endpoint runs on that feedback. Without
// any it takes the time since its first packet as the round trip, cuts the
// estimate by a fifth every second from 3 s on to its 30 kbps floor, and
// stops forwarding the endpoint any video above that: the tunnel's stream
// goes dark in one direction while the other side keeps sending (issue #12).
func TestConferenceReceiverSendsTransportCCFeedback(t *testing.T) {
	bridge := newTaggingBridge(t)
	endpointAPI, err := newConferenceAPI(nil)
	if err != nil {
		t.Fatalf("newConferenceAPI: %v", err)
	}
	endpoint, err := endpointAPI.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("endpoint pc: %v", err)
	}
	t.Cleanup(func() { _ = endpoint.Close() })
	endpoint.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		buf := make([]byte, 1500)
		for {
			if _, _, readErr := track.Read(buf); readErr != nil {
				return
			}
		}
	})

	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8}, "video", "bridge")
	if err != nil {
		t.Fatalf("track: %v", err)
	}
	sender, err := bridge.AddTrack(track)
	if err != nil {
		t.Fatalf("add track: %v", err)
	}
	connectPair(t, bridge, endpoint)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go forwardFrames(ctx, track)
	if err := waitTransportCC(ctx, sender); err != nil {
		t.Fatalf("the bridge got no transport-cc feedback from the endpoint: %v", err)
	}
}

// newTaggingBridge is the bridge side: default codecs, and transport-wide
// sequence numbers on every packet it sends, as JVB puts on what it forwards.
func newTaggingBridge(t *testing.T) *webrtc.PeerConnection {
	t.Helper()
	codecs := &webrtc.MediaEngine{}
	if err := codecs.RegisterDefaultCodecs(); err != nil {
		t.Fatalf("bridge codecs: %v", err)
	}
	registry := &pioninterceptor.Registry{}
	if err := webrtc.ConfigureTWCCHeaderExtensionSender(codecs, registry); err != nil {
		t.Fatalf("bridge transport-cc: %v", err)
	}
	api := webrtc.NewAPI(webrtc.WithMediaEngine(codecs), webrtc.WithInterceptorRegistry(registry))
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("bridge pc: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

// connectPair runs offer and answer with complete gathering, so no trickle.
func connectPair(t *testing.T, offerer, answerer *webrtc.PeerConnection) {
	t.Helper()
	offer, err := offerer.CreateOffer(nil)
	if err != nil {
		t.Fatalf("offer: %v", err)
	}
	gathered := webrtc.GatheringCompletePromise(offerer)
	if err = offerer.SetLocalDescription(offer); err != nil {
		t.Fatalf("set offer: %v", err)
	}
	<-gathered
	if err = answerer.SetRemoteDescription(*offerer.LocalDescription()); err != nil {
		t.Fatalf("apply offer: %v", err)
	}
	answer, err := answerer.CreateAnswer(nil)
	if err != nil {
		t.Fatalf("answer: %v", err)
	}
	gathered = webrtc.GatheringCompletePromise(answerer)
	if err = answerer.SetLocalDescription(answer); err != nil {
		t.Fatalf("set answer: %v", err)
	}
	<-gathered
	if err = offerer.SetRemoteDescription(*answerer.LocalDescription()); err != nil {
		t.Fatalf("apply answer: %v", err)
	}
}

// forwardFrames writes a small VP8 frame every 20 ms until ctx ends.
func forwardFrames(ctx context.Context, track *webrtc.TrackLocalStaticSample) {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	frame := append([]byte{}, 0x30, 0x01, 0x00, 0x9d, 0x01, 0x2a, 0x10, 0x00, 0x10, 0x00)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = track.WriteSample(media.Sample{Data: frame, Duration: 20 * time.Millisecond})
		}
	}
}

var errNoTransportCC = errors.New("no transport-cc feedback before the deadline")

// waitTransportCC reads the bridge sender's RTCP until a transport-cc
// feedback packet arrives or ctx ends.
func waitTransportCC(ctx context.Context, sender *webrtc.RTPSender) error {
	found := make(chan struct{})
	go func() {
		for {
			pkts, _, err := sender.ReadRTCP()
			if err != nil {
				return
			}
			for _, pkt := range pkts {
				if _, ok := pkt.(*rtcp.TransportLayerCC); ok {
					close(found)
					return
				}
			}
		}
	}()
	select {
	case <-found:
		return nil
	case <-ctx.Done():
		return errNoTransportCC
	}
}
