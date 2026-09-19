package vp8channel

// ai-generated: the whole file (issue #12: the data lane against an SFU that
// stops forwarding a stream over its budget).

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"

	"github.com/openlibrecommunity/olcrtc/internal/transport"
)

// budgetRelay is one direction of an SFU the way JVB forwards a stream: it
// measures what the sender pushes at it and, at every allocation, stops
// forwarding all of it while the last window was over the budget, and
// forwards it again once a window is back under. JVB allocates every 5 s;
// what matters is that the window outlasts KCP's retransmission rounds, so
// resending keeps the stream over the budget. Frames reach the receiver on
// their own goroutine, as they would off the network.
type budgetRelay struct {
	budget int // bytes per window; zero forwards everything
	window time.Duration

	mu       sync.Mutex
	arrivals []relayArrival
	dark     bool
	frames   chan []byte
}

type relayArrival struct {
	at   time.Time
	size int
}

func newBudgetRelay(budget int, window time.Duration) *budgetRelay {
	return &budgetRelay{budget: budget, window: window, frames: make(chan []byte, 4096)}
}

// write is the sender's track.
func (r *budgetRelay) write(frame []byte) bool {
	r.mu.Lock()
	r.arrivals = append(r.arrivals, relayArrival{at: time.Now(), size: len(frame)})
	dark := r.dark
	r.mu.Unlock()
	if dark {
		return true
	}
	select {
	case r.frames <- append([]byte(nil), frame...):
	default:
	}
	return true
}

// run re-decides every period and delivers frames to the receiver until ctx ends.
func (r *budgetRelay) run(ctx context.Context, period time.Duration, to func([]byte)) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case frame := <-r.frames:
				to(frame)
			}
		}
	}()
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			r.allocate(now)
		}
	}
}

func (r *budgetRelay) allocate(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	kept, total := r.arrivals[:0], 0
	for _, a := range r.arrivals {
		if now.Sub(a.at) <= r.window {
			kept = append(kept, a)
			total += a.size
		}
	}
	r.arrivals = kept
	r.dark = r.budget > 0 && total > r.budget
}

// newLaneTestTransport is a transport on a relay, with the lane's timers
// scaled down to the relay's.
func newLaneTestTransport(t *testing.T, cfg transport.Config, relay *budgetRelay) *streamTransport {
	t.Helper()
	cfg.ChannelID = "lane-test"
	tr := newStreamTransport(&fakeVideoStream{canSend: true}, nil, cfg, Options{FPS: 50, BatchSize: 8})
	tr.sampleWriter = relay.write
	tr.blackoutAfter = 600 * time.Millisecond
	tr.probeEvery = 100 * time.Millisecond
	tr.growEvery = 500 * time.Millisecond
	if err := tr.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

// TestDataLaneBringsBackAStreamTheSFUStoppedForwarding is issue #12 in
// small: a server pulls to a client through an SFU that stops forwarding the
// server's stream as soon as a burst takes it over its budget. KCP resends
// every unacknowledged segment on each timeout, so a lane that keeps writing
// whatever KCP queues keeps the stream over the budget and dark: the client
// stops receiving for as long as that lasts, which on JVB was minutes. A lane
// that goes quiet once nothing is acknowledged lets the SFU take the stream
// back, and the transfer keeps moving.
func TestDataLaneBringsBackAStreamTheSFUStoppedForwarding(t *testing.T) {
	runLanePair(t, lanePair{toClient: 256 << 10, pull: 768 << 10})
}

// TestDataLanesKeepAnsweringWhileBothAreDark pulls and pushes at once through
// an SFU that polices both directions, so both lanes go dark together, as a
// push started on the tail of a pull did live. A dark lane must still carry
// what answers the peer: holding back acknowledgements too leaves each side
// waiting for the other's, and neither direction comes back.
func TestDataLanesKeepAnsweringWhileBothAreDark(t *testing.T) {
	runLanePair(t, lanePair{toClient: 256 << 10, toServer: 256 << 10, pull: 512 << 10, push: 512 << 10})
}

// lanePair is a server and a client on budget relays: the budgets per
// window each way (zero forwards everything) and what to move each way.
type lanePair struct {
	toClient, toServer int
	pull, push         int
}

// runLanePair moves the pair's bytes and fails once nothing has arrived
// either way for five seconds before they all did.
func runLanePair(t *testing.T, pair lanePair) {
	t.Helper()
	const (
		window   = time.Second
		allocate = 500 * time.Millisecond
		stallFor = 5 * time.Second
	)
	toClient := newBudgetRelay(pair.toClient, window)
	toServer := newBudgetRelay(pair.toServer, window)

	var pulled, pushed atomic.Int64
	client := newLaneTestTransport(t, transport.Config{
		OnData: func(b []byte) { pulled.Add(int64(len(b))) },
	}, toServer)
	server := newLaneTestTransport(t, transport.Config{
		OnPeerData: func(_ string, b []byte) { pushed.Add(int64(len(b))) },
	}, toClient)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go toClient.run(ctx, allocate, client.handleIncomingFrame)
	go toServer.run(ctx, allocate, server.handleIncomingFrame)

	if err := client.ConfirmPeer(server.LocalPeerID()); err != nil {
		t.Fatalf("ConfirmPeer: %v", err)
	}
	peer := client.LocalPeerID()
	waitFor(t, 5*time.Second, "the server to see the client", func() bool {
		return server.peers.get(client.localEpochValue()) != nil
	})

	go sendChunks(ctx, pair.pull, func(b []byte) error { return server.SendTo(peer, b) })
	go sendChunks(ctx, pair.push, client.Send)

	want := int64(pair.pull + pair.push)
	last, lastMove := int64(0), time.Now()
	for pulled.Load()+pushed.Load() < want {
		time.Sleep(20 * time.Millisecond)
		if n := pulled.Load() + pushed.Load(); n != last {
			last, lastMove = n, time.Now()
			continue
		}
		if time.Since(lastMove) > stallFor {
			t.Fatalf("stalled: pulled %d of %d, pushed %d of %d, nothing moved for %s",
				pulled.Load(), pair.pull, pushed.Load(), pair.push, stallFor)
		}
	}
}

// sendChunks sends size random bytes through send in 16 KiB messages.
func sendChunks(ctx context.Context, size int, send func([]byte) error) {
	const chunk = 16 << 10
	payload := make([]byte, size)
	_, _ = rand.Read(payload)
	for off := 0; off < size && ctx.Err() == nil; off += chunk {
		if err := send(payload[off:min(off+chunk, size)]); err != nil {
			return
		}
	}
}

// waitFor polls cond until it holds or the timeout passes.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// kcpSegments builds a KCP packet of the given commands, each with body as
// its data.
func kcpSegments(body []byte, cmds ...byte) []byte {
	var packet []byte
	for _, cmd := range cmds {
		hdr := make([]byte, kcp.IKCP_OVERHEAD)
		hdr[kcpCmdOff] = cmd
		binary.LittleEndian.PutUint32(hdr[kcpLenOff:], uint32(len(body))) //nolint:gosec // test body
		packet = append(append(packet, hdr...), body...)
	}
	return packet
}

func TestPushesWalksTheSegmentsAndStopsAtAHostileLength(t *testing.T) {
	ack, push := byte(kcp.IKCP_CMD_ACK), byte(kcp.IKCP_CMD_PUSH)
	if !pushes(kcpSegments(nil, ack, ack, push)) {
		t.Fatal("pushes() missed a push behind two acknowledgements")
	}
	if pushes(kcpSegments(nil, ack, ack)) || pushes(kcpSegments([]byte("x"), ack)) {
		t.Fatal("pushes() found a push among acknowledgements")
	}
	hostile := kcpSegments(nil, ack, push)
	binary.LittleEndian.PutUint32(hostile[kcpLenOff:], 0xffffffff)
	if pushes(hostile) {
		t.Fatal("pushes() read past a length longer than the packet")
	}
	if !answers(kcpSegments(nil, ack, push)) || !answers(kcpSegments(nil, kcp.IKCP_CMD_WINS)) ||
		answers(kcpSegments(nil, push, ack)) || answers([]byte{1, 2}) {
		t.Fatal("answers() misread the first segment")
	}
}

func TestKCPConnHoldsPushesBackButNotAnswers(t *testing.T) {
	out := make(chan *packetBuffer, 16)
	acks := make(chan *packetBuffer, 16)
	c := newKCPConn(out, 16, testEpochHdr(1))
	c.acks = acks
	write := func(p []byte) { _, _ = c.WriteTo(p, nil) }
	ack, push := byte(kcp.IKCP_CMD_ACK), byte(kcp.IKCP_CMD_PUSH)

	write(kcpSegments(nil, ack))
	write(kcpSegments([]byte("d"), push))
	write(kcpSegments([]byte("d"), ack, push))
	if len(acks) != 1 || len(out) != 2 {
		t.Fatalf("acks=%d out=%d, want the lone acknowledgement apart and the rest with the data", len(acks), len(out))
	}

	c.hold(time.Hour)
	write(kcpSegments([]byte("d"), push)) // the probe
	write(kcpSegments([]byte("d"), push)) // held back
	write(kcpSegments([]byte("d"), ack, push))
	write(kcpSegments(nil, ack))
	if len(out) != 4 || len(acks) != 2 {
		t.Fatalf("while held: out=%d acks=%d, want one probe and everything that answers", len(out), len(acks))
	}
	c.hold(0)
	write(kcpSegments([]byte("d"), push))
	if len(out) != 5 {
		t.Fatalf("after the hold: out=%d, want the push through", len(out))
	}
}

func TestCappedLaneDropsStalePushesButNotAnswers(t *testing.T) {
	out := make(chan *packetBuffer, 8)
	l := &dataLane{out: out, pace: pace{rate: minPaceRate}}
	now := 10 * second
	hdr := testEpochHdr(1)
	queue := func(queued int64, cmds ...byte) {
		frame := append(append([]byte(nil), hdr[:]...), kcpSegments([]byte("d"), cmds...)...)
		out <- &packetBuffer{data: frame, queued: queued}
	}
	stale := now - 3*int64(capQueue)
	queue(stale, kcp.IKCP_CMD_PUSH)
	queue(stale, kcp.IKCP_CMD_ACK, kcp.IKCP_CMD_PUSH)
	queue(now, kcp.IKCP_CMD_PUSH)
	if got := l.takeFresh(now); got == nil || got.queued != stale {
		t.Fatal("takeFresh() dropped a stale packet that answers the peer")
	}
	if got := l.takeFresh(now); got == nil || got.queued != now {
		t.Fatal("takeFresh() did not skip the stale push to the fresh one")
	}
	l.pace.rate = 0
	queue(stale, kcp.IKCP_CMD_PUSH)
	if got := l.takeFresh(now); got == nil {
		t.Fatal("takeFresh() dropped a stale push on an uncapped lane")
	}
}
