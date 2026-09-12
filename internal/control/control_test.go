package control

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func controlPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a, b
}

func TestRunPingPongReportsRTT(t *testing.T) {
	a, b := controlPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	got := make(chan Health, 1)
	cfg := Config{
		Interval: 10 * time.Millisecond,
		Timeout:  100 * time.Millisecond,
		Failures: 2,
		OnPong: func(h Health) {
			select {
			case got <- h:
			default:
			}
		},
	}
	errCh := make(chan error, 2)
	go func() { errCh <- Run(ctx, a, cfg) }()
	go func() { errCh <- Run(ctx, b, cfg) }()

	select {
	case h := <-got:
		if h.Seq == 0 {
			t.Fatal("Health.Seq = 0")
		}
		if h.RTT < 0 {
			t.Fatalf("Health.RTT = %v", h.RTT)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for pong health")
	}

	cancel()
	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatalf("Run() after cancel = %v", err)
		}
	}
}

func TestRunMarksUnhealthyAfterMissedPongs(t *testing.T) {
	a, b := controlPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_, _ = io.Copy(io.Discard, b)
	}()

	missedCh := make(chan int, 1)
	missedCallbackCh := make(chan int, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, a, Config{
			Interval: 10 * time.Millisecond,
			Timeout:  5 * time.Millisecond,
			Failures: 2,
			OnMissedPong: func(missed int) {
				select {
				case missedCallbackCh <- missed:
				default:
				}
			},
			OnUnhealthy: func(missed int) { missedCh <- missed },
		})
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrUnhealthy) {
			t.Fatalf("Run() error = %v, want ErrUnhealthy", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for unhealthy result")
	}
	if missed := <-missedCh; missed < 2 {
		t.Fatalf("missed = %d, want >= 2", missed)
	}
	if missed := <-missedCallbackCh; missed < 1 {
		t.Fatalf("missed callback = %d, want >= 1", missed)
	}
}

func TestRunRejectsBadProtocolVersion(t *testing.T) {
	a, b := controlPair(t)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(context.Background(), a, Config{Interval: time.Hour})
	}()
	if err := writeFrame(b, Message{Version: 999, Type: TypePing, Seq: 1}); err != nil {
		t.Fatalf("writeFrame() error = %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrProtocolVersion) {
			t.Fatalf("Run() error = %v, want ErrProtocolVersion", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for protocol error")
	}
}

func TestRunStopsOnPeerClose(t *testing.T) {
	a, b := controlPair(t)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(context.Background(), a, Config{Interval: time.Hour})
	}()
	if err := SendClose(b); err != nil {
		t.Fatalf("SendClose() error = %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrClosedByPeer) {
			t.Fatalf("Run() error = %v, want ErrClosedByPeer", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for peer close")
	}
}

func TestReadFrameRejectsTooLarge(t *testing.T) {
	a, b := controlPair(t)
	go func() {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], MaxMessageSize+1)
		_, _ = b.Write(hdr[:])
	}()
	_, err := readFrame(a)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("readFrame() error = %v, want ErrFrameTooLarge", err)
	}
}

// A peer that never answers a ping but keeps sending payload is the shape of a
// speedtest on a transport with no control plane of its own: the pong sits
// behind megabytes of queued data. The stream must stay up while that lasts.
func TestPayloadProgressKeepsALateStreamAlive(t *testing.T) {
	a, b := controlPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _, _ = io.Copy(io.Discard, b) }()

	var sent atomic.Uint64
	stalls := make(chan int, 8)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, a, Config{
			// Slow enough that the run below stays well inside
			// maxStalledProbes, fast enough that an unfixed build
			// would have given up several probes ago.
			Interval: 20 * time.Millisecond,
			Timeout:  time.Millisecond,
			Failures: 2,
			Progress: func() uint64 { return sent.Add(4096) },
			OnStalled: func(timedOut int) {
				select {
				case stalls <- timedOut:
				default:
				}
			},
			OnUnhealthy: func(int) {},
		})
	}()

	select {
	case timedOut := <-stalls:
		if timedOut < 1 {
			t.Fatalf("stalled probes = %d, want >= 1", timedOut)
		}
	case err := <-errCh:
		t.Fatalf("Run() ended while the peer was still sending: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a stalled probe")
	}

	// Well past Failures probes, and still short of maxStalledProbes:
	// without the progress check this would have returned ErrUnhealthy.
	select {
	case err := <-errCh:
		t.Fatalf("Run() ended while the peer was still sending: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("Run() after cancel = %v", err)
	}
}

// Payload progress excuses a late pong, it does not excuse a control stream
// that has stopped answering for good.
func TestProgressCannotHoldAWedgedStreamOpenForever(t *testing.T) {
	a, b := controlPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _, _ = io.Copy(io.Discard, b) }()

	var sent atomic.Uint64
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, a, Config{
			Interval:    time.Millisecond,
			Timeout:     time.Millisecond,
			Failures:    2,
			Progress:    func() uint64 { return sent.Add(4096) },
			OnUnhealthy: func(int) {},
		})
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrUnhealthy) {
			t.Fatalf("Run() error = %v, want ErrUnhealthy", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("a stream silent for more than %d probes stayed up", maxStalledProbes)
	}
}

// A counter that never moves is not progress, so nothing is excused.
func TestStaleProgressCounterDoesNotExcuseMissedPongs(t *testing.T) {
	a, b := controlPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _, _ = io.Copy(io.Discard, b) }()

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, a, Config{
			Interval:    5 * time.Millisecond,
			Timeout:     time.Millisecond,
			Failures:    2,
			Progress:    func() uint64 { return 7 },
			OnStalled:   func(int) { t.Error("a motionless counter must not excuse a probe") },
			OnUnhealthy: func(int) {},
		})
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrUnhealthy) {
			t.Fatalf("Run() error = %v, want ErrUnhealthy", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for unhealthy result")
	}
}
