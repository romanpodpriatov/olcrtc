package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtaci/smux"

	"github.com/openlibrecommunity/olcrtc/internal/control"
	cryptopkg "github.com/openlibrecommunity/olcrtc/internal/crypto"
	"github.com/openlibrecommunity/olcrtc/internal/handshake"
	"github.com/openlibrecommunity/olcrtc/internal/muxconn"
	"github.com/openlibrecommunity/olcrtc/internal/runtime"
	"github.com/openlibrecommunity/olcrtc/internal/transport"
)

// ai-generated: the whole file (olcrtc#19).
//
// The client's reconnect paths against a fake provider and a fake server:
// the provider callback, the fallback that stands in when it is late, and
// what happens when the handshakes after either go unanswered. The rig's
// link is a transport with a control plane; every control conn the client
// opens gets a fresh smux session on the server's side, the way a server
// builds one per epoch, and the server answers hellos only while told to.

var errRigGateClosed = errors.New("rig: provider not sendable")

// rigKey is the tunnel key both sides of the rig use.
var rigKey = []byte("01234567890123456789012345678901")

// rigLink is the client's transport. gate stands for the provider's CanSend.
type rigLink struct {
	server *rigServer
	gate   atomic.Bool

	mu          sync.Mutex
	onReconnect func()
	onControl   func([]byte)
	// onRequest, when set, runs inside Reconnect: an engine that calls back
	// before the request returns.
	onRequest func(reason string)
	requests  chan string
}

func (l *rigLink) Connect(context.Context) error { return nil }
func (l *rigLink) Send([]byte) error             { return nil }
func (l *rigLink) Close() error                  { return nil }
func (l *rigLink) SetReconnectCallback(cb func()) {
	l.mu.Lock()
	l.onReconnect = cb
	l.mu.Unlock()
}
func (l *rigLink) SetShouldReconnect(func() bool)      {}
func (l *rigLink) SetEndedCallback(func(string))       {}
func (l *rigLink) WatchConnection(ctx context.Context) { <-ctx.Done() }
func (l *rigLink) CanSend() bool                       { return l.gate.Load() }
func (l *rigLink) Features() transport.Features        { return transport.Features{} }
func (l *rigLink) ResetPeer()                          {}
func (l *rigLink) ControlCanSend() bool                { return l.gate.Load() }

func (l *rigLink) Reconnect(reason string) {
	l.mu.Lock()
	onRequest := l.onRequest
	l.mu.Unlock()
	select {
	case l.requests <- reason:
	default:
	}
	if onRequest != nil {
		onRequest(reason)
	}
}

func (l *rigLink) ControlSend(data []byte) error {
	if !l.gate.Load() {
		return errRigGateClosed
	}
	l.server.push(data)
	return nil
}

// SetControlOnData is called for every control conn the client opens, so the
// server starts a session for it.
func (l *rigLink) SetControlOnData(cb func([]byte)) {
	l.mu.Lock()
	l.onControl = cb
	l.mu.Unlock()
	l.server.reset(l.deliver)
}

func (l *rigLink) deliver(data []byte) {
	l.mu.Lock()
	cb := l.onControl
	l.mu.Unlock()
	if cb != nil {
		cb(data)
	}
}

// callback is the provider calling back after it rebuilt its connection.
func (l *rigLink) callback() {
	l.mu.Lock()
	cb := l.onReconnect
	l.mu.Unlock()
	cb()
}

// rigServer counts the client control conns it has seen in sessions, one per
// handshake attempt, and answers the hellos of those from answerFrom on: a
// server that is gone answers nothing, and one that is back answers the
// sessions that reach it from then on.
type rigServer struct {
	keys       *cryptopkg.KeySet
	answerFrom atomic.Int32
	sessions   atomic.Int32
	welcomed   atomic.Int32

	mu      sync.Mutex
	conn    *muxconn.Conn
	sess    *smux.Session
	streams []*smux.Stream
}

func (s *rigServer) reset(toClient func([]byte)) {
	conn := muxconn.NewControl(&rigServerLink{toClient: toClient}, s.keys)
	sess, err := smux.Server(conn, runtime.ControlSmuxConfig(0))
	if err != nil {
		panic(err)
	}
	s.mu.Lock()
	oldConn, oldSess := s.conn, s.sess
	s.conn, s.sess = conn, sess
	s.mu.Unlock()
	if oldSess != nil {
		_ = oldSess.Close()
		_ = oldConn.Close()
	}
	go s.serve(sess, s.sessions.Add(1))
}

func (s *rigServer) stopAnswering() { s.answerFrom.Store(math.MaxInt32) }

func (s *rigServer) answerNew() { s.answerFrom.Store(s.sessions.Load() + 1) }

func (s *rigServer) push(data []byte) {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn != nil {
		conn.Push(data)
	}
}

func (s *rigServer) serve(sess *smux.Session, index int32) {
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return
		}
		if index < s.answerFrom.Load() {
			go func() { _, _ = io.Copy(io.Discard, stream) }()
			continue
		}
		go s.welcome(stream)
	}
}

func (s *rigServer) welcome(stream *smux.Stream) {
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	auth := func(string, map[string]any) (string, error) {
		return fmt.Sprintf("rig-%d", s.welcomed.Add(1)), nil
	}
	if _, _, err := handshake.Server(stream, auth, ""); err != nil {
		_ = stream.Close()
		return
	}
	_ = stream.SetDeadline(time.Time{})
	s.mu.Lock()
	s.streams = append(s.streams, stream)
	s.mu.Unlock()
}

// closeSession tells the client its session is over, as a server does when
// its own provider has rebuilt. The client can be done with its handshake a
// moment before the server's side of it has returned, so a session not yet
// recorded is waited for.
func (s *rigServer) closeSession() error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		if n := len(s.streams); n > 0 {
			stream := s.streams[n-1]
			s.mu.Unlock()
			return control.SendClose(stream)
		}
		s.mu.Unlock()
		if time.Now().After(deadline) {
			return errors.New("rig: no session to close")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (s *rigServer) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sess != nil {
		_ = s.sess.Close()
		_ = s.conn.Close()
	}
}

// rigServerLink is the server's side of the control plane.
type rigServerLink struct {
	toClient func([]byte)
}

func (l *rigServerLink) Connect(context.Context) error   { return nil }
func (l *rigServerLink) Send([]byte) error               { return nil }
func (l *rigServerLink) Close() error                    { return nil }
func (l *rigServerLink) SetReconnectCallback(func())     {}
func (l *rigServerLink) SetShouldReconnect(func() bool)  {}
func (l *rigServerLink) SetEndedCallback(func(string))   {}
func (l *rigServerLink) WatchConnection(context.Context) {}
func (l *rigServerLink) CanSend() bool                   { return true }
func (l *rigServerLink) Features() transport.Features    { return transport.Features{} }
func (l *rigServerLink) Reconnect(string)                {}
func (l *rigServerLink) ControlSend(data []byte) error   { l.toClient(data); return nil }
func (l *rigServerLink) SetControlOnData(func([]byte))   {}
func (l *rigServerLink) ControlCanSend() bool            { return true }

type rig struct {
	t      *testing.T
	ctx    context.Context
	cancel context.CancelFunc
	link   *rigLink
	server *rigServer
	client *Client
}

// newRig brings a client up over the rig through bringUpLink, the way
// RunWithAddress does, with tune applied to the client first.
func newRig(t *testing.T, tune func(*Client)) *rig {
	t.Helper()
	serverKeys, err := cryptopkg.NewKeySet(rigKey, cryptopkg.Server)
	if err != nil {
		t.Fatalf("NewKeySet(server) error = %v", err)
	}
	clientKeys, err := cryptopkg.NewKeySet(rigKey, cryptopkg.Client)
	if err != nil {
		t.Fatalf("NewKeySet(client) error = %v", err)
	}
	server := &rigServer{keys: serverKeys}
	link := &rigLink{server: server, requests: make(chan string, 16)}
	link.gate.Store(true)
	name := "reconnect-rig-" + t.Name()
	transport.Register(name, func(context.Context, transport.Config) (transport.Transport, error) {
		return link, nil
	})
	c := &Client{
		keys: clientKeys, deviceID: "rig", health: runtime.NewHealthTracker(nil),
		sessionReady: make(chan struct{}), shutdownGrace: time.Second,
	}
	if tune != nil {
		tune(c)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := c.bringUpLink(ctx, Config{Transport: name}, cancel); err != nil {
		cancel()
		t.Fatalf("bringUpLink() error = %v", err)
	}
	t.Cleanup(func() {
		cancel()
		c.shutdown()
		server.close()
	})
	return &rig{t: t, ctx: ctx, cancel: cancel, link: link, server: server, client: c}
}

func (r *rig) sessionID() string {
	r.client.sessMu.RLock()
	defer r.client.sessMu.RUnlock()
	return r.client.sessionID
}

// waitNewSession waits for an established session other than old.
func (r *rig) waitNewSession(old string, within time.Duration) {
	r.t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if id := r.sessionID(); id != "" && id != old && r.client.sessionEstablished() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.t.Fatalf("no new session within %v", within)
}

// waitRequest waits for the client to ask the provider for a new connection
// with reason.
func (r *rig) waitRequest(reason string, within time.Duration) {
	r.t.Helper()
	timer := time.NewTimer(within)
	defer timer.Stop()
	for {
		select {
		case got := <-r.link.requests:
			if got == reason {
				return
			}
		case <-timer.C:
			r.t.Fatalf("the client did not ask the provider to reconnect (%s) within %v", reason, within)
		}
	}
}

// loseSession ends the session from the server's side and waits for the
// client to give it up and ask the provider for a new connection.
func (r *rig) loseSession() {
	r.t.Helper()
	if err := r.server.closeSession(); err != nil {
		r.t.Fatalf("closeSession() error = %v", err)
	}
	r.waitRequest(reconnectLiveness, 2*time.Second)
}

// An engine may hold its send gate closed until its reconnect callback
// returns: LiveKit did until olcrtc#19. The callback must still return at
// once, handing the handshake to a goroutine that sends once the gate opens,
// rather than retrying on the provider's reconnect loop against a gate that
// cannot open while it does.
func TestProviderCallbackReturnsBeforeItsHandshake(t *testing.T) {
	r := newRig(t, func(c *Client) { c.handshakeTimeout = 300 * time.Millisecond })
	first := r.sessionID()

	r.link.gate.Store(false)
	returned := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		r.link.callback()
		returned <- time.Since(start)
		r.link.gate.Store(true)
	}()
	select {
	case took := <-returned:
		if took > 100*time.Millisecond {
			t.Fatalf("the provider callback took %v to return", took)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the provider callback did not return while its handshake could not send")
	}
	r.waitNewSession(first, 2*time.Second)
}

// A provider callback that comes while the fallback is handshaking takes
// over at once: the fallback's handshake runs on the connection the rebuild
// has just replaced. It used to wait on reconnectMu until the fallback had
// spent its attempts.
func TestLateProviderCallbackTakesOverFromFallback(t *testing.T) {
	r := newRig(t, func(c *Client) {
		c.livenessFallback = 20 * time.Millisecond
		c.handshakeTimeout = 3 * time.Second
	})
	first := r.sessionID()
	r.server.stopAnswering()
	r.loseSession()

	// The fallback fires and opens its first hello; nobody answers it.
	deadline := time.Now().Add(2 * time.Second)
	for r.server.sessions.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the fallback did not start a handshake")
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.server.answerNew()
	start := time.Now()
	r.link.callback()
	r.waitNewSession(first, 2*time.Second)
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the provider callback's session took %v; it waited for the fallback", took)
	}
}

// The handshakes after a provider callback run with the fallback disarmed,
// and when they all go unanswered the client asks the provider for a new
// connection. It used to stop there: the fallback that the callback should
// have disarmed ran three more attempts after the callback's five, and then
// nothing was left to retry.
func TestFailedCallbackHandshakesAskProviderAgain(t *testing.T) {
	r := newRig(t, func(c *Client) {
		c.livenessFallback = 50 * time.Millisecond
		c.handshakeTimeout = 100 * time.Millisecond
		c.retryDelay = 10 * time.Millisecond
	})
	first := r.sessionID()
	r.server.stopAnswering()
	r.loseSession()
	before := r.server.sessions.Load()

	r.link.callback()
	r.waitRequest(reconnectHandshake, 3*time.Second)
	if got, want := int(r.server.sessions.Load()-before), maxHandshakeAttempts(reconnectProvider); got != want {
		t.Fatalf("handshake attempts before asking the provider again = %d, want the callback's %d alone", got, want)
	}

	r.server.answerNew()
	r.link.callback()
	r.waitNewSession(first, time.Second)
}

// A fallback whose handshakes go unanswered asks the provider for a new
// connection too, instead of leaving the tunnel without a session and
// nothing to retry it.
func TestFailedFallbackHandshakesAskProviderAgain(t *testing.T) {
	r := newRig(t, func(c *Client) {
		c.livenessFallback = 20 * time.Millisecond
		c.handshakeTimeout = 100 * time.Millisecond
		c.retryDelay = 10 * time.Millisecond
	})
	first := r.sessionID()
	r.server.stopAnswering()
	r.loseSession()

	r.waitRequest(reconnectHandshake, 3*time.Second)
	r.server.answerNew()
	r.link.callback()
	r.waitNewSession(first, time.Second)
}

// An engine can call back before the request that asked for the rebuild has
// even returned. The callback owns the recovery from then on: the fallback
// armed for that request is off, and the handshake starts at once rather
// than when the fallback would have fired.
func TestCallbackInsideTheRequestOwnsTheRecovery(t *testing.T) {
	r := newRig(t, func(c *Client) { c.livenessFallback = 5 * time.Second })
	first := r.sessionID()
	r.link.mu.Lock()
	r.link.onRequest = func(reason string) {
		if reason == reconnectLiveness {
			r.link.callback()
		}
	}
	r.link.mu.Unlock()

	if err := r.server.closeSession(); err != nil {
		t.Fatalf("closeSession() error = %v", err)
	}
	r.waitNewSession(first, time.Second)
}

// A control loop can end after its session has been replaced: its stream is
// closed by the teardown, but it may have seen the end before it was told to
// stop. What it reports is the death of its own session, not of the one a
// provider callback has put in its place since.
func TestLateSessionDeathLeavesTheReplacementAlone(t *testing.T) {
	r := newRig(t, nil)
	first := r.sessionID()
	r.client.sessMu.RLock()
	dead := r.client.controlStrm
	r.client.sessMu.RUnlock()

	r.link.callback()
	r.waitNewSession(first, 2*time.Second)
	second := r.sessionID()

	r.client.onSessionDeath(r.ctx, Config{}, r.cancel, dead)
	if got := r.sessionID(); got != second || !r.client.sessionEstablished() {
		t.Fatalf("session after a late death of the one it replaced = %q (established=%v), want %q",
			got, r.client.sessionEstablished(), second)
	}
	select {
	case reason := <-r.link.requests:
		t.Fatalf("the client asked the provider to reconnect (%s) for a session already replaced", reason)
	default:
	}
}
