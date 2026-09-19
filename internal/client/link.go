package client

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/xtaci/smux"

	"github.com/openlibrecommunity/olcrtc/internal/handshake"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/muxconn"
	"github.com/openlibrecommunity/olcrtc/internal/transport"
	"github.com/openlibrecommunity/olcrtc/internal/tunnelcore"
)

const peerWaitTimeout = handshake.DefaultTimeout

// helloResendInterval is how long the client waits for SERVER_WELCOME before
// it sends CLIENT_HELLO again on a fresh stream, keeping the earlier streams
// open. A relay may lose the first hello for good: the Jitsi videobridge
// drops a message addressed to an endpoint whose message channel is not open
// yet, and the server's channel can open seconds after ours when it is the
// slower side of the room - a phone on LTE against a server whose ICE takes
// a few seconds. The old single hello spent the whole handshake timeout
// waiting for an answer that could never come (olcbox#22). Every hello
// carries its own challenge and its reply comes back on the stream that sent
// it, so the first welcome wins and the other streams are closed; a server
// that answered the first one sees the later streams close unused.
//
// ai-generated: this paragraph and the value (was 4 s). The interval is also
// how long a hello can lag a server's channel that has just opened, since the
// next one after it is the one that gets through: a late server is ready up
// to an interval after it could be. 2 s is still several round trips through
// the videobridge, and halves what a late server adds to a connect (olcrtc#10).
var helloResendInterval = 2 * time.Second //nolint:gochecknoglobals // tests shorten it

// maxHelloAttempts bounds the streams one handshake may open. At the default
// interval and timeout that is seven; the cap only matters to a caller that
// passes a long timeout.
const maxHelloAttempts = 8

func (c *Client) bringUpLink(ctx context.Context, cfg Config, cancel context.CancelFunc) error {
	// ai-generated: added this lock, held for the whole function. WatchConnection starts below,
	// before the handshake completes, so a mid-handshake reconnect can race this call: handleReconnect
	// takes reconnectMu too, and without serializing here it can install a fresh working session via
	// retryHandshake while this call is still in flight, then get overwritten when this call finally
	// reaches installPairLocked with its own, by-then-stale pair. Safe to hold: every step below is
	// bounded by handshake.DefaultTimeout/peerWaitTimeout (15s each, twice for the handshake: this
	// side's path, then the reply), not unbounded.
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()
	linkCfg := tunnelcore.BuildTransportConfig(tunnelcore.LinkConfig{
		Provider: cfg.Provider, RoomURL: cfg.RoomURL, Engine: cfg.Engine,
		URL: cfg.URL, Token: cfg.Token, ProviderToken: cfg.ProviderToken,
		ChannelID: cfg.ChannelID, DNSServer: cfg.DNSServer,
		Options: cfg.TransportOptions, Traffic: cfg.Traffic,
	}, tunnelcore.LinkRoleConfig{
		DeviceID: c.deviceID, OnData: c.onData, OnDatagram: c.onDatagram, Resolver: cfg.Resolver,
		RequireTargetedPeer: true,
	})
	link, err := transport.New(ctx, cfg.Transport, linkCfg)
	if err != nil {
		return fmt.Errorf("failed to create link: %w", err)
	}
	c.ln = link
	link.SetEndedCallback(func(reason string) {
		logger.Infof("Client link reported conference end: %s", reason)
		cancel()
	})
	link.SetShouldReconnect(func() bool { return ctx.Err() == nil })
	link.SetReconnectCallback(func() {
		if ctx.Err() == nil {
			c.onProviderReconnect(ctx, cfg, cancel)
		}
	})
	if connectErr := link.Connect(ctx); connectErr != nil {
		return fmt.Errorf("failed to connect link: %w", connectErr)
	}
	// ai-generated: moved this call earlier in the function (was after the
	// handshake block below) and added this comment explaining why.
	// Start watching for reconnect requests now, not after the handshake
	// below succeeds: goolom's DataChannel can close mid-handshake (its
	// publisher-side connection is not as stable as Jitsi's), and
	// onDataChannelClose's queueReconnect() would otherwise queue a request
	// with nobody consuming it yet - a deadlock where the fix (reconnect)
	// waits on the very handshake it needs to unstick.
	c.goTracked(func() { link.WatchConnection(ctx) })
	conn := muxconn.New(link, c.keys)
	controlConn := muxconn.NewControl(link, c.keys)
	// ai-generated: write under sessMu. onData reads c.conn under sessMu.RLock from the transport's
	// delivery goroutine, live from the moment link.Connect() above succeeded; an unlocked write here
	// raced it.
	c.sessMu.Lock()
	c.conn, c.controlConn = conn, controlConn
	c.sessMu.Unlock()
	pair, err := tunnelcore.NewSessionPairWithConns(
		link, conn, controlConn, tunnelcore.ClientRole,
	)
	if err != nil {
		if pair != nil {
			_ = pair.Close()
		}
		return fmt.Errorf("create smux sessions: %w", err)
	}
	control, sessionID, peerID, err := openControlStream(ctx, pair.ControlSession, c.deviceID, c.claims)
	if err != nil {
		err = c.classifyHandshakeFailure(err, conn, controlConn)
		_ = pair.Close()
		return fmt.Errorf("handshake: %w", err)
	}
	if err := confirmPeer(link, peerID); err != nil {
		_ = pair.Close()
		return err
	}
	if waitErr := waitForPeer(ctx, link); waitErr != nil {
		_ = pair.Close()
		return waitErr
	}
	logger.Infof("session %s opened (device=%s)", sessionID, c.deviceID)
	c.sessMu.Lock()
	c.installPairLocked(pair)
	c.controlStrm = control
	c.sessionID = sessionID
	c.sessMu.Unlock()
	c.signalSessionReady()
	c.health.RecordSession(sessionID)
	c.startControlLoop(ctx, cfg, cancel, control)
	return nil
}

func waitForPeer(ctx context.Context, link transport.Transport) error {
	waiter, ok := link.(transport.PeerReadyTransport)
	if !ok {
		return nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, peerWaitTimeout)
	defer cancel()
	if err := waiter.WaitForPeer(waitCtx); err != nil {
		return fmt.Errorf("wait for peer: %w", err)
	}
	return nil
}

func confirmPeer(link transport.Transport, peerID string) error {
	if peerID == "" {
		return nil
	}
	identity, ok := link.(transport.PeerIdentity)
	if !ok {
		return fmt.Errorf("confirm peer: %w", transport.ErrPeerIdentityUnsupported)
	}
	if err := identity.ConfirmPeer(peerID); err != nil {
		return fmt.Errorf("confirm peer: %w", err)
	}
	return nil
}

func openControlStream(
	ctx context.Context,
	session *smux.Session,
	deviceID string,
	claims map[string]any,
) (*smux.Stream, string, string, error) {
	return openControlStreamTimeout(ctx, session, deviceID, claims, handshake.DefaultTimeout)
}

// openControlStreamTimeout sends the hellos and returns the stream the first
// welcome came back on. timeout bounds two waits in turn: this side's path
// taking the first hello, then the reply to it, with a hello again at every
// helloResendInterval until then.
//
// ai-generated: the two waits and openFirst (olcrtc#10). The first stream
// opens only once the path takes its SYN (smux writes it before OpenStream
// returns, and muxconn holds that write until the transport can send), which
// on Jitsi is when this side's bridge is open after ICE on the relay: seconds
// on a slow one. A window counted from the start lost those seconds to the
// peer: every hello went out before a server whose bridge opened 8 s after
// ours was up, and the client gave up seconds after it was.
func openControlStreamTimeout(
	ctx context.Context,
	session *smux.Session,
	deviceID string,
	claims map[string]any,
	timeout time.Duration,
) (*smux.Stream, string, string, error) {
	race := &helloRace{
		session: session, deviceID: deviceID, claims: claims,
		replies: make(chan helloResult, maxHelloAttempts),
	}
	first, err := race.openFirst(ctx, timeout)
	if err != nil {
		return nil, "", "", err
	}
	race.deadline = time.Now().Add(timeout)
	race.start(first)
	resend := time.NewTicker(helloResendInterval)
	defer resend.Stop()
	for {
		select {
		case <-ctx.Done():
			race.closeAllBut(nil)
			return nil, "", "", fmt.Errorf("handshake client: %w", ctx.Err())
		case <-resend.C:
			race.resend()
		case r := <-race.replies:
			if result, done := race.settle(ctx, r); done {
				return result.stream, result.sessionID, result.peerID, result.err
			}
		}
	}
}

// helloResult is what one hello stream came back with.
type helloResult struct {
	stream    *smux.Stream
	sessionID string
	peerID    string
	err       error
}

// helloRace is one handshake's hellos in flight: each on its own stream with
// its own challenge, all sharing one deadline. See helloResendInterval.
type helloRace struct {
	session  *smux.Session
	deviceID string
	claims   map[string]any
	deadline time.Time
	replies  chan helloResult
	streams  []*smux.Stream
	pending  int
}

// openFirst opens the first hello's stream, waiting at most timeout for this
// side's path to take its SYN, and less if ctx ends. An OpenStream still
// blocked when it gives up is released by the session, which the caller
// closes on the error.
//
// ai-generated: the whole function (olcrtc#10).
func (h *helloRace) openFirst(ctx context.Context, timeout time.Duration) (*smux.Stream, error) {
	opened := make(chan helloResult, 1)
	go func() {
		stream, err := h.session.OpenStream()
		opened <- helloResult{stream: stream, err: err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-opened:
		if r.err != nil {
			return nil, fmt.Errorf("open control stream: %w", r.err)
		}
		return r.stream, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("handshake client: %w", ctx.Err())
	case <-timer.C:
		return nil, fmt.Errorf("open control stream: %w", smux.ErrTimeout)
	}
}

func (h *helloRace) send() error {
	stream, err := h.session.OpenStream()
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	h.start(stream)
	return nil
}

// start sends a hello on an open stream and reads its reply off the loop.
func (h *helloRace) start(stream *smux.Stream) {
	h.streams = append(h.streams, stream)
	h.pending++
	_ = stream.SetDeadline(h.deadline)
	go func() {
		sessionID, peerID, err := handshake.Client(stream, h.deviceID, h.claims)
		h.replies <- helloResult{stream: stream, sessionID: sessionID, peerID: peerID, err: err}
	}()
}

// resend sends another hello when the cap and the deadline allow it; a hello
// that would time out half an interval later is not worth sending.
func (h *helloRace) resend() bool {
	if len(h.streams) >= maxHelloAttempts || time.Until(h.deadline) <= helloResendInterval/2 {
		return false
	}
	if err := h.send(); err != nil {
		logger.Debugf("handshake: resend hello: %v", err)
		return false
	}
	return true
}

func (h *helloRace) closeAllBut(keep *smux.Stream) {
	for _, stream := range h.streams {
		if stream != keep {
			_ = stream.Close()
		}
	}
}

// settle takes one stream's result and reports whether the race is decided:
// by a welcome, by an answer that makes another hello pointless, or by the
// last unanswered hello with no time left for another.
func (h *helloRace) settle(ctx context.Context, r helloResult) (helloResult, bool) {
	h.pending--
	if r.err == nil {
		_ = r.stream.SetDeadline(time.Time{})
		h.closeAllBut(r.stream)
		return r, true
	}
	_ = r.stream.Close()
	if ctx.Err() != nil {
		h.closeAllBut(nil)
		return helloResult{err: fmt.Errorf("handshake client: %w", ctx.Err())}, true
	}
	if !helloAnswered(r.err) && (h.pending > 0 || h.resend()) {
		return helloResult{}, false
	}
	h.closeAllBut(nil)
	return helloResult{err: fmt.Errorf("handshake client: %w", r.err)}, true
}

// helloAnswered reports whether the peer replied to a hello, however badly:
// a rejection, a version mismatch or a malformed reply is an answer, and
// sending the hello again would only get the same one. A timeout or a closed
// stream is silence.
func helloAnswered(err error) bool {
	return errors.Is(err, handshake.ErrRejected) ||
		errors.Is(err, handshake.ErrProtocolVersion) ||
		errors.Is(err, handshake.ErrUnexpectedMessage) ||
		errors.Is(err, handshake.ErrChallengeMismatch) ||
		errors.Is(err, handshake.ErrFrameTooLarge)
}

// onProviderReconnect re-establishes the session over the connection the
// provider has just rebuilt, on a goroutine of its own.
//
// The callback runs on the provider's reconnect loop, which serves no other
// request until it returns, and handshakes the peer does not answer take
// over a minute to give up on: run inline, they held the loop that long. The
// callback also takes the recovery over from a fallback started because it
// came late, which is handshaking over the connection just replaced.
//
// ai-generated: the whole function (olcrtc#19).
func (c *Client) onProviderReconnect(ctx context.Context, cfg Config, cancel context.CancelFunc) {
	run, gen := c.recovery.take(ctx)
	c.goTracked(func() {
		defer c.recovery.release(gen)
		c.handleReconnect(ctx, run, cfg, cancel, reconnectProvider)
	})
}

// handleReconnect re-handshakes over the connection the provider has just
// rebuilt, tearing down whatever session it finds, and hands the rebuild back
// to the provider when those handshakes fail too. run ends when a later
// recovery takes over.
//
// ai-generated: run, the teardown split out to dropSessionLocked, and the
// rebuild after a failed retry (olcrtc#19).
func (c *Client) handleReconnect(ctx, run context.Context, cfg Config, cancel context.CancelFunc, reason string) {
	expect := c.recovery.generation()
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()
	if run.Err() != nil {
		return
	}
	c.dropSessionLocked(reason, nil)
	if !c.retryHandshake(ctx, run, cfg, cancel, reason) && run.Err() == nil && c.ln != nil {
		c.rebuildProvider(ctx, cfg, cancel, reconnectHandshake, expect)
	}
}

// onSessionDeath gives up the session whose control stream the liveness loop
// declared dead and hands the rebuild to the provider, whose callback then
// drives the handshake.
//
// ai-generated: the whole function, the liveness half of what handleReconnect
// was (olcrtc#19). It drops only the session that died: one a provider
// callback has put in its place since is left alone, and so is the recovery
// that callback runs.
func (c *Client) onSessionDeath(ctx context.Context, cfg Config, cancel context.CancelFunc, dead *smux.Stream) {
	expect := c.recovery.generation()
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()
	if !c.dropSessionLocked(reconnectLiveness, dead) || c.ln == nil {
		return
	}
	c.rebuildProvider(ctx, cfg, cancel, reconnectLiveness, expect)
}

// dropSessionLocked tears the installed session down, or with dead set only
// the session whose control stream that is, and reports whether it did.
// Callers hold reconnectMu.
//
// ai-generated: split out of handleReconnect with the dead check (olcrtc#19);
// the teardown is as it was.
func (c *Client) dropSessionLocked(reason string, dead *smux.Stream) bool {
	if dead != nil {
		c.sessMu.RLock()
		current := c.controlStrm == dead
		c.sessMu.RUnlock()
		if !current {
			return false
		}
	}
	c.health.RecordReconnect()
	logger.Infof("client reconnect reason=%s - tearing down smux session", reason)
	tunnelcore.ResetPeer(c.ln)
	c.sessMu.RLock()
	if c.pair != nil {
		_ = c.pair.CloseConns()
	} else {
		if c.conn != nil {
			_ = c.conn.Close()
		}
		if c.controlConn != nil {
			_ = c.controlConn.Close()
		}
	}
	c.sessMu.RUnlock()
	c.sessMu.Lock()
	oldPair := c.pair
	oldControl := c.controlStrm
	oldControlStop := c.controlStop
	oldSession := c.session
	oldControlSession := c.controlSess
	c.pair = nil
	// Clear the conns rather than installing replacements. On the liveness
	// path no smux session is built over them for up to livenessFallback, so
	// a reader-less conn would fill its inbound queue and then block the
	// transport's delivery goroutine inside Push. PushData treats nil as a
	// no-op, and tryReopenSession builds its own conns anyway.
	c.conn, c.controlConn = nil, nil
	c.session, c.controlSess = nil, nil
	c.controlStrm, c.controlStop = nil, nil
	c.sessionID = ""
	c.sessMu.Unlock()
	if oldControlStop != nil {
		oldControlStop()
	}
	closeClientPair(oldPair, oldSession, oldControlSession)
	if oldControl != nil {
		_ = oldControl.Close()
	}
	return true
}

func closeClientPair(pair *tunnelcore.SessionPair, session, controlSession *smux.Session) {
	if pair != nil {
		_ = pair.Close()
		return
	}
	if session != nil {
		_ = session.Close()
	}
	if controlSession != nil && controlSession != session {
		_ = controlSession.Close()
	}
}

// rebuildProvider asks the provider for a new connection, whose callback
// then drives the handshake, and arms the fallback in case that callback
// never comes. expect is the recovery generation read before the session was
// given up: a callback that has come since is handshaking over a connection
// newer than this one and owns the recovery, so nothing is asked for.
//
// ai-generated: the whole function (olcrtc#19).
func (c *Client) rebuildProvider(
	ctx context.Context, cfg Config, cancel context.CancelFunc, reason string, expect uint64,
) {
	if c.armFallback(ctx, cfg, cancel, expect) {
		c.ln.Reconnect(reason)
	}
}

// armFallback re-establishes the session on its own when the provider has
// not called back within the fallback window: a provider that silently never
// does would otherwise leave sessionReady unsignalled for good.
//
// ai-generated: arming on the recovery generation, the disarm by a provider
// callback and the rebuild when its handshakes fail too (olcrtc#19). The
// fallback used to go by sessionEstablished alone, so a callback that had
// come but whose handshake was still retrying did not stop it: it logged a
// callback that never came, queued on reconnectMu behind the callback's
// handshakes and ran its own after them. Now a callback disarms it, or stops
// its handshakes if they have begun; and when they fail it asks the provider
// again rather than leave the tunnel without a session and nothing retrying.
func (c *Client) armFallback(ctx context.Context, cfg Config, cancel context.CancelFunc, expect uint64) bool {
	run, gen, ok := c.recovery.takeIf(ctx, expect)
	if !ok {
		return false
	}
	delay := c.livenessFallback
	if delay <= 0 {
		delay = defaultLivenessFallback
	}
	c.goTracked(func() {
		defer c.recovery.release(gen)
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-run.Done():
			return
		case <-timer.C:
		}
		if c.sessionEstablished() {
			return
		}
		logger.Warnf("client reconnect: no provider callback within %s - re-establishing session", delay)
		c.reconnectMu.Lock()
		defer c.reconnectMu.Unlock()
		if run.Err() != nil || c.sessionEstablished() {
			return
		}
		if !c.retryHandshake(ctx, run, cfg, cancel, reconnectFallback) && run.Err() == nil {
			c.rebuildProvider(ctx, cfg, cancel, reconnectHandshake, gen)
		}
	})
	return true
}

func (c *Client) sessionEstablished() bool {
	c.sessMu.RLock()
	defer c.sessMu.RUnlock()
	return c.session != nil && !c.session.IsClosed() && c.sessionID != ""
}

// retryHandshake reports whether it installed a session. It stops when the
// reason's attempts run out or when run ends; the control loop of a session
// it installs runs on ctx.
//
// ai-generated: run, the result and retryDelay (olcrtc#19).
func (c *Client) retryHandshake(ctx, run context.Context, cfg Config, cancel context.CancelFunc, reason string) bool {
	const (
		initialDelay = 300 * time.Millisecond
		maxDelay     = 5 * time.Second
	)
	delay := initialDelay
	if c.retryDelay > 0 {
		delay = c.retryDelay
	}
	maxAttempts := maxHandshakeAttempts(reason)
	for attempt := 1; ; attempt++ {
		if run.Err() != nil {
			return false
		}
		logger.Infof("client reconnect attempt=%d reason=%s", attempt, reason)
		if c.tryReopenSession(ctx, run, cfg, cancel, attempt) {
			return true
		}
		if maxAttempts > 0 && attempt >= maxAttempts {
			logger.Warnf("client reconnect: exhausted %d handshake attempts (reason=%s) - "+
				"asking the provider for a new connection", attempt, reason)
			return false
		}
		select {
		case <-run.Done():
			return false
		case <-time.After(delay):
		}
		if delay < maxDelay {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
}

func maxHandshakeAttempts(reason string) int {
	switch reason {
	case reconnectProvider:
		return 5
	case reconnectFallback:
		return 3
	default:
		return 0
	}
}

// tryReopenSession runs one handshake. Its waits end with run; the session
// it installs runs on ctx.
//
// ai-generated: run, helloTimeout and the check before installing (olcrtc#19).
func (c *Client) tryReopenSession(
	ctx, run context.Context,
	cfg Config,
	cancel context.CancelFunc,
	attempt int,
) bool {
	conn := muxconn.New(c.ln, c.keys)
	controlConn := muxconn.NewControl(c.ln, c.keys)
	c.sessMu.Lock()
	oldConn, oldControlConn := c.conn, c.controlConn
	c.conn, c.controlConn = conn, controlConn
	c.sessMu.Unlock()
	if oldConn != nil {
		_ = oldConn.Close()
	}
	if oldControlConn != nil {
		_ = oldControlConn.Close()
	}
	pair, err := tunnelcore.NewSessionPairWithConns(
		c.ln, conn, controlConn, tunnelcore.ClientRole,
	)
	if err != nil {
		logger.Warnf("smux re-init failed (attempt %d): %v", attempt, err)
		if pair != nil {
			_ = pair.Close()
		}
		return false
	}
	control, sessionID, peerID, err := openControlStreamTimeout(
		run, pair.ControlSession, c.deviceID, c.claims, c.helloTimeout(),
	)
	if err != nil {
		if run.Err() == nil {
			logger.Warnf("handshake on reconnect failed (attempt %d): %v", attempt,
				c.classifyHandshakeFailure(err, conn, controlConn))
		}
		_ = pair.Close()
		return false
	}
	if err := confirmPeer(c.ln, peerID); err != nil {
		logger.Warnf("peer confirmation on reconnect failed (attempt %d): %v", attempt, err)
		_ = pair.Close()
		return false
	}
	if waitErr := waitForPeer(run, c.ln); waitErr != nil {
		logger.Warnf("wait for peer on reconnect failed (attempt %d): %v", attempt, waitErr)
		_ = pair.Close()
		return false
	}
	// A recovery that took over while this handshake ran is rebuilding the
	// connection it ran on; it installs its own session.
	if run.Err() != nil {
		_ = pair.Close()
		return false
	}
	logger.Infof("session %s reopened (device=%s)", sessionID, c.deviceID)
	c.sessMu.Lock()
	c.installPairLocked(pair)
	c.controlStrm = control
	c.sessionID = sessionID
	c.sessMu.Unlock()
	c.signalSessionReady()
	c.health.RecordSession(sessionID)
	c.startControlLoop(ctx, cfg, cancel, control)
	return true
}

// helloTimeout is the handshake timeout of a reconnect. ai-generated (olcrtc#19).
func (c *Client) helloTimeout() time.Duration {
	if c.handshakeTimeout > 0 {
		return c.handshakeTimeout
	}
	return handshake.DefaultTimeout
}

func (c *Client) installPairLocked(pair *tunnelcore.SessionPair) {
	c.pair = pair
	c.conn = pair.DataConn
	c.controlConn = pair.ControlConn
	c.session = pair.DataSession
	c.controlSess = pair.ControlSession
}

func (c *Client) signalSessionReady() {
	c.sessMu.Lock()
	old := c.sessionReady
	c.sessionReady = make(chan struct{})
	c.sessMu.Unlock()
	close(old)
}

func (c *Client) readyChannel() chan struct{} {
	c.sessMu.RLock()
	defer c.sessMu.RUnlock()
	return c.sessionReady
}

// sessionSnapshot returns the live session together with the ready channel
// that will fire when it is replaced, both read in one critical section.
func (c *Client) sessionSnapshot() (*smux.Session, string, <-chan struct{}) {
	c.sessMu.RLock()
	defer c.sessMu.RUnlock()
	return c.session, c.sessionID, c.sessionReady
}
