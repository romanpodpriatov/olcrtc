// Package client implements the local SOCKS5 client side of the olcrtc tunnel.
package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/xtaci/smux"

	"github.com/openlibrecommunity/olcrtc/internal/control"
	"github.com/openlibrecommunity/olcrtc/internal/crypto"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/muxconn"
	"github.com/openlibrecommunity/olcrtc/internal/protect"
	"github.com/openlibrecommunity/olcrtc/internal/route"
	"github.com/openlibrecommunity/olcrtc/internal/runtime"
	"github.com/openlibrecommunity/olcrtc/internal/transport"
	"github.com/openlibrecommunity/olcrtc/internal/tunnelcore"
)

var (
	ErrConnectFailed           = errors.New("tunnel connection failed")
	ErrProxyAuth               = errors.New("SOCKS proxy auth failed")
	ErrKeySize                 = runtime.ErrKeySize
	ErrInvalidSOCKSVersion     = errors.New("invalid socks version")
	ErrUnsupportedSOCKSCommand = errors.New("unsupported socks command")
	ErrUnsupportedAddressType  = errors.New("unsupported address type")
	ErrRemoteNotReady          = errors.New("remote not ready")
	ErrSOCKSAuthFailed         = errors.New("SOCKS5 authentication failed")
	ErrSOCKSCredTooLong        = errors.New("socks5 user/pass exceeds 255 bytes")
	ErrEmptySOCKSDomain        = errors.New("empty socks5 domain")
)

const (
	reconnectProvider = "provider"
	reconnectLiveness = "liveness"
	reconnectFallback = "liveness-fallback"
	// reconnectHandshake asks the provider for a new connection after the
	// handshakes over the one it gave went unanswered. ai-generated (olcrtc#19).
	reconnectHandshake = "handshake"
)

const (
	defaultLivenessFallback = 30 * time.Second

	// defaultShutdownGrace bounds how long shutdown waits for tracked
	// goroutines after they have been told to stop.
	//
	// It has to be comfortably smaller than the deadline the host gives the
	// whole teardown, and it was not: the mobile runtime allows 5 s for all of
	// shutdown, and this step alone was allowed the same 5 s, so any drain that
	// did not finish immediately pushed the whole stop past its deadline. On a
	// phone that showed up as a tunnel that could not be switched to another
	// room. A goroutine still alive two seconds after being cancelled is stuck
	// rather than busy, and waiting longer for it only delays the tunnel the
	// user asked for next.
	defaultShutdownGrace = 2 * time.Second
)

// Client handles local SOCKS5 connections and tunnels them to the server.
type Client struct {
	ln          transport.Transport
	keys        *crypto.KeySet
	pair        *tunnelcore.SessionPair
	conn        *muxconn.Conn
	controlConn *muxconn.Conn
	session     *smux.Session
	controlSess *smux.Session
	controlStrm *smux.Stream
	controlStop context.CancelFunc
	sessMu      sync.RWMutex
	reconnectMu sync.Mutex
	health      *runtime.HealthTracker

	// controlLastPong is independent corroboration for the transport's fast
	// peer-restart heuristic, not a second session reconnect detector.
	controlLastPong  atomic.Value // time.Time
	deviceID         string
	sessionID        string
	claims           map[string]any
	dnsServer        string
	socksUser        string
	socksPass        string
	sessionReady     chan struct{}
	wg               sync.WaitGroup
	socksMu          sync.Mutex
	socksConns       map[net.Conn]struct{}
	socksClosed      bool
	livenessFallback time.Duration
	shutdownGrace    time.Duration

	// ai-generated: recovery, handshakeTimeout and retryDelay (olcrtc#19).
	// recovery is the attempt re-establishing the session, if one is (see
	// recovery.go). handshakeTimeout and retryDelay stand in for
	// handshake.DefaultTimeout and the first pause between reconnect
	// handshakes; zero means the default, and only tests set them.
	recovery         recovery
	handshakeTimeout time.Duration
	retryDelay       time.Duration

	// parked counts the requests waiting for a session that is not there
	// (tunnelWhenReady, waitSessionReady). With a tun2socks in front every
	// one of them is also a session over there, with a stack of its own that
	// no Go memory limit sees, and a phone whose apps retry through a network
	// gap parks hundreds in seconds (olcbox#37). maxParkedRequests bounds
	// it; parkedSaturated keeps the warning to one line per episode.
	// sessionReadyTimeout is how long a request waits; zero means the default.
	parked              atomic.Int32
	parkedSaturated     atomic.Bool
	sessionReadyTimeout time.Duration

	// UDP relay state: one entry per (association, SOCKS source, target).
	udpMu        sync.Mutex
	udpFlows     map[uint64]clientUDPFlow
	udpFlowIndex map[clientUDPFlowKey]uint64
	// udpSweepOnce starts the one idle-flow sweeper shared by every association.
	udpSweepOnce sync.Once
	udpDisabled  bool
	maxUDPFlows  int

	// DNS over the stream (dns.go): queries in flight, and the session the
	// info line was last written for.
	dnsInFlight         atomic.Int32
	dnsAnnouncedSession string

	// rules names the destinations dialed directly (direct.go); nil sends
	// everything through the tunnel. dialer opens those sockets, protected
	// and resolving through the session's lookup; exchanger answers direct
	// names' queries on the resolver ring (dns.go), when the lookup is one;
	// directUDP is the flows this process relays itself (direct_udp.go).
	rules              *route.Rules
	dialer             *protect.Dialer
	exchanger          protect.Exchanger
	directUDP          map[clientUDPFlowKey]*directUDPFlow
	dnsDirectAnnounced atomic.Bool
}

// HealthFunc is called when the client control health snapshot changes.
type HealthFunc func(control.Status)

// Config holds runtime configuration for [Run], [RunWithReady], and [RunWithAddress].
type Config struct {
	Transport        string
	Provider         string
	RoomURL          string
	ChannelID        string
	KeyHex           string
	LocalAddr        string
	DNSServer        string
	Resolver         protect.Lookup
	SOCKSUser        string
	SOCKSPass        string
	TransportOptions transport.Options
	Engine           string
	URL              string
	Token            string
	ProviderToken    string
	Liveness         control.Config
	Traffic          transport.TrafficConfig
	DeviceID         string
	DeviceIDPath     string
	Claims           map[string]any
	OnHealth         HealthFunc
	// UDPDisabled turns the SOCKS5 UDP ASSOCIATE relay off; UDPMaxFlows caps
	// concurrent flows (0 means the default).
	UDPDisabled bool
	UDPMaxFlows int
	// Direct names the destinations dialed from this process instead of
	// through the tunnel; nil, the default, tunnels everything.
	Direct *route.Rules
}

// Run starts the client with the given configuration.
func Run(ctx context.Context, cfg Config) error {
	return RunWithAddress(ctx, cfg, nil)
}

// RunWithReady starts the client and invokes onReady after the SOCKS listener opens.
func RunWithReady(ctx context.Context, cfg Config, onReady func()) error {
	if onReady == nil {
		return RunWithAddress(ctx, cfg, nil)
	}
	return RunWithAddress(ctx, cfg, func(string) { onReady() })
}

// RunWithAddress starts the client and reports the actual SOCKS listener address.
func RunWithAddress(ctx context.Context, cfg Config, onReady func(actualAddr string)) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	keys, err := tunnelcore.SetupKeySet(cfg.KeyHex, crypto.Client)
	if err != nil {
		return fmt.Errorf("setup key set: %w", err)
	}
	deviceID, err := resolveDeviceID(cfg.DeviceID, cfg.DeviceIDPath)
	if err != nil {
		return fmt.Errorf("resolve device id: %w", err)
	}
	client := &Client{
		keys: keys, deviceID: deviceID, claims: cfg.Claims, dnsServer: cfg.DNSServer,
		socksUser: cfg.SOCKSUser, socksPass: cfg.SOCKSPass,
		health: runtime.NewHealthTracker(cfg.OnHealth), sessionReady: make(chan struct{}),
		udpFlows: make(map[uint64]clientUDPFlow), udpFlowIndex: make(map[clientUDPFlowKey]uint64),
		udpDisabled: cfg.UDPDisabled, maxUDPFlows: normalizeMaxUDPFlows(cfg.UDPMaxFlows),
		rules: cfg.Direct, dialer: protect.NewDialer(cfg.Resolver),
	}
	if exchanger, ok := cfg.Resolver.(protect.Exchanger); ok {
		client.exchanger = exchanger
	}
	defer func() {
		cancel()
		client.shutdown()
	}()
	if bringUpErr := client.bringUpLink(runCtx, cfg, cancel); bringUpErr != nil {
		return bringUpErr
	}
	listener, err := (&net.ListenConfig{}).Listen(runCtx, "tcp4", cfg.LocalAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", cfg.LocalAddr, err)
	}
	defer func() { _ = listener.Close() }()
	actualAddr := listener.Addr().String()
	logger.Infof("SOCKS5 server listening on %s", actualAddr)
	if client.rules != nil {
		logger.Infof("direct rules: %s", client.rules.Summary())
	}
	if onReady != nil {
		onReady(actualAddr)
	}
	client.goTracked(func() { client.acceptLoop(runCtx, listener) })
	<-runCtx.Done()
	return nil
}

// registerSocksConn tracks conn so shutdown can close it, and enforces the
// concurrency cap. It reports false when the cap is reached or the client is
// tearing down; the caller then closes conn itself.
func (c *Client) registerSocksConn(conn net.Conn) bool {
	c.socksMu.Lock()
	defer c.socksMu.Unlock()
	if c.socksClosed {
		return false
	}
	if len(c.socksConns) >= maxSocksConns {
		logger.Warnf("SOCKS5: %d concurrent connections reached, refusing new ones", maxSocksConns)
		return false
	}
	if c.socksConns == nil {
		c.socksConns = make(map[net.Conn]struct{})
	}
	c.socksConns[conn] = struct{}{}
	return true
}

func (c *Client) unregisterSocksConn(conn net.Conn) {
	c.socksMu.Lock()
	delete(c.socksConns, conn)
	c.socksMu.Unlock()
}

// closeSocksConns closes every live SOCKS connection. Without it shutdown
// would have to wait out the negotiation deadline of a client that connected
// and then went quiet.
func (c *Client) closeSocksConns() {
	c.socksMu.Lock()
	conns := c.socksConns
	c.socksConns = nil
	c.socksClosed = true
	c.socksMu.Unlock()
	for conn := range conns {
		_ = conn.Close()
	}
}

func (c *Client) goTracked(fn func()) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		fn()
	}()
}

func resolveDeviceID(deviceID, path string) (string, error) {
	if deviceID != "" {
		return deviceID, nil
	}
	if path == "" {
		return uuid.NewString(), nil
	}
	data, err := os.ReadFile(path) // #nosec G304 - path is explicit user configuration
	if err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			return id, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read device id %s: %w", path, err)
	}
	id := uuid.NewString()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", fmt.Errorf("mkdir device id dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write device id %s: %w", path, err)
	}
	return id, nil
}
