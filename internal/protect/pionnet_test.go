// SPDX-License-Identifier: WTFPL

package protect

import (
	"context"
	"errors"
	"net"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/fakedns"
	"github.com/pion/transport/v4"
)

func TestIsTunInterface(t *testing.T) {
	t.Parallel()

	cases := map[string]bool{
		"tun0":   true,
		"tun":    true,
		"ppp0":   true,
		"pptp0":  true,
		"wlan0":  false,
		"eth0":   false,
		"rmnet0": false,
		"lo":     false,
	}
	for name, want := range cases {
		if got := isTunInterface(name); got != want {
			t.Errorf("isTunInterface(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestInterfacesHidesTun(t *testing.T) {
	t.Parallel()

	n, err := NewProtectedNet()
	if err != nil {
		t.Fatalf("NewProtectedNet: %v", err)
	}
	ifaces, err := n.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}
	for _, ifc := range ifaces {
		if isTunInterface(ifc.Name) {
			t.Errorf("Interfaces returned tun device %q", ifc.Name)
		}
	}
}

func TestInterfaceByNameRejectsTun(t *testing.T) {
	t.Parallel()

	n, err := NewProtectedNet()
	if err != nil {
		t.Fatalf("NewProtectedNet: %v", err)
	}
	if _, err := n.InterfaceByName("tun0"); !errors.Is(err, transport.ErrInterfaceNotFound) {
		t.Errorf("InterfaceByName(tun0) error = %v, want %v", err, transport.ErrInterfaceNotFound)
	}
}

// TestControlFuncFailClosed verifies that Protector can reject a socket.
func TestControlFuncFailClosed(t *testing.T) {
	old := Protector
	t.Cleanup(func() { Protector = old })

	Protector = func(int) bool { return false }
	lc := net.ListenConfig{Control: controlFunc}
	pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err == nil {
		_ = pc.Close()
		t.Fatal("expected protected ListenPacket to fail when Protector rejects fd")
	}
}

// TestControlFuncProtects verifies that Protector receives a real fd.
func TestControlFuncProtects(t *testing.T) {
	old := Protector
	t.Cleanup(func() { Protector = old })

	var calls int
	Protector = func(fd int) bool {
		if fd < 0 {
			t.Errorf("protector got negative fd %d", fd)
		}
		calls++
		return true
	}
	lc := net.ListenConfig{Control: controlFunc}
	pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer func() { _ = pc.Close() }()
	if calls == 0 {
		t.Error("protector was not invoked")
	}
}

// TestCreateDialerProtectsAndChains verifies that CreateDialer copies the
// caller's Dialer and keeps the caller's Control hook.
func TestCreateDialerProtectsAndChains(t *testing.T) {
	old := Protector
	t.Cleanup(func() { Protector = old })

	var protectorRan bool
	Protector = func(int) bool { protectorRan = true; return true }

	n, err := NewProtectedNet()
	if err != nil {
		t.Fatalf("NewProtectedNet: %v", err)
	}

	// Dial a local TCP listener.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		if c, aerr := ln.Accept(); aerr == nil {
			_ = c.Close()
		}
	}()

	var callerControlRan bool
	caller := &net.Dialer{
		Control: func(_, _ string, _ syscall.RawConn) error {
			callerControlRan = true
			return nil
		},
	}
	callerControl := caller.Control

	dialer := n.CreateDialer(caller)

	// Keep the caller's Control unchanged.
	if reflect.ValueOf(caller.Control).Pointer() != reflect.ValueOf(callerControl).Pointer() {
		t.Error("CreateDialer mutated the caller's Dialer.Control")
	}

	conn, err := dialer.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial via CreateDialer: %v", err)
	}
	_ = conn.Close()

	if !protectorRan {
		t.Error("protector hook did not run for the CreateDialer dialer")
	}
	if !callerControlRan {
		t.Error("caller's Control hook did not run (chain dropped it)")
	}
}

// TestCreateDialerProtectsAndChainsControlContext verifies that CreateDialer
// keeps the caller's ControlContext hook.
func TestCreateDialerProtectsAndChainsControlContext(t *testing.T) {
	old := Protector
	t.Cleanup(func() { Protector = old })

	var protectorRan bool
	Protector = func(int) bool { protectorRan = true; return true }

	n, err := NewProtectedNet()
	if err != nil {
		t.Fatalf("NewProtectedNet: %v", err)
	}

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		if c, aerr := ln.Accept(); aerr == nil {
			_ = c.Close()
		}
	}()

	var callerControlContextRan bool
	caller := &net.Dialer{
		ControlContext: func(_ context.Context, _, _ string, _ syscall.RawConn) error {
			callerControlContextRan = true
			return nil
		},
	}
	callerControlContext := caller.ControlContext

	dialer := n.CreateDialer(caller)

	if reflect.ValueOf(caller.ControlContext).Pointer() != reflect.ValueOf(callerControlContext).Pointer() {
		t.Error("CreateDialer mutated the caller's Dialer.ControlContext")
	}

	conn, err := dialer.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial via CreateDialer: %v", err)
	}
	_ = conn.Close()

	if !protectorRan {
		t.Error("protector hook did not run for the CreateDialer dialer")
	}
	if !callerControlContextRan {
		t.Error("caller's ControlContext hook did not run (chain dropped it)")
	}
}

const turnTestIP = "192.0.2.40"

// Pion resolves its STUN and TURN servers through the Net it is handed, and
// the shim used to leave that to Pion's standard net - the system resolver,
// which inside an iOS packet tunnel is the tunnel's own, unserved until the
// cores are up. Server names now go the way of every other protected lookup:
// the configured servers first, the host's resolver behind them.
func TestProtectedNetResolvesServerNamesThroughTheConfiguredServers(t *testing.T) {
	dns, err := fakedns.Start(map[string]string{"turn.test": turnTestIP})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dns.Close() }()
	SetDNSServers(dns.Addr)
	t.Cleanup(func() { SetDNSServers() })

	n, err := NewProtectedNet()
	if err != nil {
		t.Fatal(err)
	}
	udp, err := n.ResolveUDPAddr("udp4", "turn.test:3478")
	if err != nil {
		t.Fatalf("ResolveUDPAddr() = %v", err)
	}
	if udp.IP.String() != turnTestIP || udp.Port != 3478 {
		t.Fatalf("ResolveUDPAddr() = %v, want %s:3478", udp, turnTestIP)
	}
	tcp, err := n.ResolveTCPAddr("tcp", "turn.test:443")
	if err != nil {
		t.Fatalf("ResolveTCPAddr() = %v", err)
	}
	if tcp.IP.String() != turnTestIP || tcp.Port != 443 {
		t.Fatalf("ResolveTCPAddr() = %v, want %s:443", tcp, turnTestIP)
	}
	if dns.Queries() == 0 {
		t.Fatal("the configured server was never asked")
	}
}

// A literal passes through untouched, zone and all: link-local candidates
// carry one, and a lookup would have nothing to add.
func TestProtectedNetKeepsALiteralAddressAsItIs(t *testing.T) {
	n, err := NewProtectedNet()
	if err != nil {
		t.Fatal(err)
	}
	literal, err := n.ResolveUDPAddr("udp", "[fe80::1%lo]:1")
	if err != nil {
		t.Fatalf("ResolveUDPAddr() of a literal = %v", err)
	}
	if literal.Zone != "lo" || literal.Port != 1 || literal.IP.String() != "fe80::1" {
		t.Fatalf("ResolveUDPAddr() of a literal = %v, want fe80::1 with zone lo and port 1", literal)
	}
}

// And when the configured servers are dark, the host's resolver answers for
// Pion too - the same fallback the dialers have, not a lookup that dies with
// the first silent server.
func TestProtectedNetFallsBackToTheHostResolver(t *testing.T) {
	silent, err := fakedns.StartSilent()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()
	system, err := fakedns.Start(map[string]string{"turn.test": "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = system.Close() }()
	SetDNSServers(silent.Addr)
	swapSystemResolver(t, NewResolver(system.Addr))
	t.Cleanup(func() { SetDNSServers() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())

	n, err := NewProtectedNet()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := n.Dial("udp", net.JoinHostPort("turn.test", port))
	if err != nil {
		t.Fatalf("Dial() = %v, want the host's resolver to answer", err)
	}
	_ = conn.Close()
	direct, err := DialContext(ctx, "udp", net.JoinHostPort("turn.test", port))
	if err != nil {
		t.Fatalf("DialContext(udp) = %v, want the host's resolver to answer", err)
	}
	_ = direct.Close()
}
