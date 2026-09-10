package e2e

import (
	"bufio"
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/client"
	"github.com/openlibrecommunity/olcrtc/internal/server"
)

const (
	altKeyHex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	badKeyHex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

// ringTunnel is what startRingTunnel brought up: the client's SOCKS address,
// the server's /stats address (empty unless asked for) and whether the
// client became ready within its budget.
type ringTunnel struct {
	socksAddr string
	statsAddr string
	ready     bool
}

// startRingTunnel runs a server holding the ring and a client holding
// clientKey. With withStats the server also serves /stats on a loopback port.
func startRingTunnel(
	t *testing.T, ring []string, clientKey string, withStats bool, readyBudget time.Duration,
) ringTunnel {
	t.Helper()
	providerName, room := registerMemoryProvider(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	socksAddr := freeLocalAddr(ctx, t)
	statsAddr := ""
	if withStats {
		statsAddr = freeLocalAddr(ctx, t)
	}
	go func() {
		_ = server.Run(ctx, server.Config{
			Transport: transportData, Provider: providerName, RoomURL: testRoom,
			Keys: ring, StatsListen: statsAddr, DNSServer: localDNSServer,
		})
	}()
	room.waitConnected(t, 1)
	ready := make(chan struct{})
	go func() {
		_ = client.RunWithReady(ctx, client.Config{
			Transport: transportData, Provider: providerName, RoomURL: testRoom,
			KeyHex: clientKey, DeviceID: testClientDeviceID, LocalAddr: socksAddr, DNSServer: localDNSServer,
		}, func() { close(ready) })
	}()
	tunnel := ringTunnel{socksAddr: socksAddr, statsAddr: statsAddr}
	select {
	case <-ready:
		tunnel.ready = true
	case <-time.After(readyBudget):
	}
	return tunnel
}

func TestMultiKeySecondRingKeyPairsAndRelays(t *testing.T) {
	echoAddr := startEchoServer(t)
	tunnel := startRingTunnel(t, []string{testKeyHex, altKeyHex}, altKeyHex, false, 20*time.Second)
	if !tunnel.ready {
		t.Fatal("client holding the second ring key never became ready")
	}
	echoOnce(t, tunnel.socksAddr, echoAddr, "olcrtc-multikey")
}

// echoOnce drives one SOCKS echo round trip and closes the stream, which is
// when the server attributes the stream's bytes.
func echoOnce(t *testing.T, socksAddr, echoAddr, tag string) int {
	t.Helper()
	conn := connectViaSOCKS(t, socksAddr, echoAddr)
	defer func() { _ = conn.Close() }()
	payload := []byte(tag + "\n")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil || !bytes.Equal(line, payload) {
		t.Fatalf("echo = %q, %v", line, err)
	}
	return len(payload)
}

func TestMultiKeyUnknownKeyNeverPairs(t *testing.T) {
	echoAddr := startEchoServer(t)
	tunnel := startRingTunnel(t, []string{testKeyHex, altKeyHex}, badKeyHex, false, 3*time.Second)
	if tunnel.ready {
		// The SOCKS listener opens only after the handshake; a client outside
		// the ring must never get there.
		conn := connectViaSOCKS(t, tunnel.socksAddr, echoAddr)
		_ = conn.Close()
		t.Fatal("a key outside the ring paired")
	}
}
