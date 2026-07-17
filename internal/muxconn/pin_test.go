package muxconn

import (
	"encoding/hex"
	"testing"
	"time"

	cryptopkg "github.com/openlibrecommunity/olcrtc/internal/crypto"
)

func ringOf(t *testing.T, bytesVals ...byte) (*cryptopkg.Ring, []*cryptopkg.Cipher) {
	t.Helper()
	keys := make([]string, len(bytesVals))
	senders := make([]*cryptopkg.Cipher, len(bytesVals))
	for i, b := range bytesVals {
		raw := make([]byte, 32)
		for j := range raw {
			raw[j] = b
		}
		keys[i] = hex.EncodeToString(raw)
		s, err := cryptopkg.NewCipher(string(raw))
		if err != nil {
			t.Fatalf("NewCipher: %v", err)
		}
		senders[i] = s
	}
	ring, err := cryptopkg.NewRing(keys)
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	return ring, senders
}

// A grouped conn pins on the first frame that any ring key opens, and the
// plaintext round-trips like the legacy path.
func TestGroupedConnPinsOnFirstMatchingFrame(t *testing.T) {
	ring, senders := ringOf(t, 0xA1, 0xB2, 0xC3)
	g := NewPinGroup(ring)
	conn := NewGrouped(&stubLink{canSend: true}, g)

	if g.Pinned() != nil {
		t.Fatal("pinned before any frame")
	}

	ct, err := senders[2].Encrypt([]byte("first frame"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	conn.Push(ct)

	entry := g.Pinned()
	if entry == nil {
		t.Fatal("not pinned after matching frame")
	}
	if entry.KeyID != ring.Entries()[2].KeyID {
		t.Fatalf("pinned wrong key: %s", entry.KeyID)
	}

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "first frame" {
		t.Fatalf("Read=%q err=%v", buf[:n], err)
	}
}

// Frames under a key outside the ring never pin and never surface bytes.
func TestGroupedConnDropsUnknownKeyFrames(t *testing.T) {
	ring, _ := ringOf(t, 0xA1)
	_, outsiders := ringOf(t, 0xEE)
	g := NewPinGroup(ring)
	conn := NewGrouped(&stubLink{canSend: true}, g)

	ct, _ := outsiders[0].Encrypt([]byte("free ride"))
	conn.Push(ct)

	if g.Pinned() != nil {
		t.Fatal("outsider frame pinned the group")
	}
	select {
	case bp := <-conn.in:
		t.Fatalf("unexpected frame surfaced: %q", *bp)
	default:
	}
}

// Write blocks until the group pins, then encrypts under the pinned key —
// never under a guessed one.
func TestGroupedConnWriteWaitsForPin(t *testing.T) {
	ring, senders := ringOf(t, 0xA1, 0xB2)
	g := NewPinGroup(ring)
	link := &stubLink{canSend: true}
	conn := NewGrouped(link, g)

	wrote := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("server says hi"))
		wrote <- err
	}()

	select {
	case err := <-wrote:
		t.Fatalf("Write returned before pin: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	// Client's first frame arrives under key #1 → pins → Write proceeds.
	ct, _ := senders[1].Encrypt([]byte("hello"))
	conn.Push(ct)

	select {
	case err := <-wrote:
		if err != nil {
			t.Fatalf("Write after pin: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Write still blocked after pin")
	}

	link.mu.Lock()
	defer link.mu.Unlock()
	if len(link.sent) != 1 {
		t.Fatalf("sent %d frames", len(link.sent))
	}
	// The emitted frame must decrypt under the PINNED key (entry 1), not any other.
	if _, err := ring.Entries()[1].Cipher.Decrypt(link.sent[0]); err != nil {
		t.Fatalf("server frame not under pinned key: %v", err)
	}
	if _, err := ring.Entries()[0].Cipher.Decrypt(link.sent[0]); err == nil {
		t.Fatal("server frame decrypts under a non-pinned key")
	}
}

// Close unblocks a pin-waiting Write with ErrClosed (dead peers can't wedge
// the server forever; smux teardown closes the conn).
func TestGroupedConnWriteUnblocksOnClose(t *testing.T) {
	ring, _ := ringOf(t, 0xA1)
	conn := NewGrouped(&stubLink{canSend: true}, NewPinGroup(ring))

	wrote := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("never sent"))
		wrote <- err
	}()
	time.Sleep(20 * time.Millisecond)
	_ = conn.Close()

	select {
	case err := <-wrote:
		if err != ErrClosed {
			t.Fatalf("want ErrClosed, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Write did not unblock on Close")
	}
}

// Two conns sharing a group (data + control planes of one peer): a pin made
// through one conn is immediately visible to the other.
func TestPinIsSharedAcrossGroupConns(t *testing.T) {
	ring, senders := ringOf(t, 0xA1, 0xB2)
	g := NewPinGroup(ring)
	control := NewGrouped(&stubLink{canSend: true}, g)
	data := NewGrouped(&stubLink{canSend: true}, g)

	ct, _ := senders[0].Encrypt([]byte("CLIENT_HELLO"))
	control.Push(ct)

	if data.Group().KeyID() != ring.Entries()[0].KeyID {
		t.Fatalf("data conn does not see the shared pin: %q", data.Group().KeyID())
	}
	// Data-plane write proceeds without the data conn ever seeing inbound bytes.
	if _, err := data.Write([]byte("welcome over data")); err != nil {
		t.Fatalf("data Write: %v", err)
	}
}

// Legacy constructors behave exactly as before: pinned from birth, "" KeyID.
func TestPrePinnedLegacyPathUnchanged(t *testing.T) {
	cipher := newTestCipher(t)
	conn := New(&stubLink{canSend: true}, cipher)
	if conn.Group().Pinned() == nil {
		t.Fatal("legacy conn not pre-pinned")
	}
	if id := conn.Group().KeyID(); id != "" {
		t.Fatalf("legacy KeyID = %q", id)
	}
	if _, err := conn.Write([]byte("immediate")); err != nil {
		t.Fatalf("legacy Write blocked: %v", err)
	}
}
