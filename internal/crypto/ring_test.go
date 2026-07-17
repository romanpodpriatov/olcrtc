package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func hexKey(b byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = b
	}
	return hex.EncodeToString(raw)
}

func TestNewRingRejectsEmptyAndBadKeys(t *testing.T) {
	if _, err := NewRing(nil); !errors.Is(err, ErrEmptyRing) {
		t.Fatalf("empty ring: got %v", err)
	}
	if _, err := NewRing([]string{"zz"}); err == nil {
		t.Fatal("bad hex accepted")
	}
	if _, err := NewRing([]string{"aabb"}); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestRingTryOpenPicksTheRightKeyOfThree(t *testing.T) {
	keys := []string{hexKey(0x11), hexKey(0x22), hexKey(0x33)}
	ring, err := NewRing(keys)
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	if ring.Len() != 3 {
		t.Fatalf("len=%d", ring.Len())
	}

	// Encrypt with the SECOND key using an independent cipher instance
	// (as a real client would).
	raw, _ := hex.DecodeString(keys[1])
	sender, err := NewCipher(string(raw))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	ct, err := sender.Encrypt([]byte("hello metering"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	pt, entry, err := ring.TryOpen(nil, ct)
	if err != nil {
		t.Fatalf("TryOpen: %v", err)
	}
	if string(pt) != "hello metering" {
		t.Fatalf("plaintext=%q", pt)
	}
	sum := sha256.Sum256(raw)
	wantID := hex.EncodeToString(sum[:])[:KeyIDLen]
	if entry.KeyID != wantID {
		t.Fatalf("keyID=%s want=%s", entry.KeyID, wantID)
	}
}

func TestRingTryOpenRejectsUnknownKey(t *testing.T) {
	ring, err := NewRing([]string{hexKey(0x11)})
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	raw, _ := hex.DecodeString(hexKey(0x99))
	outsider, _ := NewCipher(string(raw))
	ct, _ := outsider.Encrypt([]byte("free ride"))
	if _, _, err := ring.TryOpen(nil, ct); !errors.Is(err, ErrNoRingMatch) {
		t.Fatalf("unknown key: got %v", err)
	}
}

func TestRingDedupesIdenticalKeys(t *testing.T) {
	ring, err := NewRing([]string{hexKey(0x11), strings.ToUpper(hexKey(0x11)), hexKey(0x22)})
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	if ring.Len() != 2 {
		t.Fatalf("dedupe failed: len=%d", ring.Len())
	}
}

func TestKeyIDFromHexStableAndCaseInsensitive(t *testing.T) {
	id1, err := KeyIDFromHex(hexKey(0x42))
	if err != nil {
		t.Fatalf("KeyIDFromHex: %v", err)
	}
	id2, err := KeyIDFromHex(strings.ToUpper(hexKey(0x42)))
	if err != nil {
		t.Fatalf("KeyIDFromHex upper: %v", err)
	}
	if id1 != id2 || len(id1) != KeyIDLen {
		t.Fatalf("id1=%s id2=%s", id1, id2)
	}
	if _, err := KeyIDFromHex("nothex"); err == nil {
		t.Fatal("bad hex accepted")
	}
}
