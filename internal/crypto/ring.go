// Ring holds an ordered set of candidate ciphers for multi-key pairing.
//
// ProofKit fork: a srv may serve clients holding different room keys (one
// per user). A peer's first inbound frame is trial-decrypted against every
// ring entry; the entry whose AEAD opens the frame identifies the peer's
// key. XChaCha20-Poly1305 makes the trial unambiguous: a wrong key fails
// the Poly1305 tag check cleanly instead of yielding garbage plaintext.
package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// KeyIDLen is the length of the hex key identifier exposed in stats.
const KeyIDLen = 16

// ErrNoRingMatch is returned when no ring entry can open a ciphertext.
var ErrNoRingMatch = errors.New("no ring key opens this frame")

// ErrEmptyRing is returned when a Ring is built with zero keys.
var ErrEmptyRing = errors.New("ring requires at least one key")

// RingEntry pairs a cipher with the stable identifier used for metering.
// KeyID is hex(sha256(raw 32-byte key))[:KeyIDLen] — never the key itself.
type RingEntry struct {
	Cipher *Cipher
	KeyID  string
}

// Ring is an immutable, ordered candidate set. Safe for concurrent use:
// entries are read-only after construction and Cipher is internally
// thread-safe (atomic nonce counter; stateless decrypt).
type Ring struct {
	entries []RingEntry
}

// KeyIDFromHex derives the metering key id from a 64-hex key string.
// The digest is over the DECODED raw key bytes, so the id is stable no
// matter how the hex is cased. Callers validate the hex separately; on
// invalid hex this returns an error rather than a bogus id.
func KeyIDFromHex(keyHex string) (string, error) {
	raw, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("key id: decode hex: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:KeyIDLen], nil
}

// NewRing builds a ring from 64-hex key strings, preserving order and
// dropping exact duplicates (same raw bytes). Order matters only for
// trial cost: put the most likely key first.
func NewRing(keysHex []string) (*Ring, error) {
	if len(keysHex) == 0 {
		return nil, ErrEmptyRing
	}
	seen := make(map[string]struct{}, len(keysHex))
	entries := make([]RingEntry, 0, len(keysHex))
	for i, kh := range keysHex {
		raw, err := hex.DecodeString(kh)
		if err != nil {
			return nil, fmt.Errorf("ring key %d: decode hex: %w", i, err)
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf("ring key %d: %w, got %d bytes", i, ErrInvalidKeySize, len(raw))
		}
		if _, dup := seen[string(raw)]; dup {
			continue
		}
		seen[string(raw)] = struct{}{}
		c, err := NewCipher(string(raw))
		if err != nil {
			return nil, fmt.Errorf("ring key %d: %w", i, err)
		}
		sum := sha256.Sum256(raw)
		entries = append(entries, RingEntry{
			Cipher: c,
			KeyID:  hex.EncodeToString(sum[:])[:KeyIDLen],
		})
	}
	return &Ring{entries: entries}, nil
}

// Single wraps an already-built cipher as a one-entry ring. keyID may be
// empty when the caller has no metering identity for it (legacy paths).
func Single(c *Cipher, keyID string) *Ring {
	return &Ring{entries: []RingEntry{{Cipher: c, KeyID: keyID}}}
}

// Len reports the number of ring entries.
func (r *Ring) Len() int { return len(r.entries) }

// Entries returns the ordered entries. Callers must not mutate the slice.
func (r *Ring) Entries() []RingEntry { return r.entries }

// TryOpen attempts each entry in order, returning the plaintext (appended
// to dst, which may be nil) and the entry that opened it. A ciphertext no
// entry can open yields ErrNoRingMatch.
func (r *Ring) TryOpen(dst, ciphertext []byte) ([]byte, *RingEntry, error) {
	for i := range r.entries {
		pt, err := r.entries[i].Cipher.DecryptInto(dst, ciphertext)
		if err == nil {
			return pt, &r.entries[i], nil
		}
	}
	return nil, nil, ErrNoRingMatch
}
