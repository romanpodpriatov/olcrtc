package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/openlibrecommunity/olcrtc/internal/app/session"
)

const (
	testModeSrv      = "srv"
	testAuthProvider = "wbstream"
	testRoomID       = "r1"
	testCryptoKey    = "deadbeef"
	testDNSServer    = "8.8.8.8:53"
)

func TestLoadAndApply(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "olcrtc.yaml")
	body := `
mode: srv
link: direct
auth:
  provider: wbstream
room:
  id: r1
crypto:
  key: deadbeef
net:
  transport: datachannel
  dns: 8.8.8.8:53
socks:
  host: 127.0.0.1
  port: 1080
  user: u
  pass: p
vp8:
  fps: 25
  batch_size: 4
liveness:
  interval: 2s
  timeout: 500ms
  failures: 4
lifecycle:
  max_session_duration: 6h
traffic:
  max_payload_size: 4096
  min_delay: 5ms
  max_delay: 30ms
udp:
  disabled: true
  max_flows: 77
gen:
  amount: 3
debug: true
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	requireLoadedFile(t, f)

	got := Apply(session.Config{}, f)
	requireAppliedConfig(t, got)
}

func requireLoadedFile(t *testing.T, f File) {
	t.Helper()
	if f.Mode != testModeSrv {
		t.Fatalf("Mode = %q, want %q", f.Mode, testModeSrv)
	}
	if f.Auth.Provider != testAuthProvider {
		t.Fatalf("Auth.Provider = %q, want %q", f.Auth.Provider, testAuthProvider)
	}
	if f.Room.ID != testRoomID {
		t.Fatalf("Room.ID = %q, want %q", f.Room.ID, testRoomID)
	}
	if f.Crypto.Key != testCryptoKey {
		t.Fatalf("Crypto.Key = %q, want %q", f.Crypto.Key, testCryptoKey)
	}
}

func requireAppliedConfig(t *testing.T, got session.Config) {
	t.Helper()
	want := session.Config{
		Mode:                  testModeSrv,
		Auth:                  testAuthProvider,
		RoomID:                testRoomID,
		KeyHex:                testCryptoKey,
		Transport:             "datachannel",
		DNSServer:             testDNSServer,
		SOCKSHost:             "127.0.0.1",
		SOCKSPort:             1080,
		SOCKSUser:             "u",
		SOCKSPass:             "p",
		VP8:                   session.VP8Config{FPS: 25, BatchSize: 4},
		LivenessInterval:      "2s",
		LivenessTimeout:       "500ms",
		LivenessFailures:      4,
		MaxSessionDuration:    "6h",
		TrafficMaxPayloadSize: 4096,
		TrafficMinDelay:       "5ms",
		TrafficMaxDelay:       "30ms",
		UDPDisabled:           true,
		UDPMaxFlows:           77,
		Amount:                3,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Apply produced wrong config: %+v, want %+v", got, want)
	}
}

func TestApplyCLIWins(t *testing.T) {
	cli := session.Config{
		Mode:      "cnc",
		KeyHex:    "from-cli",
		SOCKSPort: 9999,
	}
	f := File{
		Mode:   testModeSrv,
		Crypto: Crypto{Key: "from-yaml"},
		SOCKS:  SOCKS{Port: 1234, Host: "0.0.0.0"},
	}
	got := Apply(cli, f)
	if got.Mode != "cnc" {
		t.Errorf("Mode: got %q, want cnc (CLI wins)", got.Mode)
	}
	if got.KeyHex != "from-cli" {
		t.Errorf("KeyHex: got %q, want from-cli (CLI wins)", got.KeyHex)
	}
	if got.SOCKSPort != 9999 {
		t.Errorf("SOCKSPort: got %d, want 9999 (CLI wins)", got.SOCKSPort)
	}
	if got.SOCKSHost != "0.0.0.0" {
		t.Errorf("SOCKSHost: got %q, want 0.0.0.0 (YAML fills empty CLI)", got.SOCKSHost)
	}
}

func TestLoadAndApplyProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "olcrtc.yaml")
	body := `
mode: srv
link: direct
crypto:
  key: shared-key
net:
  dns: 8.8.8.8:53
liveness:
  interval: 5s
  timeout: 2s
  failures: 5
lifecycle:
  max_session_duration: 6h
traffic:
  max_payload_size: 8192
  min_delay: 10ms
  max_delay: 40ms
udp:
  enabled: true
  max_flows: 100
profiles:
  - name: wb-vp8
    auth:
      provider: wbstream
    room:
      id: wb-room
    net:
      transport: vp8channel
    vp8:
      fps: 30
    liveness:
      interval: 1s
    lifecycle:
      max_session_duration: 30m
    traffic:
      max_payload_size: 4096
      max_delay: 20ms
    udp:
      disabled: true
      max_flows: 10
  - name: jitsi-dc
    auth:
      provider: jitsi
    room:
      id: https://meet.example/room
    net:
      transport: datachannel
      dns: 8.8.8.8:53
failover:
  retry_delay: 100ms
  max_cycles: 2
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(f.Profiles) != 2 {
		t.Fatalf("profiles = %d, want 2", len(f.Profiles))
	}
	if f.Failover.RetryDelay != "100ms" || f.Failover.MaxCycles != 2 {
		t.Fatalf("Failover = %+v, want retry_delay 100ms max_cycles 2", f.Failover)
	}

	base := Apply(session.Config{}, f)
	first := ApplyProfile(base, f.Profiles[0])
	requireFirstProfile(t, first)
	second := ApplyProfile(base, f.Profiles[1])
	requireSecondProfile(t, second)
}

func TestApplyProfileCanOverrideUDPZeroValues(t *testing.T) {
	// ProofKit fork: re-enabling takes an explicit `enabled: true` — a bare
	// `disabled: false` is a no-op (the fork's opt-in gate).
	enabled := true
	maxFlows := 0
	base := session.Config{UDPDisabled: true, UDPMaxFlows: 10}
	got := ApplyProfile(base, Profile{UDP: UDP{Enabled: &enabled, MaxFlows: &maxFlows}})

	if got.UDPDisabled {
		t.Fatal("UDPDisabled = true, want false")
	}
	if got.UDPMaxFlows != 0 {
		t.Fatalf("UDPMaxFlows = %d, want 0", got.UDPMaxFlows)
	}
}

// TestForkUDPGateDefaultsOff locks the ProofKit fork's opt-in gate: a config
// without `udp: { enabled: true }` must run UDP-disabled (byte-identical to
// the pre-UDP fork build), and `disabled: true` must beat `enabled: true`.
func TestForkUDPGateDefaultsOff(t *testing.T) {
	if got := Apply(session.Config{}, File{}); !got.UDPDisabled {
		t.Fatal("no udp block: UDPDisabled = false, want true (fork opt-in gate)")
	}

	enabled := true
	if got := Apply(session.Config{}, File{UDP: UDP{Enabled: &enabled}}); got.UDPDisabled {
		t.Fatal("udp.enabled=true: UDPDisabled = true, want false")
	}

	disabled := true
	got := Apply(session.Config{}, File{UDP: UDP{Enabled: &enabled, Disabled: &disabled}})
	if !got.UDPDisabled {
		t.Fatal("udp.enabled+disabled: UDPDisabled = false, want disabled to win")
	}

	profEnabled := true
	base := Apply(session.Config{}, File{})
	if got := ApplyProfile(base, Profile{UDP: UDP{Enabled: &profEnabled}}); got.UDPDisabled {
		t.Fatal("profile udp.enabled=true over gated base: UDPDisabled = true, want false")
	}
}

func TestApplyKeepsCLIUDPDisabled(t *testing.T) {
	disabled := false
	got := Apply(session.Config{UDPDisabled: true}, File{UDP: UDP{Disabled: &disabled}})
	if !got.UDPDisabled {
		t.Fatal("UDPDisabled = false, want CLI true to win")
	}
}

func requireFirstProfile(t *testing.T, first session.Config) {
	t.Helper()
	want := session.Config{
		Mode:                  testModeSrv,
		Auth:                  "wbstream",
		RoomID:                "wb-room",
		KeyHex:                "shared-key",
		Transport:             "vp8channel",
		DNSServer:             testDNSServer,
		VP8:                   session.VP8Config{FPS: 30},
		LivenessInterval:      "1s",
		LivenessTimeout:       "2s",
		LivenessFailures:      5,
		MaxSessionDuration:    "30m",
		TrafficMaxPayloadSize: 4096,
		TrafficMinDelay:       "10ms",
		TrafficMaxDelay:       "20ms",
		UDPDisabled:           true,
		UDPMaxFlows:           10,
	}
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("first profile = %+v, want %+v", first, want)
	}
}

func requireSecondProfile(t *testing.T, second session.Config) {
	t.Helper()
	want := session.Config{
		Mode:                  testModeSrv,
		Auth:                  "jitsi",
		RoomID:                "https://meet.example/room",
		KeyHex:                "shared-key",
		Transport:             "datachannel",
		DNSServer:             testDNSServer,
		LivenessInterval:      "5s",
		LivenessTimeout:       "2s",
		LivenessFailures:      5,
		MaxSessionDuration:    "6h",
		TrafficMaxPayloadSize: 8192,
		TrafficMinDelay:       "10ms",
		TrafficMaxDelay:       "40ms",
		UDPMaxFlows:           100,
	}
	if !reflect.DeepEqual(second, want) {
		t.Fatalf("second profile = %+v, want %+v", second, want)
	}
}

func TestLoadProfileCryptoKeyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "profile.key"), []byte(testCryptoKey+"\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	path := filepath.Join(dir, "olcrtc.yaml")
	body := `
profiles:
  - name: file-key
    crypto:
      key_file: profile.key
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := f.Profiles[0].Crypto.Key; got != testCryptoKey {
		t.Fatalf("profile key = %q, want %q", got, testCryptoKey)
	}
}

func TestLoadCryptoKeyFileRelativeToConfig(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(keyPath, []byte(testCryptoKey+"\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	path := filepath.Join(dir, "olcrtc.yaml")
	body := `
mode: srv
crypto:
  key_file: secret.key
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if f.Crypto.Key != testCryptoKey {
		t.Fatalf("Crypto.Key = %q, want %q", f.Crypto.Key, testCryptoKey)
	}
}

func TestLoadCryptoKeyFileConflict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "olcrtc.yaml")
	body := `
crypto:
  key: deadbeef
  key_file: secret.key
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(path)
	if !errors.Is(err, ErrCryptoKeyConflict) {
		t.Fatalf("Load() error = %v, want %v", err, ErrCryptoKeyConflict)
	}
}

func TestLoadCryptoKeyFileEmpty(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(keyPath, []byte("\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	path := filepath.Join(dir, "olcrtc.yaml")
	body := `
crypto:
  key_file: secret.key
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(path)
	if !errors.Is(err, ErrCryptoKeyFileEmpty) {
		t.Fatalf("Load() error = %v, want %v", err, ErrCryptoKeyFileEmpty)
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadInvalidUTF8(t *testing.T) {
	path := filepath.Join(t.TempDir(), "olcrtc.yaml")
	if err := os.WriteFile(path, []byte{'m', 'o', 'd', 'e', ':', ' ', 0xff}, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, err := Load(path)
	if !errors.Is(err, ErrConfigInvalidUTF8) {
		t.Fatalf("Load() error = %v, want invalid UTF-8 error", err)
	}
}
