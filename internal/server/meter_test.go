package server

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestMeterAttributesPerKeyAndTotals(t *testing.T) {
	m := newMeter()
	m.bind("sess-A", "keyaaa0000000000")
	m.bind("sess-B", "keybbb0000000000")

	m.add("sess-A", 100, 200)
	m.add("sess-A", 10, 20)
	m.add("sess-B", 1, 2)
	m.add("unbound-session", 999, 999) // no bound key → ignored

	snap := m.snapshot()
	if snap.Keys["keyaaa0000000000"] != (statsDirection{Up: 110, Down: 220}) {
		t.Fatalf("key A = %+v", snap.Keys["keyaaa0000000000"])
	}
	if snap.Keys["keybbb0000000000"] != (statsDirection{Up: 1, Down: 2}) {
		t.Fatalf("key B = %+v", snap.Keys["keybbb0000000000"])
	}
	if snap.Total != (statsDirection{Up: 111, Down: 222}) {
		t.Fatalf("total = %+v", snap.Total)
	}
	if len(snap.Keys) != 2 {
		t.Fatalf("unbound traffic leaked a bucket: %d keys", len(snap.Keys))
	}
}

func TestMeterBindIgnoresEmptyKey(t *testing.T) {
	m := newMeter()
	m.bind("sess", "") // legacy/unpaired → not metered
	m.add("sess", 500, 500)
	if len(m.snapshot().Keys) != 0 {
		t.Fatal("empty-key session was metered")
	}
}

func TestStatsHandlerServesContractJSON(t *testing.T) {
	m := newMeter()
	m.bind("s", "deadbeefdeadbeef")
	m.add("s", 7, 9)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/stats", nil)
	m.statsHandler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var body statsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad json: %v (%s)", err, rec.Body.String())
	}
	if body.Keys["deadbeefdeadbeef"].Up != 7 || body.Keys["deadbeefdeadbeef"].Down != 9 {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if body.Total.Up != 7 || body.Total.Down != 9 {
		t.Fatalf("total = %+v", body.Total)
	}
}
