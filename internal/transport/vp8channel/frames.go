package vp8channel

// ai-generated: the whole file (issue #12: the frame size a data lane keeps
// on a path that loses packets).

import (
	"cmp"
	"encoding/binary"
	"math"
	"sync"

	kcp "github.com/xtaci/kcp-go/v5"
)

const (
	// deliveryBucketMs is how many milliseconds of KCP timestamps one bucket
	// of the delivery count spans.
	deliveryBucketMs = 250
	// minJudgedPushes is the fewest pushed packets a judgement rests on.
	minJudgedPushes = 64
	// minFramePackets is the fewest KCP packets a capped lane puts in a
	// frame.
	minFramePackets = 4
	// A lane shrinks its frames while fewer than lossyShare of the packets
	// it pushes come back acknowledged, to what should bring back
	// aimShare of them, and grows them by a quarter while more than
	// cleanShare do. Under darkShare next to nothing got through: a relay
	// that stopped forwarding, which the lane's dark spells deal with, not
	// loss. What a lane pushed before it came back from a dark spell is not
	// weighed at all (forget).
	darkShare  = 0.02
	lossyShare = 0.5
	aimShare   = 0.65
	cleanShare = 0.85

	// kcpTSOff is where the timestamp sits in a KCP segment header.
	kcpTSOff = 8
)

// deliveryTrack counts the packets with a push a conn sends and the packets
// of acknowledgements that come back for them, both under the timestamp of
// the packet's last push: an acknowledgement echoes it. A conn acknowledges
// every packet it receives on its own (SetACKNoDelay), always including the
// packet's last push, so the second count over the first is the share of
// packets that got through and back. Pushes go out, and acknowledgements
// come back, in timestamp order, so once one for a later bucket is back,
// an earlier bucket has all it is going to get, whatever the round trip.
type deliveryTrack struct {
	mu        sync.Mutex
	buckets   [32]deliveryBucket
	newestAck uint32 // the bucket of the newest push acknowledged, zero for none
}

// deliveryBucket is one bucket of the count; id is the timestamp over
// deliveryBucketMs plus one, zero for an unused bucket.
type deliveryBucket struct {
	id           uint32
	pushes, acks int
}

// count adds pushes and acknowledgements under the push timestamp ts. An
// acknowledgement for a bucket already judged or reused is dropped.
func (t *deliveryTrack) count(ts uint32, pushes, acks int) {
	id := ts/deliveryBucketMs + 1
	t.mu.Lock()
	defer t.mu.Unlock()
	if acks > 0 && (t.newestAck == 0 || int32(id-t.newestAck) > 0) { //nolint:gosec // wrapping timestamp difference
		t.newestAck = id
	}
	b := &t.buckets[id%uint32(len(t.buckets))]
	if b.id != id {
		if pushes == 0 || (b.id != 0 && int32(id-b.id) < 0) { //nolint:gosec // wrapping timestamp difference
			return
		}
		*b = deliveryBucket{id: id}
	}
	b.pushes += pushes
	b.acks += acks
}

// take clears the buckets from before the newest acknowledged one, which
// have all they are going to get, and returns the pushes and
// acknowledgements of those from the bucket id from on.
func (t *deliveryTrack) take(from uint32) (int, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	pushes, acks, before := 0, 0, t.newestAck
	if before == 0 {
		return 0, 0
	}
	for i := range t.buckets {
		b := &t.buckets[i]
		if b.id == 0 || int32(before-b.id) <= 0 { //nolint:gosec // wrapping timestamp difference
			continue
		}
		if int32(b.id-from) >= 0 { //nolint:gosec // wrapping timestamp difference
			pushes += b.pushes
			acks += b.acks
		}
		*b = deliveryBucket{}
	}
	return pushes, acks
}

// frameCap is the most KCP packets a data lane puts in one frame. A frame
// reaches the peer only when every RTP packet of it does, so on a path that
// loses one packet in twenty-five a full frame of fifty is lost seven times
// in eight, and every segment in it with it: KCP resends the same segments
// in the same full frames, backs their timeouts off each time, and the
// transfer crawls while the small control frames still get through.
type frameCap struct {
	// limit is the cap, zero for none. newest is the newest bucket a push
	// went out in, and since the first bucket whose pushes went out under
	// the current limit. pushes and acks are the evidence gathered since.
	limit         int
	newest, since uint32
	pushes, acks  int
}

// pushed counts a packet with a push that went out under timestamp ts.
func (f *frameCap) pushed(track *deliveryTrack, ts uint32) {
	track.count(ts, 1, 0)
	f.newest = ts/deliveryBucketMs + 1
}

// forget drops the evidence gathered so far, and what was pushed before now:
// the lane came back from a dark spell, which says nothing of how lossy the
// path is.
func (f *frameCap) forget() {
	f.pushes, f.acks, f.since = 0, 0, f.newest+1
}

// halve halves the cap, down to minFramePackets, as the lane goes dark, and
// reports whether it changed. On a path that loses one packet in twelve
// next to no full frame gets through, the lane goes dark before a share
// could be weighed, and halving is what lets one be: frames half the size
// come back several times as often. A relay that stopped forwarding for
// being over its budget takes smaller frames just as well, and the cap
// grows back once they come back clean.
func (f *frameCap) halve(full int) bool {
	limit := max(cmp.Or(f.limit, full)/2, minFramePackets)
	changed := limit != f.limit
	f.limit = limit
	f.forget()
	return changed
}

// judge weighs what came back of the packets pushed before the newest one
// acknowledged, and changes the cap when there is enough of it: while under
// lossyShare got through, down to what should bring back aimShare, at most
// half of it; while over cleanShare, a quarter up, to full, the batch size,
// which lifts it. It returns the share judged and whether the cap changed.
func (f *frameCap) judge(track *deliveryTrack, full int) (float64, bool) {
	pushes, acks := track.take(f.since)
	f.pushes += pushes
	f.acks += acks
	if f.pushes < minJudgedPushes {
		return 0, false
	}
	share := float64(f.acks) / float64(f.pushes)
	f.pushes, f.acks = 0, 0
	limit := f.limit
	switch {
	case share < darkShare:
		return share, false
	case share < lossyShare:
		limit = shrunk(cmp.Or(limit, full), share)
	case share > cleanShare && limit > 0:
		limit += max(limit/4, 1)
		if limit >= full {
			limit = 0
		}
	}
	if limit == f.limit {
		return share, false
	}
	f.limit, f.since = limit, f.newest+1
	return share, true
}

// shrunk is the frame size that should bring back aimShare of the pushed
// packets where frames of limit packets brought back share: every packet of
// a frame has to get through, so the share falls as a power of the size.
// It is at most half of limit and at least minFramePackets.
func shrunk(limit int, share float64) int {
	aim := float64(limit) * math.Log(aimShare) / math.Log(share)
	return max(min(int(aim), limit/2), minFramePackets)
}

// packetStamp is what stampsOf reads off a KCP packet: the timestamps of its
// last push and of its last acknowledgement, and whether it has either.
type packetStamp struct {
	push, ack     uint32
	pushed, acked bool
}

// stampsOf walks a KCP packet for its packetStamp. kcp-go packs
// acknowledgements first and a packet of them alone is walked to its end; a
// length longer than what is left ends the walk.
func stampsOf(segs []byte) packetStamp {
	var st packetStamp
	for len(segs) >= kcp.IKCP_OVERHEAD {
		ts := binary.LittleEndian.Uint32(segs[kcpTSOff:])
		switch segs[kcpCmdOff] {
		case kcp.IKCP_CMD_PUSH:
			st.push, st.pushed = ts, true
		case kcp.IKCP_CMD_ACK:
			st.ack, st.acked = ts, true
		}
		size := binary.LittleEndian.Uint32(segs[kcpLenOff:])
		rest := segs[kcp.IKCP_OVERHEAD:]
		if uint64(size) > uint64(len(rest)) {
			break
		}
		segs = rest[size:]
	}
	return st
}
