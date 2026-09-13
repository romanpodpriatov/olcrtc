package mobile

import (
	"math"
	"runtime/debug"
)

// SetMemoryLimit gives the Go runtime a soft memory ceiling, in bytes.
//
// A host with a hard limit needs this. An iOS packet tunnel provider is given
// roughly 50 MB for everything and is killed for exceeding it without being
// told, and the ceiling is reached the way Go reaches ceilings: not by
// climbing to it, but in one step, when the heap doubles between collections.
// A trace from a phone showed 35.1 MB one sample and 46.0 MB the next, 250 ms
// apart, and then nothing.
//
// The limit is what the runtime collects against rather than a cap it
// enforces: as the heap approaches it the collector runs more often, spending
// CPU to avoid the step. Go will not spend more than half the CPU doing it, so
// a limit set too low costs throughput rather than deadlocking.
//
// It governs the whole runtime, which on iOS is the one shared by olcRTC,
// sing-box and Xray inside Cores.xcframework — the right scope, since they
// share the process that gets killed. Pass a non-positive value to remove a
// limit that was set.
func SetMemoryLimit(bytes int64) {
	if bytes <= 0 {
		debug.SetMemoryLimit(math.MaxInt64)
		return
	}
	debug.SetMemoryLimit(bytes)
}

// MemoryLimit reports the soft ceiling in force, or 0 when there is none.
func MemoryLimit() int64 {
	current := debug.SetMemoryLimit(-1)
	if current == math.MaxInt64 {
		return 0
	}
	return current
}
