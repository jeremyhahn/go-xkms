// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package mem

import "sync/atomic"

// GuardedBuffer holds sensitive key material in memory protected by
// OS-level safeguards. On Linux, the buffer is allocated via mmap with
// leading and trailing guard pages (PROT_NONE) to detect overflows,
// and the data pages are locked into RAM with mlock to prevent the
// kernel from swapping them to disk. On platforms that lack these
// primitives, the implementation degrades gracefully to a plain heap
// allocation with guaranteed zeroing on Free.
type GuardedBuffer struct {
	// data is the usable byte slice within the allocated region.
	data []byte

	// region is the full mmap allocation including guard pages.
	// On non-Linux platforms this is nil.
	region []byte

	// size is the caller-requested buffer size in bytes.
	size int

	// freed tracks whether the buffer has been freed.
	// Uses atomic.Bool for lock-free concurrent access.
	freed atomic.Bool
}

// NewGuardedBuffer allocates a new guarded buffer of the given size.
// On Linux, the buffer is backed by an anonymous mmap region with
// guard pages and mlock protection. On other platforms, a plain heap
// allocation is used. Returns an error if size is non-positive or
// the underlying allocation fails.
func NewGuardedBuffer(size int) (*GuardedBuffer, error) {
	return newGuardedBuffer(size)
}

// Bytes returns the interior byte slice containing the buffer data.
// Panics if the buffer has been freed.
func (g *GuardedBuffer) Bytes() []byte {
	if g.freed.Load() {
		panic("mem: use of freed GuardedBuffer")
	}
	return g.data
}

// Size returns the usable size of the buffer in bytes.
func (g *GuardedBuffer) Size() int {
	return g.size
}

// IsFreed reports whether the buffer has been freed.
func (g *GuardedBuffer) IsFreed() bool {
	return g.freed.Load()
}

// Clone creates a new GuardedBuffer with an independent copy of this
// buffer's contents. The clone receives the same OS-level protections
// as the original. Panics if the buffer has been freed.
func (g *GuardedBuffer) Clone() (*GuardedBuffer, error) {
	if g.freed.Load() {
		panic("mem: clone of freed GuardedBuffer")
	}
	clone, err := NewGuardedBuffer(g.size)
	if err != nil {
		return nil, err
	}
	copy(clone.data, g.data)
	return clone, nil
}

// Write copies src into the buffer starting at offset 0. At most
// g.Size() bytes are copied. Returns the number of bytes copied.
// Panics if the buffer has been freed.
func (g *GuardedBuffer) Write(src []byte) int {
	if g.freed.Load() {
		panic("mem: write to freed GuardedBuffer")
	}
	return copy(g.data, src)
}

// Zero overwrites the buffer contents with zeros without freeing it.
// This is useful for clearing sensitive material before reusing the
// buffer. Panics if the buffer has been freed.
func (g *GuardedBuffer) Zero() {
	if g.freed.Load() {
		panic("mem: zero of freed GuardedBuffer")
	}
	Zero(g.data)
}

// Free zeros the buffer contents, releases OS-level protections
// (munlock, munmap on Linux), and marks the buffer as freed.
// Subsequent calls to Free are safe no-ops. After Free, any call
// to Bytes, Zero, Clone, or Write will panic.
func (g *GuardedBuffer) Free() {
	if g.freed.CompareAndSwap(false, true) {
		Zero(g.data)
		freeGuardedMemory(g)
	}
}

// ZeroAndFree zeros and frees a GuardedBuffer. Safe to call with nil.
func ZeroAndFree(b *GuardedBuffer) {
	if b != nil {
		b.Free()
	}
}
