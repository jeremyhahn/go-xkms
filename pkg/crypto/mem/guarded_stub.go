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

//go:build !linux

package mem

// newGuardedBuffer allocates a plain heap buffer on non-Linux platforms.
// Guard pages and mlock are not available, but the buffer still
// guarantees zeroing on Free.
func newGuardedBuffer(size int) (*GuardedBuffer, error) {
	if size <= 0 {
		return nil, &ErrInvalidSize{Size: size}
	}
	data := make([]byte, size)
	return &GuardedBuffer{
		data: data,
		size: size,
	}, nil
}

// freeGuardedMemory releases the heap buffer on non-Linux platforms.
func freeGuardedMemory(g *GuardedBuffer) {
	g.data = nil
}
