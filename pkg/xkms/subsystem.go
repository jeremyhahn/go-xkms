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

package xkms

import "sync/atomic"

// subsystem holds one store-backed subsystem that a host wires into the
// service after construction (compose.Stores.Wire). A host that mounts the
// xkms ServiceModule composes its stores on first use by any transport, so a
// Set* call can run while other transports already serve requests through
// the same service; the reference is therefore published and read
// atomically, without a lock. The zero value holds nothing.
//
// T may be a pointer or an interface type: the value is boxed once per
// store, which lets one type cover both where atomic.Pointer alone covers
// only pointers.
type subsystem[T any] struct {
	ref atomic.Pointer[T]
}

// store publishes v.
func (h *subsystem[T]) store(v T) {
	h.ref.Store(&v)
}

// load returns the published value, or T's zero value when none was stored.
// A caller loads once and uses the result, so a request sees one consistent
// subsystem even if a host re-wires it concurrently.
func (h *subsystem[T]) load() T {
	if p := h.ref.Load(); p != nil {
		return *p
	}
	var zero T
	return zero
}
