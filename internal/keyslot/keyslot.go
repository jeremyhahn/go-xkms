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

// Package keyslot tells whether a key provider puts every key it generates in
// one fixed slot, without a public method on the provider. A backend package
// whose providers can have a fixed slot registers a probe; callers that keep
// one key per name ask Fixed.
package keyslot

import "sync"

// Probe reports whether provider has a fixed key slot. known is false when
// the probe does not recognise the provider.
type Probe func(provider any) (fixed, known bool)

var (
	mu     sync.RWMutex
	probes = map[int]Probe{}
	nextID int
)

// Register adds a probe and returns the function that removes it.
func Register(p Probe) (unregister func()) {
	mu.Lock()
	id := nextID
	nextID++
	probes[id] = p
	mu.Unlock()
	return func() {
		mu.Lock()
		delete(probes, id)
		mu.Unlock()
	}
}

// Fixed reports whether a registered probe knows provider and says every key
// it generates lands in one slot.
func Fixed(provider any) bool {
	mu.RLock()
	defer mu.RUnlock()
	for _, p := range probes {
		if fixed, known := p(provider); known {
			return fixed
		}
	}
	return false
}
