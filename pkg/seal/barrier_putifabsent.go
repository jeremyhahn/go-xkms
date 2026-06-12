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

package seal

import (
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// BarrierBackend adapts a go-qrdb *Barrier (StorageBarrier) to the
// storage.Backend interface. The barrier natively implements every Backend
// method — including the PutIfAbsent compare-and-set, which the upstream
// StorageBarrier delegates to its base backend's consistency domain — so this
// type is pure embedding with no local logic. It is retained (rather than
// returning the barrier directly) only to preserve the established
// NewBarrierBackend constructor API across xkey, the SDK re-exports, and
// downstream consumers.
type BarrierBackend struct {
	*Barrier
}

// Compile-time assertion that BarrierBackend satisfies storage.Backend.
var _ storage.Backend = (*BarrierBackend)(nil)

// NewBarrierBackend wraps a barrier so it satisfies storage.Backend. A nil
// barrier yields a nil backend so callers can pass the result straight through.
func NewBarrierBackend(b *Barrier) *BarrierBackend {
	if b == nil {
		return nil
	}
	return &BarrierBackend{Barrier: b}
}
