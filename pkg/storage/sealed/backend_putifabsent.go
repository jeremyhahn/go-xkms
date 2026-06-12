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

package sealed

import (
	"context"
	"encoding/json"
	"fmt"
)

// PutIfAbsent seals the value exactly as Put does, then delegates the
// check-then-write to the inner backend's PutIfAbsent. Encryption is applied
// before delegation so the stored envelope is identical to Put's, and the
// atomicity guarantee is inherited unchanged from the inner backend.
func (b *Backend) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	sealed, err := b.sealer.Seal(ctx, value, b.sealOpts)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrSealFailed, err)
	}

	data, err := json.Marshal(sealed)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrMarshalFailed, err)
	}

	return b.inner.PutIfAbsent(ctx, key, data)
}
