// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

var _ storage.FencedCreator = (*Backend)(nil)

// PutIfAllAbsent seals the value exactly as Put does, then delegates the
// fenced create to the inner backend; the condition is existence, so the
// envelope does not affect the outcome, and the atomicity is the inner
// backend's. An inner backend without the capability reports
// storage.ErrFencedCreateUnsupported.
func (b *Backend) PutIfAllAbsent(ctx context.Context, key string, value []byte, fences ...string) (bool, error) {
	fc, ok := b.inner.(storage.FencedCreator)
	if !ok {
		return false, storage.ErrFencedCreateUnsupported
	}
	sealed, err := b.sealer.Seal(ctx, value, b.sealOpts)
	if err != nil {
		return false, &errs.Joined{Lead: ErrSealFailed, Cause: err}
	}
	data, err := json.Marshal(sealed)
	if err != nil {
		return false, &errs.Joined{Lead: ErrMarshalFailed, Cause: err}
	}
	return fc.PutIfAllAbsent(ctx, key, data, fences...)
}
