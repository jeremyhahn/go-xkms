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

package store

import "context"

// PutIfAbsent mirrors errorBackend.Put: it returns putError, otherwise reports
// the value as stored.
func (e *errorBackend) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	if e.putError != nil {
		return false, e.putError
	}
	return true, nil
}
