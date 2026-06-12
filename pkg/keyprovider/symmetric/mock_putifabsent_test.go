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

package symmetric

import (
	"context"
	"fmt"
)

// PutIfAbsent mirrors MockFailingStorage.Put: it fails when failOnPut is set,
// otherwise reports the value as stored.
func (m *MockFailingStorage) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	if m.failOnPut {
		return false, fmt.Errorf("storage error: put failed")
	}
	return true, nil
}
