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

package hardware

import (
	"bytes"
	"context"
)

// CompareAndDelete removes key only when it still holds expected, mirroring
// mockBackendWithErrors.Delete under the same lock.
func (m *mockBackendWithErrors) CompareAndDelete(_ context.Context, key string, expected []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		return false, nil
	}
	current, ok := m.data[key]
	if !ok || !bytes.Equal(current, expected) {
		return false, nil
	}
	delete(m.data, key)
	return true, nil
}
