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

package mocks

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// PutIfAbsent stores value under key only when key is absent, performing the
// check-then-write under the mock's write lock so it is atomic for concurrent
// callers (implements storage.Backend). Returns stored=false when key already
// held a value, leaving the stored value unchanged.
func (m *MockCertStorage) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return false, &errs.Message{Msg: "storage is closed"}
	}

	if _, exists := m.data[key]; exists {
		return false, nil
	}

	valueCopy := make([]byte, len(value))
	copy(valueCopy, value)
	m.data[key] = valueCopy

	return true, nil
}
