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
	"bytes"
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

var _ storage.CompareAndDeleter = (*MockCertStorage)(nil)

// CompareAndDelete removes key only when its stored value still equals expected,
// performing the compare-then-delete under the mock's write lock so it is atomic
// for concurrent callers (implements storage.Backend). Returns deleted=false,
// with a nil error, when the key was absent or held a different value, leaving
// the store unchanged.
//
// This implements the full contract rather than a stub, so a test can exercise
// the guard — including the stale-releaser and one-winner-under-concurrency
// cases — against the mock exactly as against a real backend.
//
// It touches m.data directly rather than calling m.Get, for the same reason
// PutIfAbsent does: sync.RWMutex is not reentrant and m.Get takes m.mu.RLock().
func (m *MockCertStorage) CompareAndDelete(_ context.Context, key string, expected []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return false, &errs.Message{Msg: "storage is closed"}
	}

	current, exists := m.data[key]
	if !exists {
		return false, nil
	}
	if !bytes.Equal(current, expected) {
		return false, nil
	}

	delete(m.data, key)
	return true, nil
}
