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

package storage

import "context"

// PutIfAbsent stores value under key only if absent, mirroring mockBackend.Put.
func (m *mockBackend) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	if _, ok := m.data[key]; ok {
		return false, nil
	}
	m.data[key] = value
	return true, nil
}

// PutIfAbsent mirrors errorMockBackend.Put: it returns putErr when set,
// otherwise reports the value as stored.
func (e *errorMockBackend) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	if e.putErr != nil {
		return false, e.putErr
	}
	return true, nil
}
