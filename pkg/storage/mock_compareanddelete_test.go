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

import (
	"bytes"
	"context"
)

// CompareAndDelete removes key only when it still holds expected, mirroring
// mockBackend.Delete.
func (m *mockBackend) CompareAndDelete(_ context.Context, key string, expected []byte) (bool, error) {
	current, ok := m.data[key]
	if !ok || !bytes.Equal(current, expected) {
		return false, nil
	}
	delete(m.data, key)
	return true, nil
}

// CompareAndDelete mirrors errorMockBackend.Delete: it returns deleteErr when
// set, otherwise reports the key as absent.
func (e *errorMockBackend) CompareAndDelete(_ context.Context, _ string, _ []byte) (bool, error) {
	if e.deleteErr != nil {
		return false, e.deleteErr
	}
	return false, nil
}
