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
	"bytes"
	"context"
)

// CompareAndDelete removes key only when it still holds expected, mirroring
// resealErrBackend.Delete.
func (r *resealErrBackend) CompareAndDelete(_ context.Context, key string, expected []byte) (bool, error) {
	current, ok := r.data[key]
	if !ok || !bytes.Equal(current, expected) {
		return false, nil
	}
	delete(r.data, key)
	return true, nil
}

// CompareAndDelete mirrors failingStorage.Delete: it returns deleteErr when
// set, otherwise removes key only when it still holds expected.
func (f *failingStorage) CompareAndDelete(_ context.Context, key string, expected []byte) (bool, error) {
	if f.deleteErr != nil {
		return false, f.deleteErr
	}
	current, ok := f.getData[key]
	if !ok || !bytes.Equal(current, expected) {
		return false, nil
	}
	delete(f.getData, key)
	return true, nil
}

// CompareAndDelete mirrors errBackend.Delete: it returns deleteErr when set,
// otherwise reports the key as removed.
func (e *errBackend) CompareAndDelete(_ context.Context, _ string, _ []byte) (bool, error) {
	if e.deleteErr != nil {
		return false, e.deleteErr
	}
	return true, nil
}

// CompareAndDelete removes key only when it still holds expected, mirroring
// memoryBackend.Delete.
func (m *memoryBackend) CompareAndDelete(_ context.Context, key string, expected []byte) (bool, error) {
	current, ok := m.data[key]
	if !ok || !bytes.Equal(current, expected) {
		return false, nil
	}
	delete(m.data, key)
	return true, nil
}
