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

import "context"

// PutIfAbsent mirrors resealErrBackend.Put: it returns putErr, otherwise stores
// the value only when key is absent.
func (r *resealErrBackend) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	if r.putErr != nil {
		return false, r.putErr
	}
	if _, ok := r.data[key]; ok {
		return false, nil
	}
	r.data[key] = value
	return true, nil
}

// PutIfAbsent mirrors failingStorage.Put, honoring the same putErr/putFailAt
// failure schedule and storing the value only when key is absent.
func (f *failingStorage) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	f.putCount++
	if f.putErr != nil {
		if f.putFailAt == 0 || f.putCount >= f.putFailAt {
			return false, f.putErr
		}
	}
	if _, ok := f.getData[key]; ok {
		return false, nil
	}
	buf := make([]byte, len(value))
	copy(buf, value)
	f.getData[key] = buf
	return true, nil
}

// PutIfAbsent mirrors errBackend.Put: it returns putErr, otherwise reports the
// value as stored.
func (e *errBackend) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	if e.putErr != nil {
		return false, e.putErr
	}
	return true, nil
}

// PutIfAbsent stores value under key only if absent, mirroring memoryBackend.Put.
func (m *memoryBackend) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	if _, ok := m.data[key]; ok {
		return false, nil
	}
	buf := make([]byte, len(value))
	copy(buf, value)
	m.data[key] = buf
	return true, nil
}
