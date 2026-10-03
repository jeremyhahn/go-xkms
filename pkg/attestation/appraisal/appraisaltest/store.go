// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-quicbaas.
//
// go-quicbaas is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package attestationtest

import (
	"context"
	"strings"
	"sync"
)

// MemoryStore is an in-memory service.AttestationStore. Fail, when set,
// makes every operation return it.
type MemoryStore struct {
	mu      sync.Mutex
	records map[string][]byte

	// Fail is returned by every operation when non-nil.
	Fail error
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: map[string][]byte{}}
}

// Put writes a record.
func (m *MemoryStore) Put(_ context.Context, key string, value []byte) error {
	if m.Fail != nil {
		return m.Fail
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[key] = append([]byte(nil), value...)
	return nil
}

// Get reads a record.
func (m *MemoryStore) Get(_ context.Context, key string) ([]byte, bool, error) {
	if m.Fail != nil {
		return nil, false, m.Fail
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.records[key]
	return append([]byte(nil), v...), ok, nil
}

// Scan returns every record under prefix.
func (m *MemoryStore) Scan(_ context.Context, prefix string) (map[string][]byte, error) {
	if m.Fail != nil {
		return nil, m.Fail
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string][]byte{}
	for k, v := range m.records {
		if strings.HasPrefix(k, prefix) {
			out[k] = append([]byte(nil), v...)
		}
	}
	return out, nil
}

// Delete removes a record.
func (m *MemoryStore) Delete(_ context.Context, key string) error {
	if m.Fail != nil {
		return m.Fail
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, key)
	return nil
}
