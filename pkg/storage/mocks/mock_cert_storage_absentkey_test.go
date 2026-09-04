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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/storagetest"
)

// Running the absent-key contract against the MOCK is the point of the mock
// implementing these verbs for real: a test that swaps a real backend for this
// one keeps the same guarantees about what absence means.
func TestMockCertStorage_AbsentKeyContract(t *testing.T) {
	storagetest.RunAbsentKeyContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			m := NewMockCertStorage()
			t.Cleanup(func() { _ = m.Close() })
			return m
		},
	})
}
