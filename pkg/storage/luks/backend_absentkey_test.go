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

package luks

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/storagetest"
)

// The LUKS backend adds no reader of its own for these verbs, so what is under
// contract here is the delegation and the locked-state gate. It runs against
// the same mockVolumeOperator the package's other tests use: no root, no
// cryptsetup, no real device.
func TestBackend_AbsentKeyContract(t *testing.T) {
	storagetest.RunAbsentKeyContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			mock := newMockVolumeOperator(t.TempDir())
			mock.exists = false
			b := NewBackend(mock)
			if err := b.Initialize(64*1024*1024, "test-passphrase"); err != nil {
				t.Fatalf("Initialize: %v", err)
			}
			t.Cleanup(func() { _ = b.Close() })
			return b
		},
		Key: "keys/contract-subject",
	})
}
