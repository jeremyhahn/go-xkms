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

package file

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/storagetest"
)

// The absent-key contract body lives in storagetest. This file supplies the
// fixture; the flags it sets are measured, not assumed.
func TestFileStorage_AbsentKeyContract(t *testing.T) {
	storagetest.RunAbsentKeyContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			fs, err := New(t.TempDir())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(func() { _ = fs.Close() })
			return fs
		},
		Key: "keys/contract-subject",
	})
}
