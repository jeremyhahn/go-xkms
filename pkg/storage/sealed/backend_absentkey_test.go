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

package sealed

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/storagetest"
)

// A sealed backend must not let the sealing layer turn an absent key into a
// present one -- an unseal of nothing is still nothing.
func TestBackend_AbsentKeyContract(t *testing.T) {
	storagetest.RunAbsentKeyContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			b := newTestBackend(t)
			t.Cleanup(func() { _ = b.Close() })
			return b
		},
		Key: "keys/contract-subject",
	})
}
