// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/storagetest"
)

func TestBackend_FencedCreateContract(t *testing.T) {
	storagetest.RunFencedCreateContract(t, storagetest.Config{
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

// A locked volume is an error, not a refusal: nothing was evaluated.
func TestBackend_FencedCreateOnALockedVolume(t *testing.T) {
	b := NewBackend(newMockVolumeOperator(t.TempDir()))
	_, err := b.PutIfAllAbsent(context.Background(), "keys/k", []byte("v"))
	assert.Error(t, err)
}
