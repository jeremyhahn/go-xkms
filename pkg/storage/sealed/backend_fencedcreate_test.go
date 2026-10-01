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

package sealed

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/storagetest"
)

func TestBackend_FencedCreateContract(t *testing.T) {
	storagetest.RunFencedCreateContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			b := newTestBackend(t)
			t.Cleanup(func() { _ = b.Close() })
			return b
		},
		Key: "keys/contract-subject",
	})
}

// The created key holds the sealed envelope, never the plaintext.
func TestBackend_FencedCreateSealsTheValue(t *testing.T) {
	b := newTestBackend(t)
	t.Cleanup(func() { _ = b.Close() })
	created, err := b.PutIfAllAbsent(context.Background(), "keys/k", []byte("plaintext"), "keys/fence")
	require.NoError(t, err)
	require.True(t, created)
	raw, err := b.inner.Get(context.Background(), "keys/k")
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "plaintext")
}
