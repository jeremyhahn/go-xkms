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

package ca

import (
	"context"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/require"
)

// TestCA_RepeatedSigningKeepsPasswordAllocationsBounded proves each signer
// lookup releases the temporary key password it opened: N signatures with a
// password-protected CA key leave the process allocator's locked bytes where
// they started. Not parallel: it measures the process-wide allocator.
func TestCA_RepeatedSigningKeepsPasswordAllocationsBounded(t *testing.T) {
	ctx := context.Background()
	backend, _ := newPKCS8CABackend(t)

	root := passwordProtectedIdentity(t, rootIdentity("PW Signing CA"), "signing-key-password")
	parent, err := NewParentCA(&Params{
		Identity:           []Identity{root},
		KeyStore:           backend,
		BackendForStore:    singleBackendFactory(backend),
		RevocationStore:    storage.NewMemory(),
		CertStore:          newInMemoryCertStore(t),
		RequireKeyPassword: true,
	})
	require.NoError(t, err)
	require.NoError(t, parent.Init(ctx))
	ca, ok := parent.(*CA)
	require.True(t, ok, "NewParentCA must return a *CA")

	alloc, err := enclave.ProcessAllocator()
	require.NoError(t, err)

	// Warm up once so lazily created state is not counted as a leak.
	_, err = ca.getSigner(ctx)
	require.NoError(t, err)

	before := alloc.InUse()
	const n = 50
	for i := 0; i < n; i++ {
		_, err := ca.getSigner(ctx)
		require.NoError(t, err)
	}
	after := alloc.InUse()
	require.LessOrEqual(t, after, before,
		"%d signer lookups grew locked bytes from %d to %d", n, before, after)
}
