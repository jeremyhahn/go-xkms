//go:build tpm_simulator

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

package xkms

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
)

// TestNewTPM2KeyProvider_KeyStorageWithoutGuardedWritesFails proves a
// key_storage that cannot make the guarded writes the TPM blob store needs
// refuses the first blob write with a typed error rather than writing it
// unguarded. The refusal comes from the first write made while the TPM is
// provisioned, so the test needs the in-memory simulator.
func TestNewTPM2KeyProvider_KeyStorageWithoutGuardedWritesFails(t *testing.T) {
	unguarded := struct{ storage.Backend }{storage.NewMemory()}
	_, err := newTPM2KeyProvider(map[string]interface{}{
		"key_storage":   unguarded,
		"use_simulator": true,
	})
	var writeErr *store.BlobWriteError
	require.ErrorAs(t, err, &writeErr)
}
