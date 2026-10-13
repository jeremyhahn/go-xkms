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

//go:build tpm_simulator

package xkms

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmblobtest"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// These tests prove #925's fix (loadStoredKeyAttrs, in service.go) resolves
// a key by kid against a second, structurally different backend -- not just
// the software one, whose PKCS#8 metadata store makes the bug easy to
// trigger and easy to fix in the same place.
//
// TPM2's own ListKeys (pkg/backend/tpm2/backend.go) does not persist
// Exportable at all -- it is a policy field this backend only ever consults
// from whatever KeyAttributes the caller passes in, never round-trips
// through the key directory it enumerates from. That is a separate,
// pre-existing gap shared with the transport-facing findKeyAttrs helper
// (servicer_helpers.go), which loads a key's attrs the same ListKeys+CN-match
// way; it is not introduced or widened by this change, and fixing it belongs
// to the TPM2 backend, not to the kid-resolution fix here. So a TPM2 key's
// Exportable always reads back false through loadStoredKeyAttrs regardless
// of what GenerateRSA was called with -- these tests assert what IS provable
// on this backend: that a key genuinely stored on tpm2 is FOUND by kid (not
// a spurious not-found from the lookup step) and reaches the backend's own
// policy/capability error, and that a truly unknown kid is reported as
// not-found.

// setupRealTPM2KID registers a simulator-backed TPM2 xkms.Backend as "tpm2".
// go-tpm-tools' simulator is a process-wide singleton, so only one such
// backend may be live at a time; t.Cleanup closes it before the next test.
func setupRealTPM2KID(t *testing.T) {
	t.Helper()
	Reset()
	t.Cleanup(Reset)

	tpmBackend, err := tpm2backend.NewBackend(&tpm2backend.Config{
		UseSimulator: true,
		Keys:         tpmblobtest.New(t),
		CN:           "xkms-925-test",
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if cerr := tpmBackend.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	})

	b, err := New(&BackendConfig{Backend: tpmBackend, CertStorage: storage.New()})
	require.NoError(t, err)

	require.NoError(t, Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"tpm2": b},
		DefaultBackend: "tpm2",
	}))
}

// TestExportKeyByKID_TPM2_ExistingKey_IsFoundNotMissing proves the fix's
// ListKeys+CN-match resolution locates a real TPM2 key by kid: the error
// returned is the backend's own Exportable policy refusal, never
// backend.ErrKeyNotFound. Before the fix this distinction was untestable on
// this backend because it also refused with ErrKeyNotExportable, but for the
// wrong reason (kid reconstruction, not the stored record) -- this assertion
// pins that the record was actually loaded, via a second sentinel: it must
// not be ErrKeyNotFound.
func TestExportKeyByKID_TPM2_ExistingKey_IsFoundNotMissing(t *testing.T) {
	setupRealTPM2KID(t)

	b, err := GetBackend("tpm2")
	require.NoError(t, err)
	_, err = b.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "tpm2-export-key",
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreTPM2,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
		Exportable:    true,
	})
	require.NoError(t, err)

	_, err = ExportKey(context.Background(), "tpm2:signing:rsa:tpm2-export-key", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotExportable)
	assert.NotErrorIs(t, err, backend.ErrKeyNotFound, "the key exists and must be found, not reported missing")
}

func TestExportKeyByKID_TPM2_UnknownKID_NotFound(t *testing.T) {
	setupRealTPM2KID(t)

	_, err := ExportKey(context.Background(), "tpm2:::does-not-exist", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
}
