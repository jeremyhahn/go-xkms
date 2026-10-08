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

package preseal

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// simulatorPlatformPCR is the PCR the simulator's platform policy reads.
const simulatorPlatformPCR = 16

// openSimulator provisions a fresh in-process simulator whose Platform SRK
// carries the platform policy over simulatorPlatformPCR. The simulator is a
// process-wide singleton, so these tests never run in parallel.
func openSimulator(t *testing.T) *tpm2backend.Backend {
	t.Helper()
	backend, err := tpm2backend.NewBackend(&tpm2backend.Config{
		UseSimulator:    true,
		KeyStorage:      storage.NewMemory(),
		CN:              "preseal-simulator",
		PlatformPCR:     simulatorPlatformPCR,
		PlatformPCRBank: pkgtpm2.PCRBankSHA256,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, backend.Close()) })
	return backend
}

// TestStore_SimulatorRoundTripsUnderThePlatformPolicy proves a PIN sealed
// under the Platform SRK and the platform policy is released unchanged,
// from a reopened store, while the platform PCRs are unchanged.
func TestStore_SimulatorRoundTripsUnderThePlatformPolicy(t *testing.T) {
	ctx := context.Background()
	tpm := openSimulator(t).TPM()
	dir := t.TempDir()

	store, err := Open(tpm, dir, nil)
	require.NoError(t, err)
	require.NoError(t, store.Put(ctx, PKCS11PIN, []byte("1234")))
	require.NoError(t, store.Close())

	reopened, err := Open(tpm, dir, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reopened.Close()) })

	pin, err := reopened.Get(ctx, PKCS11PIN)
	require.NoError(t, err)
	require.Equal(t, []byte("1234"), pin)

	require.NoError(t, reopened.Put(ctx, PKCS11PIN, []byte("87654321")))
	pin, err = reopened.Get(ctx, PKCS11PIN)
	require.NoError(t, err)
	require.Equal(t, []byte("87654321"), pin, "resealing must replace the PIN")
}

// TestStore_SimulatorRefusesAfterThePlatformChanges proves a PCR change on
// the platform policy's PCR makes the TPM refuse the PIN with a typed
// error, rather than releasing it or failing opaquely.
func TestStore_SimulatorRefusesAfterThePlatformChanges(t *testing.T) {
	ctx := context.Background()
	tpm := openSimulator(t).TPM()

	store, err := New(tpm, storage.NewMemory(), nil)
	require.NoError(t, err)
	require.NoError(t, store.Put(ctx, PKCS11PIN, []byte("1234")))

	require.NoError(t, tpm.ExtendPCR(simulatorPlatformPCR, "sha256", []byte("a different boot")))

	_, err = store.Get(ctx, PKCS11PIN)
	var refused *RefusedError
	require.ErrorAs(t, err, &refused)
	require.Equal(t, PKCS11PIN, refused.Name)
}
