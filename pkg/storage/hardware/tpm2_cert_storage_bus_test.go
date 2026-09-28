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

package hardware

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/tpm2test/tpmbus"
	"github.com/stretchr/testify/require"
)

// setOwnerAuth changes the owner hierarchy authorization of a fresh simulator
// from empty to soPIN.
func setOwnerAuth(t *testing.T, tpm transport.TPM, soPIN []byte) {
	t.Helper()
	_, err := tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NewAuth: tpm2.TPM2BAuth{Buffer: soPIN},
	}.Execute(tpm)
	require.NoError(t, err)
}

// newOwnerAuthStore returns a TPM2CertStorage on tpm authorizing the owner
// hierarchy with ownerAuth.
func newOwnerAuthStore(t *testing.T, tpm transport.TPMCloser, ownerAuth []byte) HardwareCertStorage {
	t.Helper()
	config := DefaultTPM2CertStorageConfig()
	config.OwnerAuth = ownerAuth
	store, err := NewTPM2CertStorage(tpm, config)
	require.NoError(t, err)
	return store
}

// TestTPM2CertStorage_SOPINNeverCrossesTheBus stores, replaces, reads and
// deletes a certificate under an owner hierarchy protected by an SO PIN,
// recording the TPM bus. Every NV command must be authorized by a salted
// session -- never a password session, which would carry the PIN itself --
// and the PIN must appear nowhere in the traffic.
func TestTPM2CertStorage_SOPINNeverCrossesTheBus(t *testing.T) {
	sim := newMockTPM(t)
	defer func() { require.NoError(t, sim.Close()) }()
	soPIN := []byte("so-pin-cert-storage-7d1e4a")
	setOwnerAuth(t, sim, soPIN)

	bus := tpmbus.New(sim)
	store := newOwnerAuthStore(t, bus, soPIN)

	first := generateNamedCert(t, "bus-capture", 1)
	require.NoError(t, store.SaveCert("bus-capture", first))
	// A certificate of another size under the same ID forces the index to be
	// undefined and redefined.
	second := generateNamedCert(t, "bus-capture-replacement-with-a-longer-name", 2)
	require.NotEqual(t, len(first.Raw), len(second.Raw))
	require.NoError(t, store.SaveCert("bus-capture", second))

	got, err := store.GetCert("bus-capture")
	require.NoError(t, err)
	require.Equal(t, second.Raw, got.Raw)
	require.NoError(t, store.DeleteCert("bus-capture"))

	bus.RequireAbsent(t, "the SO PIN", soPIN)
	bus.RequireSaltedAuthorization(t, tpm2.TPMCCNVDefineSpace)
	bus.RequireSaltedAuthorization(t, tpm2.TPMCCNVWrite)
	bus.RequireSaltedAuthorization(t, tpm2.TPMCCNVRead)
	bus.RequireSaltedAuthorization(t, tpm2.TPMCCNVUndefineSpace)
	bus.RequireAllSessionsSalted(t)
}

// TestTPM2CertStorage_WrongSOPINIsRefused proves the salted session really
// proves the owner authorization: a store holding the wrong SO PIN cannot
// define an NV index.
func TestTPM2CertStorage_WrongSOPINIsRefused(t *testing.T) {
	sim := newMockTPM(t)
	defer func() { require.NoError(t, sim.Close()) }()
	setOwnerAuth(t, sim, []byte("so-pin-correct-51c0"))

	store := newOwnerAuthStore(t, sim, []byte("so-pin-wrong-9e2b"))

	err := store.SaveCert("refused", generateNamedCert(t, "refused", 3))
	require.Error(t, err)
	var opErr *OperationError
	require.ErrorAs(t, err, &opErr)
	require.ErrorIs(t, err, tpm2.TPMRCBadAuth)
}
