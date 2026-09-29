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

package tpm2

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestCreateRSA_RefusesUndersizedModulus_Simulator proves CreateRSA itself
// -- not just the RPC service layer above it -- refuses to create a key
// below types.RSAKeySize2048 when a caller asks for one explicitly. Before
// this check existed, a direct CreateRSA caller (bypassing the RPC service's
// own KeyAttributes.Validate call) got a 1024-bit key straight off the TPM
// with no refusal at all (go-xkms#1204).
func TestCreateRSA_RefusesUndersizedModulus_Simulator(t *testing.T) {
	tpm, srkAttrs, backend := deleteKeyRegressionFixture(t)
	tpmImpl := tpm.(*TPM2)

	genAttrs := &types.KeyAttributes{
		CN:            "undersized-rsa-repro",
		KeyAlgorithm:  x509.RSA,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreTPM2,
		Parent:        srkAttrs,
		RSAAttributes: &types.RSAAttributes{KeySize: 1024},
	}

	pub, err := tpmImpl.CreateRSA(genAttrs, backend, true)
	require.Error(t, err, "CreateRSA must refuse a 1024-bit modulus")
	require.Nil(t, pub)

	var sizeErr *types.RSAKeySizeError
	require.True(t, errors.As(err, &sizeErr), "refusal must be the typed types.RSAKeySizeError, got %T: %v", err, err)
	require.Equal(t, 1024, sizeErr.Requested)
}

// TestCreateRSA_AcceptsDocumentedSizes_Simulator is the success-path
// counterpart: RSAKeySize2048 must still create a usable key once the
// go-xkms#1204 floor is in place, so the refusal above is provably a floor
// and not an accidental rejection of every request.
//
// RSAKeySize3072 and RSAKeySize4096 are not exercised here: the go-tpm
// in-process simulator this suite runs against only implements the 1024 and
// 2048-bit RSA moduli TCG's reference implementation ships by default (its
// own TPM2_GetCapability answer, surfaced through KeyTemplate's
// device-capability check, names exactly those two). That is a property of
// the simulator, not of this fix -- types.ValidateRSAKeySize accepts 3072
// and 4096 identically to 2048 (see pkg/types/algorithms_test.go), and
// pkg/xkms's service-level tests exercise all three sizes end to end against
// the software backend, which has no such hardware ceiling.
func TestCreateRSA_AcceptsDocumentedSizes_Simulator(t *testing.T) {
	tpm, srkAttrs, backend := deleteKeyRegressionFixture(t)
	tpmImpl := tpm.(*TPM2)

	genAttrs := &types.KeyAttributes{
		CN:            "rsa-2048-accepted",
		KeyAlgorithm:  x509.RSA,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreTPM2,
		Parent:        srkAttrs,
		RSAAttributes: &types.RSAAttributes{KeySize: types.RSAKeySize2048},
	}

	pub, err := tpmImpl.CreateRSA(genAttrs, backend, true)
	require.NoError(t, err)
	require.NotNil(t, pub)
	require.Equal(t, types.RSAKeySize2048, pub.N.BitLen())
}
