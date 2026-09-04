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

package software

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The five methods below route to a sub-backend by algorithm family while
// KeyAttributes.ID resolves the family differently, and all three sub-backends
// share one flat storage namespace. Each test drives a contradictory descriptor
// through one of them and asserts the operation is refused with the specific
// sentinel -- and, where the site is destructive, that the key it would have
// reached is still intact afterwards.
//
// Every one of these fails if requireSingleAlgorithmFamily is removed from its
// call site. The two destructive ones failed on main before it was added, with
// the outcomes recorded in each test.

// generateRSAVictim stores an RSA key under the honest descriptor and returns
// both descriptors addressing it.
func generateRSAVictim(t *testing.T, b *SoftwareBackend, cn string) (honest, contradictory *types.KeyAttributes) {
	t.Helper()
	honest = honestRSAAttrs()
	honest.CN = cn
	contradictory = contradictoryRSAAttrs()
	contradictory.CN = cn

	_, err := b.GenerateKey(context.Background(), honest)
	require.NoError(t, err, "generate the RSA key under test")
	require.Equal(t, honest.ID(), contradictory.ID(),
		"both descriptors must address the same stored key for this test to mean anything")
	return honest, contradictory
}

// TestDeleteKey_ContradictoryAttributesDoNotDestroyTheAsymmetricKey.
//
// Before the gate: DeleteKey returned nil and the RSA private key at
// "software:tls:<cn>:rsa" was gone -- the caller was told a symmetric key was
// deleted, and an asymmetric one had been. Silent and unrecoverable.
func TestDeleteKey_ContradictoryAttributesDoNotDestroyTheAsymmetricKey(t *testing.T) {
	b := familyGateBackend(t)
	ctx := context.Background()
	honest, contradictory := generateRSAVictim(t, b, "delete-victim")

	err := b.DeleteKey(ctx, contradictory)
	require.Error(t, err, "a contradictory descriptor must not reach the delete")
	assert.ErrorIs(t, err, ErrContradictoryAlgorithmFamilies)

	_, getErr := b.GetKey(ctx, honest)
	require.NoError(t, getErr, "the RSA private key must still be readable")
}

// TestRotateKey_ContradictoryAttributesDoNotOverwriteTheAsymmetricKey.
//
// Before the gate: RotateKey returned nil and replaced the RSA key with fresh
// AES key bytes, after which GetKey failed to parse PKCS#8. This site is not
// listed on go-xkms#158; it was found by enumerating the dispatch table.
func TestRotateKey_ContradictoryAttributesDoNotOverwriteTheAsymmetricKey(t *testing.T) {
	b := familyGateBackend(t)
	ctx := context.Background()
	honest, contradictory := generateRSAVictim(t, b, "rotate-victim")

	before, err := b.GetKey(ctx, honest)
	require.NoError(t, err)
	require.NotNil(t, before)

	err = b.RotateKey(ctx, contradictory)
	require.Error(t, err, "a contradictory descriptor must not reach the rotate")
	assert.ErrorIs(t, err, ErrContradictoryAlgorithmFamilies)

	after, getErr := b.GetKey(ctx, honest)
	require.NoError(t, getErr, "the RSA private key must still parse as PKCS#8")
	require.NotNil(t, after)
}

// TestImportKey_ContradictoryAttributesAreRefused. Import writes material under
// an identifier built from the other half of the descriptor, so the stored key
// does not describe itself.
func TestImportKey_ContradictoryAttributesAreRefused(t *testing.T) {
	b := familyGateBackend(t)

	err := b.ImportKey(context.Background(), contradictoryRSAAttrs(), &backend.WrappedKeyMaterial{
		WrappedKey:  []byte("irrelevant, the descriptor is refused first"),
		ImportToken: []byte("unused"),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrContradictoryAlgorithmFamilies)
}

// TestExportKey_ContradictoryAttributesAreRefused.
//
// On main this failed closed already, but only by accident downstream: the
// symmetric store rejected the stored PKCS#8 DER with "invalid AES key size:
// 9736 bits". That is a size check doing a job nobody assigned it, and it stops
// protecting anything the moment a stored blob is 16, 24 or 32 bytes. The
// refusal belongs at the boundary, named.
func TestExportKey_ContradictoryAttributesAreRefused(t *testing.T) {
	b := familyGateBackend(t)
	ctx := context.Background()
	_, contradictory := generateRSAVictim(t, b, "export-victim")

	_, err := b.ExportKey(ctx, contradictory, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrContradictoryAlgorithmFamilies)
}

// TestExportKeyMaterial_ContradictoryAttributesAreRefused.
//
// ExportKeyMaterial refuses asymmetric keys outright -- releasing raw private
// key material is the thing it exists to prevent. That refusal consults
// IsSymmetric, so a descriptor naming both families satisfies it and walks
// straight through the guard.
//
// Note on the gate's position, measured rather than assumed: moving it BELOW
// the asymmetric guard does not change this outcome, because the contradictory
// descriptor passes that guard and reaches the gate anyway. The position is a
// uniformity choice, not a control, and this test does not pin it -- only the
// gate's presence, which the mutation check does cover.
func TestExportKeyMaterial_ContradictoryAttributesAreRefused(t *testing.T) {
	b := familyGateBackend(t)
	ctx := context.Background()
	honest, contradictory := generateRSAVictim(t, b, "export-material-victim")

	// Control: the honest descriptor is refused by the asymmetric guard.
	_, ctrlErr := b.ExportKeyMaterial(ctx, honest)
	require.ErrorIs(t, ctrlErr, backend.ErrAsymmetricKeyExportNotAllowed,
		"control: the asymmetric refusal must still apply to an honest descriptor")

	material, err := b.ExportKeyMaterial(ctx, contradictory)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrContradictoryAlgorithmFamilies)
	assert.Empty(t, material, "no key material may be released")
}

// TestGatedMethods_StillAcceptHonestDescriptors is the success half: the gate
// must not have narrowed any of the five methods for ordinary attributes.
func TestGatedMethods_StillAcceptHonestDescriptors(t *testing.T) {
	b := familyGateBackend(t)
	ctx := context.Background()

	honest, _ := generateRSAVictim(t, b, "honest-lifecycle")

	require.NoError(t, b.RotateKey(ctx, honest), "rotate an honest asymmetric key")
	_, err := b.GetKey(ctx, honest)
	require.NoError(t, err, "the rotated key is readable")
	require.NoError(t, b.DeleteKey(ctx, honest), "delete an honest asymmetric key")

	symmetric := &types.KeyAttributes{
		CN: "honest-aes", StoreType: types.StoreSoftware, KeyType: types.KeyTypeSecret,
		SymmetricAlgorithm: types.SymmetricAES256GCM, Exportable: true,
	}
	_, err = b.GenerateSymmetricKey(ctx, symmetric)
	require.NoError(t, err)

	material, err := b.ExportKeyMaterial(ctx, symmetric)
	require.NoError(t, err, "export an honest symmetric key")
	require.NotEmpty(t, material)

	require.NoError(t, b.DeleteKey(ctx, symmetric), "delete an honest symmetric key")
}
