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
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func familyGateBackend(t *testing.T) *SoftwareBackend {
	t.Helper()
	be, err := NewBackend(&Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	return be.(*SoftwareBackend)
}

// honestRSAAttrs is a descriptor naming exactly one family: asymmetric RSA.
func honestRSAAttrs() *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:            "family-gate-target",
		StoreType:     types.StoreSoftware,
		KeyType:       types.KeyTypeTLS,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
		Exportable:    true,
	}
}

// contradictoryRSAAttrs is honestRSAAttrs with a symmetric algorithm added.
// KeyAttributes.Validate accepts it -- it walks the same precedence as ID and
// stops at the asymmetric arm -- while IsSymmetric reports true.
func contradictoryRSAAttrs() *types.KeyAttributes {
	attrs := honestRSAAttrs()
	attrs.SymmetricAlgorithm = types.SymmetricAES256GCM
	return attrs
}

// TestContradictoryAttributes_PassValidateAndSplitIDFromRouting pins the
// premise the rest of this file rests on. If any of these three stop holding,
// the gate is guarding a hazard that no longer exists and should be revisited
// rather than kept.
func TestContradictoryAttributes_PassValidateAndSplitIDFromRouting(t *testing.T) {
	attrs := contradictoryRSAAttrs()

	require.NoError(t, attrs.Validate(),
		"Validate stops at the first family in precedence order, so it does not see the contradiction")
	assert.True(t, attrs.IsSymmetric(),
		"routing consults SymmetricAlgorithm alone and sends this to the symmetric backend")
	assert.Equal(t, honestRSAAttrs().ID(), attrs.ID(),
		"ID resolves KeyAlgorithm before SymmetricAlgorithm, so it addresses the RSA key")
}

// --- declaredAlgorithmFamilies ---

// TestDeclaredAlgorithmFamilies_OneFamilyEach covers the ordinary case: each
// family declared on its own is reported, and only it.
func TestDeclaredAlgorithmFamilies_OneFamilyEach(t *testing.T) {
	cases := []struct {
		name  string
		attrs *types.KeyAttributes
		want  algorithmFamily
	}{
		{"x25519", &types.KeyAttributes{X25519Attributes: &types.X25519Attributes{}}, familyX25519},
		{"quantum", &types.KeyAttributes{QuantumAttributes: &types.QuantumAttributes{Algorithm: types.QuantumAlgorithmMLDSA44}}, familyQuantum},
		{"asymmetric", &types.KeyAttributes{KeyAlgorithm: x509.RSA}, familyAsymmetric},
		{"symmetric", &types.KeyAttributes{SymmetricAlgorithm: types.SymmetricAES256GCM}, familySymmetric},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, []algorithmFamily{tc.want}, declaredAlgorithmFamilies(tc.attrs))
		})
	}
}

// TestDeclaredAlgorithmFamilies_NilAndZeroDeclareNothing is the bad-input case.
// Neither is an error here; see requireSingleAlgorithmFamily.
func TestDeclaredAlgorithmFamilies_NilAndZeroDeclareNothing(t *testing.T) {
	assert.Empty(t, declaredAlgorithmFamilies(nil))
	assert.Empty(t, declaredAlgorithmFamilies(&types.KeyAttributes{CN: "no-algorithm"}))
}

// TestDeclaredAlgorithmFamilies_ReportsEveryFamilyInIDPrecedence proves the
// helper reports ALL families rather than stopping at the first, and in the
// order KeyAttributes.ID resolves them. Stopping at the first is exactly what
// KeyAttributes.Validate does, which is why it accepts these.
func TestDeclaredAlgorithmFamilies_ReportsEveryFamilyInIDPrecedence(t *testing.T) {
	all := &types.KeyAttributes{
		X25519Attributes:   &types.X25519Attributes{},
		QuantumAttributes:  &types.QuantumAttributes{Algorithm: types.QuantumAlgorithmMLDSA44},
		KeyAlgorithm:       x509.RSA,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	assert.Equal(t,
		[]algorithmFamily{familyX25519, familyQuantum, familyAsymmetric, familySymmetric},
		declaredAlgorithmFamilies(all))
}

// --- requireSingleAlgorithmFamily ---

// TestRequireSingleAlgorithmFamily_OneFamilyIsPermitted is the success case.
func TestRequireSingleAlgorithmFamily_OneFamilyIsPermitted(t *testing.T) {
	require.NoError(t, requireSingleAlgorithmFamily(honestRSAAttrs()))
	require.NoError(t, requireSingleAlgorithmFamily(&types.KeyAttributes{SymmetricAlgorithm: types.SymmetricAES256GCM}))
	require.NoError(t, requireSingleAlgorithmFamily(&types.KeyAttributes{X25519Attributes: &types.X25519Attributes{}}))
	require.NoError(t, requireSingleAlgorithmFamily(&types.KeyAttributes{QuantumAttributes: &types.QuantumAttributes{Algorithm: types.QuantumAlgorithmMLDSA44}}))
}

// TestRequireSingleAlgorithmFamily_ZeroFamiliesIsPermitted is a regression
// guard, not a convenience.
//
// go-xkms PR #63 refused zero families as well as many ("must describe exactly
// one algorithm family but name []"). That made the MCP import tool
// unsatisfiable by ANY request shape, because its handler built attributes
// carrying little more than a common name -- one of the reasons that PR was
// closed unmerged in favour of #247. Refusing the zero case here would
// reintroduce a check no legitimate producer can satisfy.
func TestRequireSingleAlgorithmFamily_ZeroFamiliesIsPermitted(t *testing.T) {
	require.NoError(t, requireSingleAlgorithmFamily(nil))
	require.NoError(t, requireSingleAlgorithmFamily(&types.KeyAttributes{CN: "only-a-common-name"}))
}

// TestRequireSingleAlgorithmFamily_ContradictoryIsRefused is the bad-input
// case, and asserts the SPECIFIC error rather than merely that one occurred:
// the refusal must be branchable as ErrContradictoryAlgorithmFamilies and must
// still satisfy the broad backend.ErrInvalidAttributes class callers already
// handle.
func TestRequireSingleAlgorithmFamily_ContradictoryIsRefused(t *testing.T) {
	err := requireSingleAlgorithmFamily(contradictoryRSAAttrs())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrContradictoryAlgorithmFamilies)
	assert.ErrorIs(t, err, backend.ErrInvalidAttributes)
	assert.Contains(t, err.Error(), "asymmetric and symmetric",
		"the refusal must name which families collided")
}

// TestRequireSingleAlgorithmFamily_RefusesEveryContradictoryPair walks the
// pairs whose ID() resolution and routing decision disagree, so the gate is
// not pinned to the single RSA+AES case the issue reported.
func TestRequireSingleAlgorithmFamily_RefusesEveryContradictoryPair(t *testing.T) {
	pairs := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{"asymmetric+symmetric", contradictoryRSAAttrs()},
		{"x25519+symmetric", &types.KeyAttributes{
			X25519Attributes:   &types.X25519Attributes{},
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		}},
		{"x25519+quantum", &types.KeyAttributes{
			X25519Attributes:  &types.X25519Attributes{},
			QuantumAttributes: &types.QuantumAttributes{Algorithm: types.QuantumAlgorithmMLDSA44},
		}},
		{"x25519+asymmetric", &types.KeyAttributes{
			X25519Attributes: &types.X25519Attributes{},
			KeyAlgorithm:     x509.RSA,
		}},
		{"quantum+asymmetric", &types.KeyAttributes{
			QuantumAttributes: &types.QuantumAttributes{Algorithm: types.QuantumAlgorithmMLDSA44},
			KeyAlgorithm:      x509.RSA,
		}},
		{"quantum+symmetric", &types.KeyAttributes{
			QuantumAttributes:  &types.QuantumAttributes{Algorithm: types.QuantumAlgorithmMLDSA44},
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		}},
	}
	for _, tc := range pairs {
		t.Run(tc.name, func(t *testing.T) {
			assert.ErrorIs(t, requireSingleAlgorithmFamily(tc.attrs), ErrContradictoryAlgorithmFamilies)
		})
	}
}

// TestRequireSingleAlgorithmFamily_AdmitsEveryListKeysDescriptor is the
// compatibility test PR #63 lacked.
//
// A gate on attributes is only safe if every legitimate PRODUCER of attributes
// satisfies it. ListKeys is the producer that matters: CopyKey, the migrator
// and the PKCS#11 C_UnwrapKey path all reason from descriptors it reconstructs
// from storage identifiers. This generates one key of every family the backend
// supports, then asserts the gate admits every descriptor ListKeys returns.
func TestRequireSingleAlgorithmFamily_AdmitsEveryListKeysDescriptor(t *testing.T) {
	b := familyGateBackend(t)
	ctx := context.Background()

	rsaAttrs := honestRSAAttrs()
	rsaAttrs.CN = "gate-rsa"
	_, err := b.GenerateKey(ctx, rsaAttrs)
	require.NoError(t, err, "generate RSA")

	x25519Attrs := &types.KeyAttributes{
		CN: "gate-x25519", StoreType: types.StoreSoftware, KeyType: types.KeyTypeEncryption,
		X25519Attributes: &types.X25519Attributes{},
	}
	_, err = b.GenerateKey(ctx, x25519Attrs)
	require.NoError(t, err, "generate X25519")

	quantumAttrs := &types.KeyAttributes{
		CN: "gate-quantum", StoreType: types.StoreSoftware, KeyType: types.KeyTypeSigning,
		QuantumAttributes: &types.QuantumAttributes{Algorithm: types.QuantumAlgorithmMLDSA44},
	}
	_, err = b.GenerateKey(ctx, quantumAttrs)
	require.NoError(t, err, "generate ML-DSA")

	symmetricAttrs := &types.KeyAttributes{
		CN: "gate-aes", StoreType: types.StoreSoftware, KeyType: types.KeyTypeSecret,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	_, err = b.GenerateSymmetricKey(ctx, symmetricAttrs)
	require.NoError(t, err, "generate AES")

	listed, err := b.ListKeys(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, listed)

	for _, attrs := range listed {
		assert.NoErrorf(t, requireSingleAlgorithmFamily(attrs),
			"ListKeys produced a descriptor the gate refuses: id=%q families=%v",
			attrs.ID(), declaredAlgorithmFamilies(attrs))
	}
}
