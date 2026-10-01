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

//go:build frost

package frost

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func TestSymmetricSecretSealKeyAttributes(t *testing.T) {
	attrs := SymmetricSecretSealKeyAttributes(types.StorePKCS11)

	assert.Equal(t, SecretSealKeyCN, attrs.CN)
	assert.Equal(t, types.StorePKCS11, attrs.StoreType)
	assert.Equal(t, types.KeyTypeEncryption, attrs.KeyType)
	assert.Equal(t, x509.UnknownPublicKeyAlgorithm, attrs.KeyAlgorithm)
	assert.Equal(t, types.SymmetricAES256GCM, attrs.SymmetricAlgorithm)
	assert.True(t, attrs.IsSymmetric())
	assert.NoError(t, attrs.Validate())
}

func TestSymmetricSecretSealKeyAttributes_DifferentStoreTypesProduceDifferentIDs(t *testing.T) {
	pkcs11Attrs := SymmetricSecretSealKeyAttributes(types.StorePKCS11)
	awsAttrs := SymmetricSecretSealKeyAttributes(types.StoreAWSKMS)

	assert.NotEqual(t, pkcs11Attrs.ID(), awsAttrs.ID(), "different store types must address distinct keys")
}

func TestAsymmetricSecretSealKeyAttributes(t *testing.T) {
	attrs := AsymmetricSecretSealKeyAttributes(types.StoreSoftware)

	assert.Equal(t, SecretSealKeyCN, attrs.CN)
	assert.Equal(t, types.StoreSoftware, attrs.StoreType)
	assert.Equal(t, types.KeyTypeEncryption, attrs.KeyType)
	assert.Equal(t, x509.Ed25519, attrs.KeyAlgorithm)
	assert.False(t, attrs.IsSymmetric())
	assert.NoError(t, attrs.Validate())
}

func TestAsymmetricSecretSealKeyAttributes_DistinctFromSymmetric(t *testing.T) {
	symmetric := SymmetricSecretSealKeyAttributes(types.StoreSoftware)
	asymmetric := AsymmetricSecretSealKeyAttributes(types.StoreSoftware)

	assert.NotEqual(t, symmetric.ID(), asymmetric.ID(), "the symmetric and asymmetric forms must never collide under the same store type")
}

func TestTPM2SecretSealKeyAttributes(t *testing.T) {
	psrkAttrs := &types.KeyAttributes{CN: "platform-srk"}

	attrs := TPM2SecretSealKeyAttributes(psrkAttrs)

	assert.Empty(t, attrs.CN, "the TPM2 template carries no CN; KeyStore fills one in per FROST key")
	assert.Same(t, psrkAttrs, attrs.Parent)
	assert.Empty(t, attrs.TPMPolicy, "a parent without a policy lends none")

	psrkAttrs.TPMPolicy = types.TPMPolicyPlatform
	attrs = TPM2SecretSealKeyAttributes(psrkAttrs)
	assert.Equal(t, types.TPMPolicyPlatform, attrs.TPMPolicy,
		"the passwordless share must be bound to the Platform SRK's policy")
}

func TestTPM2SecretSealKeyAttributes_NilParent(t *testing.T) {
	attrs := TPM2SecretSealKeyAttributes(nil)

	assert.Nil(t, attrs.Parent)
	assert.Empty(t, attrs.CN)
	assert.Empty(t, attrs.TPMPolicy)
}

func TestKeyStore_SecretSealKeyAttributesFor_NilTemplate(t *testing.T) {
	ks := NewKeyStore(newMockStorageBackend(), newMockSecretBackend(), nil)

	assert.Nil(t, ks.secretSealKeyAttributesFor("any-key"))
}

func TestKeyStore_SecretSealKeyAttributesFor_FixedCNReusedAcrossKeys(t *testing.T) {
	fixed := SymmetricSecretSealKeyAttributes(types.StorePKCS11)
	ks := NewKeyStore(newMockStorageBackend(), newMockSecretBackend(), fixed)

	a := ks.secretSealKeyAttributesFor("key-a")
	b := ks.secretSealKeyAttributesFor("key-b")

	assert.Same(t, fixed, a, "a fixed-CN template is returned unchanged, not cloned")
	assert.Same(t, fixed, b)
	assert.Equal(t, a.CN, b.CN, "the same reusable wrapping key is used for every FROST key")
}

func TestKeyStore_SecretSealKeyAttributesFor_TemplateGetsPerKeyCN(t *testing.T) {
	template := TPM2SecretSealKeyAttributes(&types.KeyAttributes{CN: "psrk"})
	ks := NewKeyStore(newMockStorageBackend(), newMockSecretBackend(), template)

	a := ks.secretSealKeyAttributesFor("key-a")
	b := ks.secretSealKeyAttributesFor("key-b")

	assert.NotSame(t, template, a, "a CN-less template is cloned, not mutated in place")
	assert.Equal(t, secretSealCN("key-a"), a.CN)
	assert.Equal(t, secretSealCN("key-b"), b.CN)
	assert.NotEqual(t, a.CN, b.CN, "each FROST key gets its own TPM-sealed object identity")
	assert.Same(t, template.Parent, a.Parent, "the Parent (PSRK) is shared, only CN differs per key")
}
