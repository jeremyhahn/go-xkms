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
	"context"
	"crypto"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// setupDeriveService brings up a service over a real software backend, which
// is the backend the PKCS#11 module's integration harness runs against. The
// mock backends used elsewhere in this package hold no key material, so they
// cannot answer a derivation at all.
func setupDeriveService(t *testing.T) *XKMSService {
	t.Helper()
	Reset()
	t.Cleanup(Reset)

	factory, ok := GetBackendFactory(BackendSoftware)
	require.True(t, ok)

	provider, err := factory(map[string]interface{}{"key_dir": "memory"})
	require.NoError(t, err)

	b, err := New(&BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)

	require.NoError(t, Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"software": b},
		DefaultBackend: "software",
	}))

	svc, err := Get()
	require.NoError(t, err)
	return svc
}

// storeSymmetricKey generates a symmetric key in the service's software
// backend and returns its key ID, which is the CN the derive request names.
func storeSymmetricKey(t *testing.T, svc *XKMSService, cn string) string {
	t.Helper()

	b, err := svc.resolveTenantBackend("software", "")
	require.NoError(t, err)

	provider, ok := b.KeyProvider().(types.SymmetricKeyProvider)
	require.True(t, ok)

	_, err = provider.GenerateSymmetricKey(context.Background(), &types.KeyAttributes{
		CN:                 cn,
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	})
	require.NoError(t, err)

	return cn
}

// hkdfOracle computes RFC 5869 HKDF-SHA256 over the material the named key was
// actually generated with, which the test obtains through ExportKeyMaterial.
func hkdfOracle(t *testing.T, svc *XKMSService, keyID string, salt, info []byte, length int) []byte {
	t.Helper()

	resp, err := svc.ExportKeyMaterial(context.Background(), &transport.ExportKeyMaterialRequest{
		Backend: "software",
		KeyID:   keyID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.KeyMaterial)

	out := make([]byte, length)
	_, err = io.ReadFull(hkdf.New(crypto.SHA256.New, resp.KeyMaterial, salt, info), out)
	require.NoError(t, err)
	return out
}

func deriveFromStored(t *testing.T, svc *XKMSService, keyID string, salt, info []byte) []byte {
	t.Helper()

	resp, err := svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Backend:   "software",
		KeyID:     keyID,
		Algorithm: "HKDF",
		Salt:      salt,
		Info:      info,
		KeyLength: 32,
		Hash:      "SHA-256",
	})
	require.NoError(t, err)
	return resp.DerivedKey
}

// TestDeriveKeyFromStoredKeyMatchesTheHKDFOracle proves the service derives
// from the key the request names, not from the name.
//
// This is the service-layer half of the defect the PKCS#11 module exposed. The
// module now sends the base key's identity rather than its bytes; if the
// service answered that with anything other than a KDF over the backend's key
// material, the module's fix would move the same wrong answer one layer down.
func TestDeriveKeyFromStoredKeyMatchesTheHKDFOracle(t *testing.T) {
	svc := setupDeriveService(t)
	keyID := storeSymmetricKey(t, svc, "derive-oracle-key")

	salt := []byte("go-xkms/servicer/salt")
	info := []byte("go-xkms/servicer/info")

	got := deriveFromStored(t, svc, keyID, salt, info)
	want := hkdfOracle(t, svc, keyID, salt, info, 32)

	assert.Equal(t, want, got,
		"the derived key does not match RFC 5869 HKDF-SHA256 over this key's own material, so "+
			"the KDF ran over something that is not the key")
}

// TestDeriveKeyFromTwoStoredKeysDiffers is the regression assertion.
//
// Two different base keys, identical salt and info. Under the old code both
// derivations ran over the key's identifier string, so they differed only
// because the identifiers did — which this first assertion alone would not
// catch. The oracle comparison is what makes it decisive: the old code could
// not satisfy it for either key.
func TestDeriveKeyFromTwoStoredKeysDiffers(t *testing.T) {
	svc := setupDeriveService(t)
	first := storeSymmetricKey(t, svc, "base-one")
	second := storeSymmetricKey(t, svc, "base-two")

	salt := []byte("identical-salt")
	info := []byte("identical-info")

	firstDerived := deriveFromStored(t, svc, first, salt, info)
	secondDerived := deriveFromStored(t, svc, second, salt, info)

	require.NotEqual(t, firstDerived, secondDerived,
		"two different base keys derived the same bytes under identical salt and info")

	assert.Equal(t, hkdfOracle(t, svc, first, salt, info, 32), firstDerived)
	assert.Equal(t, hkdfOracle(t, svc, second, salt, info, 32), secondDerived)
}

// TestDeriveKeyFromStoredKeyVariesWithSaltAndInfo changes one parameter at a
// time; each must change the output on its own.
func TestDeriveKeyFromStoredKeyVariesWithSaltAndInfo(t *testing.T) {
	svc := setupDeriveService(t)
	keyID := storeSymmetricKey(t, svc, "vary-key")

	base := deriveFromStored(t, svc, keyID, []byte("salt-a"), []byte("info-a"))

	assert.NotEqual(t, base, deriveFromStored(t, svc, keyID, []byte("salt-b"), []byte("info-a")),
		"changing only the salt produced the same key")
	assert.NotEqual(t, base, deriveFromStored(t, svc, keyID, []byte("salt-a"), []byte("info-b")),
		"changing only the info produced the same key")
}

// TestDeriveKeyFromStoredKeySP800108 proves the three SP 800-108r1 modes reach
// a stored base key with their label and context intact, and that each mode
// produces its own key.
//
// 64 bytes is two SHA-256 PRF blocks. At one block, SP 800-108r1 §4.1 and §4.2
// give counter mode and feedback mode with an empty K(0) the same PRF input,
// so a shorter output could not tell the modes apart.
func TestDeriveKeyFromStoredKeySP800108(t *testing.T) {
	svc := setupDeriveService(t)
	keyID := storeSymmetricKey(t, svc, "sp800108-key")

	derive := func(t *testing.T, algorithm string, label, kdfContext []byte) []byte {
		t.Helper()
		resp, err := svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
			Backend:   "software",
			KeyID:     keyID,
			Algorithm: algorithm,
			Label:     label,
			Context:   kdfContext,
			KeyLength: 64,
			Hash:      "SHA-256",
		})
		require.NoError(t, err)
		return resp.DerivedKey
	}

	label := []byte("purpose")
	ctxBytes := []byte("context")

	outputs := map[string][]byte{}
	for _, algorithm := range []string{
		"SP800-108-COUNTER",
		"SP800-108-FEEDBACK",
		"SP800-108-DOUBLE-PIPELINE",
	} {
		out := derive(t, algorithm, label, ctxBytes)
		require.Len(t, out, 64)
		outputs[algorithm] = out
	}

	for a, outA := range outputs {
		for b, outB := range outputs {
			if a >= b {
				continue
			}
			assert.NotEqual(t, outA, outB,
				"%s and %s derived identical keys, so the mode is not reaching the KDF", a, b)
		}
	}

	t.Run("label and context reach the KDF", func(t *testing.T) {
		base := outputs["SP800-108-COUNTER"]
		assert.NotEqual(t, base, derive(t, "SP800-108-COUNTER", []byte("other-purpose"), ctxBytes),
			"changing only the label produced the same key; SP 800-108r1 §4 binds the label into "+
				"the fixed input data precisely so two protocols do not share a key")
		assert.NotEqual(t, base, derive(t, "SP800-108-COUNTER", label, []byte("other-context")),
			"changing only the context produced the same key")
	})
}

// TestDeriveKeyRejectsAnAmbiguousBaseKey covers the bad-input case introduced
// with the identity form.
//
// input_key_material and key_id name two different base keys. Answering such a
// request means picking one and returning a key derived from material the
// caller did not select, in a response indistinguishable from the one they
// wanted.
func TestDeriveKeyRejectsAnAmbiguousBaseKey(t *testing.T) {
	svc := setupDeriveService(t)
	keyID := storeSymmetricKey(t, svc, "ambiguous-key")

	_, err := svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Backend:          "software",
		KeyID:            keyID,
		InputKeyMaterial: []byte("a-completely-different-base-key!"),
		Algorithm:        "HKDF",
		KeyLength:        32,
		Hash:             "SHA-256",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
}

// TestDeriveKeyFromAKeyThatDoesNotExist proves an unresolvable base key is an
// error, never a defaulted derivation.
func TestDeriveKeyFromAKeyThatDoesNotExist(t *testing.T) {
	svc := setupDeriveService(t)

	_, err := svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Backend:   "software",
		KeyID:     "no-such-key",
		Algorithm: "HKDF",
		KeyLength: 32,
		Hash:      "SHA-256",
	})
	require.Error(t, err)
}

// TestDeriveKeyFromABackendWithoutTheCapability proves the refusal is truthful
// rather than a silent substitution.
//
// A backend that cannot reach its own symmetric key material does not
// implement types.SymmetricKeyDeriver, and the service reports that instead of
// deriving from whatever it can see. AWS KMS, GCP KMS, Azure Key Vault, Vault
// Transit and the phone backend are all in this position by design.
func TestDeriveKeyFromABackendWithoutTheCapability(t *testing.T) {
	setupService(t) // mock backends, which hold no key material
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Backend:   "software",
		KeyID:     "any-key",
		Algorithm: "HKDF",
		KeyLength: 32,
		Hash:      "SHA-256",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOperationNotSupported)
}

// TestDeriveKeyAfterGenerateKeyIsTheModulesOwnPath walks the exact two calls
// the PKCS#11 module makes: C_GenerateKey creates the base key in the backend,
// then C_DeriveKey names it by identity.
//
// Testing the pair together is what catches a mismatch between the attributes
// generation stores under and the attributes derivation looks the key up with.
// Either call alone succeeds while the pair fails.
func TestDeriveKeyAfterGenerateKeyIsTheModulesOwnPath(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()

	// "Symmetric" is the key type the module sends for CKM_AES_KEY_GEN,
	// CKM_DES3_KEY_GEN and CKM_GENERIC_SECRET_KEY_GEN alike.
	const keyID = "module-generated-base"
	_, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID:   keyID,
		Backend: "software",
		KeyType: "Symmetric", Algorithm: "Symmetric",
		KeySize:    256,
		Exportable: true,
	})
	require.NoError(t, err)

	salt := []byte("module-path-salt")
	info := []byte("module-path-info")

	got := deriveFromStored(t, svc, keyID, salt, info)
	assert.Equal(t, hkdfOracle(t, svc, keyID, salt, info, 32), got,
		"the derived key does not match HKDF over the material C_GenerateKey created")
}
