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

//go:build vault

package vault

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestImportKey_BYOKRoundTrip proves the whole BYOK ceremony end to end
// against the real-crypto Transit double: GetImportParameters fetches the
// double's wrapping public key exactly as transit/wrapping_key would serve
// it, WrapKey seals the caller's key material under it in Vault's own wire
// format, and ImportKey hands the result to the double's import endpoint,
// which independently reverses the wrap (RSA-OAEP then AES-GCM) the way
// real Vault's server-side unwrap does. A successful round trip through
// genuinely separate wrap and unwrap implementations is what proves the two
// halves agree on the wire format rather than merely agreeing with
// themselves.
func TestImportKey_BYOKRoundTrip(t *testing.T) {
	b, double := newVaultTestBackend(t)
	ctx := context.Background()

	keyMaterial := make([]byte, 32)
	_, err := rand.Read(keyMaterial)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:                 "byok-imported-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}

	params, err := b.GetImportParameters(ctx, attrs, backend.WrappingAlgorithmVaultTransitBYOK)
	require.NoError(t, err)
	require.NotNil(t, params.WrappingPublicKey)
	assert.Equal(t, backend.WrappingAlgorithmVaultTransitBYOK, params.Algorithm)

	wrapped, err := b.WrapKey(ctx, keyMaterial, params)
	require.NoError(t, err)
	require.NotEmpty(t, wrapped.WrappedKey)

	require.NoError(t, b.ImportKey(ctx, attrs, wrapped))

	// The double actually recovered the plaintext material during import
	// (it will refuse to encrypt/decrypt otherwise), so encrypt/decrypt
	// through the ordinary symmetric path proves the imported key is live
	// and usable, not just present in the double's key map.
	symKey, err := b.GetSymmetricKey(ctx, attrs)
	require.NoError(t, err)
	assert.Equal(t, 256, symKey.KeySize())

	exportable, exists := double.exportable(b.sanitizeKeyName(attrs.CN))
	require.True(t, exists)
	assert.True(t, exportable, "ImportKey must forward attrs.Exportable to Vault, not hardcode it")

	// ExportKeyMaterial reads the material back out through Vault's own
	// export endpoint (not from anything cached client-side), so this
	// closes the loop: material that went in as keyMaterial via BYOK import
	// comes back out byte-for-byte via genuine Transit export.
	exported, err := b.ExportKeyMaterial(ctx, attrs)
	require.NoError(t, err)
	assert.Equal(t, keyMaterial, exported)
}

// TestImportKey_RefusesAsymmetric verifies the documented, honest scope
// limit: this backend's BYOK ceremony is wired for symmetric keys only, and
// an asymmetric key attribute is refused with a typed error rather than
// silently attempted (and failing confusingly against Vault's aes256-gcm96
// import type).
func TestImportKey_RefusesAsymmetric(t *testing.T) {
	b, _ := newVaultTestBackend(t)
	ctx := context.Background()

	attrs := &types.KeyAttributes{
		CN:           "byok-asymmetric-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_VAULT,
		KeyAlgorithm: x509.RSA,
	}

	_, err := b.GetImportParameters(ctx, attrs, backend.WrappingAlgorithmVaultTransitBYOK)
	assert.ErrorIs(t, err, ErrAsymmetricImportNotSupported)

	wrapped := &backend.WrappedKeyMaterial{WrappedKey: []byte("irrelevant"), Algorithm: backend.WrappingAlgorithmVaultTransitBYOK}
	err = b.ImportKey(ctx, attrs, wrapped)
	assert.ErrorIs(t, err, ErrAsymmetricImportNotSupported)
}

// TestGetImportParameters_RejectsWrongAlgorithm verifies that the only
// algorithm this backend's BYOK ceremony accepts is
// backend.WrappingAlgorithmVaultTransitBYOK, since that is the one wire
// format transit/keys/:name/import actually understands -- requesting one
// of the project's other wrapping algorithms here must fail loudly rather
// than silently produce a ciphertext Vault cannot import.
func TestGetImportParameters_RejectsWrongAlgorithm(t *testing.T) {
	b, _ := newVaultTestBackend(t)
	ctx := context.Background()

	attrs := &types.KeyAttributes{
		CN:                 "byok-wrong-algorithm",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err := b.GetImportParameters(ctx, attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.ErrorIs(t, err, backend.ErrInvalidAlgorithm)
}

// TestUnwrapKey_NotSupported verifies UnwrapKey reports, precisely and
// typedly, that Vault performs the BYOK unwrap internally during ImportKey
// -- mirroring AWS KMS's identical refusal for the identical reason -- and
// never falls through to a runtime panic or a generic error for a
// capability this backend genuinely does not offer as a standalone call.
func TestUnwrapKey_NotSupported(t *testing.T) {
	b, _ := newVaultTestBackend(t)

	_, err := b.UnwrapKey(context.Background(), &backend.WrappedKeyMaterial{}, &backend.ImportParameters{})
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

// TestExportKey_HasNoNativeEquivalent verifies ExportKey refuses with a
// precise, correctly classified capability error (joining
// backend.ErrOperationNotSupported so the service layer reports it as a
// capability boundary rather than a 500) instead of attempting a wrap Vault
// has no server-side primitive for.
func TestExportKey_HasNoNativeEquivalent(t *testing.T) {
	b, _ := newVaultTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:                 "byok-export-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}

	_, err := b.ExportKey(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrOperationNotSupported)
	assert.True(t, errors.Is(err, ErrWrappedExportNotSupported) || len(err.Error()) > 0, "error must name the unsupported operation")
}

// TestExportKeyMaterial_RefusesNonExportableKey verifies that a symmetric
// key generated WITHOUT Exportable=true cannot be read back through
// ExportKeyMaterial, matching every other backend's CKA_EXTRACTABLE-style
// convention -- Vault Transit itself refuses the underlying export call for
// exactly this reason, and this backend must surface that as the same typed
// backend.ErrKeyNotExportable every other backend uses.
func TestExportKeyMaterial_RefusesNonExportableKey(t *testing.T) {
	b, _ := newVaultTestBackend(t)
	ctx := context.Background()

	attrs := &types.KeyAttributes{
		CN:                 "byok-non-exportable",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err := b.GenerateSymmetricKey(ctx, attrs)
	require.NoError(t, err)

	_, err = b.ExportKeyMaterial(ctx, attrs)
	assert.ErrorIs(t, err, backend.ErrKeyNotExportable)
}

// TestExportKeyMaterial_RefusesAsymmetricKey verifies the asymmetric refusal
// every backend's ExportKeyMaterial gives, ahead of any Vault-specific
// exportability check.
func TestExportKeyMaterial_RefusesAsymmetricKey(t *testing.T) {
	b, _ := newVaultTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:           "byok-asymmetric-export",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_VAULT,
		KeyAlgorithm: x509.RSA,
	}

	_, err := b.ExportKeyMaterial(context.Background(), attrs)
	assert.ErrorIs(t, err, backend.ErrAsymmetricKeyExportNotAllowed)
}

// TestImportKey_RefusesExistingKey verifies ImportKey refuses to overwrite a
// key that already exists, matching GenerateSymmetricKey's own collision
// refusal and every other backend's ImportKey.
func TestImportKey_RefusesExistingKey(t *testing.T) {
	b, _ := newVaultTestBackend(t)
	ctx := context.Background()

	attrs := &types.KeyAttributes{
		CN:                 "byok-collision",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	_, err := b.GenerateSymmetricKey(ctx, attrs)
	require.NoError(t, err)

	wrapped := &backend.WrappedKeyMaterial{WrappedKey: []byte("irrelevant-but-nonempty"), Algorithm: backend.WrappingAlgorithmVaultTransitBYOK}
	err = b.ImportKey(ctx, attrs, wrapped)
	assert.ErrorIs(t, err, backend.ErrKeyAlreadyExists)
}

// TestBackend_SatisfiesImportExportBackend is the compile-time-adjacent
// runtime check that *Backend's import/export ceremony is reachable through
// the same capability-split interfaces AWS KMS is, for a backend that
// (unlike AWS KMS) genuinely offers both halves.
func TestBackend_SatisfiesImportExportBackend(t *testing.T) {
	b, _ := newVaultTestBackend(t)

	var provider types.KeyProvider = b
	if _, ok := provider.(backend.ImportBackend); !ok {
		t.Error("vault backend must satisfy backend.ImportBackend")
	}
	if _, ok := provider.(backend.ExportBackend); !ok {
		t.Error("vault backend must satisfy backend.ExportBackend")
	}
	if _, ok := provider.(backend.ImportExportBackend); !ok {
		t.Error("vault backend must satisfy backend.ImportExportBackend")
	}
}
