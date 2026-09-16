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
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newVaultTestBackend builds a Backend against a fresh in-process Transit
// double, returning both so a test can inspect the double's internal state
// (e.g. whether a key was created exportable) alongside driving the backend
// through its public API.
func newVaultTestBackend(t *testing.T) (*Backend, *transitDouble) {
	t.Helper()

	double, addr := newTransitDouble(t)
	config := &Config{
		Address:     addr,
		Token:       "test-token",
		TransitPath: "transit",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })

	return b, double
}

// TestGenerateKey_CreatesNonExportableKey verifies that GenerateKey never
// asks Vault for an exportable Transit key (H8): Capabilities() advertises
// Export: false, and the public key is already available through the
// ordinary read-key endpoint, so exportable:true only adds an unused way to
// extract the private key.
func TestGenerateKey_CreatesNonExportableKey(t *testing.T) {
	b, double := newVaultTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:           "test-non-exportable",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_VAULT,
		KeyAlgorithm: x509.RSA,
	}

	_, err := b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	exportable, exists := double.exportable(b.sanitizeKeyName(attrs.CN))
	require.True(t, exists, "key must have been created in Vault")
	assert.False(t, exportable, "GenerateKey must create keys with exportable:false")
}

// TestGenerateKey_RejectsNilAttributes verifies error handling for invalid
// input.
func TestGenerateKey_RejectsNilAttributes(t *testing.T) {
	b, _ := newVaultTestBackend(t)

	_, err := b.GenerateKey(context.Background(), nil)
	require.Error(t, err)
}

// TestEncryptDecrypt_SurvivesRotation verifies that ciphertext produced
// before a key rotation can still be decrypted afterward, and that
// ciphertext produced after the rotation decrypts too (H9). The backend
// must preserve the full "vault:v<n>:" envelope as the opaque ciphertext
// payload instead of stripping it (on encrypt) and replacing it with a
// hardcoded "vault:v1:" prefix (on decrypt).
func TestEncryptDecrypt_SurvivesRotation(t *testing.T) {
	b, _ := newVaultTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:           "test-rotate-envelope",
		KeyType:      backend.KEY_TYPE_ENCRYPTION,
		StoreType:    backend.STORE_VAULT,
		KeyAlgorithm: x509.RSA,
	}
	_, err := b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	ctx := context.Background()

	preRotation := []byte("secret encrypted before rotation")
	preCiphertext, err := b.Encrypt(ctx, attrs, preRotation)
	require.NoError(t, err)

	require.NoError(t, b.RotateKey(ctx, attrs))

	postRotation := []byte("secret encrypted after rotation")
	postCiphertext, err := b.Encrypt(ctx, attrs, postRotation)
	require.NoError(t, err)

	// The two envelopes must differ: they were sealed under different key
	// versions, so identical handling of both is not masking the bug.
	assert.NotEqual(t, preCiphertext, postCiphertext)

	decrypter, err := b.Decrypter(ctx, attrs)
	require.NoError(t, err)

	gotPre, err := decrypter.Decrypt(nil, preCiphertext, nil)
	require.NoError(t, err, "ciphertext from before the rotation must still decrypt")
	assert.Equal(t, preRotation, gotPre)

	gotPost, err := decrypter.Decrypt(nil, postCiphertext, nil)
	require.NoError(t, err, "ciphertext from after the rotation must decrypt")
	assert.Equal(t, postRotation, gotPost)
}

// TestEncrypt_RejectsNonRSAKey verifies error handling for invalid input:
// Encrypt only supports RSA transit keys.
func TestEncrypt_RejectsNonRSAKey(t *testing.T) {
	b, _ := newVaultTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:           "test-encrypt-wrong-algorithm",
		KeyType:      backend.KEY_TYPE_ENCRYPTION,
		StoreType:    backend.STORE_VAULT,
		KeyAlgorithm: x509.ECDSA,
	}

	_, err := b.Encrypt(context.Background(), attrs, []byte("data"))
	require.Error(t, err)
}

// TestSanitizeKeyName_Injective verifies that CNs a naive scheme would
// collapse together map to distinct Vault key names, and that the mapping
// round-trips through desanitizeKeyName (H10).
func TestSanitizeKeyName_Injective(t *testing.T) {
	b := &Backend{}

	names := []string{"a.b", "a_b", "a-b", "a b", "A.B", "tenant/key", "plain"}
	seen := make(map[string]string, len(names))
	for _, cn := range names {
		sanitized := b.sanitizeKeyName(cn)
		if existing, collided := seen[sanitized]; collided {
			t.Fatalf("sanitizeKeyName(%q) == sanitizeKeyName(%q) == %q: collision", cn, existing, sanitized)
		}
		seen[sanitized] = cn

		assert.Equal(t, cn, b.desanitizeKeyName(sanitized), "desanitizeKeyName must invert sanitizeKeyName")
	}
}

// TestSanitizeKeyName_OnlyProducesVaultSafeCharacters verifies error/edge
// handling: the escaping scheme never emits characters ('/' in particular)
// that would be misrouted as a path separator by Vault's HTTP API.
func TestSanitizeKeyName_OnlyProducesVaultSafeCharacters(t *testing.T) {
	b := &Backend{}

	sanitized := b.sanitizeKeyName("tenant/key with spaces.and.dots")
	for _, r := range sanitized {
		safe := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') || r == '_'
		assert.Truef(t, safe, "sanitizeKeyName produced unsafe character %q in %q", r, sanitized)
	}
	assert.NotContains(t, sanitized, "/", "sanitizeKeyName must never emit a path separator")
}

// TestSigner_PinsVersionAcrossRotation verifies that a Signer built before
// a key rotation keeps signing with (and reporting the public key of) the
// version it was constructed against, instead of silently following the
// key to its latest version (H12).
func TestSigner_PinsVersionAcrossRotation(t *testing.T) {
	b, _ := newVaultTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:           "test-signer-pin",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_VAULT,
		KeyAlgorithm: x509.RSA,
	}
	_, err := b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	ctx := context.Background()
	oldSigner, err := b.Signer(ctx, attrs)
	require.NoError(t, err)
	oldPublicKey, ok := oldSigner.Public().(*rsa.PublicKey)
	require.True(t, ok)

	require.NoError(t, b.RotateKey(ctx, attrs))

	newSigner, err := b.Signer(ctx, attrs)
	require.NoError(t, err)
	newPublicKey, ok := newSigner.Public().(*rsa.PublicKey)
	require.True(t, ok)

	// Confirm the rotation really produced a new key.
	assert.False(t, oldPublicKey.Equal(newPublicKey))

	digest := sha256.Sum256([]byte("pin me to my version"))

	oldSig, err := oldSigner.Sign(nil, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.NoError(t, rsa.VerifyPKCS1v15(oldPublicKey, crypto.SHA256, digest[:], oldSig),
		"pre-rotation signer must still sign with its own (old) key")
	assert.Error(t, rsa.VerifyPKCS1v15(newPublicKey, crypto.SHA256, digest[:], oldSig),
		"pre-rotation signature must not verify under the post-rotation key")

	newSig, err := newSigner.Sign(nil, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.NoError(t, rsa.VerifyPKCS1v15(newPublicKey, crypto.SHA256, digest[:], newSig),
		"post-rotation signer must sign with the new key")
}

// TestSigner_RejectsMissingKey verifies error handling: Signer on a CN with
// no stored metadata returns an error instead of a signer over a
// nonexistent key.
func TestSigner_RejectsMissingKey(t *testing.T) {
	b, _ := newVaultTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:           "does-not-exist",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_VAULT,
		KeyAlgorithm: x509.RSA,
	}

	_, err := b.Signer(context.Background(), attrs)
	require.Error(t, err)
}
