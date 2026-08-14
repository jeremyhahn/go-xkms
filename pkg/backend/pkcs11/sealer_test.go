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

//go:build pkcs11

package pkcs11

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestCanSeal_NotInitialized tests CanSeal returns false when not initialized
func TestCanSeal_NotInitialized(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	if b.CanSeal() {
		t.Error("CanSeal() should return false when not initialized")
	}
}

// TestSeal_NilOptions tests Seal fails with nil options
func TestSeal_NilOptions(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	ctx := context.Background()
	_, err = b.Seal(ctx, []byte("test"), nil)
	if err == nil {
		t.Error("Seal() should fail with nil options")
	}
}

// TestSeal_NilKeyAttributes tests Seal fails with nil KeyAttributes
func TestSeal_NilKeyAttributes(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	ctx := context.Background()
	_, err = b.Seal(ctx, []byte("test"), &types.SealOptions{
		KeyAttributes: nil,
	})
	if err == nil {
		t.Error("Seal() should fail with nil KeyAttributes")
	}
}

// TestSeal_NotInitialized tests Seal fails when not initialized
func TestSeal_NotInitialized(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:                 "test-seal",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	ctx := context.Background()
	_, err = b.Seal(ctx, []byte("test data"), &types.SealOptions{
		KeyAttributes: attrs,
	})
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Seal() error = %v, want %v", err, ErrNotInitialized)
	}
}

// TestUnseal_NilSealedData tests Unseal fails with nil sealed data
func TestUnseal_NilSealedData(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	ctx := context.Background()
	_, err = b.Unseal(ctx, nil, &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{},
	})
	if err == nil {
		t.Error("Unseal() should fail with nil sealed data")
	}
}

// TestUnseal_WrongBackend tests Unseal fails with wrong backend type
func TestUnseal_WrongBackend(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypeSoftware, // Wrong backend
		Ciphertext: []byte("test"),
		Nonce:      []byte("test-nonce"),
	}

	ctx := context.Background()
	_, err = b.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{},
	})
	if err == nil {
		t.Error("Unseal() should fail with wrong backend type")
	}
}

// TestUnseal_NilOptions tests Unseal fails with nil options
func TestUnseal_NilOptions(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypePKCS11,
		Ciphertext: []byte("test"),
		Nonce:      []byte("test-nonce"),
	}

	ctx := context.Background()
	_, err = b.Unseal(ctx, sealed, nil)
	if err == nil {
		t.Error("Unseal() should fail with nil options")
	}
}

// TestUnseal_NilKeyAttributes tests Unseal fails with nil KeyAttributes
func TestUnseal_NilKeyAttributes(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypePKCS11,
		Ciphertext: []byte("test"),
		Nonce:      []byte("test-nonce"),
	}

	ctx := context.Background()
	_, err = b.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: nil,
	})
	if err == nil {
		t.Error("Unseal() should fail with nil KeyAttributes")
	}
}

// TestUnseal_KeyMismatch tests Unseal fails with mismatched key ID
func TestUnseal_KeyMismatch(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypePKCS11,
		Ciphertext: []byte("test"),
		Nonce:      []byte("test-nonce"),
		KeyID:      "original-key-id",
	}

	attrs := &types.KeyAttributes{
		CN:                 "different-key", // Different from KeyID
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	ctx := context.Background()
	_, err = b.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if err == nil {
		t.Error("Unseal() should fail with mismatched key ID")
	}
}

// TestUnseal_NotInitialized tests Unseal fails when not initialized
func TestUnseal_NotInitialized(t *testing.T) {
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library: %v", err)
	}

	config := &Config{
		Library:     tempLib,
		TokenLabel:  "test",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("NewBackend() failed: %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:                 "test-unseal",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	sealed := &types.SealedData{
		Backend:    types.BackendTypePKCS11,
		Ciphertext: []byte("test"),
		Nonce:      make([]byte, 12),
		Tag:        make([]byte, 16),
		KeyID:      attrs.ID(),
	}

	ctx := context.Background()
	_, err = b.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: attrs,
	})
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Unseal() error = %v, want %v", err, ErrNotInitialized)
	}
}

// TestMarshalUnmarshalSealedData tests JSON serialization of SealedData
func TestMarshalUnmarshalSealedData(t *testing.T) {
	original := &types.SealedData{
		Backend:    types.BackendTypePKCS11,
		Ciphertext: []byte("encrypted data"),
		Nonce:      []byte("test-nonce-12"),
		Tag:        []byte("test-tag-16-byte"),
		KeyID:      "test-key-id",
		Metadata: map[string][]byte{
			"pkcs11:algorithm": []byte("AES-256-GCM"),
		},
	}

	// Marshal
	data, err := MarshalSealedData(original)
	if err != nil {
		t.Fatalf("MarshalSealedData() failed: %v", err)
	}

	// Unmarshal
	restored, err := UnmarshalSealedData(data)
	if err != nil {
		t.Fatalf("UnmarshalSealedData() failed: %v", err)
	}

	// Verify
	if restored.Backend != original.Backend {
		t.Errorf("Backend mismatch: got %s, want %s", restored.Backend, original.Backend)
	}
	if string(restored.Ciphertext) != string(original.Ciphertext) {
		t.Error("Ciphertext mismatch")
	}
	if string(restored.Nonce) != string(original.Nonce) {
		t.Error("Nonce mismatch")
	}
	if string(restored.Tag) != string(original.Tag) {
		t.Error("Tag mismatch")
	}
	if restored.KeyID != original.KeyID {
		t.Errorf("KeyID mismatch: got %s, want %s", restored.KeyID, original.KeyID)
	}
}

// newSealingBackend returns a provisioned backend together with the attributes
// of an AES-256-GCM key that exists on its token, which is the precondition for
// every Seal/Unseal operation.
func newSealingBackend(t *testing.T, label, cn string) (*Backend, *types.KeyAttributes) {
	t.Helper()

	b := newProvisionedBackend(t, label)

	attrs := &types.KeyAttributes{
		CN:                 cn,
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_PKCS11,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	require.NoError(t, attrs.Validate())

	_, err := b.GenerateSymmetricKey(context.Background(), attrs)
	require.NoError(t, err, "the sealing key must exist on the token")

	return b, attrs
}

// TestCanSeal_Initialized verifies CanSeal reports true only once both the
// session pool and the PKCS#11 context exist, which is what the sealing path
// dereferences.
func TestCanSeal_Initialized(t *testing.T) {
	b := newProvisionedBackend(t, "seal-cansealed")
	require.True(t, b.CanSeal())

	require.NoError(t, b.Close())
	require.False(t, b.CanSeal(), "a closed backend must not claim it can seal")
}

// TestSeal_Unseal_RoundTrip verifies the full hardware sealing path: the
// plaintext must be recoverable, and the sealed envelope must actually be an
// envelope — ciphertext distinct from plaintext, a nonce present, and the key
// identity recorded so a later unseal can be matched to the right key.
func TestSeal_Unseal_RoundTrip(t *testing.T) {
	b, attrs := newSealingBackend(t, "seal-roundtrip", "seal-roundtrip-key")
	ctx := context.Background()

	plaintext := []byte("hardware sealed payload")

	sealed, err := b.Seal(ctx, plaintext, &types.SealOptions{KeyAttributes: attrs})
	require.NoError(t, err)
	require.NotNil(t, sealed)

	require.Equal(t, types.BackendTypePKCS11, sealed.Backend)
	require.NotEmpty(t, sealed.Ciphertext)
	require.NotEqual(t, plaintext, sealed.Ciphertext, "the payload must not be stored in the clear")
	require.NotEmpty(t, sealed.Nonce, "AES-GCM requires a nonce for every seal")
	require.Equal(t, attrs.ID(), sealed.KeyID)
	require.Equal(t, string(types.SymmetricAES256GCM), string(sealed.Metadata["pkcs11:algorithm"]))
	require.NotContains(t, sealed.Metadata, "pkcs11:has_aad", "no AAD was supplied")

	unsealed, err := b.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: attrs})
	require.NoError(t, err)
	require.Equal(t, plaintext, unsealed)
}

// TestSeal_Unseal_NonceIsUnique verifies that two seals of the same plaintext
// under the same key produce different envelopes. A repeated GCM nonce under
// one key destroys confidentiality, so this is a security invariant rather than
// a cosmetic one.
func TestSeal_Unseal_NonceIsUnique(t *testing.T) {
	b, attrs := newSealingBackend(t, "seal-nonce-unique", "seal-nonce-key")
	ctx := context.Background()

	plaintext := []byte("repeated payload")

	first, err := b.Seal(ctx, plaintext, &types.SealOptions{KeyAttributes: attrs})
	require.NoError(t, err)
	second, err := b.Seal(ctx, plaintext, &types.SealOptions{KeyAttributes: attrs})
	require.NoError(t, err)

	require.NotEqual(t, first.Nonce, second.Nonce, "each seal must use a fresh GCM nonce")
	require.NotEqual(t, first.Ciphertext, second.Ciphertext)

	for _, sealed := range []*types.SealedData{first, second} {
		got, err := b.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: attrs})
		require.NoError(t, err)
		require.Equal(t, plaintext, got)
	}
}

// TestSeal_Unseal_AAD verifies that additional authenticated data is bound to
// the envelope: unsealing succeeds only with the identical AAD, and the
// metadata records that AAD was used.
//
// The negative halves matter more than the positive one. If the AAD were
// dropped on the way to the token, every one of these mismatched unseals would
// succeed and the caller's context binding would be silently worthless.
func TestSeal_Unseal_AAD(t *testing.T) {
	b, attrs := newSealingBackend(t, "seal-aad", "seal-aad-key")
	ctx := context.Background()

	plaintext := []byte("aad bound payload")
	aad := []byte("tenant=acme,purpose=barrier")

	sealed, err := b.Seal(ctx, plaintext, &types.SealOptions{KeyAttributes: attrs, AAD: aad})
	require.NoError(t, err)
	require.Equal(t, []byte("true"), sealed.Metadata["pkcs11:has_aad"])

	got, err := b.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: attrs, AAD: aad})
	require.NoError(t, err)
	require.Equal(t, plaintext, got)

	_, err = b.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: attrs, AAD: []byte("tenant=evil")})
	require.Error(t, err, "a different AAD must not authenticate")
	var wrongAAD *errs.Wrapped
	require.True(t, errors.As(err, &wrongAAD))
	require.Equal(t, "failed to decrypt data (check key and AAD)", wrongAAD.Msg)

	_, err = b.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: attrs})
	require.Error(t, err, "omitting the AAD must not authenticate")
}

// TestSeal_Unseal_TamperedCiphertext verifies the AEAD integrity guarantee: a
// single flipped bit in the sealed payload must be detected rather than
// returning corrupted plaintext.
func TestSeal_Unseal_TamperedCiphertext(t *testing.T) {
	b, attrs := newSealingBackend(t, "seal-tamper", "seal-tamper-key")
	ctx := context.Background()

	sealed, err := b.Seal(ctx, []byte("tamper target payload"), &types.SealOptions{KeyAttributes: attrs})
	require.NoError(t, err)
	require.NotEmpty(t, sealed.Ciphertext)

	sealed.Ciphertext[0] ^= 0x01

	_, err = b.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: attrs})
	require.Error(t, err, "a modified envelope must not unseal")

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.Equal(t, "failed to decrypt data (check key and AAD)", wrapped.Msg)
}

// TestSeal_Unseal_WrongKey verifies that an envelope sealed with one key cannot
// be opened with another. The key-ID guard in Unseal is expected to catch this
// before any token call.
func TestSeal_Unseal_WrongKey(t *testing.T) {
	b, attrs := newSealingBackend(t, "seal-wrongkey", "seal-key-a")
	ctx := context.Background()

	other := &types.KeyAttributes{
		CN:                 "seal-key-b",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_PKCS11,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	require.NoError(t, other.Validate())
	_, err := b.GenerateSymmetricKey(ctx, other)
	require.NoError(t, err)

	sealed, err := b.Seal(ctx, []byte("wrong key payload"), &types.SealOptions{KeyAttributes: attrs})
	require.NoError(t, err)

	_, err = b.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: other})
	require.Error(t, err)
	require.Contains(t, err.Error(), "key ID mismatch")
}

// TestSeal_AsymmetricKeyRejected verifies that an asymmetric key is refused for
// sealing, since the PKCS#11 sealing path is AES-GCM on an HSM-resident secret
// key.
func TestSeal_AsymmetricKeyRejected(t *testing.T) {
	b := newProvisionedBackend(t, "seal-asymmetric")
	ctx := context.Background()

	attrs := &types.KeyAttributes{
		CN:           "seal-asymmetric-key",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_PKCS11,
		KeyAlgorithm: x509.RSA,
	}

	_, err := b.Seal(ctx, []byte("payload"), &types.SealOptions{KeyAttributes: attrs})
	require.Error(t, err)
	require.Contains(t, err.Error(), "PKCS#11 sealing requires a symmetric key")

	sealed := &types.SealedData{
		Backend:    types.BackendTypePKCS11,
		Ciphertext: []byte("ciphertext"),
	}
	_, err = b.Unseal(ctx, sealed, &types.UnsealOptions{KeyAttributes: attrs})
	require.Error(t, err)
	require.Contains(t, err.Error(), "PKCS#11 unsealing requires a symmetric key")
}

// TestSeal_MissingKey verifies that sealing with a symmetric key that was never
// generated fails with the encrypter-lookup context rather than silently
// creating a key.
func TestSeal_MissingKey(t *testing.T) {
	b := newProvisionedBackend(t, "seal-missing-key")
	ctx := context.Background()

	attrs := &types.KeyAttributes{
		CN:                 "seal-never-generated",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_PKCS11,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	require.NoError(t, attrs.Validate())

	_, err := b.Seal(ctx, []byte("payload"), &types.SealOptions{KeyAttributes: attrs})
	require.Error(t, err)

	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped))
	require.Equal(t, "failed to get symmetric encrypter", wrapped.Msg)
}

// TestSealedData_SurvivesJSONRoundTrip verifies that a sealed envelope can be
// persisted and restored through MarshalSealedData/UnmarshalSealedData and
// still unseal. The binary fields are the risk here: a serialization that
// mangled the nonce or tag would only show up at unseal time.
func TestSealedData_SurvivesJSONRoundTrip(t *testing.T) {
	b, attrs := newSealingBackend(t, "seal-json", "seal-json-key")
	ctx := context.Background()

	plaintext := []byte("persisted payload")
	aad := []byte("persisted-aad")

	sealed, err := b.Seal(ctx, plaintext, &types.SealOptions{KeyAttributes: attrs, AAD: aad})
	require.NoError(t, err)

	encoded, err := MarshalSealedData(sealed)
	require.NoError(t, err)

	restored, err := UnmarshalSealedData(encoded)
	require.NoError(t, err)

	got, err := b.Unseal(ctx, restored, &types.UnsealOptions{KeyAttributes: attrs, AAD: aad})
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}

// TestUnmarshalSealedData_InvalidJSON verifies the decode failure path returns
// the JSON error instead of a zero-valued envelope that would later be
// misinterpreted as an empty seal.
func TestUnmarshalSealedData_InvalidJSON(t *testing.T) {
	restored, err := UnmarshalSealedData([]byte("{not json"))
	require.Nil(t, restored)
	require.Error(t, err)

	var syntaxErr *json.SyntaxError
	require.True(t, errors.As(err, &syntaxErr), "the JSON decoding error must reach the caller")
}
