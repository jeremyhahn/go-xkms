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

package software

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Coverage-gap tests: real behavior + error paths not exercised elsewhere.
// ============================================================================

// countingListFailStorage wraps a real storage.Backend and fails the Nth
// call (1-indexed) to List, succeeding on every other call. This lets a
// test target exactly one of ListKeys' three delegate calls (pkcs8,
// symmetric, quantum) without affecting the others.
type countingListFailStorage struct {
	storage.Backend
	failOnCall int32
	calls      atomic.Int32
}

func (s *countingListFailStorage) List(ctx context.Context, prefix string) ([]string, error) {
	n := s.calls.Add(1)
	if n == s.failOnCall {
		return nil, &errs.Message{Msg: fmt.Sprintf("injected list failure on call %d", n)}
	}
	return s.Backend.List(ctx, prefix)
}

// closeFailStorage wraps a real storage.Backend whose Close() always
// errors, so callers can exercise Close-propagation branches.
type closeFailStorage struct {
	storage.Backend
}

func (s *closeFailStorage) Close() error {
	return &errs.Message{Msg: "injected close failure"}
}

// putFailStorage wraps a real storage.Backend whose Put() always errors,
// so callers can exercise storage-write failure branches without
// disturbing reads.
type putFailStorage struct {
	storage.Backend
}

func (s *putFailStorage) Put(_ context.Context, _ string, _ []byte) error {
	return &errs.Message{Msg: "injected put failure"}
}

// TestImportTokenData_DestroyNilReceiver verifies destroy() is safe to
// call on a nil *importTokenData (defensive nil-receiver guard).
func TestImportTokenData_DestroyNilReceiver(t *testing.T) {
	var td *importTokenData
	td.destroy() // must not panic
}

// TestClose_PKCS8CloseError verifies that Close propagates a failure from
// the underlying PKCS8 backend's storage.Close().
func TestClose_PKCS8CloseError(t *testing.T) {
	fail := &closeFailStorage{Backend: storage.New()}
	be, err := NewBackend(&Config{KeyStorage: fail})
	require.NoError(t, err)

	err = be.(*SoftwareBackend).Close()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to close PKCS8 backend")
}

// TestListKeys_PKCS8DelegateError verifies ListKeys propagates a failure
// from the first delegate call (pkcs8Backend.ListKeys).
func TestListKeys_PKCS8DelegateError(t *testing.T) {
	fail := &countingListFailStorage{Backend: storage.New(), failOnCall: 1}
	be, err := NewBackend(&Config{KeyStorage: fail})
	require.NoError(t, err)
	defer func() { _ = be.Close() }()

	_, err = be.ListKeys(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list PKCS8 keys")
}

// TestListKeys_SymmetricDelegateError verifies ListKeys propagates a
// failure from the second delegate call (symmetricBackend.ListKeys).
func TestListKeys_SymmetricDelegateError(t *testing.T) {
	fail := &countingListFailStorage{Backend: storage.New(), failOnCall: 2}
	be, err := NewBackend(&Config{KeyStorage: fail})
	require.NoError(t, err)
	defer func() { _ = be.Close() }()

	_, err = be.ListKeys(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list symmetric keys")
}

// TestListKeys_QuantumDelegateError verifies ListKeys propagates a
// failure from the third delegate call (quantumBackend.ListKeys).
func TestListKeys_QuantumDelegateError(t *testing.T) {
	fail := &countingListFailStorage{Backend: storage.New(), failOnCall: 3}
	be, err := NewBackend(&Config{KeyStorage: fail})
	require.NoError(t, err)
	defer func() { _ = be.Close() }()

	_, err = be.ListKeys(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list quantum keys")
}

// TestWrapKey_OversizedKeyMaterial verifies that WrapKey propagates an
// RSA-OAEP encryption failure when the key material exceeds the maximum
// plaintext size for the wrapping key's modulus (a real, not injected,
// cryptographic limit).
func TestWrapKey_OversizedKeyMaterial(t *testing.T) {
	be := createFullTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("wrap-oversized.com", 2048)
	params, err := be.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	// RSA-2048 OAEP-SHA256 max plaintext is 256 - 2*32 - 2 = 190 bytes.
	oversized := make([]byte, 512)
	_, err = be.WrapKey(context.Background(), oversized, params)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to wrap key")
}

// TestUnwrapKey_ClosedBackend verifies UnwrapKey's closed-backend guard
// fires when non-nil wrapped/params are supplied (the existing
// TestBackendClosed test passes nil params, which short-circuits earlier).
func TestUnwrapKey_ClosedBackend(t *testing.T) {
	be := createFullTestBackend(t)
	require.NoError(t, be.Close())

	wrapped := &backend.WrappedKeyMaterial{WrappedKey: []byte{1, 2, 3}}
	params := &backend.ImportParameters{}

	_, err := be.UnwrapKey(context.Background(), wrapped, params)
	require.ErrorIs(t, err, ErrStorageClosed)
}

// TestUnwrapKey_EnclaveAlreadyDestroyed verifies UnwrapKey surfaces an
// error when the sealed wrapping key enclave has already been destroyed
// (Open() on a destroyed Secret fails).
func TestUnwrapKey_EnclaveAlreadyDestroyed(t *testing.T) {
	be := createFullTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("enclave-destroyed.com", 2048)
	params, err := be.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	wrapped, err := be.WrapKey(context.Background(), []byte("some key material"), params)
	require.NoError(t, err)

	be.importMu.Lock()
	be.importTokens[string(wrapped.ImportToken)].privateKey.Destroy()
	be.importMu.Unlock()

	_, err = be.UnwrapKey(context.Background(), wrapped, params)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open wrapping key enclave")
}

// TestUnwrapKey_CorruptedEnclaveData verifies UnwrapKey surfaces a parse
// error when the sealed enclave contains data that is not valid PKCS#8.
func TestUnwrapKey_CorruptedEnclaveData(t *testing.T) {
	be := createFullTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("enclave-corrupted.com", 2048)
	params, err := be.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	wrapped, err := be.WrapKey(context.Background(), []byte("some key material"), params)
	require.NoError(t, err)

	garbage, err := secure.NewSecret([]byte("this is not a valid pkcs8 der blob"))
	require.NoError(t, err)

	be.importMu.Lock()
	be.importTokens[string(wrapped.ImportToken)].privateKey.Destroy()
	be.importTokens[string(wrapped.ImportToken)].privateKey = garbage
	be.importMu.Unlock()

	_, err = be.UnwrapKey(context.Background(), wrapped, params)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse wrapping key")
}

// TestUnwrapKey_EnclaveNotRSA verifies UnwrapKey rejects an enclave whose
// sealed PKCS#8 DER decodes to a non-RSA private key (the wrapping key
// must always be RSA for the wrapping algorithms this backend supports).
func TestUnwrapKey_EnclaveNotRSA(t *testing.T) {
	be := createFullTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("enclave-not-rsa.com", 2048)
	params, err := be.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	wrapped, err := be.WrapKey(context.Background(), []byte("some key material"), params)
	require.NoError(t, err)

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	require.NoError(t, err)
	sealedECDSA, err := secure.NewSecret(der)
	require.NoError(t, err)

	be.importMu.Lock()
	be.importTokens[string(wrapped.ImportToken)].privateKey.Destroy()
	be.importTokens[string(wrapped.ImportToken)].privateKey = sealedECDSA
	be.importMu.Unlock()

	_, err = be.UnwrapKey(context.Background(), wrapped, params)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wrapping key is not RSA")
	assert.ErrorIs(t, err, backend.ErrInvalidKeyType)
}

// TestUnwrapKey_DecryptFailure verifies UnwrapKey propagates an
// RSA-OAEP decryption failure for corrupted ciphertext.
func TestUnwrapKey_DecryptFailure(t *testing.T) {
	be := createFullTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("unwrap-decrypt-fail.com", 2048)
	params, err := be.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	wrapped, err := be.WrapKey(context.Background(), []byte("some key material"), params)
	require.NoError(t, err)

	// Corrupt the ciphertext so RSA-OAEP decryption fails.
	corrupted := make([]byte, len(wrapped.WrappedKey))
	copy(corrupted, wrapped.WrappedKey)
	corrupted[0] ^= 0xFF
	corrupted[len(corrupted)-1] ^= 0xFF
	wrapped.WrappedKey = corrupted

	_, err = be.UnwrapKey(context.Background(), wrapped, params)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unwrap key")
}

// TestImportKey_UnwrapFailure verifies ImportKey wraps an UnwrapKey
// failure (algorithm mismatch between the wrapped material and the
// token's expected algorithm).
func TestImportKey_UnwrapFailure(t *testing.T) {
	be := createFullTestBackend(t)
	defer func() { _ = be.Close() }()

	wrapAttrs := createRSAAttrs("import-unwrap-fail.com", 2048)
	params, err := be.GetImportParameters(context.Background(), wrapAttrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	wrapped, err := be.WrapKey(context.Background(), []byte("some key material"), params)
	require.NoError(t, err)

	// Claim a different algorithm than the token was created with.
	wrapped.Algorithm = backend.WrappingAlgorithmRSAES_OAEP_SHA_1

	err = be.ImportKey(context.Background(), wrapAttrs, wrapped)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unwrap key material")
}

// TestExportKey_SymmetricKeyNotFound verifies ExportKey surfaces a "failed
// to get symmetric key" error when the referenced symmetric key does not
// exist.
func TestExportKey_SymmetricKeyNotFound(t *testing.T) {
	be := createFullTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createAESAttrs("export-symmetric-missing", 256, types.SymmetricAES256GCM)
	attrs.Exportable = true

	_, err := be.ExportKey(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get symmetric key")
}

// TestExportKey_AsymmetricKeyNotFound verifies ExportKey surfaces a
// "failed to get private key" error when the referenced asymmetric key
// does not exist.
func TestExportKey_AsymmetricKeyNotFound(t *testing.T) {
	be := createFullTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("export-asymmetric-missing", 2048)
	attrs.Exportable = true

	_, err := be.ExportKey(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get private key")
}

// TestImportKey_SymmetricStorageError verifies importSymmetricKey
// propagates a storage.Put failure.
func TestImportKey_SymmetricStorageError(t *testing.T) {
	fail := &putFailStorage{Backend: storage.New()}
	be, err := NewBackend(&Config{KeyStorage: fail})
	require.NoError(t, err)
	sb := be.(*SoftwareBackend)
	defer func() { _ = sb.Close() }()

	wrapAttrs := createRSAAttrs("import-sym-storage-wrap", 2048)
	params, err := sb.GetImportParameters(context.Background(), wrapAttrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	keyMaterial := make([]byte, 32) // AES-256
	wrapped, err := sb.WrapKey(context.Background(), keyMaterial, params)
	require.NoError(t, err)

	importAttrs := createAESAttrs("import-sym-storage-fail", 256, types.SymmetricAES256GCM)
	err = sb.ImportKey(context.Background(), importAttrs, wrapped)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to store symmetric key")
}

// TestImportKey_KeyTypeMismatch verifies importAsymmetricKey rejects
// PKCS8 key material whose actual type does not match attrs.KeyAlgorithm.
func TestImportKey_KeyTypeMismatch(t *testing.T) {
	be := createFullTestBackend(t)
	defer func() { _ = be.Close() }()

	wrapAttrs := createRSAAttrs("import-typemismatch-wrap", 2048)
	// PKCS8 RSA key material exceeds plain RSA-OAEP's plaintext limit, so
	// use the hybrid RSA+AES wrap algorithm designed for larger payloads.
	params, err := be.GetImportParameters(context.Background(), wrapAttrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.NoError(t, err)

	// Marshal a real RSA private key as the "unwrapped" material.
	rsaAttrs := createRSAAttrs("actual-rsa-material", 2048)
	rsaPriv, err := be.GenerateKey(context.Background(), rsaAttrs)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(rsaPriv)
	require.NoError(t, err)

	wrapped, err := be.WrapKey(context.Background(), der, params)
	require.NoError(t, err)

	// Claim it's an ECDSA key even though the material is RSA.
	importAttrs := createECDSAAttrs("import-typemismatch", "P-256")
	err = be.ImportKey(context.Background(), importAttrs, wrapped)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key type validation failed")
}

// TestImportKey_AsymmetricStorageError verifies importAsymmetricKey
// propagates a storage.Put failure.
func TestImportKey_AsymmetricStorageError(t *testing.T) {
	fail := &putFailStorage{Backend: storage.New()}
	be, err := NewBackend(&Config{KeyStorage: fail})
	require.NoError(t, err)
	sb := be.(*SoftwareBackend)
	defer func() { _ = sb.Close() }()

	wrapAttrs := createRSAAttrs("import-asym-storage-wrap", 2048)
	// PKCS8 RSA key material exceeds plain RSA-OAEP's plaintext limit, so
	// use the hybrid RSA+AES wrap algorithm designed for larger payloads.
	params, err := sb.GetImportParameters(context.Background(), wrapAttrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.NoError(t, err)

	// Build valid PKCS8 RSA material without persisting it (storage.Put
	// always fails on this backend, so we can't GenerateKey through sb).
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)

	wrapped, err := sb.WrapKey(context.Background(), der, params)
	require.NoError(t, err)

	importAttrs := createRSAAttrs("import-asym-storage-fail", 2048)
	err = sb.ImportKey(context.Background(), importAttrs, wrapped)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to store asymmetric key")
}

// TestValidateKeyType_ECDSAMatchingAttrs verifies validateKeyType admits an
// ECDSA private key whose attributes declare ECDSA.
//
// It used to be named for the no-op default arm it reached, which go-xkms#53
// replaced with a dedicated ECDSA arm and a refusing default; the property
// worth keeping is that a correct declaration is still admitted.
func TestValidateKeyType_ECDSAMatchingAttrs(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	attrs := createECDSAAttrs("validate-ecdsa-default", "P-256")
	err = validateKeyType(ecdsaKey, attrs)
	assert.NoError(t, err)
}

// TestSeal_UnderlyingError verifies SoftwareBackend.Seal propagates a
// failure from the delegated pkcs8Backend.Seal call (nonexistent key).
func TestSeal_UnderlyingError(t *testing.T) {
	be := createFullTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("seal-underlying-missing", 2048)
	_, err := be.Seal(context.Background(), []byte("data"), &types.SealOptions{KeyAttributes: attrs})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load sealing key")
}
