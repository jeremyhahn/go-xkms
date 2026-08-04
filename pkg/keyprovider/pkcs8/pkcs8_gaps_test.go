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

package pkcs8

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ============================================================================
// Coverage-gap tests: real behavior + error paths not exercised elsewhere.
// ============================================================================

// failingRandReader is an io.Reader that always fails. It is swapped into
// the package-level crypto/rand.Reader var (never in parallel with other
// tests, since none of these gap tests call t.Parallel()) to force key
// generation failures that cannot otherwise be injected.
type failingRandReader struct{}

func (failingRandReader) Read(_ []byte) (int, error) {
	return 0, &errs.Message{Msg: "injected rand failure"}
}

// withFailingRand swaps crypto/rand.Reader for the duration of fn and
// restores the original reader afterward.
func withFailingRand(fn func()) {
	orig := rand.Reader
	rand.Reader = failingRandReader{}
	defer func() { rand.Reader = orig }()
	fn()
}

// selectiveFailStorage wraps a real storage.Backend and selectively injects
// failures for specific operations so GenerateKey/RotateKey error-recovery
// paths (storage failures, metadata rollback) can be exercised without a
// bespoke storage implementation.
type selectiveFailStorage struct {
	storage.Backend
	failPutIfAbsent bool
	failMetaPut     bool
	failDelete      bool
}

func (s *selectiveFailStorage) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if s.failPutIfAbsent {
		return false, &errs.Message{Msg: "injected putifabsent failure"}
	}
	return s.Backend.PutIfAbsent(ctx, key, value)
}

func (s *selectiveFailStorage) Put(ctx context.Context, key string, value []byte) error {
	if s.failMetaPut && strings.HasPrefix(key, "meta/") {
		return &errs.Message{Msg: "injected metadata put failure"}
	}
	return s.Backend.Put(ctx, key, value)
}

func (s *selectiveFailStorage) Delete(ctx context.Context, key string) error {
	if s.failDelete {
		return &errs.Message{Msg: "injected delete failure"}
	}
	return s.Backend.Delete(ctx, key)
}

// TestGenerateKey_SymmetricAlgorithmUnsupported verifies that GenerateKey
// rejects a request carrying a valid SymmetricAlgorithm (which passes
// KeyAttributes.Validate()) since the PKCS#8 backend only handles
// asymmetric key material.
func TestGenerateKey_SymmetricAlgorithmUnsupported(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "symmetric-on-pkcs8.com",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err := be.GenerateKey(context.Background(), attrs)
	if err == nil {
		t.Fatal("GenerateKey should reject a symmetric-only request on the PKCS#8 backend")
	}
	if !errors.Is(err, backend.ErrInvalidAlgorithm) {
		t.Errorf("expected backend.ErrInvalidAlgorithm, got: %v", err)
	}
}

// TestGenerateKey_RandFailure forces the underlying RNG to fail, exercising
// GenerateKey's "key generation failed" wrapping branch.
//
// This repo builds with GOEXPERIMENT=BoringCrypto, under which
// rsa.GenerateKey, ecdsa.GenerateKey, and crypto/ecdh's X25519 GenerateKey
// all route through BoringSSL's own FIPS RNG and ignore the passed
// io.Reader entirely, so overriding crypto/rand.Reader cannot force a
// failure for those algorithms in this build. ed25519.GenerateKey has no
// BoringCrypto substitution and reads directly from the supplied
// io.Reader, so it remains the one algorithm this technique can exercise.
func TestGenerateKey_RandFailure(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createEd25519Attrs("rand-fail-ed25519.com")

	withFailingRand(func() {
		_, err := be.GenerateKey(context.Background(), attrs)
		if err == nil {
			t.Fatal("GenerateKey should fail when the RNG is exhausted")
		}
		if !strings.Contains(err.Error(), "key generation failed") {
			t.Errorf("expected 'key generation failed' error, got: %v", err)
		}
	})
}

// TestGenerateKey_PutIfAbsentStorageError exercises the "failed to store
// key" branch when the atomic PutIfAbsent guard itself errors.
func TestGenerateKey_PutIfAbsentStorageError(t *testing.T) {
	fail := &selectiveFailStorage{Backend: storage.New(), failPutIfAbsent: true}
	be, err := NewBackend(&Config{KeyStorage: fail, AllowPlaintextKeys: true})
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("putifabsent-fail.com", 2048)
	_, err = be.(*PKCS8Backend).GenerateKey(context.Background(), attrs)
	if err == nil {
		t.Fatal("GenerateKey should fail when PutIfAbsent errors")
	}
	if !strings.Contains(err.Error(), "failed to store key") {
		t.Errorf("expected 'failed to store key' error, got: %v", err)
	}
}

// TestGenerateKey_MetadataPutFailure_RollbackSucceeds exercises the
// metadata-write failure branch where the key blob is successfully rolled
// back, and verifies the rollback actually removed the orphaned key.
func TestGenerateKey_MetadataPutFailure_RollbackSucceeds(t *testing.T) {
	fail := &selectiveFailStorage{Backend: storage.New(), failMetaPut: true}
	be, err := NewBackend(&Config{KeyStorage: fail, AllowPlaintextKeys: true})
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}
	pb := be.(*PKCS8Backend)
	defer func() { _ = pb.Close() }()

	attrs := createRSAAttrs("meta-fail-rollback-ok.com", 2048)
	_, err = pb.GenerateKey(context.Background(), attrs)
	if err == nil {
		t.Fatal("GenerateKey should fail when metadata Put errors")
	}
	if !strings.Contains(err.Error(), "failed to store metadata") {
		t.Errorf("expected 'failed to store metadata' error, got: %v", err)
	}

	// Rollback should have deleted the orphaned key blob, so a fresh
	// GenerateKey attempt (with metadata write now allowed) must succeed
	// rather than failing with ErrKeyAlreadyExists.
	fail.failMetaPut = false
	_, err = pb.GenerateKey(context.Background(), attrs)
	if err != nil {
		t.Fatalf("expected regeneration to succeed after rollback, got: %v", err)
	}
}

// TestGenerateKey_MetadataPutFailure_RollbackFails exercises the branch
// where both the metadata write AND the rollback delete fail, producing a
// combined error message.
func TestGenerateKey_MetadataPutFailure_RollbackFails(t *testing.T) {
	fail := &selectiveFailStorage{Backend: storage.New(), failMetaPut: true, failDelete: true}
	be, err := NewBackend(&Config{KeyStorage: fail, AllowPlaintextKeys: true})
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("meta-fail-rollback-fail.com", 2048)
	_, err = be.(*PKCS8Backend).GenerateKey(context.Background(), attrs)
	if err == nil {
		t.Fatal("GenerateKey should fail when metadata Put errors")
	}
	if !strings.Contains(err.Error(), "failed to store metadata") || !strings.Contains(err.Error(), "rollback") {
		t.Errorf("expected combined metadata+rollback failure message, got: %v", err)
	}
}

// TestListKeys_SkipsSecretAndQuantumKeys verifies that ListKeys filters
// out symmetric ("secret") and post-quantum key IDs, which are owned by
// sibling backends sharing the same storage namespace.
func TestListKeys_SkipsSecretAndQuantumKeys(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	normalAttrs := createRSAAttrs("normal-listed.com", 2048)
	if _, err := be.GenerateKey(ctx, normalAttrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if err := storage.SaveKey(ctx, be.storage, "sw:secret:my-secret.com:aes256gcm", []byte("raw-secret-bytes")); err != nil {
		t.Fatalf("SaveKey (secret) failed: %v", err)
	}
	if err := storage.SaveKey(ctx, be.storage, "sw:tls:my-quantum.com:ml-dsa-65", []byte("raw-quantum-bytes")); err != nil {
		t.Fatalf("SaveKey (quantum) failed: %v", err)
	}

	keys, err := be.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected ListKeys to skip secret/quantum entries and return only the RSA key, got %d entries", len(keys))
	}
	if keys[0].CN != normalAttrs.CN {
		t.Errorf("expected surviving entry to be %s, got %s", normalAttrs.CN, keys[0].CN)
	}
}

// TestListKeys_UnknownKeyTypeDefaultsToTLS verifies that a key ID with an
// unrecognized key-type segment is defaulted to KeyTypeTLS rather than
// left at its zero value.
func TestListKeys_UnknownKeyTypeDefaultsToTLS(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	if err := storage.SaveKey(ctx, be.storage, "sw:bogustype:unknown-keytype.com:rsa", []byte("dummy")); err != nil {
		t.Fatalf("SaveKey failed: %v", err)
	}

	keys, err := be.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].KeyType != types.KeyTypeTLS {
		t.Errorf("expected unrecognized key type to default to KeyTypeTLS, got %v", keys[0].KeyType)
	}
}

// TestListKeys_UnknownAlgorithmDefaultsToRSA verifies that a key ID with
// an unrecognized algorithm segment is defaulted to RSA-2048 rather than
// left as UnknownPublicKeyAlgorithm.
func TestListKeys_UnknownAlgorithmDefaultsToRSA(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	if err := storage.SaveKey(ctx, be.storage, "sw:tls:unknown-algo.com:mystery", []byte("dummy")); err != nil {
		t.Fatalf("SaveKey failed: %v", err)
	}

	keys, err := be.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].KeyAlgorithm != x509.RSA {
		t.Errorf("expected unrecognized algorithm to default to RSA, got %v", keys[0].KeyAlgorithm)
	}
	if keys[0].RSAAttributes == nil || keys[0].RSAAttributes.KeySize != 2048 {
		t.Errorf("expected default RSAAttributes with 2048-bit key size, got %+v", keys[0].RSAAttributes)
	}
}

// TestEncodeKey_EncryptedMarshalError exercises encodeKey's encrypted
// (password-protected) PKCS#8 marshal failure branch by passing a key
// type that youmark/pkcs8.MarshalPrivateKey does not recognize.
func TestEncodeKey_EncryptedMarshalError(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	_, err := be.encodeKey("not-a-real-private-key", backend.StaticPassword("secret"))
	if err == nil {
		t.Fatal("encodeKey should fail for an unsupported key type with a password")
	}
	if !errors.Is(err, ErrKeyEncodingFailed) {
		t.Errorf("expected ErrKeyEncodingFailed, got: %v", err)
	}
}

// TestEncodeKey_UnencryptedMarshalError exercises encodeKey's unencrypted
// PKCS#8 marshal failure branch (AllowPlaintextKeys enabled) by passing a
// key type x509.MarshalPKCS8PrivateKey does not recognize.
func TestEncodeKey_UnencryptedMarshalError(t *testing.T) {
	be, _ := createTestBackend(t) // AllowPlaintextKeys: true
	defer func() { _ = be.Close() }()

	_, err := be.encodeKey(42, nil)
	if err == nil {
		t.Fatal("encodeKey should fail for an unsupported key type with no password")
	}
	if !errors.Is(err, ErrKeyEncodingFailed) {
		t.Errorf("expected ErrKeyEncodingFailed, got: %v", err)
	}
}

// TestDecodeKey_PasswordProvidedButUnencryptedParseFails verifies the
// diagnostic branch that fires when a Password object is present (so the
// caller expected an encrypted key) but its Bytes() are empty and the
// unencrypted PKCS#8 parse also fails — this typically indicates a failed
// password retrieval (e.g. TPM unseal error) rather than a genuinely
// unencrypted key.
func TestDecodeKey_PasswordProvidedButUnencryptedParseFails(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	_, err := be.decodeKey([]byte("not valid pkcs8 der"), backend.NoPassword{})
	if err == nil {
		t.Fatal("decodeKey should fail for corrupt data")
	}
	if !errors.Is(err, ErrKeyDecodingFailed) {
		t.Errorf("expected ErrKeyDecodingFailed, got: %v", err)
	}
	if !strings.Contains(err.Error(), "possible TPM unseal failure") {
		t.Errorf("expected diagnostic message about password retrieval, got: %v", err)
	}
}

// TestRotateKey_DeleteStorageError exercises RotateKey's "failed to
// delete old key" branch when the underlying Delete call errors for a
// reason other than ErrKeyNotFound.
func TestRotateKey_DeleteStorageError(t *testing.T) {
	fail := &selectiveFailStorage{Backend: storage.New()}
	be, err := NewBackend(&Config{KeyStorage: fail, AllowPlaintextKeys: true})
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}
	pb := be.(*PKCS8Backend)
	defer func() { _ = pb.Close() }()

	attrs := createRSAAttrs("rotate-delete-fail.com", 2048)
	if _, err := pb.GenerateKey(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	fail.failDelete = true
	err = pb.RotateKey(context.Background(), attrs)
	if err == nil {
		t.Fatal("RotateKey should fail when Delete errors")
	}
	if !strings.Contains(err.Error(), "failed to delete old key") {
		t.Errorf("expected 'failed to delete old key' error, got: %v", err)
	}
}

// TestRotateKey_RegenerateStorageError exercises RotateKey's "failed to
// generate new key" branch: the old key is deleted successfully, but the
// subsequent GenerateKey call fails at the storage layer.
func TestRotateKey_RegenerateStorageError(t *testing.T) {
	fail := &selectiveFailStorage{Backend: storage.New()}
	be, err := NewBackend(&Config{KeyStorage: fail, AllowPlaintextKeys: true})
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}
	pb := be.(*PKCS8Backend)
	defer func() { _ = pb.Close() }()

	attrs := createRSAAttrs("rotate-regen-fail.com", 2048)
	if _, err := pb.GenerateKey(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	fail.failPutIfAbsent = true
	err = pb.RotateKey(context.Background(), attrs)
	if err == nil {
		t.Fatal("RotateKey should fail when the regenerate step errors")
	}
	if !strings.Contains(err.Error(), "failed to generate new key") {
		t.Errorf("expected 'failed to generate new key' error, got: %v", err)
	}
}
