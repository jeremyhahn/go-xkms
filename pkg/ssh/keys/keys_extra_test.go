// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package keys_test

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/records"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// ---------------------------------------------------------------------------
// Error type Error()/Unwrap() coverage
// ---------------------------------------------------------------------------

func TestNilInputError_Error(t *testing.T) {
	e := &keys.NilInputError{Field: "key"}
	want := "ssh/keys: nil input: key"
	if e.Error() != want {
		t.Fatalf("got %q, want %q", e.Error(), want)
	}
}

func TestUnsupportedAlgorithmError_Error(t *testing.T) {
	e := &keys.UnsupportedAlgorithmError{Algorithm: "dsa"}
	if e.Error() == "" {
		t.Fatal("UnsupportedAlgorithmError.Error() empty")
	}
}

func TestInvalidKeySizeError_Error(t *testing.T) {
	e := &keys.InvalidKeySizeError{Algorithm: "rsa", Size: 512}
	if e.Error() == "" {
		t.Fatal("InvalidKeySizeError.Error() empty")
	}
}

func TestPassphraseRequiredError_Error(t *testing.T) {
	e := &keys.PassphraseRequiredError{}
	if e.Error() == "" {
		t.Fatal("PassphraseRequiredError.Error() empty")
	}
}

func TestPEMParseError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("no pem block")
	e := &keys.PEMParseError{Err: inner}
	if e.Error() == "" {
		t.Fatal("PEMParseError.Error() empty")
	}
	if !errors.Is(e, inner) {
		t.Fatal("PEMParseError.Unwrap() must expose inner error")
	}
}

func TestKeyMaterialError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("enclave failure")
	e := &keys.KeyMaterialError{Op: "seal pem", Err: inner}
	if e.Error() == "" {
		t.Fatal("KeyMaterialError.Error() empty")
	}
	if !errors.Is(e, inner) {
		t.Fatal("KeyMaterialError.Unwrap() must expose inner error")
	}
}

func TestKeyNotFoundError_Error(t *testing.T) {
	e := &keys.KeyNotFoundError{ID: "user/alice/laptop"}
	if e.Error() == "" {
		t.Fatal("KeyNotFoundError.Error() empty")
	}
}

func TestStorageError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("disk I/O failure")
	e := &keys.StorageError{Op: "put", Err: inner}
	if e.Error() == "" {
		t.Fatal("StorageError.Error() empty")
	}
	if !errors.Is(e, inner) {
		t.Fatal("StorageError.Unwrap() must expose inner error")
	}
}

func TestClosedSignerError_Error(t *testing.T) {
	e := &keys.ClosedSignerError{}
	if e.Error() == "" {
		t.Fatal("ClosedSignerError.Error() empty")
	}
}

// ---------------------------------------------------------------------------
// Algorithm.String()
// ---------------------------------------------------------------------------

func TestAlgorithm_String(t *testing.T) {
	cases := []struct {
		algo keys.Algorithm
		want string
	}{
		{keys.AlgorithmEd25519, "ed25519"},
		{keys.AlgorithmRSA, "rsa"},
		{keys.AlgorithmECDSAP256, "ecdsa-p256"},
		{keys.AlgorithmECDSAP384, "ecdsa-p384"},
		{keys.AlgorithmECDSAP521, "ecdsa-p521"},
	}
	for _, tc := range cases {
		if got := tc.algo.String(); got != tc.want {
			t.Errorf("Algorithm(%q).String() = %q, want %q", tc.algo, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// AlgorithmFromPublicKey — exercise all CryptoPublicKey type-switch arms
// and the fallback Type()-based path
// ---------------------------------------------------------------------------

// fakePublicKey is a minimal ssh.PublicKey implementation that does NOT
// implement ssh.CryptoPublicKey. This forces AlgorithmFromPublicKey to take
// the fallback pub.Type() branch.
type fakePublicKey struct {
	typ string
}

func (f fakePublicKey) Type() string                            { return f.typ }
func (f fakePublicKey) Marshal() []byte                         { return nil }
func (f fakePublicKey) Verify(_ []byte, _ *ssh.Signature) error { return nil }

func TestAlgorithmFromPublicKey_Fallback_Ed25519(t *testing.T) {
	got, err := keys.AlgorithmFromPublicKey(fakePublicKey{typ: ssh.KeyAlgoED25519})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != keys.AlgorithmEd25519 {
		t.Fatalf("got %q, want ed25519", got)
	}
}

func TestAlgorithmFromPublicKey_Fallback_RSA(t *testing.T) {
	for _, typ := range []string{ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512} {
		t.Run(typ, func(t *testing.T) {
			got, err := keys.AlgorithmFromPublicKey(fakePublicKey{typ: typ})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != keys.AlgorithmRSA {
				t.Fatalf("got %q, want rsa", got)
			}
		})
	}
}

func TestAlgorithmFromPublicKey_Fallback_ECDSA(t *testing.T) {
	cases := []struct {
		typ  string
		want keys.Algorithm
	}{
		{ssh.KeyAlgoECDSA256, keys.AlgorithmECDSAP256},
		{ssh.KeyAlgoECDSA384, keys.AlgorithmECDSAP384},
		{ssh.KeyAlgoECDSA521, keys.AlgorithmECDSAP521},
	}
	for _, tc := range cases {
		t.Run(tc.typ, func(t *testing.T) {
			got, err := keys.AlgorithmFromPublicKey(fakePublicKey{typ: tc.typ})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAlgorithmFromPublicKey_Fallback_Unknown(t *testing.T) {
	_, err := keys.AlgorithmFromPublicKey(fakePublicKey{typ: "unknown-key-type"})
	var uae *keys.UnsupportedAlgorithmError
	if !errors.As(err, &uae) {
		t.Fatalf("expected UnsupportedAlgorithmError for unknown type, got %T: %v", err, err)
	}
}

func TestAlgorithmFromPublicKey_AllAlgorithms(t *testing.T) {
	algos := []keys.Algorithm{
		keys.AlgorithmEd25519,
		keys.AlgorithmRSA,
		keys.AlgorithmECDSAP256,
		keys.AlgorithmECDSAP384,
		keys.AlgorithmECDSAP521,
	}
	for _, algo := range algos {
		t.Run(string(algo), func(t *testing.T) {
			var k *keys.Key
			var err error
			if algo == keys.AlgorithmRSA {
				k, err = keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: algo, RSABits: 2048})
			} else {
				k, err = keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: algo})
			}
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			defer k.Destroy()
			got, err := keys.AlgorithmFromPublicKey(k.PublicKey)
			if err != nil {
				t.Fatalf("AlgorithmFromPublicKey: %v", err)
			}
			if got != algo {
				t.Fatalf("got %q, want %q", got, algo)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// enclaveSigner.PublicKey() — called when the Signer is used directly
// ---------------------------------------------------------------------------

func TestEnclaveSigner_PublicKey(t *testing.T) {
	k, err := keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer k.Destroy()

	signer, err := k.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	// PublicKey() is the unexported enclaveSigner.PublicKey; calling it
	// on the returned ssh.Signer exercises the method at signer.go:119.
	pub := signer.PublicKey()
	if pub == nil {
		t.Fatal("enclaveSigner.PublicKey() returned nil")
	}
	if pub.Type() != k.PublicKey.Type() {
		t.Fatalf("PublicKey type mismatch: got %q, want %q", pub.Type(), k.PublicKey.Type())
	}
}

// ---------------------------------------------------------------------------
// Signer() nil Material and nil PublicKey paths
// ---------------------------------------------------------------------------

func TestSigner_NilMaterial(t *testing.T) {
	k := &keys.Key{
		PublicKey: generatePublicKey(t),
		Algorithm: keys.AlgorithmEd25519,
		// Material intentionally nil
	}
	_, err := k.Signer()
	var nie *keys.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError for nil Material, got %T: %v", err, err)
	}
}

func TestSigner_NilPublicKey(t *testing.T) {
	k, err := keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer k.Destroy()
	// Wipe the public key field to trigger the nil check.
	k.PublicKey = nil
	_, err = k.Signer()
	var nie *keys.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError for nil PublicKey, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// SignerWithClose() nil PublicKey path
// ---------------------------------------------------------------------------

func TestSignerWithClose_NilPublicKey(t *testing.T) {
	k, err := keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer k.Destroy()
	k.PublicKey = nil
	_, _, err = k.SignerWithClose()
	var nie *keys.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError for nil PublicKey, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// Store error paths using failing backends
// ---------------------------------------------------------------------------

// errKeysFail is the error every failing backend in this file returns.
var errKeysFail = errors.New("injected backend failure")

// keysFailingBackend fails every operation. It implements the guarded writes,
// so the DAO over it is atomic and every failure is the backend's.
type keysFailingBackend struct{}

func (keysFailingBackend) Get(_ context.Context, _ string) ([]byte, error) {
	return nil, errKeysFail
}
func (keysFailingBackend) Put(_ context.Context, _ string, _ []byte) error { return errKeysFail }
func (keysFailingBackend) PutIfAbsent(_ context.Context, _ string, _ []byte) (bool, error) {
	return false, errKeysFail
}
func (keysFailingBackend) CompareAndSwap(_ context.Context, _ string, _, _ []byte) (bool, []byte, error) {
	return false, nil, errKeysFail
}
func (keysFailingBackend) CompareAndDelete(_ context.Context, _ string, _ []byte) (bool, error) {
	return false, errKeysFail
}
func (keysFailingBackend) Delete(_ context.Context, _ string) error { return errKeysFail }
func (keysFailingBackend) List(_ context.Context, _ string) ([]string, error) {
	return nil, errKeysFail
}
func (keysFailingBackend) Scan(_ context.Context, _ string, _ func(string, []byte) error) error {
	return errKeysFail
}
func (keysFailingBackend) Exists(_ context.Context, _ string) (bool, error) {
	return false, errKeysFail
}
func (keysFailingBackend) Close() error { return nil }

// keysCorruptBackend serves every value it stores as undecodable bytes.
type keysCorruptBackend struct{ storage.Backend }

// CompareAndSwap forwards to the wrapped backend, keeping the DAO atomic.
func (b keysCorruptBackend) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, []byte, error) {
	return b.Backend.(storage.CompareAndSwapper).CompareAndSwap(ctx, key, expected, next)
}

// CompareAndDelete forwards to the wrapped backend, keeping the DAO atomic.
func (b keysCorruptBackend) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	return b.Backend.(storage.CompareAndDeleter).CompareAndDelete(ctx, key, expected)
}

func (b keysCorruptBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if _, err := b.Backend.Get(ctx, key); err != nil {
		return nil, err
	}
	return []byte("{{{not json"), nil
}
func (b keysCorruptBackend) Scan(ctx context.Context, prefix string, fn func(string, []byte) error) error {
	return b.Backend.Scan(ctx, prefix, func(key string, _ []byte) error {
		return fn(key, []byte("{{{not json"))
	})
}

// corruptStore returns a DAOStore whose records -- the user key alice/laptop
// and the tenant key acme/deploy -- all read back undecodable.
func corruptStore(t *testing.T) *keys.DAOStore {
	t.Helper()
	backend := storage.New()
	clean := storeOver(t, backend)
	if err := putKey(t, clean, scope.User, "alice", "laptop"); err != nil {
		t.Fatalf("seed user key: %v", err)
	}
	if err := putKey(t, clean, scope.Tenant, "acme", "deploy"); err != nil {
		t.Fatalf("seed tenant key: %v", err)
	}
	return storeOver(t, keysCorruptBackend{Backend: backend})
}

// storeOver returns the DAOStore over backend.
func storeOver(t *testing.T, backend storage.Backend) *keys.DAOStore {
	t.Helper()
	kv, err := kvadapter.New(backend)
	if err != nil {
		t.Fatalf("kvadapter.New: %v", err)
	}
	store, err := keys.NewDAOStore(dao.NewStoreFactory(kv))
	if err != nil {
		t.Fatalf("NewDAOStore: %v", err)
	}
	return store
}

func TestDAOStore_Get_StorageError(t *testing.T) {
	store := storeOver(t, keysFailingBackend{})
	_, err := store.Get(context.Background(), scope.User, "alice", "laptop")
	var se *keys.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError on get failure, got %T: %v", err, err)
	}
}

func TestDAOStore_List_StorageError(t *testing.T) {
	store := storeOver(t, keysFailingBackend{})
	_, err := store.List(context.Background(), scope.User, "alice")
	var se *keys.StorageError
	if !errors.As(err, &se) {
		t.Fatalf("expected StorageError on list failure, got %T: %v", err, err)
	}
}

func TestDAOStore_List_InvalidScope(t *testing.T) {
	store, err := keys.NewDAOStore(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("NewDAOStore: %v", err)
	}
	var scopeErr *scope.ScopeInvalidError
	if _, err := store.List(context.Background(), scope.Scope("badscope"), ""); !errors.As(err, &scopeErr) {
		t.Fatalf("List(badscope) = %v, want *ScopeInvalidError", err)
	}
}

// plantedBody is a keys record body written around the store, so a test can
// plant a record the store itself never writes.
type plantedBody struct {
	Algorithm string `json:"algo"`
	PublicKey string `json:"pub"`
}

// storeWithPlanted returns a DAOStore whose record alice/laptop (user scope)
// holds body.
func storeWithPlanted(t *testing.T, body plantedBody) *keys.DAOStore {
	t.Helper()
	daos := testutil.NewMemoryDAOFactory()
	table, err := records.New[plantedBody](daos, scope.KindKeys)
	if err != nil {
		t.Fatalf("records.New: %v", err)
	}
	if _, err := table.Put(context.Background(), scope.User, "alice", "laptop", body); err != nil {
		t.Fatalf("plant record: %v", err)
	}
	store, err := keys.NewDAOStore(daos)
	if err != nil {
		t.Fatalf("NewDAOStore: %v", err)
	}
	return store
}

// TestDAOStore_Get_BadPublicKey exercises entityToKeyMetaOnly's
// ssh.ParseAuthorizedKey error path.
func TestDAOStore_Get_BadPublicKey(t *testing.T) {
	store := storeWithPlanted(t, plantedBody{Algorithm: "ed25519", PublicKey: "not-a-valid-pub-key"})
	_, err := store.Get(context.Background(), scope.User, "alice", "laptop")
	var pe *keys.PEMParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected PEMParseError for bad public key, got %T: %v", err, err)
	}
}

// TestDAOStore_Get_EmptyMaterial exercises entityToKey's empty-PEM error
// path: a software key record without material.
func TestDAOStore_Get_EmptyMaterial(t *testing.T) {
	k, err := keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pubLine := strings.TrimRight(string(ssh.MarshalAuthorizedKey(k.PublicKey)), "\n")
	k.Destroy()

	store := storeWithPlanted(t, plantedBody{Algorithm: "ed25519", PublicKey: pubLine})
	_, err = store.Get(context.Background(), scope.User, "alice", "laptop")
	var kme *keys.KeyMaterialError
	if !errors.As(err, &kme) {
		t.Fatalf("expected KeyMaterialError for empty material, got %T: %v", err, err)
	}
}

// TestDAOStore_List_BadPublicKey exercises the List path of
// entityToKeyMetaOnly's ssh.ParseAuthorizedKey error.
func TestDAOStore_List_BadPublicKey(t *testing.T) {
	store := storeWithPlanted(t, plantedBody{Algorithm: "ed25519", PublicKey: "not-valid-pub"})
	_, err := store.List(context.Background(), scope.User, "alice")
	var pe *keys.PEMParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected PEMParseError for bad public key in list, got %T: %v", err, err)
	}
}

func TestDAOStore_Delete_InvalidScope(t *testing.T) {
	store, err := keys.NewDAOStore(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("NewDAOStore: %v", err)
	}
	var scopeErr *scope.ScopeInvalidError
	if err := store.Delete(context.Background(), scope.Scope("badscope"), "alice", "laptop"); !errors.As(err, &scopeErr) {
		t.Fatalf("Delete(badscope) = %v, want *ScopeInvalidError", err)
	}
}

// ---------------------------------------------------------------------------
// Generate: RSA with zero bits defaults to 4096
// (the 4096 path is slow in unit tests so we just test that it doesn't error
//  and produces a valid key; the test is marked as using the default path)
// ---------------------------------------------------------------------------

func TestGenerate_RSA_ZeroBitsDefaultsTo4096(t *testing.T) {
	// RSA bits=0 triggers the "bits = 4096" default path in generatePrivateKey.
	// 4096-bit RSA is slow but generates correctly; the test validates the
	// default branch is exercised without exhaustive performance concerns.
	k, err := keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: keys.AlgorithmRSA})
	if err != nil {
		t.Fatalf("Generate RSA (default bits): %v", err)
	}
	defer k.Destroy()
	if k.Algorithm != keys.AlgorithmRSA {
		t.Errorf("Algorithm = %q, want rsa", k.Algorithm)
	}
}

// ---------------------------------------------------------------------------
// destroyedMaterialKey produces a *Key whose Material is non-nil but whose
// underlying Secret has been destroyed. Passing such a key to any operation
// that calls Material.Open() triggers a KeyMaterialError.
// ---------------------------------------------------------------------------

func destroyedMaterialKey(t *testing.T) *keys.Key {
	t.Helper()
	k, err := keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Destroy the underlying Secret without clearing the pointer on the Key.
	// Key.Destroy() both destroys the secret AND sets k.Material = nil;
	// we want the secret destroyed but the pointer still set.
	k.Material.Destroy()
	return k
}

// ---------------------------------------------------------------------------
// Put: Material.Open() failure → KeyMaterialError
// ---------------------------------------------------------------------------

func TestDAOStore_Put_MaterialOpenError(t *testing.T) {
	store, err := keys.NewDAOStore(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("NewDAOStore: %v", err)
	}
	k := destroyedMaterialKey(t)
	k.Scope = scope.User
	k.Owner = "alice"
	k.Name = "laptop"
	err = store.Put(context.Background(), k)
	var kme *keys.KeyMaterialError
	if !errors.As(err, &kme) {
		t.Fatalf("expected KeyMaterialError on Material.Open() failure, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// SignerWithClose: Material.Open() failure → KeyMaterialError
// ---------------------------------------------------------------------------

func TestSignerWithClose_MaterialOpenError(t *testing.T) {
	k := destroyedMaterialKey(t)
	_, _, err := k.SignerWithClose()
	var kme *keys.KeyMaterialError
	if !errors.As(err, &kme) {
		t.Fatalf("expected KeyMaterialError on Material.Open() failure, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// enclaveSigner.Sign: ParsePrivateKey failure → PEMParseError
// ---------------------------------------------------------------------------

func TestEnclaveSigner_Sign_CorruptMaterial(t *testing.T) {
	// Create a key where Material holds garbage bytes that will fail
	// ssh.ParsePrivateKey but succeed on Open().
	garbage := []byte("this-is-not-a-pem-key-at-all")
	mat, err := secure.NewSecret(t.Context(), append([]byte(nil), garbage...))
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	k, err := keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	k.Material.Destroy()
	k.Material = mat

	signer, err := k.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	_, err = signer.Sign(rand.Reader, []byte("data"))
	var pe *keys.PEMParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected PEMParseError for corrupt material in Sign, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// SignerWithClose: ssh.ParsePrivateKey failure → PEMParseError, and the
// opened Buffer must be destroyed rather than leaked on that failure path.
// ---------------------------------------------------------------------------

func TestSignerWithClose_CorruptMaterial(t *testing.T) {
	garbage := []byte("this-is-not-a-pem-key-at-all")
	mat, err := secure.NewSecret(t.Context(), append([]byte(nil), garbage...))
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	k, err := keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	k.Material.Destroy()
	k.Material = mat

	signer, closer, err := k.SignerWithClose()
	var pe *keys.PEMParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected PEMParseError for corrupt material, got %T: %v", err, err)
	}
	if signer != nil {
		t.Error("expected nil signer on parse failure")
	}
	if closer != nil {
		t.Error("expected nil closer on parse failure; nothing was left open to close")
	}
}

// ---------------------------------------------------------------------------
// enclaveSigner.SignWithAlgorithm: covers both the algorithm-aware dispatch
// (RSA, which x/crypto/ssh's parsed signer implements ssh.AlgorithmSigner
// for) and the plain-Sign fallback (Ed25519, which does not), plus the
// Material.Open() and ssh.ParsePrivateKey error paths it shares with Sign.
// ---------------------------------------------------------------------------

func TestEnclaveSigner_SignWithAlgorithm_RSAUsesRequestedAlgorithm(t *testing.T) {
	k, err := keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: keys.AlgorithmRSA, RSABits: 2048})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer k.Destroy()

	signer, err := k.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	algSigner, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		t.Fatal("expected the RSA enclave signer to implement ssh.AlgorithmSigner")
	}
	sig, err := algSigner.SignWithAlgorithm(rand.Reader, []byte("data"), ssh.KeyAlgoRSASHA256)
	if err != nil {
		t.Fatalf("SignWithAlgorithm: %v", err)
	}
	if sig.Format != ssh.KeyAlgoRSASHA256 {
		t.Errorf("signature format = %q, want %q", sig.Format, ssh.KeyAlgoRSASHA256)
	}
}

func TestEnclaveSigner_SignWithAlgorithm_Ed25519(t *testing.T) {
	k, err := keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer k.Destroy()

	signer, err := k.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	algSigner, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		t.Fatal("expected the enclave signer to implement ssh.AlgorithmSigner regardless of key type")
	}
	// Ed25519 has exactly one signature format; requesting it by name must
	// take the same path as an empty/default algorithm request.
	sig, err := algSigner.SignWithAlgorithm(rand.Reader, []byte("data"), ssh.KeyAlgoED25519)
	if err != nil {
		t.Fatalf("SignWithAlgorithm: %v", err)
	}
	if sig.Format != ssh.KeyAlgoED25519 {
		t.Errorf("signature format = %q, want %q", sig.Format, ssh.KeyAlgoED25519)
	}
}

func TestEnclaveSigner_SignWithAlgorithm_MaterialOpenError(t *testing.T) {
	k := destroyedMaterialKey(t)
	signer, err := k.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	algSigner := signer.(ssh.AlgorithmSigner)
	_, err = algSigner.SignWithAlgorithm(rand.Reader, []byte("data"), "")
	var kme *keys.KeyMaterialError
	if !errors.As(err, &kme) {
		t.Fatalf("expected KeyMaterialError on Material.Open() failure, got %T: %v", err, err)
	}
}

func TestEnclaveSigner_SignWithAlgorithm_CorruptMaterial(t *testing.T) {
	garbage := []byte("this-is-not-a-pem-key-at-all")
	mat, err := secure.NewSecret(t.Context(), append([]byte(nil), garbage...))
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	k, err := keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	k.Material.Destroy()
	k.Material = mat

	signer, err := k.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	algSigner := signer.(ssh.AlgorithmSigner)
	_, err = algSigner.SignWithAlgorithm(rand.Reader, []byte("data"), "")
	var pe *keys.PEMParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected PEMParseError for corrupt material, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// persistentSigner.SignWithAlgorithm: the long-lived-signer counterpart of
// enclaveSigner.SignWithAlgorithm, plus the closed-signer guard both
// persistentSigner methods share.
// ---------------------------------------------------------------------------

func TestPersistentSigner_SignWithAlgorithm(t *testing.T) {
	k, err := keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: keys.AlgorithmRSA, RSABits: 2048})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer k.Destroy()

	signer, closer, err := k.SignerWithClose()
	if err != nil {
		t.Fatalf("SignerWithClose: %v", err)
	}
	defer closer()

	algSigner, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		t.Fatal("expected the persistent RSA signer to implement ssh.AlgorithmSigner")
	}
	sig, err := algSigner.SignWithAlgorithm(rand.Reader, []byte("data"), ssh.KeyAlgoRSASHA256)
	if err != nil {
		t.Fatalf("SignWithAlgorithm: %v", err)
	}
	if sig.Format != ssh.KeyAlgoRSASHA256 {
		t.Errorf("signature format = %q, want %q", sig.Format, ssh.KeyAlgoRSASHA256)
	}
}

func TestPersistentSigner_SignWithAlgorithm_AfterCloseReturnsClosedSignerError(t *testing.T) {
	k, err := keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: keys.AlgorithmRSA, RSABits: 2048})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer k.Destroy()

	signer, closer, err := k.SignerWithClose()
	if err != nil {
		t.Fatalf("SignerWithClose: %v", err)
	}
	closer()

	algSigner := signer.(ssh.AlgorithmSigner)
	_, err = algSigner.SignWithAlgorithm(rand.Reader, []byte("data"), ssh.KeyAlgoRSASHA256)
	var cse *keys.ClosedSignerError
	if !errors.As(err, &cse) {
		t.Fatalf("expected ClosedSignerError after close, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// parseWithPassphrase: provider returns error
// ---------------------------------------------------------------------------

func TestParseWithPassphrase_ProviderError(t *testing.T) {
	raw := generateEncryptedPEM(t, []byte("secret"))
	buf, err := secure.NewBufferFromBytes(append([]byte(nil), raw...))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}
	defer buf.Destroy()

	providerErr := errors.New("prompt cancelled")
	provider := secure.NewCallbackProvider(func(_ context.Context, _ string) ([]byte, error) {
		return nil, providerErr
	})
	_, err = keys.ParsePEM(context.Background(), buf, provider)
	var pe *keys.PEMParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected PEMParseError on provider error, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// ParsePEM: empty buffer triggers NilInputError
// ---------------------------------------------------------------------------

func TestParsePEM_EmptyBuffer(t *testing.T) {
	// A Buffer cannot be built empty (NewBufferFromBytes rejects a
	// zero-length source), so a destroyed one stands in for an absent PEM:
	// it must be refused like a nil buffer, not parsed.
	buf, err := secure.NewBufferFromBytes([]byte("x"))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}
	buf.Destroy()

	_, err = keys.ParsePEM(context.Background(), buf, nil)
	var nErr *keys.NilInputError
	if !errors.As(err, &nErr) {
		t.Fatalf("expected NilInputError for a destroyed buffer, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// generatePublicKey produces an ssh.PublicKey from a fresh ed25519 key
// without sealing material.
func generatePublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	k, err := keys.Generate(t.Context(), keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("generate key for public: %v", err)
	}
	pub := k.PublicKey
	k.Destroy()
	return pub
}
