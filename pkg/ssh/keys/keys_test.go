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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// generatePEM is a test helper that produces a raw OpenSSH PEM block
// (unencrypted) from a freshly generated ed25519 key.
func generatePEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return pem.EncodeToMemory(block)
}

// generateEncryptedPEM returns an encrypted OpenSSH PEM with the given
// passphrase.
func generateEncryptedPEM(t *testing.T, passphrase []byte) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "test", passphrase)
	if err != nil {
		t.Fatalf("marshal with passphrase: %v", err)
	}
	return pem.EncodeToMemory(block)
}

func TestGenerate_Ed25519(t *testing.T) {
	key, err := keys.Generate(keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer key.Destroy()

	if key.Algorithm != keys.AlgorithmEd25519 {
		t.Errorf("algorithm = %q", key.Algorithm)
	}
	if key.PublicKey == nil {
		t.Error("nil public key")
	}
	if !strings.HasPrefix(key.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint = %q", key.Fingerprint)
	}
	if key.Material == nil {
		t.Error("nil material")
	}
}

// TestGenerate_RSA_MinimumBits exercises the smallest allowed RSA size
// (2048). We do NOT test the default 4096 in unit tests — it takes
// seconds — but we do verify the floor works.
func TestGenerate_RSA_MinimumBits(t *testing.T) {
	key, err := keys.Generate(keys.GenerateOptions{
		Algorithm: keys.AlgorithmRSA,
		RSABits:   2048,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer key.Destroy()
	if key.Algorithm != keys.AlgorithmRSA {
		t.Errorf("algorithm = %q", key.Algorithm)
	}
}

func TestGenerate_RSA_UnderMinimum(t *testing.T) {
	_, err := keys.Generate(keys.GenerateOptions{
		Algorithm: keys.AlgorithmRSA,
		RSABits:   1024,
	})
	var szErr *keys.InvalidKeySizeError
	if !errors.As(err, &szErr) {
		t.Fatalf("expected InvalidKeySizeError, got %T: %v", err, err)
	}
}

func TestGenerate_ECDSA_P256(t *testing.T) {
	key, err := keys.Generate(keys.GenerateOptions{Algorithm: keys.AlgorithmECDSAP256})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer key.Destroy()
	if key.Algorithm != keys.AlgorithmECDSAP256 {
		t.Errorf("algorithm = %q", key.Algorithm)
	}
}

func TestGenerate_ECDSA_P384(t *testing.T) {
	key, err := keys.Generate(keys.GenerateOptions{Algorithm: keys.AlgorithmECDSAP384})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer key.Destroy()
	if key.Algorithm != keys.AlgorithmECDSAP384 {
		t.Errorf("algorithm = %q", key.Algorithm)
	}
}

func TestGenerate_ECDSA_P521(t *testing.T) {
	key, err := keys.Generate(keys.GenerateOptions{Algorithm: keys.AlgorithmECDSAP521})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer key.Destroy()
	if key.Algorithm != keys.AlgorithmECDSAP521 {
		t.Errorf("algorithm = %q", key.Algorithm)
	}
}

func TestGenerate_UnsupportedAlgorithm(t *testing.T) {
	_, err := keys.Generate(keys.GenerateOptions{Algorithm: keys.Algorithm("dsa-1024")})
	var uaErr *keys.UnsupportedAlgorithmError
	if !errors.As(err, &uaErr) {
		t.Fatalf("expected UnsupportedAlgorithmError, got %T", err)
	}
}

func TestGenerate_EmptyAlgorithm(t *testing.T) {
	_, err := keys.Generate(keys.GenerateOptions{})
	var uaErr *keys.UnsupportedAlgorithmError
	if !errors.As(err, &uaErr) {
		t.Fatalf("expected UnsupportedAlgorithmError, got %T", err)
	}
}

func TestParsePEM_Unencrypted(t *testing.T) {
	raw := generatePEM(t)
	buf, err := secure.NewBufferFromBytes(append([]byte(nil), raw...))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}
	defer buf.Destroy()

	key, err := keys.ParsePEM(context.Background(), buf, nil)
	if err != nil {
		t.Fatalf("ParsePEM: %v", err)
	}
	defer key.Destroy()
	if key.Algorithm != keys.AlgorithmEd25519 {
		t.Errorf("algorithm=%q", key.Algorithm)
	}
	if !strings.HasPrefix(key.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint=%q", key.Fingerprint)
	}
}

func TestParsePEM_EncryptedNoProvider(t *testing.T) {
	raw := generateEncryptedPEM(t, []byte("hunter2"))
	buf, err := secure.NewBufferFromBytes(append([]byte(nil), raw...))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}
	defer buf.Destroy()

	_, err = keys.ParsePEM(context.Background(), buf, nil)
	var prErr *keys.PassphraseRequiredError
	if !errors.As(err, &prErr) {
		t.Fatalf("expected PassphraseRequiredError, got %T: %v", err, err)
	}
}

func TestParsePEM_EncryptedWithProvider(t *testing.T) {
	pass := []byte("correct-horse-battery-staple")
	raw := generateEncryptedPEM(t, pass)
	buf, err := secure.NewBufferFromBytes(append([]byte(nil), raw...))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}
	defer buf.Destroy()

	provider := secure.NewCallbackProvider(func(_ context.Context, _ string) ([]byte, error) {
		return append([]byte(nil), pass...), nil
	})
	key, err := keys.ParsePEM(context.Background(), buf, provider)
	if err != nil {
		t.Fatalf("ParsePEM: %v", err)
	}
	defer key.Destroy()
	if key.Algorithm != keys.AlgorithmEd25519 {
		t.Errorf("algorithm=%q", key.Algorithm)
	}
}

func TestParsePEM_WrongPassphrase(t *testing.T) {
	raw := generateEncryptedPEM(t, []byte("actual"))
	buf, err := secure.NewBufferFromBytes(append([]byte(nil), raw...))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}
	defer buf.Destroy()

	provider := secure.NewCallbackProvider(func(_ context.Context, _ string) ([]byte, error) {
		return []byte("wrong"), nil
	})
	_, err = keys.ParsePEM(context.Background(), buf, provider)
	var pErr *keys.PEMParseError
	if !errors.As(err, &pErr) {
		t.Fatalf("expected PEMParseError, got %T: %v", err, err)
	}
}

func TestParsePEM_NilBuffer(t *testing.T) {
	_, err := keys.ParsePEM(context.Background(), nil, nil)
	var nErr *keys.NilInputError
	if !errors.As(err, &nErr) {
		t.Fatalf("expected NilInputError, got %T", err)
	}
}

func TestParsePEM_Garbage(t *testing.T) {
	buf, err := secure.NewBufferFromBytes([]byte("not a pem"))
	if err != nil {
		t.Fatalf("NewBufferFromBytes: %v", err)
	}
	defer buf.Destroy()
	_, err = keys.ParsePEM(context.Background(), buf, nil)
	var pErr *keys.PEMParseError
	if !errors.As(err, &pErr) {
		t.Fatalf("expected PEMParseError, got %T: %v", err, err)
	}
}

func TestSigner_RoundTrip(t *testing.T) {
	key, err := keys.Generate(keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer key.Destroy()

	signer, err := key.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}

	data := []byte("hello, ssh")
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := key.PublicKey.Verify(data, sig); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestSigner_RepeatedCalls(t *testing.T) {
	// Each Sign() re-opens the Secret; confirm that two back-to-back
	// signs both succeed and the second isn't broken by the first's
	// Buffer destroy.
	key, err := keys.Generate(keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer key.Destroy()

	signer, err := key.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := signer.Sign(rand.Reader, []byte("data")); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
}

func TestSigner_NilKey(t *testing.T) {
	var k *keys.Key
	_, err := k.Signer()
	var nErr *keys.NilInputError
	if !errors.As(err, &nErr) {
		t.Fatalf("expected NilInputError, got %T", err)
	}
}

func TestFingerprint(t *testing.T) {
	key, err := keys.Generate(keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer key.Destroy()

	fp := keys.Fingerprint(key.PublicKey)
	if fp == "" {
		t.Error("empty fingerprint")
	}
	if fp != key.Fingerprint {
		t.Errorf("mismatch: direct=%q stored=%q", fp, key.Fingerprint)
	}
	if got := keys.Fingerprint(nil); got != "" {
		t.Errorf("nil fingerprint = %q", got)
	}
}

func TestDecodePEMBlock(t *testing.T) {
	raw := generatePEM(t)
	block, err := keys.DecodePEMBlock(raw)
	if err != nil {
		t.Fatalf("DecodePEMBlock: %v", err)
	}
	if !strings.Contains(block.Type, "PRIVATE KEY") {
		t.Errorf("block type = %q", block.Type)
	}
	if _, err := keys.DecodePEMBlock([]byte("garbage")); err == nil {
		t.Error("expected error on garbage")
	}
}

func TestKey_ID(t *testing.T) {
	k := &keys.Key{Scope: scope.User, Owner: "alice", Name: "laptop"}
	if id := k.ID(); id != "user/alice/laptop" {
		t.Errorf("ID = %q", id)
	}
	// Invalid scope => empty string.
	bad := &keys.Key{Scope: scope.Scope("admin"), Owner: "o", Name: "n"}
	if id := bad.ID(); id != "" {
		t.Errorf("bad ID = %q, want empty", id)
	}
	// Nil receiver => empty string.
	var nilK *keys.Key
	if id := nilK.ID(); id != "" {
		t.Errorf("nil ID = %q, want empty", id)
	}
}

func TestKey_DestroyIdempotent(t *testing.T) {
	key, err := keys.Generate(keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	key.Destroy()
	key.Destroy() // must be a no-op
	var nilK *keys.Key
	nilK.Destroy() // must be a no-op
}

// --- Store round-trip tests using the in-memory storage backend. ---

func TestBackendStore_RoundTrip(t *testing.T) {
	backend := storage.NewMemory()
	store, err := keys.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}

	key, err := keys.Generate(keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519, Comment: "hello"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	key.Scope = scope.User
	key.Owner = "alice"
	key.Name = "laptop"

	ctx := context.Background()
	if err := store.Put(ctx, key); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Record public key before destroying original.
	wantPub := key.PublicKey.Marshal()
	wantFP := key.Fingerprint
	key.Destroy()

	got, err := store.Get(ctx, scope.User, "alice", "laptop")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer got.Destroy()

	if !bytes.Equal(got.PublicKey.Marshal(), wantPub) {
		t.Errorf("public key mismatch")
	}
	if got.Fingerprint != wantFP {
		t.Errorf("fingerprint mismatch: got %q want %q", got.Fingerprint, wantFP)
	}

	// Signer still works after reload.
	signer, err := got.Signer()
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	if _, err := signer.Sign(rand.Reader, []byte("x")); err != nil {
		t.Errorf("Sign after reload: %v", err)
	}
}

func TestBackendStore_GetMissing(t *testing.T) {
	backend := storage.NewMemory()
	store, err := keys.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	_, err = store.Get(context.Background(), scope.User, "nobody", "nothing")
	var nfErr *keys.KeyNotFoundError
	if !errors.As(err, &nfErr) {
		t.Fatalf("expected KeyNotFoundError, got %T: %v", err, err)
	}
}

func TestBackendStore_DeleteMissing(t *testing.T) {
	backend := storage.NewMemory()
	store, err := keys.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	err = store.Delete(context.Background(), scope.User, "x", "y")
	var nfErr *keys.KeyNotFoundError
	if !errors.As(err, &nfErr) {
		t.Fatalf("expected KeyNotFoundError, got %T: %v", err, err)
	}
}

func TestBackendStore_DeleteExisting(t *testing.T) {
	backend := storage.NewMemory()
	store, err := keys.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	key, _ := keys.Generate(keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	key.Scope = scope.User
	key.Owner = "alice"
	key.Name = "laptop"
	if err := store.Put(context.Background(), key); err != nil {
		t.Fatalf("Put: %v", err)
	}
	key.Destroy()

	if err := store.Delete(context.Background(), scope.User, "alice", "laptop"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = store.Get(context.Background(), scope.User, "alice", "laptop")
	var nfErr *keys.KeyNotFoundError
	if !errors.As(err, &nfErr) {
		t.Fatalf("expected KeyNotFoundError after delete, got %T: %v", err, err)
	}
}

func TestBackendStore_List(t *testing.T) {
	backend := storage.NewMemory()
	store, err := keys.NewBackendStore(backend)
	if err != nil {
		t.Fatalf("NewBackendStore: %v", err)
	}
	ctx := context.Background()

	// Populate: two user keys for alice, one for bob, one tenant key.
	populate := func(sc scope.Scope, owner, name string) {
		k, _ := keys.Generate(keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
		k.Scope = sc
		k.Owner = owner
		k.Name = name
		if err := store.Put(ctx, k); err != nil {
			t.Fatalf("Put %s/%s/%s: %v", sc, owner, name, err)
		}
		k.Destroy()
	}
	populate(scope.User, "alice", "laptop")
	populate(scope.User, "alice", "server")
	populate(scope.User, "bob", "desktop")
	populate(scope.Tenant, "acme", "shared")

	// All keys.
	all, err := store.List(ctx, scope.Scope(""), "")
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if len(all) != 4 {
		t.Errorf("all list count = %d, want 4", len(all))
	}
	// Material must be nil in list results.
	for _, k := range all {
		if k.Material != nil {
			t.Error("list result has non-nil Material")
		}
	}

	// Scope filter.
	users, err := store.List(ctx, scope.User, "")
	if err != nil {
		t.Fatalf("List users: %v", err)
	}
	if len(users) != 3 {
		t.Errorf("users count = %d, want 3", len(users))
	}

	// Scope + owner filter.
	alice, err := store.List(ctx, scope.User, "alice")
	if err != nil {
		t.Fatalf("List alice: %v", err)
	}
	if len(alice) != 2 {
		t.Errorf("alice count = %d, want 2", len(alice))
	}
}

func TestBackendStore_NilBackend(t *testing.T) {
	_, err := keys.NewBackendStore(nil)
	var nErr *keys.NilInputError
	if !errors.As(err, &nErr) {
		t.Fatalf("expected NilInputError, got %T", err)
	}
}

func TestBackendStore_PutNilKey(t *testing.T) {
	backend := storage.NewMemory()
	store, _ := keys.NewBackendStore(backend)
	err := store.Put(context.Background(), nil)
	var nErr *keys.NilInputError
	if !errors.As(err, &nErr) {
		t.Fatalf("expected NilInputError, got %T", err)
	}
}

func TestBackendStore_PutNoMaterial(t *testing.T) {
	backend := storage.NewMemory()
	store, _ := keys.NewBackendStore(backend)
	k := &keys.Key{Scope: scope.User, Owner: "alice", Name: "laptop"}
	err := store.Put(context.Background(), k)
	var nErr *keys.NilInputError
	if !errors.As(err, &nErr) {
		t.Fatalf("expected NilInputError, got %T", err)
	}
}

// TestSignerWithClose_HappyPath asserts the persistent signer produces
// valid signatures and the closer is idempotent.
func TestSignerWithClose_HappyPath(t *testing.T) {
	key, err := keys.Generate(keys.GenerateOptions{Algorithm: keys.AlgorithmEd25519})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer key.Destroy()

	signer, closer, err := key.SignerWithClose()
	if err != nil {
		t.Fatalf("SignerWithClose: %v", err)
	}

	msg := []byte("the quick brown fox")
	sig, err := signer.Sign(rand.Reader, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.PublicKey().Verify(msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Closer is idempotent — call twice, both must return normally.
	closer()
	closer()

	// After close, Sign returns ClosedSignerError.
	_, err = signer.Sign(rand.Reader, msg)
	var cse *keys.ClosedSignerError
	if !errors.As(err, &cse) {
		t.Fatalf("expected ClosedSignerError after close, got %T: %v", err, err)
	}
}

// TestSignerWithClose_NilInputs rejects invalid callers with typed
// errors rather than panicking.
func TestSignerWithClose_NilInputs(t *testing.T) {
	var k *keys.Key
	if _, _, err := k.SignerWithClose(); err == nil {
		t.Fatal("expected error on nil receiver")
	} else {
		var nie *keys.NilInputError
		if !errors.As(err, &nie) {
			t.Fatalf("expected NilInputError, got %T: %v", err, err)
		}
	}

	empty := &keys.Key{}
	if _, _, err := empty.SignerWithClose(); err == nil {
		t.Fatal("expected error on zero Key")
	} else {
		var nie *keys.NilInputError
		if !errors.As(err, &nie) {
			t.Fatalf("expected NilInputError, got %T: %v", err, err)
		}
	}
}
