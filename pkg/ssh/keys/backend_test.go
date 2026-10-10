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

package keys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// fakeBackendProvider is an in-memory BackendProvider: it mints real
// ed25519/ECDSA signers and remembers them by (backendID, keyID) so Signer
// returns the same key. It exercises the keys package without pulling in the
// xkms backend stack — fast and host-safe.
type fakeBackendProvider struct {
	keys     map[string]crypto.Signer
	genErr   error
	signErr  error
	genCalls int
}

func newFakeProvider() *fakeBackendProvider {
	return &fakeBackendProvider{keys: map[string]crypto.Signer{}}
}

func (f *fakeBackendProvider) GenerateKey(_ context.Context, backendID, keyID string, algo Algorithm, _ int) (crypto.Signer, error) {
	f.genCalls++
	if f.genErr != nil {
		return nil, f.genErr
	}
	var signer crypto.Signer
	switch algo {
	case AlgorithmEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		signer = priv
	case AlgorithmECDSAP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		signer = priv
	default:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		signer = priv
	}
	f.keys[backendID+"/"+keyID] = signer
	return signer, nil
}

func (f *fakeBackendProvider) Signer(_ context.Context, backendID, keyID string, _ Algorithm) (crypto.Signer, error) {
	if f.signErr != nil {
		return nil, f.signErr
	}
	s, ok := f.keys[backendID+"/"+keyID]
	if !ok {
		return nil, errors.New("key not found")
	}
	return s, nil
}

func TestGenerateOnBackend_RoundTripAndSign(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider()

	key, err := GenerateOnBackend(ctx, p, "tpm2", GenerateOptions{Algorithm: AlgorithmEd25519, Comment: "alice@host"}, scope.User, "alice", "laptop")
	if err != nil {
		t.Fatalf("GenerateOnBackend: %v", err)
	}
	if !key.IsBackendBacked() {
		t.Fatal("expected backend-backed key")
	}
	if key.Material != nil {
		t.Fatal("backend-backed key must not carry Material")
	}
	if key.BackendID != "tpm2" || key.BackendKeyID == "" {
		t.Fatalf("unexpected backend ref: id=%q keyID=%q", key.BackendID, key.BackendKeyID)
	}
	if key.PublicKey == nil || key.Fingerprint == "" {
		t.Fatal("expected public key + fingerprint")
	}

	// Sign through the backend signer and verify with the public key.
	signer, err := key.BackendSigner(ctx, p)
	if err != nil {
		t.Fatalf("BackendSigner: %v", err)
	}
	msg := []byte("the quick brown fox")
	sig, err := signer.Sign(rand.Reader, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := key.PublicKey.Verify(msg, sig); err != nil {
		t.Fatalf("signature did not verify: %v", err)
	}
}

func TestGenerateOnBackend_StorePutGetList(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider()
	st, err := NewDAOStore(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("NewDAOStore: %v", err)
	}

	key, err := GenerateOnBackend(ctx, p, "pkcs11", GenerateOptions{Algorithm: AlgorithmECDSAP256}, scope.User, "bob", "yubikey")
	if err != nil {
		t.Fatalf("GenerateOnBackend: %v", err)
	}
	if err := st.Put(ctx, key); err != nil {
		t.Fatalf("Put backend-backed key: %v", err)
	}

	got, err := st.Get(ctx, scope.User, "bob", "yubikey")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.IsBackendBacked() || got.BackendID != "pkcs11" || got.BackendKeyID != key.BackendKeyID {
		t.Fatalf("round-trip lost backend ref: %+v", got)
	}
	if got.Material != nil {
		t.Fatal("rehydrated backend key must have nil Material")
	}
	if ssh.FingerprintSHA256(got.PublicKey) != ssh.FingerprintSHA256(key.PublicKey) {
		t.Fatal("public key changed across round-trip")
	}

	// List returns meta-only with the backend ref preserved.
	list, err := st.List(ctx, scope.User, "bob")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].BackendID != "pkcs11" {
		t.Fatalf("List did not preserve backend ref: %+v", list)
	}

	// The rehydrated key still signs through the backend.
	signer, err := got.BackendSigner(ctx, p)
	if err != nil {
		t.Fatalf("BackendSigner after reload: %v", err)
	}
	msg := []byte("payload")
	sig, err := signer.Sign(rand.Reader, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := got.PublicKey.Verify(msg, sig); err != nil {
		t.Fatalf("verify after reload: %v", err)
	}
}

func TestGenerateOnBackend_Errors(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider()

	if _, err := GenerateOnBackend(ctx, nil, "tpm2", GenerateOptions{Algorithm: AlgorithmEd25519}, scope.User, "a", "k"); err == nil {
		t.Fatal("expected error for nil provider")
	}
	if _, err := GenerateOnBackend(ctx, p, "", GenerateOptions{Algorithm: AlgorithmEd25519}, scope.User, "a", "k"); err == nil {
		t.Fatal("expected error for empty backendID")
	}
	if _, err := GenerateOnBackend(ctx, p, "tpm2", GenerateOptions{Algorithm: ""}, scope.User, "a", "k"); err == nil {
		t.Fatal("expected error for empty algorithm")
	}
	if _, err := GenerateOnBackend(ctx, p, "tpm2", GenerateOptions{Algorithm: Algorithm("bogus")}, scope.User, "a", "k"); err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
	if _, err := GenerateOnBackend(ctx, p, "tpm2", GenerateOptions{Algorithm: AlgorithmRSA, RSABits: 1024}, scope.User, "a", "k"); err == nil {
		t.Fatal("expected error for under-minimum RSA bits")
	}
	// go-xkms#1260: refused here, before the backend's GenerateKey is ever
	// called, so an oversized request never reaches a backend that might not
	// enforce its own ceiling.
	if _, err := GenerateOnBackend(ctx, p, "tpm2", GenerateOptions{Algorithm: AlgorithmRSA, RSABits: 65536}, scope.User, "a", "k"); err == nil {
		t.Fatal("expected error for over-maximum RSA bits")
	}

	// Backend generation failure surfaces as KeyMaterialError.
	p.genErr = errors.New("hardware unavailable")
	if _, err := GenerateOnBackend(ctx, p, "tpm2", GenerateOptions{Algorithm: AlgorithmEd25519}, scope.User, "a", "k"); err == nil {
		t.Fatal("expected error when backend generation fails")
	}
}

func TestBackendSigner_Errors(t *testing.T) {
	ctx := context.Background()
	p := newFakeProvider()

	// Software key (not backend-backed) must reject BackendSigner.
	sw, err := Generate(t.Context(), GenerateOptions{Algorithm: AlgorithmEd25519})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	defer sw.Destroy()
	if _, err := sw.BackendSigner(ctx, p); err == nil {
		t.Fatal("expected error: software key is not backend-backed")
	}

	key, err := GenerateOnBackend(ctx, p, "tpm2", GenerateOptions{Algorithm: AlgorithmEd25519}, scope.User, "a", "k")
	if err != nil {
		t.Fatalf("GenerateOnBackend: %v", err)
	}
	if _, err := key.BackendSigner(ctx, nil); err == nil {
		t.Fatal("expected error for nil provider")
	}
	p.signErr = errors.New("device locked")
	if _, err := key.BackendSigner(ctx, p); err == nil {
		t.Fatal("expected error when backend signer resolution fails")
	}
}

// TestBackendSigner_NilKey verifies the nil-receiver guard: BackendSigner
// must report *NilInputError rather than dereferencing a nil *Key.
func TestBackendSigner_NilKey(t *testing.T) {
	var k *Key
	_, err := k.BackendSigner(context.Background(), newFakeProvider())
	var nie *NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected *NilInputError for a nil key, got %T: %v", err, err)
	}
}

// unsupportedPublicKeySigner is a crypto.Signer whose Public() type
// ssh.NewSignerFromSigner does not recognize, exercising BackendSigner's
// "ssh.NewSignerFromSigner" error-wrapping branch -- a backend that resolves
// successfully but hands back key material in an algorithm this package
// cannot wrap for SSH.
type unsupportedPublicKeySigner struct{}

func (unsupportedPublicKeySigner) Public() crypto.PublicKey { return "not-a-real-public-key" }

func (unsupportedPublicKeySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("unsupportedPublicKeySigner: Sign must not be called")
}

// TestBackendSigner_UnsupportedPublicKeyType verifies that a backend signer
// resolving successfully but carrying a public key type ssh.NewSignerFromSigner
// cannot wrap surfaces as *KeyMaterialError, not a raw ssh package error.
func TestBackendSigner_UnsupportedPublicKeyType(t *testing.T) {
	p := newFakeProvider()
	p.keys["tpm2/bad-key"] = unsupportedPublicKeySigner{}
	key := &Key{BackendID: "tpm2", BackendKeyID: "bad-key", Algorithm: AlgorithmEd25519}

	_, err := key.BackendSigner(context.Background(), p)
	var kme *KeyMaterialError
	if !errors.As(err, &kme) {
		t.Fatalf("expected *KeyMaterialError for an unsupported public key type, got %T: %v", err, err)
	}
}

// TestEnvelopeV1BackwardCompat ensures a legacy v1 software envelope (no
// backend fields) still decodes after the v2 schema bump.
func TestEnvelopeV1BackwardCompat(t *testing.T) {
	ctx := context.Background()
	st, err := NewDAOStore(testutil.NewMemoryDAOFactory())
	if err != nil {
		t.Fatalf("NewDAOStore: %v", err)
	}
	sw, err := Generate(t.Context(), GenerateOptions{Algorithm: AlgorithmEd25519})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sw.Scope, sw.Owner, sw.Name = scope.User, "carol", "key1"
	if err := st.Put(ctx, sw); err != nil {
		t.Fatalf("Put software key: %v", err)
	}
	got, err := st.Get(ctx, scope.User, "carol", "key1")
	if err != nil {
		t.Fatalf("Get software key: %v", err)
	}
	if got.IsBackendBacked() {
		t.Fatal("software key must not be backend-backed")
	}
	if got.Material == nil {
		t.Fatal("software key must rehydrate Material")
	}
	if _, err := got.Signer(); err != nil {
		t.Fatalf("software signer: %v", err)
	}
}
