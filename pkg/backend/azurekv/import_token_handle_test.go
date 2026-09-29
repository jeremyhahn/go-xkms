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

//go:build azurekv

package azurekv

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/importtoken"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// go-xkms#1340: GetImportParameters used to return the ephemeral wrapping
// PRIVATE key (PKCS#1 DER) as ImportParameters.ImportToken, and UnwrapKey
// parsed the private key back out of the caller-supplied token. The token
// is now an opaque random handle naming a sealed wrapping key that never
// leaves the backend.

// newTestSealedRSAKey returns a freshly generated sealed wrapping key for
// tests that populate b.importTokens directly.
func newTestSealedRSAKey(t *testing.T) *importtoken.SealedRSAKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	sealed, err := importtoken.NewSealedRSAKey(priv)
	if err != nil {
		t.Fatalf("NewSealedRSAKey() error = %v", err)
	}
	return sealed
}

// importHandleParams runs GetImportParameters for a throwaway RSA key.
func importHandleParams(t *testing.T, b *Backend, cn string, alg backend.WrappingAlgorithm) *backend.ImportParameters {
	t.Helper()
	params, err := b.GetImportParameters(context.Background(), &types.KeyAttributes{
		CN:           cn,
		KeyAlgorithm: x509.RSA,
	}, alg)
	if err != nil {
		t.Fatalf("GetImportParameters() error = %v", err)
	}
	return params
}

// TestGetImportParameters_TokenCarriesNoPrivateKey verifies the import
// token is an opaque handle: it does not parse as a PKCS#1 or PKCS#8
// private key, it has exactly the handle's length, and the wrapping key it
// names stays in the backend's store.
func TestGetImportParameters_TokenCarriesNoPrivateKey(t *testing.T) {
	b, _ := testBackend(t)
	params := importHandleParams(t, b, "handle-only", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	if _, err := x509.ParsePKCS1PrivateKey(params.ImportToken); err == nil {
		t.Fatal("ImportToken parses as a PKCS#1 private key; the wrapping private key must never leave the backend")
	}
	if _, err := x509.ParsePKCS8PrivateKey(params.ImportToken); err == nil {
		t.Fatal("ImportToken parses as a PKCS#8 private key; the wrapping private key must never leave the backend")
	}
	if got, want := len(params.ImportToken), len(uuid.New().String()); got != want {
		t.Errorf("len(ImportToken) = %d, want the handle length %d", got, want)
	}
	if _, err := uuid.Parse(string(params.ImportToken)); err != nil {
		t.Errorf("ImportToken is not a random handle: %v", err)
	}

	stored, err := b.importTokens.Peek(string(params.ImportToken))
	if err != nil {
		t.Fatalf("importTokens.Peek() error = %v; the handle must name a stored wrapping key", err)
	}
	pub, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("WrappingPublicKey is %T, want *rsa.PublicKey", params.WrappingPublicKey)
	}
	if !pub.Equal(stored.PublicKey()) {
		t.Error("WrappingPublicKey does not match the stored wrapping key")
	}
}

// TestGetImportParameters_DistinctHandlesPerCeremony verifies two
// ceremonies for the same CN get independent handles and wrapping keys:
// the old CN-derived store key let the second ceremony overwrite the
// first's wrapping key.
func TestGetImportParameters_DistinctHandlesPerCeremony(t *testing.T) {
	b, _ := testBackend(t)
	alg := backend.WrappingAlgorithmRSAES_OAEP_SHA_256
	first := importHandleParams(t, b, "same-cn", alg)
	second := importHandleParams(t, b, "same-cn", alg)

	if bytes.Equal(first.ImportToken, second.ImportToken) {
		t.Fatal("two ceremonies for the same CN received the same import token")
	}

	for i, params := range []*backend.ImportParameters{first, second} {
		material := []byte("0123456789abcdef0123456789abcdef")
		wrapped, err := b.WrapKey(context.Background(), material, params)
		if err != nil {
			t.Fatalf("ceremony %d: WrapKey() error = %v", i, err)
		}
		got, err := b.UnwrapKey(context.Background(), wrapped, params)
		if err != nil {
			t.Fatalf("ceremony %d: UnwrapKey() error = %v", i, err)
		}
		if !bytes.Equal(got, material) {
			t.Errorf("ceremony %d: UnwrapKey() returned different material", i)
		}
	}
}

// TestUnwrapKey_RoundTripThroughHandle verifies wrap then unwrap recovers
// the original material through the handle for every supported wrapping
// algorithm.
func TestUnwrapKey_RoundTripThroughHandle(t *testing.T) {
	algorithms := []backend.WrappingAlgorithm{
		backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
	}
	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			b, _ := testBackend(t)
			params := importHandleParams(t, b, "round-trip", alg)

			material := []byte("0123456789abcdef0123456789abcdef")
			wrapped, err := b.WrapKey(context.Background(), material, params)
			if err != nil {
				t.Fatalf("WrapKey() error = %v", err)
			}
			got, err := b.UnwrapKey(context.Background(), wrapped, params)
			if err != nil {
				t.Fatalf("UnwrapKey() error = %v", err)
			}
			if !bytes.Equal(got, material) {
				t.Error("UnwrapKey() did not recover the wrapped material")
			}
			if b.importTokens.Len() != 0 {
				t.Error("UnwrapKey() must consume the import token")
			}
		})
	}
}

// TestUnwrapKey_RefusesUnknownHandle verifies a handle the backend never
// issued is refused with backend.ErrKeyNotFound.
func TestUnwrapKey_RefusesUnknownHandle(t *testing.T) {
	b, _ := testBackend(t)
	params := importHandleParams(t, b, "unknown", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	wrapped, err := b.WrapKey(context.Background(), []byte("0123456789abcdef"), params)
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}
	wrapped.ImportToken = []byte(uuid.New().String())

	_, err = b.UnwrapKey(context.Background(), wrapped, params)
	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Fatalf("UnwrapKey() error = %v, want backend.ErrKeyNotFound", err)
	}
}

// TestUnwrapKey_RefusesCallerSuppliedPrivateKey verifies the pre-#1340
// token shape -- a caller-supplied PKCS#1 wrapping private key -- is now
// just an unknown handle, so a caller can no longer choose the key the
// backend unwraps with.
func TestUnwrapKey_RefusesCallerSuppliedPrivateKey(t *testing.T) {
	b, _ := testBackend(t)

	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	params := &backend.ImportParameters{
		WrappingPublicKey: &attackerKey.PublicKey,
		ImportToken:       x509.MarshalPKCS1PrivateKey(attackerKey),
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}
	wrapped, err := b.WrapKey(context.Background(), []byte("0123456789abcdef"), params)
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}

	_, err = b.UnwrapKey(context.Background(), wrapped, params)
	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Fatalf("UnwrapKey() error = %v, want backend.ErrKeyNotFound", err)
	}
}

// TestUnwrapKey_RefusesReplayedHandle verifies a handle is single-use:
// after one successful unwrap, the same handle is refused.
func TestUnwrapKey_RefusesReplayedHandle(t *testing.T) {
	b, _ := testBackend(t)
	params := importHandleParams(t, b, "replay", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	wrapped, err := b.WrapKey(context.Background(), []byte("0123456789abcdef"), params)
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}
	if _, err := b.UnwrapKey(context.Background(), wrapped, params); err != nil {
		t.Fatalf("first UnwrapKey() error = %v", err)
	}

	_, err = b.UnwrapKey(context.Background(), wrapped, params)
	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Fatalf("replayed UnwrapKey() error = %v, want backend.ErrKeyNotFound", err)
	}
}

// TestUnwrapKey_FailedUnwrapConsumesHandle verifies a failed unwrap also
// consumes the handle, so a caller cannot keep probing the same wrapping
// key with different ciphertexts.
func TestUnwrapKey_FailedUnwrapConsumesHandle(t *testing.T) {
	b, _ := testBackend(t)
	params := importHandleParams(t, b, "probe", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey:  []byte("not a valid ciphertext"),
		Algorithm:   params.Algorithm,
		ImportToken: params.ImportToken,
	}
	if _, err := b.UnwrapKey(context.Background(), wrapped, params); err == nil {
		t.Fatal("UnwrapKey() of a corrupt ciphertext expected an error")
	}

	_, err := b.UnwrapKey(context.Background(), wrapped, params)
	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Fatalf("UnwrapKey() after a failed attempt: error = %v, want backend.ErrKeyNotFound", err)
	}
}

// TestUnwrapKey_RefusesExpiredHandle verifies a handle past its TTL is
// refused like an unknown one.
func TestUnwrapKey_RefusesExpiredHandle(t *testing.T) {
	b, _ := testBackend(t)
	b.importTokens = importtoken.New[*importtoken.SealedRSAKey](time.Nanosecond, importtoken.DefaultMaxTokens, (*importtoken.SealedRSAKey).Destroy)
	params := importHandleParams(t, b, "expired", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)

	wrapped, err := b.WrapKey(context.Background(), []byte("0123456789abcdef"), params)
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}
	time.Sleep(time.Millisecond)

	_, err = b.UnwrapKey(context.Background(), wrapped, params)
	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Fatalf("UnwrapKey() error = %v, want backend.ErrKeyNotFound", err)
	}
}

// TestImportKey_RefusesUnknownAndReplayedHandles verifies ImportKey
// resolves the handle through the same single-use Take: an unknown handle
// is refused, and a handle already used for one import cannot import a
// second key.
func TestImportKey_RefusesUnknownAndReplayedHandles(t *testing.T) {
	b, mockClient := testBackend(t)

	attrs := &types.KeyAttributes{
		CN:           "import-replay",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}
	params, err := b.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters() error = %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	wrapped, err := b.WrapKey(context.Background(), keyBytes, params)
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}

	unknown := *wrapped
	unknown.ImportToken = []byte(uuid.New().String())
	if err := b.ImportKey(context.Background(), attrs, &unknown); !errors.Is(err, backend.ErrKeyNotFound) {
		t.Fatalf("ImportKey() with an unknown handle: error = %v, want backend.ErrKeyNotFound", err)
	}
	if _, exists := mockClient.keys[attrs.CN]; exists {
		t.Fatal("ImportKey() with an unknown handle must not import anything")
	}

	if err := b.ImportKey(context.Background(), attrs, wrapped); err != nil {
		t.Fatalf("ImportKey() error = %v", err)
	}

	replayAttrs := *attrs
	replayAttrs.CN = "import-replay-second"
	if err := b.ImportKey(context.Background(), &replayAttrs, wrapped); !errors.Is(err, backend.ErrKeyNotFound) {
		t.Fatalf("replayed ImportKey() error = %v, want backend.ErrKeyNotFound", err)
	}
	if _, exists := mockClient.keys[replayAttrs.CN]; exists {
		t.Error("replayed ImportKey() must not import a second key")
	}
}
