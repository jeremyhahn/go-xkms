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
// parsed the private key back out of the caller-supplied token. go-xkms#1342
// replaced the ephemeral-local-wrapping-keypair ceremony entirely with Azure
// Key Vault's native BYOK flow: the token is an opaque random handle naming
// a kekBinding -- the vault's key-encryption key's kid and the wrapping
// algorithm -- that never carries or names any key material at all, local
// or remote.

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
// private key, it has exactly the handle's length, and the binding it
// names in the backend's store carries the KEK's real kid rather than any
// key material.
func TestGetImportParameters_TokenCarriesNoPrivateKey(t *testing.T) {
	b, _ := testBackend(t)
	params := importHandleParams(t, b, "handle-only", backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)

	if _, err := x509.ParsePKCS1PrivateKey(params.ImportToken); err == nil {
		t.Fatal("ImportToken parses as a PKCS#1 private key; the token must never carry key material")
	}
	if _, err := x509.ParsePKCS8PrivateKey(params.ImportToken); err == nil {
		t.Fatal("ImportToken parses as a PKCS#8 private key; the token must never carry key material")
	}
	if got, want := len(params.ImportToken), len(uuid.New().String()); got != want {
		t.Errorf("len(ImportToken) = %d, want the handle length %d", got, want)
	}
	if _, err := uuid.Parse(string(params.ImportToken)); err != nil {
		t.Errorf("ImportToken is not a random handle: %v", err)
	}

	binding, err := b.importTokens.Peek(string(params.ImportToken))
	if err != nil {
		t.Fatalf("importTokens.Peek() error = %v; the handle must name a stored binding", err)
	}
	if binding.algorithm != backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256 {
		t.Errorf("binding.algorithm = %s, want %s", binding.algorithm, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	}
	if binding.kekKID == "" {
		t.Error("binding.kekKID is empty")
	}
}

// TestGetImportParameters_DistinctHandlesPerCeremony verifies two
// ceremonies for the same CN get independent handles: the old CN-derived
// store key let the second ceremony overwrite the first's wrapping state.
// Both handles remain individually usable through a full WrapKey/ImportKey
// ceremony, even though both share the same reused KEK.
func TestGetImportParameters_DistinctHandlesPerCeremony(t *testing.T) {
	b, mockClient := testBackend(t)
	alg := backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256
	first := importHandleParams(t, b, "same-cn-1", alg)
	second := importHandleParams(t, b, "same-cn-2", alg)

	if bytes.Equal(first.ImportToken, second.ImportToken) {
		t.Fatal("two ceremonies received the same import token")
	}

	for i, tc := range []struct {
		cn     string
		params *backend.ImportParameters
	}{
		{cn: "same-cn-1", params: first},
		{cn: "same-cn-2", params: second},
	} {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("ceremony %d: rsa.GenerateKey() error = %v", i, err)
		}
		keyBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
		if err != nil {
			t.Fatalf("ceremony %d: MarshalPKCS8PrivateKey() error = %v", i, err)
		}
		wrapped, err := b.WrapKey(context.Background(), keyBytes, tc.params)
		if err != nil {
			t.Fatalf("ceremony %d: WrapKey() error = %v", i, err)
		}
		attrs := &types.KeyAttributes{CN: tc.cn, KeyAlgorithm: x509.RSA}
		if err := b.ImportKey(context.Background(), attrs, wrapped); err != nil {
			t.Fatalf("ceremony %d: ImportKey() error = %v", i, err)
		}
		if _, exists := mockClient.keys[tc.cn]; !exists {
			t.Errorf("ceremony %d: ImportKey() did not create key %q", i, tc.cn)
		}
	}
}

// TestImportKey_RefusesExpiredHandle verifies a handle past its TTL is
// refused like an unknown one, and never reaches Azure Key Vault.
func TestImportKey_RefusesExpiredHandle(t *testing.T) {
	b, mockClient := testBackend(t)
	b.importTokens = importtoken.New[*kekBinding](time.Nanosecond, importtoken.DefaultMaxTokens, nil)

	attrs := &types.KeyAttributes{CN: "expired", KeyAlgorithm: x509.RSA}
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
	time.Sleep(time.Millisecond)

	err = b.ImportKey(context.Background(), attrs, wrapped)
	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Fatalf("ImportKey() error = %v, want backend.ErrKeyNotFound", err)
	}
	if _, exists := mockClient.keys[attrs.CN]; exists {
		t.Error("ImportKey() with an expired handle must not import anything")
	}
}
