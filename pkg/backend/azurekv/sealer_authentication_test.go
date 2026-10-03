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

//go:build azurekv

package azurekv

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

var azureSealAuthAAD = []byte("tenant=acme,purpose=barrier")

// azureSealAuthFixture is a backend over the mock Secrets API with two
// sealing keys and one value sealed under the first.
type azureSealAuthFixture struct {
	backend *Backend
	secrets *MockSecretsClient
	keyA    *types.KeyAttributes
	keyB    *types.KeyAttributes
	sealed  *types.SealedData
}

func newAzureSealAuthFixture(t *testing.T) *azureSealAuthFixture {
	t.Helper()
	b, secrets := testBackendWithSecrets(t)
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	key := func(cn string) *types.KeyAttributes {
		attrs := &types.KeyAttributes{
			CN:                 cn,
			KeyType:            backend.KEY_TYPE_SECRET,
			StoreType:          backend.STORE_AZUREKV,
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		}
		if _, err := b.GenerateSymmetricKey(context.Background(), attrs); err != nil {
			t.Fatalf("GenerateSymmetricKey(%s): %v", cn, err)
		}
		return attrs
	}
	f := &azureSealAuthFixture{backend: b, secrets: secrets, keyA: key("seal-auth-a"), keyB: key("seal-auth-b")}
	sealed, err := b.Seal(context.Background(), []byte("vault sealed root key"), &types.SealOptions{KeyAttributes: f.keyA, AAD: azureSealAuthAAD})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	f.sealed = sealed
	return f
}

func cloneSealedData(sealed *types.SealedData) *types.SealedData {
	c := *sealed
	c.Ciphertext = bytes.Clone(sealed.Ciphertext)
	c.Nonce = bytes.Clone(sealed.Nonce)
	c.Tag = bytes.Clone(sealed.Tag)
	c.Metadata = make(map[string][]byte, len(sealed.Metadata))
	for k, v := range sealed.Metadata {
		c.Metadata[k] = bytes.Clone(v)
	}
	return &c
}

// TestUnseal_SealedDataAuthentication proves every way the sealed data itself
// can be wrong is reported as types.ErrSealedDataAuthentication, with
// ErrCiphertextRejected still reachable where the AES-GCM open refused it.
func TestUnseal_SealedDataAuthentication(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(f *azureSealAuthFixture, s *types.SealedData) *types.UnsealOptions
		rejected bool
	}{
		{"ciphertext bit flipped", func(f *azureSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext[0] ^= 0x01
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: azureSealAuthAAD}
		}, true},
		{"tag bit flipped", func(f *azureSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.Tag[0] ^= 0x01
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: azureSealAuthAAD}
		}, true},
		{"truncated", func(f *azureSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = s.Ciphertext[:len(s.Ciphertext)-1]
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: azureSealAuthAAD}
		}, true},
		{"extended", func(f *azureSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = append(s.Ciphertext, 0x00)
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: azureSealAuthAAD}
		}, true},
		{"AAD mismatch", func(f *azureSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: []byte("tenant=evil")}
		}, true},
		{"AAD omitted", func(f *azureSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			return &types.UnsealOptions{KeyAttributes: f.keyA}
		}, true},
		{"foreign key named by sealed KeyID", func(f *azureSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			return &types.UnsealOptions{KeyAttributes: f.keyB, AAD: azureSealAuthAAD}
		}, false},
		{"foreign key detected by AES-GCM", func(f *azureSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.KeyID = ""
			return &types.UnsealOptions{KeyAttributes: f.keyB, AAD: azureSealAuthAAD}
		}, true},
		{"wrong backend", func(f *azureSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.Backend = types.BackendTypeAWSKMS
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: azureSealAuthAAD}
		}, false},
		{"malformed: nonce missing", func(f *azureSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.Nonce = nil
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: azureSealAuthAAD}
		}, true},
		{"malformed: tag short", func(f *azureSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.Tag = s.Tag[:4]
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: azureSealAuthAAD}
		}, true},
		{"malformed: unknown nonce mode", func(f *azureSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.Metadata["azurekv:gcm_nonce_mode"] = []byte("bogus")
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: azureSealAuthAAD}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAzureSealAuthFixture(t)
			mutated := cloneSealedData(f.sealed)
			opts := tc.mutate(f, mutated)

			out, err := f.backend.Unseal(context.Background(), mutated, opts)
			if out != nil {
				t.Fatalf("Unseal returned plaintext %q for bad sealed data", out)
			}
			if !errors.Is(err, types.ErrSealedDataAuthentication) {
				t.Fatalf("Unseal error %v does not match ErrSealedDataAuthentication", err)
			}
			if got := errors.Is(err, ErrCiphertextRejected); got != tc.rejected {
				t.Fatalf("errors.Is(err, ErrCiphertextRejected) = %v, want %v (err: %v)", got, tc.rejected, err)
			}
		})
	}

	t.Run("untouched envelope still unseals", func(t *testing.T) {
		f := newAzureSealAuthFixture(t)
		got, err := f.backend.Unseal(context.Background(), f.sealed, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: azureSealAuthAAD})
		if err != nil {
			t.Fatalf("Unseal: %v", err)
		}
		if !bytes.Equal(got, []byte("vault sealed root key")) {
			t.Fatalf("Unseal = %q", got)
		}
	})
}

// TestUnseal_EnvironmentFailuresAreNotAuthentication proves Key Vault
// outages, permission failures, unusable key material and a cancelled
// context are never reported as sealed-data authentication failures, even
// when the sealed data handed in would itself fail authentication.
func TestUnseal_EnvironmentFailuresAreNotAuthentication(t *testing.T) {
	faults := []struct {
		name  string
		fault error
	}{
		{"vault unavailable", &azcore.ResponseError{StatusCode: http.StatusServiceUnavailable, ErrorCode: "ServiceUnavailable"}},
		{"throttled", &azcore.ResponseError{StatusCode: http.StatusTooManyRequests, ErrorCode: "Throttled"}},
		{"forbidden", &azcore.ResponseError{StatusCode: http.StatusForbidden, ErrorCode: "Forbidden"}},
		{"secret not found", &azcore.ResponseError{StatusCode: http.StatusNotFound, ErrorCode: "SecretNotFound"}},
		{"network", errors.New("dial tcp: connection refused")},
	}
	for _, tc := range faults {
		t.Run(tc.name, func(t *testing.T) {
			f := newAzureSealAuthFixture(t)
			tampered := cloneSealedData(f.sealed)
			tampered.Ciphertext[0] ^= 0x01
			f.secrets.SetGetError(tc.fault)

			_, err := f.backend.Unseal(context.Background(), tampered, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: azureSealAuthAAD})
			if err == nil {
				t.Fatal("Unseal must fail when Key Vault fails")
			}
			if errors.Is(err, types.ErrSealedDataAuthentication) {
				t.Fatalf("environment failure %v reported as sealed-data authentication", err)
			}
			if !errors.Is(err, tc.fault) {
				t.Fatalf("Unseal error %v lost the Key Vault cause", err)
			}
		})
	}

	t.Run("key material that is not an AES key", func(t *testing.T) {
		f := newAzureSealAuthFixture(t)
		short := base64.StdEncoding.EncodeToString([]byte("five!"))
		f.secrets.SetSecretValue(f.keyA.CN, &short)

		_, err := f.backend.Unseal(context.Background(), f.sealed, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: azureSealAuthAAD})
		if err == nil {
			t.Fatal("Unseal must fail with unusable key material")
		}
		if errors.Is(err, types.ErrSealedDataAuthentication) {
			t.Fatalf("unusable key material %v reported as sealed-data authentication", err)
		}
	})

	t.Run("cancelled context with tampered data", func(t *testing.T) {
		f := newAzureSealAuthFixture(t)
		tampered := cloneSealedData(f.sealed)
		tampered.Ciphertext[0] ^= 0x01
		tampered.Backend = types.BackendTypeVault

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := f.backend.Unseal(ctx, tampered, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: azureSealAuthAAD})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Unseal error %v, want context.Canceled", err)
		}
		if errors.Is(err, types.ErrSealedDataAuthentication) {
			t.Fatal("a cancelled context must not be reported as sealed-data authentication")
		}
	})
}
