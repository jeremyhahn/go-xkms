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

//go:build vault

package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

var vaultSealAuthAAD = []byte("tenant=acme,purpose=barrier")

// vaultSealAuthFixture is a backend over a fresh Transit double, with two
// sealing keys and one value sealed under the first with AAD.
type vaultSealAuthFixture struct {
	backend *Backend
	double  *transitDouble
	keyA    *types.KeyAttributes
	keyB    *types.KeyAttributes
	sealed  *types.SealedData
}

// newVaultSealAuthFixture builds the fixture. Its Vault client does not
// retry, so an injected 5xx or 429 answers at once instead of after the
// client's backoff.
func newVaultSealAuthFixture(t *testing.T) *vaultSealAuthFixture {
	t.Helper()
	double, addr := newTransitDouble(t)

	clientConfig := vaultapi.DefaultConfig()
	clientConfig.Address = addr
	clientConfig.MaxRetries = 0
	client, err := vaultapi.NewClient(clientConfig)
	require.NoError(t, err)
	client.SetToken("test-token")

	b, err := NewBackendWithClient(&Config{
		Address:     addr,
		Token:       "test-token",
		TransitPath: "transit",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, newDefaultVaultClient(client))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })

	key := func(cn string) *types.KeyAttributes {
		attrs := &types.KeyAttributes{
			CN:                 cn,
			KeyType:            backend.KEY_TYPE_SECRET,
			StoreType:          backend.STORE_VAULT,
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		}
		_, err := b.GenerateSymmetricKey(context.Background(), attrs)
		require.NoError(t, err)
		return attrs
	}
	f := &vaultSealAuthFixture{backend: b, double: double, keyA: key("seal-auth-a"), keyB: key("seal-auth-b")}
	f.sealed, err = b.Seal(context.Background(), []byte("transit sealed root key"), &types.SealOptions{KeyAttributes: f.keyA, AAD: vaultSealAuthAAD})
	require.NoError(t, err)
	return f
}

func cloneSealedData(sealed *types.SealedData) *types.SealedData {
	c := *sealed
	c.Ciphertext = bytes.Clone(sealed.Ciphertext)
	c.Metadata = make(map[string][]byte, len(sealed.Metadata))
	for k, v := range sealed.Metadata {
		c.Metadata[k] = bytes.Clone(v)
	}
	return &c
}

// reencode rewrites the base64 body of a "vault:v<n>:<base64>" envelope.
func reencode(t *testing.T, envelope []byte, edit func([]byte) []byte) []byte {
	t.Helper()
	cut := strings.LastIndex(string(envelope), ":")
	require.Positive(t, cut)
	body, err := base64.StdEncoding.DecodeString(string(envelope[cut+1:]))
	require.NoError(t, err)
	return []byte(string(envelope[:cut+1]) + base64.StdEncoding.EncodeToString(edit(body)))
}

// TestUnseal_SealedDataAuthentication proves every way the sealed data itself
// can be wrong is reported as types.ErrSealedDataAuthentication, with Vault's
// own error response still reachable where Transit produced one.
func TestUnseal_SealedDataAuthentication(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(t *testing.T, f *vaultSealAuthFixture, s *types.SealedData) *types.UnsealOptions
		fromVault bool
	}{
		{"bit flipped", func(t *testing.T, f *vaultSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = reencode(t, s.Ciphertext, func(b []byte) []byte { b[len(b)-1] ^= 0x01; return b })
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: vaultSealAuthAAD}
		}, true},
		{"truncated", func(t *testing.T, f *vaultSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = reencode(t, s.Ciphertext, func(b []byte) []byte { return b[:len(b)-1] })
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: vaultSealAuthAAD}
		}, true},
		{"truncated below a nonce", func(t *testing.T, f *vaultSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = reencode(t, s.Ciphertext, func(b []byte) []byte { return b[:5] })
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: vaultSealAuthAAD}
		}, true},
		{"extended", func(t *testing.T, f *vaultSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = reencode(t, s.Ciphertext, func(b []byte) []byte { return append(b, 0x00) })
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: vaultSealAuthAAD}
		}, true},
		{"AAD mismatch", func(t *testing.T, f *vaultSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: []byte("tenant=evil")}
		}, true},
		{"AAD omitted", func(t *testing.T, f *vaultSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			return &types.UnsealOptions{KeyAttributes: f.keyA}
		}, true},
		{"foreign key named by sealed KeyID", func(t *testing.T, f *vaultSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			return &types.UnsealOptions{KeyAttributes: f.keyB, AAD: vaultSealAuthAAD}
		}, false},
		{"foreign key detected by Transit", func(t *testing.T, f *vaultSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.KeyID = ""
			return &types.UnsealOptions{KeyAttributes: f.keyB, AAD: vaultSealAuthAAD}
		}, true},
		{"wrong backend", func(t *testing.T, f *vaultSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.Backend = types.BackendTypeGCPKMS
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: vaultSealAuthAAD}
		}, false},
		{"malformed: ciphertext missing", func(t *testing.T, f *vaultSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = nil
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: vaultSealAuthAAD}
		}, false},
		{"malformed: no vault prefix", func(t *testing.T, f *vaultSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = s.Ciphertext[len("vault:v1:"):]
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: vaultSealAuthAAD}
		}, true},
		{"malformed: body not base64", func(t *testing.T, f *vaultSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = []byte("vault:v1:!!!!")
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: vaultSealAuthAAD}
		}, true},
		{"malformed: version not a number", func(t *testing.T, f *vaultSealAuthFixture, s *types.SealedData) *types.UnsealOptions {
			s.Ciphertext = []byte("vault:vX:" + string(s.Ciphertext[len("vault:v1:"):]))
			return &types.UnsealOptions{KeyAttributes: f.keyA, AAD: vaultSealAuthAAD}
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newVaultSealAuthFixture(t)
			mutated := cloneSealedData(f.sealed)
			opts := tc.mutate(t, f, mutated)

			out, err := f.backend.Unseal(context.Background(), mutated, opts)
			require.Nil(t, out, "bad sealed data must not produce plaintext")
			require.ErrorIs(t, err, types.ErrSealedDataAuthentication)
			var respErr *vaultapi.ResponseError
			require.Equal(t, tc.fromVault, errors.As(err, &respErr), "Vault's response must stay reachable exactly when Transit answered")
		})
	}

	t.Run("untouched envelope still unseals", func(t *testing.T) {
		f := newVaultSealAuthFixture(t)
		got, err := f.backend.Unseal(context.Background(), f.sealed, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: vaultSealAuthAAD})
		require.NoError(t, err)
		require.Equal(t, []byte("transit sealed root key"), got)
	})
}

// TestUnseal_EnvironmentFailuresAreNotAuthentication proves outages,
// throttling, permission failures, missing keys or key versions, a server
// that ignores associated_data and a cancelled context are never reported as
// sealed-data authentication failures.
func TestUnseal_EnvironmentFailuresAreNotAuthentication(t *testing.T) {
	faults := []transitFault{
		{http.StatusServiceUnavailable, "Vault is sealed"},
		{http.StatusInternalServerError, "internal error"},
		{http.StatusTooManyRequests, "request path \"transit/decrypt\": rate limit quota exceeded"},
		{http.StatusForbidden, "permission denied"},
		{http.StatusBadRequest, "encryption key not found"},
		{http.StatusBadRequest, "ciphertext or signature version is disallowed by policy (too old)"},
		{http.StatusBadRequest, "invalid ciphertext: version is too new"},
	}
	for _, fault := range faults {
		t.Run(fault.message, func(t *testing.T) {
			f := newVaultSealAuthFixture(t)
			f.double.decryptFault = &fault

			_, err := f.backend.Unseal(context.Background(), f.sealed, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: vaultSealAuthAAD})
			require.Error(t, err)
			require.NotErrorIs(t, err, types.ErrSealedDataAuthentication)
			var respErr *vaultapi.ResponseError
			require.True(t, errors.As(err, &respErr), "Vault's response must stay reachable")
			require.Equal(t, fault.status, respErr.StatusCode)
		})
	}

	t.Run("version too new from a real envelope", func(t *testing.T) {
		f := newVaultSealAuthFixture(t)
		mutated := cloneSealedData(f.sealed)
		mutated.Ciphertext = []byte("vault:v9:" + string(mutated.Ciphertext[len("vault:v1:"):]))
		_, err := f.backend.Unseal(context.Background(), mutated, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: vaultSealAuthAAD})
		require.Error(t, err)
		require.NotErrorIs(t, err, types.ErrSealedDataAuthentication)
	})

	t.Run("server ignores associated_data", func(t *testing.T) {
		// A server without associated_data support decrypts a value sealed
		// without AAD even when the unseal presents AAD -- it never sees
		// it. Returning that plaintext would drop the binding the caller
		// asked for, so the unseal fails closed instead.
		f := newVaultSealAuthFixture(t)
		sealed, err := f.backend.Seal(context.Background(), []byte("no aad"), &types.SealOptions{KeyAttributes: f.keyA})
		require.NoError(t, err)
		f.double.legacyTransit = true

		out, err := f.backend.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: vaultSealAuthAAD})
		require.Nil(t, out)
		require.ErrorIs(t, err, ErrAssociatedDataIgnored)
		require.NotErrorIs(t, err, types.ErrSealedDataAuthentication)
	})

	t.Run("cancelled context with tampered data", func(t *testing.T) {
		f := newVaultSealAuthFixture(t)
		tampered := cloneSealedData(f.sealed)
		tampered.Ciphertext = reencode(t, tampered.Ciphertext, func(b []byte) []byte { b[0] ^= 0x01; return b })
		tampered.Backend = types.BackendTypeAWSKMS

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := f.backend.Unseal(ctx, tampered, &types.UnsealOptions{KeyAttributes: f.keyA, AAD: vaultSealAuthAAD})
		require.ErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, types.ErrSealedDataAuthentication)
	})

	t.Run("sealing key unknown to the backend", func(t *testing.T) {
		f := newVaultSealAuthFixture(t)
		mutated := cloneSealedData(f.sealed)
		mutated.KeyID = ""
		never := &types.KeyAttributes{
			CN:                 "seal-auth-never-created",
			KeyType:            backend.KEY_TYPE_SECRET,
			StoreType:          backend.STORE_VAULT,
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		}
		_, err := f.backend.Unseal(context.Background(), mutated, &types.UnsealOptions{KeyAttributes: never, AAD: vaultSealAuthAAD})
		require.Error(t, err)
		require.NotErrorIs(t, err, types.ErrSealedDataAuthentication)
	})
}

// TestSeal_AssociatedDataIsBound proves Seal sends the AAD where Transit
// binds it: a server that ignores associated_data makes Seal fail closed
// rather than return a ciphertext with no AAD binding.
func TestSeal_AssociatedDataIsBound(t *testing.T) {
	f := newVaultSealAuthFixture(t)
	f.double.legacyTransit = true

	_, err := f.backend.Seal(context.Background(), []byte("x"), &types.SealOptions{KeyAttributes: f.keyA, AAD: vaultSealAuthAAD})
	require.ErrorIs(t, err, ErrAssociatedDataIgnored)

	sealed, err := f.backend.Seal(context.Background(), []byte("x"), &types.SealOptions{KeyAttributes: f.keyA})
	require.NoError(t, err, "a seal without AAD needs nothing the server lacks")
	got, err := f.backend.Unseal(context.Background(), sealed, &types.UnsealOptions{KeyAttributes: f.keyA})
	require.NoError(t, err)
	require.Equal(t, []byte("x"), got)
}

// TestRejectsSealedData pins the Transit response classification.
func TestRejectsSealedData(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"authentication failed", &vaultapi.ResponseError{StatusCode: 400, Errors: []string{"cipher: message authentication failed"}}, true},
		{"invalid ciphertext length", &vaultapi.ResponseError{StatusCode: 400, Errors: []string{"invalid ciphertext length"}}, true},
		{"no prefix", &vaultapi.ResponseError{StatusCode: 400, Errors: []string{"invalid ciphertext: no prefix"}}, true},
		{"version too new", &vaultapi.ResponseError{StatusCode: 400, Errors: []string{"invalid ciphertext: version is too new"}}, false},
		{"key not found", &vaultapi.ResponseError{StatusCode: 400, Errors: []string{"encryption key not found"}}, false},
		{"mixed messages", &vaultapi.ResponseError{StatusCode: 400, Errors: []string{"cipher: message authentication failed", "encryption key not found"}}, false},
		{"no messages", &vaultapi.ResponseError{StatusCode: 400}, false},
		{"authentication text on a 500", &vaultapi.ResponseError{StatusCode: 500, Errors: []string{"cipher: message authentication failed"}}, false},
		{"permission denied", &vaultapi.ResponseError{StatusCode: 403, Errors: []string{"permission denied"}}, false},
		{"not a Vault response", errors.New("cipher: message authentication failed"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, rejectsSealedData(tc.err))
		})
	}
}
