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

package importtoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

func TestErrors_Messages(t *testing.T) {
	cause := errors.New("enclave gone")
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"not found", &NotFoundError{Token: "tok"}, "importtoken: token not found or expired: tok"},
		{"limit", &LimitExceededError{Limit: 3}, "importtoken: store at capacity (3 tokens)"},
		{"unavailable no cause", &UnavailableError{}, "importtoken: wrapping key is not available"},
		{"unavailable with cause", &UnavailableError{Err: cause}, "importtoken: failed to open wrapping key enclave: enclave gone"},
		{"not rsa", &NotRSAKeyError{}, "importtoken: wrapping key is not RSA"},
		{
			"algorithm mismatch",
			&AlgorithmMismatchError{
				Issued:    backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
				Requested: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
			},
			"importtoken: wrapped with " + backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256.String() +
				" but token was issued for " + backend.WrappingAlgorithmRSAES_OAEP_SHA_256.String(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Error())
		})
	}
}

func TestUnavailableError_UnwrapsCause(t *testing.T) {
	cause := errors.New("enclave gone")
	assert.ErrorIs(t, &UnavailableError{Err: cause}, cause)
	assert.NoError(t, (&UnavailableError{}).Unwrap())
}

func TestStore_PeekUnknownToken(t *testing.T) {
	store := New(time.Hour, 10, func(string) {})

	_, err := store.Peek("missing")
	var notFound *NotFoundError
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, "missing", notFound.Token)
}

func TestStore_PeekExpiredTokenIsSwept(t *testing.T) {
	var destroyed []string
	store := New(10*time.Millisecond, 10, func(v string) { destroyed = append(destroyed, v) })

	_, err := store.Put("expiring", "secret-1")
	require.NoError(t, err)

	time.Sleep(20 * time.Millisecond)

	_, err = store.Peek("expiring")
	var notFound *NotFoundError
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, []string{"secret-1"}, destroyed)
	assert.Equal(t, 0, store.Len())
}

// sealDER seals arbitrary DER bytes as if they were a wrapping key, so the
// tests can model a tampered or substituted enclave payload.
func sealDER(t *testing.T, der []byte) *SealedRSAKey {
	t.Helper()
	sealed, err := secure.NewSecret(t.Context(), der)
	require.NoError(t, err)
	key := NewSealedRSAKeyFromSecret(sealed, nil)
	t.Cleanup(key.Destroy)
	return key
}

func TestSealedRSAKey_UseRejectsNonRSAKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)
	key := sealDER(t, der)

	called := false
	err = key.Use(t.Context(), func(*rsa.PrivateKey) error { called = true; return nil })
	var notRSA *NotRSAKeyError
	require.ErrorAs(t, err, &notRSA)
	assert.False(t, called)
}

func TestSealedRSAKey_UseRejectsCorruptPayload(t *testing.T) {
	key := sealDER(t, []byte("not a pkcs8 key"))

	called := false
	err := key.Use(t.Context(), func(*rsa.PrivateKey) error { called = true; return nil })
	require.Error(t, err)
	var notRSA *NotRSAKeyError
	assert.False(t, errors.As(err, &notRSA))
	assert.False(t, called)
}
