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

// Package vaulttest holds personal-vault fixtures for tests of the
// transports: deterministic passkey credentials, a call of every vault
// method, one lifecycle scenario every transport runs end to end, and
// SimulatedKey, the security key every client surface's passkey tests use.
// It imports only pkg/api/transport and pkg/fido2 (neither imports a
// transport), so every transport package's tests can use it; the real
// service the scenario runs against is in vaultservice.
package vaulttest

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Client is the part of transport.PasswordService the vault scenario drives.
type Client interface {
	PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error
	PasswordStoreLock(ctx context.Context) error
	PasswordVaultStatus(ctx context.Context) (*transport.PasswordVaultStatusResponse, error)
	PasswordVaultEnroll(ctx context.Context, req *transport.PasswordVaultEnrollRequest) (*transport.PasswordVaultEnrollResponse, error)
	PasswordVaultRotate(ctx context.Context, req *transport.PasswordVaultRotateRequest) (*transport.PasswordVaultEnrollResponse, error)
	PasswordVaultRemoveFactor(ctx context.Context, req *transport.PasswordVaultRemoveFactorRequest) error
	PasswordVaultRecover(ctx context.Context, req *transport.PasswordVaultRecoverRequest) (*transport.PasswordVaultEnrollResponse, error)
}

// Passkey returns name's test passkey: a credential ID, a 32-byte PRF salt
// and a 32-byte PRF output derived from name, as an authenticator's
// hmac-secret evaluation would give them.
func Passkey(name string) transport.PasswordVaultCredential {
	secret := sha256.Sum256([]byte("prf-output:" + name))
	salt := sha256.Sum256([]byte("prf-salt:" + name))
	return transport.PasswordVaultCredential{
		Factor:       "passkey",
		CredentialID: []byte("credential-" + name),
		PRFSalt:      salt[:],
		Secret:       secret[:],
		Label:        name,
	}
}

// Calls returns one call of every vault method on c, keyed by method name,
// each with a minimal request. A test runs them to prove a property of the
// whole method set, such as refusing before a transport is connected.
func Calls(ctx context.Context, c Client) map[string]func() error {
	return map[string]func() error{
		"PasswordVaultStatus": func() error { _, err := c.PasswordVaultStatus(ctx); return err },
		"PasswordVaultEnroll": func() error {
			_, err := c.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: Passkey("k")})
			return err
		},
		"PasswordVaultRotate": func() error {
			_, err := c.PasswordVaultRotate(ctx, &transport.PasswordVaultRotateRequest{FactorID: "f", PasswordVaultCredential: Passkey("k")})
			return err
		},
		"PasswordVaultRemoveFactor": func() error {
			return c.PasswordVaultRemoveFactor(ctx, &transport.PasswordVaultRemoveFactorRequest{FactorID: "f"})
		},
		"PasswordVaultRecover": func() error {
			_, err := c.PasswordVaultRecover(ctx, &transport.PasswordVaultRecoverRequest{RecoveryCode: "c", PasswordVaultCredential: Passkey("k")})
			return err
		},
	}
}

// RunLifecycle drives c through the whole vault lifecycle as a user with no
// vault yet: the first enrollment returns a recovery code and opens the
// session; a wrong passkey is refused and the right one unlocks; a second
// passkey is enrolled, rotated and removed; the last factor cannot be
// removed; the recovery code enrolls a new passkey once and only once. It
// asserts only success or failure, so it runs over any transport whatever
// its error vocabulary.
func RunLifecycle(t *testing.T, ctx context.Context, c Client) {
	t.Helper()

	before, err := c.PasswordVaultStatus(ctx)
	require.NoError(t, err)
	require.False(t, before.Initialized, "the scenario starts with no vault")

	first, err := c.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: Passkey("first")})
	require.NoError(t, err)
	require.NotEmpty(t, first.RecoveryCode, "the first enrollment issues the recovery code")
	assert.Equal(t, "passkey", first.Factor.Factor)
	assert.Equal(t, Passkey("first").CredentialID, first.Factor.CredentialID)

	after, err := c.PasswordVaultStatus(ctx)
	require.NoError(t, err)
	assert.True(t, after.Initialized)
	assert.True(t, after.Unlocked, "the first enrollment opens the session")

	require.NoError(t, c.PasswordStoreLock(ctx))
	wrong := Passkey("first")
	wrong.Secret = make([]byte, len(wrong.Secret))
	require.Error(t, c.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: wrong}),
		"a wrong PRF output is refused")
	require.NoError(t, c.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: Passkey("first")}))

	second, err := c.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: Passkey("second")})
	require.NoError(t, err)
	assert.Empty(t, second.RecoveryCode, "only the first enrollment issues a recovery code")

	rotated := Passkey("second")
	rotated.Secret = []byte("0123456789abcdef0123456789abcdef")
	rotatedFactor, err := c.PasswordVaultRotate(ctx, &transport.PasswordVaultRotateRequest{FactorID: second.Factor.ID, PasswordVaultCredential: rotated})
	require.NoError(t, err)

	require.NoError(t, c.PasswordVaultRemoveFactor(ctx, &transport.PasswordVaultRemoveFactorRequest{FactorID: rotatedFactor.Factor.ID}))
	require.Error(t, c.PasswordVaultRemoveFactor(ctx, &transport.PasswordVaultRemoveFactorRequest{FactorID: first.Factor.ID}),
		"the last passkey cannot be removed")

	require.NoError(t, c.PasswordStoreLock(ctx))
	recovered, err := c.PasswordVaultRecover(ctx, &transport.PasswordVaultRecoverRequest{
		RecoveryCode: first.RecoveryCode, PasswordVaultCredential: Passkey("recovered"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, recovered.RecoveryCode)
	assert.NotEqual(t, first.RecoveryCode, recovered.RecoveryCode, "recovery replaces the code")

	require.NoError(t, c.PasswordStoreLock(ctx))
	_, err = c.PasswordVaultRecover(ctx, &transport.PasswordVaultRecoverRequest{
		RecoveryCode: first.RecoveryCode, PasswordVaultCredential: Passkey("again"),
	})
	require.Error(t, err, "a used recovery code is spent")
	require.NoError(t, c.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: Passkey("recovered")}))
}
