// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package xkms

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
)

// testPasskey is a passkey credential: the hmac-secret output a
// FIDO2 authenticator returned for credential "cred-1" over the salt.
func testPasskey(output byte) transport.PasswordVaultCredential {
	return transport.PasswordVaultCredential{
		Factor:       "passkey",
		CredentialID: []byte("cred-1"),
		PRFSalt:      bytes.Repeat([]byte{0x5a}, staticpw.PRFSaltLength),
		Secret:       bytes.Repeat([]byte{output}, staticpw.PasskeySecretLength),
		Label:        "laptop key",
		RPID:         "kms.example.com",
	}
}

func TestPasswordVault_EnrollStatusAndPasskeyUnlock(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := sharedPasswordCtx("alice")

	status, err := svc.PasswordVaultStatus(ctx)
	require.NoError(t, err)
	assert.False(t, status.Initialized)

	first, err := svc.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: testVaultPassphrase})
	require.NoError(t, err)
	assert.NotEmpty(t, first.RecoveryCode, "the first enrollment issues the recovery code")
	assert.Equal(t, "passphrase", first.Factor.Factor)

	second, err := svc.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: testPasskey(0x11)})
	require.NoError(t, err)
	assert.Empty(t, second.RecoveryCode)
	assert.Equal(t, []byte("cred-1"), second.Factor.CredentialID)

	_, err = svc.PasswordAdd(ctx, &transport.PasswordAddRequest{Name: "bank", Password: "secret"})
	require.NoError(t, err)
	require.NoError(t, svc.PasswordStoreLock(ctx))

	status, err = svc.PasswordVaultStatus(ctx)
	require.NoError(t, err)
	assert.True(t, status.Initialized)
	assert.False(t, status.Unlocked)
	require.Len(t, status.Factors, 3)
	for _, f := range status.Factors {
		if f.Factor == "passkey" {
			assert.Len(t, f.PRFSalt, staticpw.PRFSaltLength, "a client reads the salt to evaluate hmac-secret")
		}
	}

	wrong := testPasskey(0x99)
	assert.ErrorIs(t, svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: wrong}), staticpw.ErrVaultCredentialRejected)
	require.NoError(t, svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: testPasskey(0x11)}))
	got, err := svc.PasswordGet(ctx, &transport.PasswordGetRequest{ID: "bank"})
	require.NoError(t, err)
	assert.Equal(t, "secret", got.Password)
}

func TestPasswordVault_RotateAndRemove(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := sharedPasswordCtx("alice")
	first, err := svc.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: testVaultPassphrase})
	require.NoError(t, err)

	next := transport.PasswordVaultCredential{Factor: "passphrase", Passphrase: "the next passphrase"}
	rotated, err := svc.PasswordVaultRotate(ctx, &transport.PasswordVaultRotateRequest{FactorID: first.Factor.ID, PasswordVaultCredential: next})
	require.NoError(t, err)
	require.NoError(t, svc.PasswordStoreLock(ctx))
	assert.ErrorIs(t, svc.PasswordStoreUnlock(ctx, unlockRequest()), staticpw.ErrVaultCredentialRejected)
	require.NoError(t, svc.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: next}))

	assert.ErrorIs(t, svc.PasswordVaultRemoveFactor(ctx, &transport.PasswordVaultRemoveFactorRequest{FactorID: rotated.Factor.ID}), staticpw.ErrVaultLastFactor)
	_, err = svc.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: testPasskey(0x11)})
	require.NoError(t, err)
	require.NoError(t, svc.PasswordVaultRemoveFactor(ctx, &transport.PasswordVaultRemoveFactorRequest{FactorID: rotated.Factor.ID}))
}

func TestPasswordVault_Recover(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := sharedPasswordCtx("alice")
	first, err := svc.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: testVaultPassphrase})
	require.NoError(t, err)
	require.NoError(t, svc.PasswordStoreLock(ctx))

	next := transport.PasswordVaultCredential{Factor: "passphrase", Passphrase: "recovered passphrase"}
	recovered, err := svc.PasswordVaultRecover(ctx, &transport.PasswordVaultRecoverRequest{RecoveryCode: first.RecoveryCode, PasswordVaultCredential: next})
	require.NoError(t, err)
	assert.NotEmpty(t, recovered.RecoveryCode)
	assert.NotEqual(t, first.RecoveryCode, recovered.RecoveryCode)

	status, err := svc.PasswordStoreStatus(ctx)
	require.NoError(t, err)
	assert.False(t, status.IsLocked, "recovery opens the session")

	_, err = svc.PasswordVaultRecover(ctx, &transport.PasswordVaultRecoverRequest{RecoveryCode: first.RecoveryCode, PasswordVaultCredential: next})
	assert.ErrorIs(t, err, staticpw.ErrVaultCredentialRejected, "the code is one-time")
}

// TestPasswordVault_IsTheCallersOwn proves one user's vault operations never
// reach another's: bob's enrollment is his own, and his passphrase does not
// open alice's session.
func TestPasswordVault_IsTheCallersOwn(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	alice, bob := sharedPasswordCtx("alice"), sharedPasswordCtx("bob")
	_, err := svc.PasswordVaultEnroll(alice, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: testVaultPassphrase})
	require.NoError(t, err)
	require.NoError(t, svc.PasswordStoreLock(alice))

	bobPass := transport.PasswordVaultCredential{Factor: "passphrase", Passphrase: "bob's own passphrase"}
	res, err := svc.PasswordVaultEnroll(bob, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: bobPass})
	require.NoError(t, err)
	assert.NotEmpty(t, res.RecoveryCode, "bob's first enrollment initializes bob's vault, not alice's")

	assert.ErrorIs(t, svc.PasswordStoreUnlock(alice, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: bobPass}), staticpw.ErrVaultCredentialRejected)
	status, err := svc.PasswordVaultStatus(alice)
	require.NoError(t, err)
	assert.False(t, status.Unlocked)
}

func TestPasswordVault_Refusals(t *testing.T) {
	svc, _ := setupServiceWithPasswordManager(t)
	ctx := sharedPasswordCtx("alice")
	noIdentity := context.Background()

	_, err := svc.PasswordVaultStatus(noIdentity)
	assert.ErrorIs(t, err, ErrOperationNotSupported, "the unscoped store has no vault")
	_, err = svc.PasswordVaultEnroll(noIdentity, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: testVaultPassphrase})
	assert.ErrorIs(t, err, ErrOperationNotSupported)

	_, err = svc.PasswordVaultEnroll(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
	_, err = svc.PasswordVaultRotate(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
	assert.ErrorIs(t, svc.PasswordVaultRemoveFactor(ctx, nil), ErrNilRequest)
	_, err = svc.PasswordVaultRecover(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)

	_, err = svc.PasswordVaultRotate(ctx, &transport.PasswordVaultRotateRequest{FactorID: "x", PasswordVaultCredential: testVaultPassphrase})
	assert.ErrorIs(t, err, staticpw.ErrVaultNotInitialized)
	_, err = svc.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: transport.PasswordVaultCredential{Factor: "passphrase", Passphrase: "short"}})
	assert.ErrorIs(t, err, staticpw.ErrVaultInvalidCredential)

	bare := &XKMSService{}
	_, err = bare.PasswordVaultStatus(ctx)
	assert.ErrorIs(t, err, ErrNotConfigured)
	flat := setupServiceWithPasswordStore(t)
	_, err = flat.PasswordVaultStatus(ctx)
	assert.ErrorIs(t, err, ErrOperationNotSupported, "a deployment without per-tenant stores has no vault")
}
