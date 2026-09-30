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

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// The password.vault.* methods driven through the real InvokeMethod dispatch
// (authorization, handler table, error classification) over a real
// XKMSService (newPasswordServer).

// vaultPassphrase is the passphrase the vault tests enroll.
const vaultPassphrase = "correct horse battery staple"

// newVaultServer returns a passwordServer whose authorizer admits every
// caller, so the tests reach the handlers through InvokeMethod.
func newVaultServer(t *testing.T) *passwordServer {
	t.Helper()
	s := newPasswordServer(t)
	s.authorizer = auth.NewAuthorizer(nil)
	return s
}

// invoke calls method through InvokeMethod with params (nil for none).
func (s *passwordServer) invoke(t *testing.T, ctx context.Context, method string, params any) (any, error) {
	t.Helper()
	var raw json.RawMessage
	if params != nil {
		data, err := json.Marshal(params)
		require.NoError(t, err)
		raw = data
	}
	return s.InvokeMethod(ctx, method, raw)
}

// vaultEnroll enrolls cred through password.vault.enroll.
func (s *passwordServer) vaultEnroll(t *testing.T, ctx context.Context, cred transport.PasswordVaultCredential) *transport.PasswordVaultEnrollResponse {
	t.Helper()
	result, err := s.invoke(t, ctx, "password.vault.enroll", cred)
	require.NoError(t, err)
	return result.(*transport.PasswordVaultEnrollResponse)
}

// vaultStatus reads the caller's vault through password.vault.status.
func (s *passwordServer) vaultStatus(t *testing.T, ctx context.Context) *transport.PasswordVaultStatusResponse {
	t.Helper()
	result, err := s.invoke(t, ctx, "password.vault.status", nil)
	require.NoError(t, err)
	return result.(*transport.PasswordVaultStatusResponse)
}

// unlockWith calls password.unlock with cred.
func (s *passwordServer) unlockWith(t *testing.T, ctx context.Context, cred transport.PasswordVaultCredential) error {
	t.Helper()
	_, err := s.invoke(t, ctx, "password.unlock", cred)
	return err
}

func TestVaultMethods_PassphraseLifecycle(t *testing.T) {
	t.Parallel()
	s := newVaultServer(t)
	alice := pwCtx(pwTenantA, pwUserA)

	assert.False(t, s.vaultStatus(t, alice).Initialized)

	enrolled := s.vaultEnroll(t, alice, transport.PasswordVaultCredential{Factor: "passphrase", Passphrase: vaultPassphrase})
	assert.NotEmpty(t, enrolled.RecoveryCode, "the first enrollment issues the recovery code")
	assert.Equal(t, "passphrase", enrolled.Factor.Factor)
	assert.True(t, s.vaultStatus(t, alice).Unlocked, "the first enrollment opens the session")

	s.lock(t, alice)
	err := s.unlockWith(t, alice, transport.PasswordVaultCredential{Factor: "passphrase", Passphrase: "not the passphrase"})
	requireCode(t, err, ErrCodeUnauthorized)
	require.NoError(t, s.unlockWith(t, alice, transport.PasswordVaultCredential{Factor: "passphrase", Passphrase: vaultPassphrase}))
	assert.False(t, s.status(t, alice).IsLocked)
}

func TestVaultMethods_PasskeyEnrollAndUnlock(t *testing.T) {
	t.Parallel()
	s := newVaultServer(t)
	alice := pwCtx(pwTenantA, pwUserA)
	passkey := pwPasskey(pwUserA)
	s.vaultEnroll(t, alice, passkey)

	var listed bool
	for _, f := range s.vaultStatus(t, alice).Factors {
		if f.Factor == "passkey" {
			listed = true
			assert.Equal(t, passkey.CredentialID, f.CredentialID)
			assert.Equal(t, passkey.PRFSalt, f.PRFSalt)
		}
	}
	assert.True(t, listed)

	s.lock(t, alice)
	wrong := pwPasskey(pwUserA)
	wrong.Secret = make([]byte, 32)
	requireCode(t, s.unlockWith(t, alice, wrong), ErrCodeUnauthorized)
	require.NoError(t, s.unlockWith(t, alice, transport.PasswordVaultCredential{
		Factor: "passkey", CredentialID: passkey.CredentialID, Secret: passkey.Secret,
	}))
}

func TestVaultMethods_EnrollErrors(t *testing.T) {
	t.Parallel()
	s := newVaultServer(t)
	alice := pwCtx(pwTenantA, pwUserA)

	_, err := s.invoke(t, alice, "password.vault.enroll", transport.PasswordVaultCredential{Factor: "passphrase", Passphrase: "short"})
	requireCode(t, err, ErrCodeInvalidParams)

	s.vaultEnroll(t, alice, pwPasskey(pwUserA))
	_, err = s.invoke(t, alice, "password.vault.enroll", pwPasskey(pwUserA))
	requireCode(t, err, sdkssh.JSONRPCCodeDuplicate)

	s.lock(t, alice)
	_, err = s.invoke(t, alice, "password.vault.enroll", pwPasskey("other-key"))
	requireCode(t, err, ErrCodeInternalError)
	assert.ErrorIs(t, err, staticpw.ErrStoreLocked, "a later enrollment needs the session open")
}

func TestVaultMethods_Rotate(t *testing.T) {
	t.Parallel()
	s := newVaultServer(t)
	alice := pwCtx(pwTenantA, pwUserA)
	enrolled := s.vaultEnroll(t, alice, pwPasskey(pwUserA))

	rotated := pwPasskey(pwUserA)
	rotated.Secret = []byte("0123456789abcdef0123456789abcdef")
	result, err := s.invoke(t, alice, "password.vault.rotate", transport.PasswordVaultRotateRequest{
		FactorID: enrolled.Factor.ID, PasswordVaultCredential: rotated,
	})
	require.NoError(t, err)
	current := result.(*transport.PasswordVaultEnrollResponse).Factor.ID

	s.lock(t, alice)
	requireCode(t, s.unlockWith(t, alice, pwPasskey(pwUserA)), ErrCodeUnauthorized)
	require.NoError(t, s.unlockWith(t, alice, rotated))

	_, err = s.invoke(t, alice, "password.vault.rotate", transport.PasswordVaultRotateRequest{FactorID: "no-such-factor", PasswordVaultCredential: rotated})
	requireCode(t, err, sdkssh.JSONRPCCodeNotFound)

	_, err = s.invoke(t, alice, "password.vault.rotate", transport.PasswordVaultRotateRequest{PasswordVaultCredential: rotated})
	requireCode(t, err, ErrCodeInvalidParams)
	assert.ErrorIs(t, err, ErrVaultFactorIDRequired)

	_, err = s.invoke(t, alice, "password.vault.rotate", transport.PasswordVaultRotateRequest{
		FactorID: current, PasswordVaultCredential: transport.PasswordVaultCredential{Factor: "passphrase", Passphrase: vaultPassphrase},
	})
	requireCode(t, err, ErrCodeInvalidParams)
}

func TestVaultMethods_RemoveFactor(t *testing.T) {
	t.Parallel()
	s := newVaultServer(t)
	alice := pwCtx(pwTenantA, pwUserA)
	first := s.vaultEnroll(t, alice, pwPasskey("key-one"))
	second := s.vaultEnroll(t, alice, pwPasskey("key-two"))

	result, err := s.invoke(t, alice, "password.vault.removeFactor", transport.PasswordVaultRemoveFactorRequest{FactorID: second.Factor.ID})
	require.NoError(t, err)
	assert.Equal(t, PasswordVaultRemoveFactorResult{Message: "Vault factor removed"}, result)

	_, err = s.invoke(t, alice, "password.vault.removeFactor", transport.PasswordVaultRemoveFactorRequest{FactorID: first.Factor.ID})
	requireCode(t, err, ErrCodeInternalError)
	assert.ErrorIs(t, err, staticpw.ErrVaultLastFactor)
	_, message := ClientError(err)
	assert.Contains(t, message, "last passphrase or passkey", "a classified refusal tells the caller why")

	_, err = s.invoke(t, alice, "password.vault.removeFactor", transport.PasswordVaultRemoveFactorRequest{FactorID: second.Factor.ID})
	requireCode(t, err, sdkssh.JSONRPCCodeNotFound)

	_, err = s.invoke(t, alice, "password.vault.removeFactor", transport.PasswordVaultRemoveFactorRequest{})
	requireCode(t, err, ErrCodeInvalidParams)
}

func TestVaultMethods_RecoverIsOneTime(t *testing.T) {
	t.Parallel()
	s := newVaultServer(t)
	alice := pwCtx(pwTenantA, pwUserA)
	enrolled := s.vaultEnroll(t, alice, pwPasskey("lost-key"))
	s.lock(t, alice)

	result, err := s.invoke(t, alice, "password.vault.recover", transport.PasswordVaultRecoverRequest{
		RecoveryCode: enrolled.RecoveryCode, PasswordVaultCredential: pwPasskey("new-key"),
	})
	require.NoError(t, err)
	recovered := result.(*transport.PasswordVaultEnrollResponse)
	assert.NotEmpty(t, recovered.RecoveryCode)
	assert.NotEqual(t, enrolled.RecoveryCode, recovered.RecoveryCode)
	assert.True(t, s.vaultStatus(t, alice).Unlocked, "recovery opens the session")

	s.lock(t, alice)
	_, err = s.invoke(t, alice, "password.vault.recover", transport.PasswordVaultRecoverRequest{
		RecoveryCode: enrolled.RecoveryCode, PasswordVaultCredential: pwPasskey("third-key"),
	})
	requireCode(t, err, ErrCodeUnauthorized)

	require.NoError(t, s.unlockWith(t, alice, pwPasskey("new-key")))
}

// One user's vault operations never read or change another user's vault.
func TestVaultMethods_UsersAreIsolated(t *testing.T) {
	t.Parallel()
	s := newVaultServer(t)
	alice, bob := pwCtx(pwTenantA, pwUserA), pwCtx(pwTenantA, pwUserB)
	aliceFactor := s.vaultEnroll(t, alice, pwPasskey(pwUserA))

	assert.False(t, s.vaultStatus(t, bob).Initialized)
	err := s.unlockWith(t, bob, pwPasskey(pwUserA))
	requireCode(t, err, ErrCodeInvalidParams)
	assert.ErrorIs(t, err, staticpw.ErrVaultNotInitialized, "Alice's passkey is not a factor of Bob's vault")

	s.vaultEnroll(t, bob, pwPasskey(pwUserB))
	_, err = s.invoke(t, bob, "password.vault.removeFactor", transport.PasswordVaultRemoveFactorRequest{FactorID: aliceFactor.Factor.ID})
	requireCode(t, err, sdkssh.JSONRPCCodeNotFound)

	assert.False(t, s.vaultStatus(t, pwCtx(pwTenantB, pwUserA)).Initialized, "the same subject in another tenant has its own vault")

	s.lock(t, alice)
	require.NoError(t, s.unlockWith(t, alice, pwPasskey(pwUserA)))
}

// A request without an identity has no personal vault: Method not found.
func TestVaultMethods_NoIdentityIsMethodNotFound(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	ctx := context.Background()

	for _, call := range []struct {
		name string
		fn   func() error
	}{
		{"status", func() error {
			_, err := s.handlePasswordVaultStatus(ctx, pwRPC(t, "password.vault.status", nil))
			return err
		}},
		{"enroll", func() error {
			_, err := s.handlePasswordVaultEnroll(ctx, pwRPC(t, "password.vault.enroll", pwPasskey("x")))
			return err
		}},
		{"rotate", func() error {
			_, err := s.handlePasswordVaultRotate(ctx, pwRPC(t, "password.vault.rotate", transport.PasswordVaultRotateRequest{FactorID: "f"}))
			return err
		}},
		{"removeFactor", func() error {
			_, err := s.handlePasswordVaultRemoveFactor(ctx, pwRPC(t, "password.vault.removeFactor", transport.PasswordVaultRemoveFactorRequest{FactorID: "f"}))
			return err
		}},
		{"recover", func() error {
			_, err := s.handlePasswordVaultRecover(ctx, pwRPC(t, "password.vault.recover", transport.PasswordVaultRecoverRequest{RecoveryCode: "c"}))
			return err
		}},
	} {
		t.Run(call.name, func(t *testing.T) {
			err := call.fn()
			requireCode(t, err, ErrCodeMethodNotFound)
			assert.ErrorIs(t, err, xkms.ErrOperationNotSupported)
		})
	}
}

func TestVaultMethods_NotConfiguredIsServiceUnavailable(t *testing.T) {
	t.Parallel()
	s := &Server{}
	ctx := pwCtx(pwTenantA, pwUserA)

	_, err := s.handlePasswordVaultStatus(ctx, pwRPC(t, "password.vault.status", nil))
	requireCode(t, err, ErrCodeServiceUnavailable)
	_, err = s.handlePasswordVaultEnroll(ctx, pwRPC(t, "password.vault.enroll", pwPasskey("x")))
	requireCode(t, err, ErrCodeServiceUnavailable)
	_, err = s.handlePasswordVaultRotate(ctx, pwRPC(t, "password.vault.rotate", transport.PasswordVaultRotateRequest{FactorID: "f"}))
	requireCode(t, err, ErrCodeServiceUnavailable)
	_, err = s.handlePasswordVaultRemoveFactor(ctx, pwRPC(t, "password.vault.removeFactor", transport.PasswordVaultRemoveFactorRequest{FactorID: "f"}))
	requireCode(t, err, ErrCodeServiceUnavailable)
	_, err = s.handlePasswordVaultRecover(ctx, pwRPC(t, "password.vault.recover", transport.PasswordVaultRecoverRequest{}))
	requireCode(t, err, ErrCodeServiceUnavailable)
}

func TestVaultMethods_SealedTenant(t *testing.T) {
	t.Parallel()
	s := newVaultServer(t)
	require.NoError(t, s.registry.SealTenant(pwTenantA))

	_, err := s.invoke(t, pwCtx(pwTenantA, pwUserA), "password.vault.status", nil)
	requireCode(t, err, ErrCodeInternalError)
	assert.ErrorIs(t, err, seal.ErrTenantSealed)
}

func TestMapPasswordVaultError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		err  error
		code int
	}{
		{staticpw.ErrVaultInvalidCredential, ErrCodeInvalidParams},
		{staticpw.ErrVaultRecoveryFactor, ErrCodeInvalidParams},
		{staticpw.ErrVaultNotInitialized, ErrCodeInvalidParams},
		{staticpw.ErrVaultCredentialRejected, ErrCodeUnauthorized},
		{staticpw.ErrVaultFactorNotFound, sdkssh.JSONRPCCodeNotFound},
		{staticpw.ErrVaultPasskeyExists, sdkssh.JSONRPCCodeDuplicate},
		{staticpw.ErrVaultLastFactor, ErrCodeInternalError},
		{staticpw.ErrStoreLocked, ErrCodeInternalError},
		{xkms.ErrOperationNotSupported, ErrCodeMethodNotFound},
		{seal.ErrTenantNotFound, sdkssh.JSONRPCCodeNotFound},
		{errors.New("boom"), ErrCodeInternalError},
	}
	for _, tc := range cases {
		t.Run(tc.err.Error(), func(t *testing.T) {
			err := mapPasswordVaultError(errors.Join(errors.New("context"), tc.err))
			requireCode(t, err, tc.code)
			assert.ErrorIs(t, err, tc.err)
		})
	}

	t.Run("not configured", func(t *testing.T) {
		err := mapPasswordVaultError(xkms.ErrNotConfigured)
		requireCode(t, err, ErrCodeServiceUnavailable)
		assert.ErrorIs(t, err, ErrPasswordStoreNotConfigured)
	})

	t.Run("a rejected credential says nothing more", func(t *testing.T) {
		err := mapPasswordVaultError(errors.Join(staticpw.ErrVaultCredentialRejected, errors.New("factor f-123 tag mismatch")))
		_, message := ClientError(err)
		assert.NotContains(t, message, "f-123")
	})
}
