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

package mcp

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// password.unlock opens the caller's session with one of the caller's own
// vault factors, through a real XKMSService (newPasswordServer).

// TestMCPPasswordUnlock_NoCredentialIsRejected is the regression test for the
// unlock bypass: the handler used to call the store manager directly, so any
// authenticated tenant user could open the password store with no credential
// whatsoever. Absent params are an unlock attempt with no credential.
func TestMCPPasswordUnlock_NoCredentialIsRejected(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	alice := pwCtx(pwTenantA, pwUserA)
	s.unlock(t, alice)
	s.lock(t, alice)

	_, err := s.handlePasswordUnlock(alice, pwRPC(t, "password.unlock", nil))

	requireCode(t, err, ErrCodeInvalidParams)
	assert.ErrorIs(t, err, staticpw.ErrVaultInvalidCredential)
	assert.True(t, s.status(t, alice).IsLocked)
}

// TestMCPPasswordUnlock_WrongCredentialIsRejected proves a credential that
// unwraps no factor is Unauthorized and leaves the session locked.
func TestMCPPasswordUnlock_WrongCredentialIsRejected(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	alice := pwCtx(pwTenantA, pwUserA)
	s.unlock(t, alice)
	s.lock(t, alice)

	wrong := pwPasskey(pwUserA)
	wrong.Secret = make([]byte, 32)
	_, err := s.handlePasswordUnlock(alice, pwRPC(t, "password.unlock", wrong))

	requireCode(t, err, ErrCodeUnauthorized)
	assert.ErrorIs(t, err, staticpw.ErrVaultCredentialRejected)
	assert.True(t, s.status(t, alice).IsLocked)
}

// TestMCPPasswordUnlock_NoFactorEnrolled proves a user with no vault factor
// is told to enroll rather than unlocking without a credential.
func TestMCPPasswordUnlock_NoFactorEnrolled(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)

	_, err := s.handlePasswordUnlock(pwCtx(pwTenantA, pwUserA), pwRPC(t, "password.unlock", pwPasskey(pwUserA)))

	requireCode(t, err, ErrCodeInvalidParams)
	assert.ErrorIs(t, err, staticpw.ErrVaultNotInitialized)
}

// TestMCPPasswordUnlock_CorrectCredentialUnlocks proves the credential check
// is a gate and not a blanket denial: the enrolled passkey opens the session.
func TestMCPPasswordUnlock_CorrectCredentialUnlocks(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	alice := pwCtx(pwTenantA, pwUserA)
	s.unlock(t, alice)
	s.lock(t, alice)

	result, err := s.handlePasswordUnlock(alice, pwRPC(t, "password.unlock", pwPasskey(pwUserA)))

	require.NoError(t, err)
	status, ok := result.(PasswordStoreStatusResult)
	require.True(t, ok)
	assert.True(t, status.Available)
	assert.False(t, status.IsLocked)
}

// TestMCPPasswordUnlock_MalformedParamsRejected proves params that are present
// but not decodable are a client error rather than a credential-less unlock.
func TestMCPPasswordUnlock_MalformedParamsRejected(t *testing.T) {
	t.Parallel()
	s := newPasswordServer(t)
	alice := pwCtx(pwTenantA, pwUserA)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.unlock", ID: 1, Params: json.RawMessage(`{"factor":`)}
	_, err := s.handlePasswordUnlock(alice, req)

	requireCode(t, err, ErrCodeInvalidParams)
	assert.True(t, s.status(t, alice).IsLocked)
}

// TestMapPasswordUnlockError covers the JSON-RPC code selected for each unlock
// outcome, so a rejection is never collapsed into a generic internal error that
// looks the same as a crash.
func TestMapPasswordUnlockError(t *testing.T) {
	t.Parallel()
	assert.NoError(t, mapPasswordUnlockError(nil))

	cases := []struct {
		name string
		err  error
		want int
	}{
		{"invalid credential", staticpw.ErrVaultInvalidCredential, ErrCodeInvalidParams},
		{"recovery code", staticpw.ErrVaultRecoveryFactor, ErrCodeInvalidParams},
		{"no factor enrolled", staticpw.ErrVaultNotInitialized, ErrCodeInvalidParams},
		{"credential rejected", staticpw.ErrVaultCredentialRejected, ErrCodeUnauthorized},
		{"operation not supported", xkms.ErrOperationNotSupported, ErrCodeMethodNotFound},
		{"nil request", xkms.ErrNilRequest, ErrCodeInvalidParams},
		{"invalid user", staticpw.ErrInvalidUserID, ErrCodeInvalidParams},
		{"already unlocked", staticpw.ErrStoreNotLocked, ErrCodeInternalError},
		{"tenant sealed", seal.ErrTenantSealed, ErrCodeInternalError},
		{"tenant not found", seal.ErrTenantNotFound, sdkssh.JSONRPCCodeNotFound},
		{"unclassified", errors.New("boom"), ErrCodeInternalError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapPasswordUnlockError(errors.Join(errors.New("context"), tc.err))
			var keyOpErr *KeyOpError
			require.ErrorAs(t, got, &keyOpErr)
			assert.Equal(t, tc.want, keyOpErr.Code)
			assert.ErrorIs(t, got, tc.err)
		})
	}

	// A store that is not wired reports the one not-configured error.
	for _, err := range []error{xkms.ErrNotConfigured, staticpw.ErrNotConfigured} {
		got := mapPasswordUnlockError(err)
		requireCode(t, got, ErrCodeServiceUnavailable)
		assert.ErrorIs(t, got, ErrPasswordStoreNotConfigured)
	}
}
