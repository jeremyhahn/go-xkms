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
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// unlockTestUserPIN is the PIN the stub PIN backend treats as correct.
const unlockTestUserPIN = "123456"

// stubPINBackend is a minimal qrdbsdk.PINBackend used to drive
// XKMSService.PasswordStoreUnlock's real credential check. Only the three
// methods the unlock path uses carry behaviour; the rest satisfy the
// interface.
type stubPINBackend struct {
	// userPIN is the provisioned user PIN. An empty value models a deployment
	// with no user PIN set.
	userPIN string

	// verifyCalls counts VerifyUserPIN invocations, proving the unlock path
	// actually reached the credential check.
	verifyCalls int
}

func (b *stubPINBackend) UserPINSet() bool { return b.userPIN != "" }

func (b *stubPINBackend) VerifyUserPIN(pin string) error {
	b.verifyCalls++
	if pin != b.userPIN {
		return errors.New("pin: verification failed, 2 attempts remaining")
	}
	return nil
}

func (b *stubPINBackend) Strategy() qrdbsdk.PINStrategyID             { return "software" }
func (b *stubPINBackend) SetSOPIN(_, _ string) error                  { return nil }
func (b *stubPINBackend) SetUserPIN(_, _ string) error                { return nil }
func (b *stubPINBackend) ChangeSOPIN(_, _ string) error               { return nil }
func (b *stubPINBackend) ChangeUserPIN(_, _ string) error             { return nil }
func (b *stubPINBackend) VerifySOPIN(_ string) error                  { return nil }
func (b *stubPINBackend) IsInitialized() bool                         { return true }
func (b *stubPINBackend) SOPINSet() bool                              { return true }
func (b *stubPINBackend) GetLockoutStatus() *qrdbsdk.PINLockoutStatus { return nil }
func (b *stubPINBackend) ResetLockout(_ string) error                 { return nil }

// unlockTestManager builds a TenantPasswordStoreManager over a registry with
// tenants registered, initialized, and therefore genuinely unlockable, so a
// successful unlock is observable rather than masked by a missing tenant.
func unlockTestManager(t *testing.T) *staticpw.TenantPasswordStoreManager {
	t.Helper()
	_, _, manager := passwordTestRegistry(t)
	return manager
}

// setupUnlockServer builds an MCP server over a real XKMS service wired with
// a tenant password store manager and a PIN backend, so the unlock path
// exercises the genuine service-layer credential check rather than a stub
// servicer.
func setupUnlockServer(t *testing.T, provisionedPIN string) (*Server, *stubPINBackend) {
	t.Helper()
	s := newPasswordServer(t, provisionedPIN)
	return s.Server, s.pin
}

// tenantCtx returns a context carrying an authenticated tenant identity.
func tenantCtx() context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "test-user",
		TenantID: "tenant-1",
	})
}

// unlockRPC builds a password.unlock JSON-RPC request with the given params.
func unlockRPC(t *testing.T, params interface{}) *JSONRPCRequest {
	t.Helper()
	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.unlock", ID: 1}
	if params != nil {
		raw, err := json.Marshal(params)
		require.NoError(t, err)
		req.Params = raw
	}
	return req
}

// TestMCPPasswordUnlock_NoPINIsRejected is the regression test for the unlock
// bypass: the handler used to call TenantPasswordStoreManager.UnlockTenant
// directly, so any authenticated tenant user could open the tenant password
// store with no credential whatsoever. The handler must now route through the
// service layer, which requires the user PIN.
func TestMCPPasswordUnlock_NoPINIsRejected(t *testing.T) {
	server, pinBackend := setupUnlockServer(t, unlockTestUserPIN)

	// No params at all: an unlock attempt carrying no PIN.
	_, err := server.handlePasswordUnlock(tenantCtx(), unlockRPC(t, nil))

	require.Error(t, err)
	assert.ErrorIs(t, err, xkms.ErrPasswordStoreUserPINRequired)
	assert.Zero(t, pinBackend.verifyCalls, "no PIN was supplied, so nothing should have been verified")

	var keyOpErr *KeyOpError
	require.ErrorAs(t, err, &keyOpErr)
	assert.Equal(t, ErrCodeInvalidParams, keyOpErr.Code)
}

// TestMCPPasswordUnlock_WrongPINIsRejected proves a bad PIN reaches the
// credential check, is rejected, and does not leak the PIN backend's message,
// which can carry retry counters and lockout state.
func TestMCPPasswordUnlock_WrongPINIsRejected(t *testing.T) {
	server, pinBackend := setupUnlockServer(t, unlockTestUserPIN)

	_, err := server.handlePasswordUnlock(tenantCtx(), unlockRPC(t, map[string]string{
		"user_pin": "999999",
	}))

	require.Error(t, err)
	assert.Equal(t, 1, pinBackend.verifyCalls, "the wrong PIN must still reach the credential check")
	assert.NotContains(t, err.Error(), "attempts remaining")

	var keyOpErr *KeyOpError
	require.ErrorAs(t, err, &keyOpErr)
	assert.Equal(t, ErrCodeInvalidParams, keyOpErr.Code)
}

// TestMCPPasswordUnlock_UnprovisionedPINIsRejected proves a deployment with no
// user PIN reports the condition instead of unlocking without a credential.
func TestMCPPasswordUnlock_UnprovisionedPINIsRejected(t *testing.T) {
	server, pinBackend := setupUnlockServer(t, "")

	_, err := server.handlePasswordUnlock(tenantCtx(), unlockRPC(t, map[string]string{
		"user_pin": unlockTestUserPIN,
	}))

	require.Error(t, err)
	assert.ErrorIs(t, err, xkms.ErrPasswordStoreUserPINNotProvisioned)
	assert.Zero(t, pinBackend.verifyCalls, "there is no provisioned PIN to verify against")
}

// TestMCPPasswordUnlock_CorrectPINUnlocks proves the credential check is a gate
// and not a blanket denial: the right PIN still opens the store.
func TestMCPPasswordUnlock_CorrectPINUnlocks(t *testing.T) {
	server, pinBackend := setupUnlockServer(t, unlockTestUserPIN)

	result, err := server.handlePasswordUnlock(tenantCtx(), unlockRPC(t, map[string]string{
		"user_pin": unlockTestUserPIN,
	}))

	require.NoError(t, err)
	assert.Equal(t, 1, pinBackend.verifyCalls)

	status, ok := result.(PasswordStoreStatusResult)
	require.True(t, ok)
	assert.True(t, status.Available)
	assert.False(t, status.IsLocked)
}

// TestMapPasswordUnlockError covers the JSON-RPC code selected for each unlock
// outcome, so a rejection is never collapsed into a generic internal error that
// looks the same as a crash.
func TestMapPasswordUnlockError(t *testing.T) {
	t.Run("nil is nil", func(t *testing.T) {
		assert.NoError(t, mapPasswordUnlockError(nil))
	})

	cases := []struct {
		name string
		err  error
		want int
	}{
		{"missing PIN", xkms.ErrPasswordStoreUserPINRequired, ErrCodeInvalidParams},
		{"unprovisioned PIN", xkms.ErrPasswordStoreUserPINNotProvisioned, ErrCodeInvalidParams},
		{"not configured", xkms.ErrNotConfigured, ErrCodeServiceUnavailable},
		{"no system barrier", staticpw.ErrNoSystemBarrier, ErrCodeServiceUnavailable},
		{"operation not supported", xkms.ErrOperationNotSupported, ErrCodeMethodNotFound},
		{"nil request", xkms.ErrNilRequest, ErrCodeInvalidParams},
		{"invalid user", staticpw.ErrInvalidUserID, ErrCodeInvalidParams},
		{"already unlocked", staticpw.ErrStoreNotLocked, ErrCodeInternalError},
		{"tenant sealed", seal.ErrTenantSealed, ErrCodeInternalError},
		{"tenant not found", seal.ErrTenantNotFound, sdkssh.JSONRPCCodeNotFound},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapPasswordUnlockError(tc.err)
			require.Error(t, got)

			var keyOpErr *KeyOpError
			require.ErrorAs(t, got, &keyOpErr)
			assert.Equal(t, tc.want, keyOpErr.Code)
		})
	}

	t.Run("wrong PIN does not leak backend detail", func(t *testing.T) {
		got := mapPasswordUnlockError(errors.New("pin: verification failed, 2 attempts remaining"))
		require.Error(t, got)

		var keyOpErr *KeyOpError
		require.ErrorAs(t, got, &keyOpErr)
		assert.Equal(t, ErrCodeInvalidParams, keyOpErr.Code)
		assert.NotContains(t, got.Error(), "attempts remaining",
			"retry counters and lockout state must not reach the caller")
	})
}

// TestMCPPasswordUnlock_MalformedParamsRejected proves params that are present
// but not decodable are a client error rather than a silent PIN-less unlock.
func TestMCPPasswordUnlock_MalformedParamsRejected(t *testing.T) {
	server, pinBackend := setupUnlockServer(t, unlockTestUserPIN)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "password.unlock", ID: 1}
	req.Params = json.RawMessage(`{"user_pin":`)

	_, err := server.handlePasswordUnlock(tenantCtx(), req)

	require.Error(t, err)
	assert.Zero(t, pinBackend.verifyCalls, "malformed params must be rejected before the credential check")
}
