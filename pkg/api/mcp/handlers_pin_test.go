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

// handlers_pin_test.go covers the MCP PIN management methods (SO PIN, user
// PIN, lockout): dispatch registration, the not-configured path taken when no
// qrdbsdk.PINBackend is composed, and the success path against a fake
// PINBackend.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// fakePINBackend is an in-memory qrdbsdk.PINBackend for exercising the PIN
// handlers' success and error paths without a real go-qrdb node. Embedding
// the interface satisfies its full method set; only the methods under test
// are overridden.
type fakePINBackend struct {
	qrdbsdk.PINBackend

	soPin, userPin string
	err            error
	lockoutStatus  *qrdbsdk.PINLockoutStatus
}

func (f *fakePINBackend) SetSOPIN(_, newPin string) error {
	if f.err != nil {
		return f.err
	}
	f.soPin = newPin
	return nil
}

func (f *fakePINBackend) SetUserPIN(_, newPin string) error {
	if f.err != nil {
		return f.err
	}
	f.userPin = newPin
	return nil
}

func (f *fakePINBackend) ChangeSOPIN(_, newPin string) error {
	if f.err != nil {
		return f.err
	}
	f.soPin = newPin
	return nil
}

func (f *fakePINBackend) ChangeUserPIN(_, newPin string) error {
	if f.err != nil {
		return f.err
	}
	f.userPin = newPin
	return nil
}

func (f *fakePINBackend) VerifySOPIN(pin string) error {
	if f.err != nil {
		return f.err
	}
	if pin != f.soPin {
		return qrdbsdk.ErrPINInvalid
	}
	return nil
}

func (f *fakePINBackend) VerifyUserPIN(pin string) error {
	if f.err != nil {
		return f.err
	}
	if pin != f.userPin {
		return qrdbsdk.ErrPINInvalid
	}
	return nil
}

func (f *fakePINBackend) GetLockoutStatus() *qrdbsdk.PINLockoutStatus {
	if f.lockoutStatus != nil {
		return f.lockoutStatus
	}
	return &qrdbsdk.PINLockoutStatus{MaxAttempts: 3}
}

func (f *fakePINBackend) ResetLockout(soPin string) error {
	if f.err != nil {
		return f.err
	}
	if soPin != f.soPin {
		return qrdbsdk.ErrPINInvalid
	}
	return nil
}

// newPINServer returns an MCP server backed by the standard test XKMS
// service, optionally composed with a PIN backend.
func newPINServer(t *testing.T, pin qrdbsdk.PINBackend) *Server {
	t.Helper()

	svc := setupTestXKMS(t)
	t.Cleanup(cleanupXKMS)
	if pin != nil {
		svc.SetPINManager(pin)
	}

	server, err := NewServer(&Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
	})
	require.NoError(t, err)
	return server
}

// pinRequest builds a JSON-RPC request with the given params object.
func pinRequest(t *testing.T, method string, params interface{}) *JSONRPCRequest {
	t.Helper()

	raw, err := json.Marshal(params)
	require.NoError(t, err)

	return &JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: raw, ID: 1}
}

// TestPINMethods_Dispatchable proves every PIN method is reachable through
// the dispatch table, and via authz's public/mapped gate.
func TestPINMethods_Dispatchable(t *testing.T) {
	for _, method := range []string{
		"xkms.setSOPIN", "xkms.setUserPIN", "xkms.changeSOPIN", "xkms.changeUserPIN",
		"xkms.verifySOPIN", "xkms.verifyUserPIN", "xkms.getLockoutStatus", "xkms.resetLockout",
	} {
		entry, ok := rpcMethods[method]
		assert.True(t, ok, "method %q must be dispatchable", method)
		assert.False(t, entry.public(), "method %q must carry a permission mapping", method)
	}
}

func TestHandleSetSOPIN_NotConfigured(t *testing.T) {
	server := newPINServer(t, nil)

	_, err := server.handleSetSOPIN(context.Background(),
		pinRequest(t, "xkms.setSOPIN", transport.SetSOPINRequest{NewSOPIN: "123456"}))

	require.Error(t, err, "a service with no PIN backend must report failure, not panic")
}

func TestHandleSetSOPIN_Success(t *testing.T) {
	pin := &fakePINBackend{}
	server := newPINServer(t, pin)

	result, err := server.handleSetSOPIN(context.Background(),
		pinRequest(t, "xkms.setSOPIN", transport.SetSOPINRequest{NewSOPIN: "123456"}))

	require.NoError(t, err)
	assert.Equal(t, pinSuccess, result)
	assert.Equal(t, "123456", pin.soPin)
}

func TestHandleSetSOPIN_InvalidParams(t *testing.T) {
	server := newPINServer(t, &fakePINBackend{})

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.setSOPIN", Params: json.RawMessage(`{`), ID: 1}
	_, err := server.handleSetSOPIN(context.Background(), req)

	require.Error(t, err)
	var keyOpErr *KeyOpError
	require.True(t, errors.As(err, &keyOpErr), "decode failure must be a *KeyOpError")
	assert.Equal(t, ErrCodeInvalidParams, keyOpErr.Code)
}

func TestHandleSetUserPIN_Success(t *testing.T) {
	pin := &fakePINBackend{soPin: "123456"}
	server := newPINServer(t, pin)

	result, err := server.handleSetUserPIN(context.Background(),
		pinRequest(t, "xkms.setUserPIN", transport.SetUserPINRequest{SOPIN: "123456", NewUserPIN: "654321"}))

	require.NoError(t, err)
	assert.Equal(t, pinSuccess, result)
	assert.Equal(t, "654321", pin.userPin)
}

func TestHandleSetUserPIN_NotConfigured(t *testing.T) {
	server := newPINServer(t, nil)

	_, err := server.handleSetUserPIN(context.Background(),
		pinRequest(t, "xkms.setUserPIN", transport.SetUserPINRequest{SOPIN: "123456", NewUserPIN: "654321"}))

	require.Error(t, err)
}

func TestHandleChangeSOPIN_Success(t *testing.T) {
	pin := &fakePINBackend{soPin: "111111"}
	server := newPINServer(t, pin)

	result, err := server.handleChangeSOPIN(context.Background(),
		pinRequest(t, "xkms.changeSOPIN", transport.ChangeSOPINRequest{CurrentSOPIN: "111111", NewSOPIN: "222222"}))

	require.NoError(t, err)
	assert.Equal(t, pinSuccess, result)
	assert.Equal(t, "222222", pin.soPin)
}

func TestHandleChangeSOPIN_NotConfigured(t *testing.T) {
	server := newPINServer(t, nil)

	_, err := server.handleChangeSOPIN(context.Background(),
		pinRequest(t, "xkms.changeSOPIN", transport.ChangeSOPINRequest{CurrentSOPIN: "111111", NewSOPIN: "222222"}))

	require.Error(t, err)
}

func TestHandleChangeUserPIN_Success(t *testing.T) {
	pin := &fakePINBackend{userPin: "111111"}
	server := newPINServer(t, pin)

	result, err := server.handleChangeUserPIN(context.Background(),
		pinRequest(t, "xkms.changeUserPIN", transport.ChangeUserPINRequest{CurrentUserPIN: "111111", NewUserPIN: "222222"}))

	require.NoError(t, err)
	assert.Equal(t, pinSuccess, result)
	assert.Equal(t, "222222", pin.userPin)
}

func TestHandleChangeUserPIN_NotConfigured(t *testing.T) {
	server := newPINServer(t, nil)

	_, err := server.handleChangeUserPIN(context.Background(),
		pinRequest(t, "xkms.changeUserPIN", transport.ChangeUserPINRequest{CurrentUserPIN: "111111", NewUserPIN: "222222"}))

	require.Error(t, err)
}

func TestHandleVerifySOPIN_Success(t *testing.T) {
	pin := &fakePINBackend{soPin: "123456"}
	server := newPINServer(t, pin)

	result, err := server.handleVerifySOPIN(context.Background(),
		pinRequest(t, "xkms.verifySOPIN", transport.VerifySOPINRequest{SOPIN: "123456"}))

	require.NoError(t, err)
	assert.Equal(t, pinSuccess, result)
}

func TestHandleVerifySOPIN_WrongPIN(t *testing.T) {
	pin := &fakePINBackend{soPin: "123456"}
	server := newPINServer(t, pin)

	_, err := server.handleVerifySOPIN(context.Background(),
		pinRequest(t, "xkms.verifySOPIN", transport.VerifySOPINRequest{SOPIN: "000000"}))

	require.Error(t, err)
	assert.True(t, errors.Is(err, qrdbsdk.ErrPINInvalid))
}

func TestHandleVerifyUserPIN_Success(t *testing.T) {
	pin := &fakePINBackend{userPin: "123456"}
	server := newPINServer(t, pin)

	result, err := server.handleVerifyUserPIN(context.Background(),
		pinRequest(t, "xkms.verifyUserPIN", transport.VerifyUserPINRequest{UserPIN: "123456"}))

	require.NoError(t, err)
	assert.Equal(t, pinSuccess, result)
}

func TestHandleVerifyUserPIN_WrongPIN(t *testing.T) {
	pin := &fakePINBackend{userPin: "123456"}
	server := newPINServer(t, pin)

	_, err := server.handleVerifyUserPIN(context.Background(),
		pinRequest(t, "xkms.verifyUserPIN", transport.VerifyUserPINRequest{UserPIN: "000000"}))

	require.Error(t, err)
	assert.True(t, errors.Is(err, qrdbsdk.ErrPINInvalid))
}

func TestHandleGetLockoutStatus_Success(t *testing.T) {
	pin := &fakePINBackend{lockoutStatus: &qrdbsdk.PINLockoutStatus{
		FailedAttempts: 2, MaxAttempts: 3, IsLocked: false, RecoverySeconds: 30,
	}}
	server := newPINServer(t, pin)

	result, err := server.handleGetLockoutStatus(context.Background(),
		pinRequest(t, "xkms.getLockoutStatus", struct{}{}))

	require.NoError(t, err)
	status, ok := result.(*transport.LockoutStatusResponse)
	require.True(t, ok, "result must be *transport.LockoutStatusResponse, got %T", result)
	assert.Equal(t, 2, status.FailedAttempts)
	assert.Equal(t, 3, status.MaxAttempts)
	assert.False(t, status.IsLocked)
}

func TestHandleGetLockoutStatus_NotConfigured(t *testing.T) {
	server := newPINServer(t, nil)

	_, err := server.handleGetLockoutStatus(context.Background(),
		pinRequest(t, "xkms.getLockoutStatus", struct{}{}))

	require.Error(t, err)
}

func TestHandleResetLockout_Success(t *testing.T) {
	pin := &fakePINBackend{soPin: "123456"}
	server := newPINServer(t, pin)

	result, err := server.handleResetLockout(context.Background(),
		pinRequest(t, "xkms.resetLockout", transport.ResetLockoutRequest{SOPIN: "123456"}))

	require.NoError(t, err)
	assert.Equal(t, pinSuccess, result)
}

func TestHandleResetLockout_WrongSOPIN(t *testing.T) {
	pin := &fakePINBackend{soPin: "123456"}
	server := newPINServer(t, pin)

	_, err := server.handleResetLockout(context.Background(),
		pinRequest(t, "xkms.resetLockout", transport.ResetLockoutRequest{SOPIN: "000000"}))

	require.Error(t, err)
	assert.True(t, errors.Is(err, qrdbsdk.ErrPINInvalid))
}
