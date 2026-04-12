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

package rest

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPINManager implements pin.PINBackend for testing.
type mockPINManager struct {
	strategy       pin.StrategyID
	setSOPINErr    error
	setUserPINErr  error
	changeSOPINErr error
	changeUserErr  error
	verifySOPINErr error
	verifyUserErr  error
	resetErr       error
	lockoutStatus  *pin.LockoutStatus
	initialized    bool
	soPINSet       bool
	userPINSet     bool
}

func (m *mockPINManager) Strategy() pin.StrategyID             { return m.strategy }
func (m *mockPINManager) SetSOPIN(_, _ string) error           { return m.setSOPINErr }
func (m *mockPINManager) SetUserPIN(_, _ string) error         { return m.setUserPINErr }
func (m *mockPINManager) ChangeSOPIN(_, _ string) error        { return m.changeSOPINErr }
func (m *mockPINManager) ChangeUserPIN(_, _ string) error      { return m.changeUserErr }
func (m *mockPINManager) VerifySOPIN(_ string) error           { return m.verifySOPINErr }
func (m *mockPINManager) VerifyUserPIN(_ string) error         { return m.verifyUserErr }
func (m *mockPINManager) GetLockoutStatus() *pin.LockoutStatus { return m.lockoutStatus }
func (m *mockPINManager) ResetLockout(_ string) error          { return m.resetErr }
func (m *mockPINManager) IsInitialized() bool                  { return m.initialized }
func (m *mockPINManager) SOPINSet() bool                       { return m.soPINSet }
func (m *mockPINManager) UserPINSet() bool                     { return m.userPINSet }

// newTestBarrierHandler creates a HandlerContext with a real barrier backed by memory storage.
func newTestBarrierHandler(t *testing.T) (*HandlerContext, *seal.Barrier) {
	t.Helper()

	store := storage.NewMemory()
	strat := seal.NewSoftwareStrategy()

	barrier, err := seal.NewBarrier(
		slog.Default(),
		store,
		seal.BarrierConfig{RootKeyPath: "test-root-key"},
		strat,
	)
	require.NoError(t, err)

	h := NewHandlerContext("test")
	h.SetBarrier(barrier)
	return h, barrier
}

// --- BarrierInitializeHandler ---

func TestBarrierInitializeHandler_Success(t *testing.T) {
	h, _ := newTestBarrierHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/initialize",
		strings.NewReader(`{"secret":"test-secret-123"}`))
	w := httptest.NewRecorder()

	h.BarrierInitializeHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp SuccessResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.Equal(t, "barrier initialized", resp.Message)
}

func TestBarrierInitializeHandler_NilBarrier(t *testing.T) {
	h := NewHandlerContext("test")

	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/initialize",
		strings.NewReader(`{"secret":"test"}`))
	w := httptest.NewRecorder()

	h.BarrierInitializeHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestBarrierInitializeHandler_InvalidJSON(t *testing.T) {
	h, _ := newTestBarrierHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/initialize",
		strings.NewReader(`{invalid`))
	w := httptest.NewRecorder()

	h.BarrierInitializeHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBarrierInitializeHandler_MissingSecret(t *testing.T) {
	h, _ := newTestBarrierHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/initialize",
		strings.NewReader(`{"secret":""}`))
	w := httptest.NewRecorder()

	h.BarrierInitializeHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBarrierInitializeHandler_AlreadyInitialized(t *testing.T) {
	h, barrier := newTestBarrierHandler(t)

	creds := seal.Credentials{Secret: "first"}
	require.NoError(t, barrier.Initialize(context.Background(), creds))

	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/initialize",
		strings.NewReader(`{"secret":"second"}`))
	w := httptest.NewRecorder()

	h.BarrierInitializeHandler(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

// --- BarrierUnsealHandler ---

func TestBarrierUnsealHandler_Success(t *testing.T) {
	h, barrier := newTestBarrierHandler(t)

	creds := seal.Credentials{Secret: "my-secret"}
	require.NoError(t, barrier.Initialize(context.Background(), creds))
	require.NoError(t, barrier.Seal())

	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/unseal",
		strings.NewReader(`{"secret":"my-secret"}`))
	w := httptest.NewRecorder()

	h.BarrierUnsealHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp SuccessResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
}

func TestBarrierUnsealHandler_NilBarrier(t *testing.T) {
	h := NewHandlerContext("test")

	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/unseal",
		strings.NewReader(`{"secret":"test"}`))
	w := httptest.NewRecorder()

	h.BarrierUnsealHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestBarrierUnsealHandler_InvalidJSON(t *testing.T) {
	h, _ := newTestBarrierHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/unseal",
		strings.NewReader(`{bad`))
	w := httptest.NewRecorder()

	h.BarrierUnsealHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBarrierUnsealHandler_MissingSecret(t *testing.T) {
	h, _ := newTestBarrierHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/unseal",
		strings.NewReader(`{"secret":""}`))
	w := httptest.NewRecorder()

	h.BarrierUnsealHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBarrierUnsealHandler_InvalidCredentials(t *testing.T) {
	h, barrier := newTestBarrierHandler(t)

	creds := seal.Credentials{Secret: "correct"}
	require.NoError(t, barrier.Initialize(context.Background(), creds))
	require.NoError(t, barrier.Seal())

	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/unseal",
		strings.NewReader(`{"secret":"wrong"}`))
	w := httptest.NewRecorder()

	h.BarrierUnsealHandler(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code)
}

// --- BarrierSealHandler ---

func TestBarrierSealHandler_Success(t *testing.T) {
	h, barrier := newTestBarrierHandler(t)

	creds := seal.Credentials{Secret: "secret"}
	require.NoError(t, barrier.Initialize(context.Background(), creds))

	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/seal", nil)
	w := httptest.NewRecorder()

	h.BarrierSealHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp SuccessResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
}

func TestBarrierSealHandler_NilBarrier(t *testing.T) {
	h := NewHandlerContext("test")

	req := httptest.NewRequest(http.MethodPost, "/v1/barrier/seal", nil)
	w := httptest.NewRecorder()

	h.BarrierSealHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// --- BarrierStatusHandler ---

func TestBarrierStatusHandler_Success(t *testing.T) {
	h, barrier := newTestBarrierHandler(t)

	creds := seal.Credentials{Secret: "secret"}
	require.NoError(t, barrier.Initialize(context.Background(), creds))

	req := httptest.NewRequest(http.MethodGet, "/v1/barrier/status", nil)
	w := httptest.NewRecorder()

	h.BarrierStatusHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp BarrierStatusResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Sealed)
}

func TestBarrierStatusHandler_NilBarrier(t *testing.T) {
	h := NewHandlerContext("test")

	req := httptest.NewRequest(http.MethodGet, "/v1/barrier/status", nil)
	w := httptest.NewRecorder()

	h.BarrierStatusHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// --- SetSOPINHandler ---

func TestSetSOPINHandler_Success(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin",
		strings.NewReader(`{"current_so_pin":"","new_so_pin":"123456"}`))
	w := httptest.NewRecorder()

	h.SetSOPINHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSetSOPINHandler_NilManager(t *testing.T) {
	h := NewHandlerContext("test")

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin",
		strings.NewReader(`{"new_so_pin":"123456"}`))
	w := httptest.NewRecorder()

	h.SetSOPINHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestSetSOPINHandler_InvalidJSON(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin",
		strings.NewReader(`{bad`))
	w := httptest.NewRecorder()

	h.SetSOPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetSOPINHandler_MissingNewSOPIN(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin",
		strings.NewReader(`{"new_so_pin":""}`))
	w := httptest.NewRecorder()

	h.SetSOPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetSOPINHandler_PINError(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{setSOPINErr: pin.ErrPINTooShort})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin",
		strings.NewReader(`{"new_so_pin":"123456"}`))
	w := httptest.NewRecorder()

	h.SetSOPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- SetUserPINHandler ---

func TestSetUserPINHandler_Success(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin",
		strings.NewReader(`{"so_pin":"654321","new_user_pin":"123456"}`))
	w := httptest.NewRecorder()

	h.SetUserPINHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSetUserPINHandler_NilManager(t *testing.T) {
	h := NewHandlerContext("test")

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin",
		strings.NewReader(`{"so_pin":"654321","new_user_pin":"123456"}`))
	w := httptest.NewRecorder()

	h.SetUserPINHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestSetUserPINHandler_InvalidJSON(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin",
		strings.NewReader(`{bad`))
	w := httptest.NewRecorder()

	h.SetUserPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetUserPINHandler_MissingSOPIN(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin",
		strings.NewReader(`{"so_pin":"","new_user_pin":"123456"}`))
	w := httptest.NewRecorder()

	h.SetUserPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetUserPINHandler_MissingNewPIN(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin",
		strings.NewReader(`{"so_pin":"654321","new_user_pin":""}`))
	w := httptest.NewRecorder()

	h.SetUserPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetUserPINHandler_Error(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{setUserPINErr: pin.ErrSOPINRequired})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin",
		strings.NewReader(`{"so_pin":"wrong","new_user_pin":"123456"}`))
	w := httptest.NewRecorder()

	h.SetUserPINHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- ChangeSOPINHandler ---

func TestChangeSOPINHandler_Success(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin/change",
		strings.NewReader(`{"current_so_pin":"old123","new_so_pin":"new123"}`))
	w := httptest.NewRecorder()

	h.ChangeSOPINHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestChangeSOPINHandler_NilManager(t *testing.T) {
	h := NewHandlerContext("test")

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin/change",
		strings.NewReader(`{"current_so_pin":"old123","new_so_pin":"new123"}`))
	w := httptest.NewRecorder()

	h.ChangeSOPINHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestChangeSOPINHandler_InvalidJSON(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin/change",
		strings.NewReader(`{`))
	w := httptest.NewRecorder()

	h.ChangeSOPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestChangeSOPINHandler_MissingCurrentSOPIN(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin/change",
		strings.NewReader(`{"current_so_pin":"","new_so_pin":"new123"}`))
	w := httptest.NewRecorder()

	h.ChangeSOPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestChangeSOPINHandler_MissingNewSOPIN(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin/change",
		strings.NewReader(`{"current_so_pin":"old123","new_so_pin":""}`))
	w := httptest.NewRecorder()

	h.ChangeSOPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestChangeSOPINHandler_Error(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{changeSOPINErr: pin.ErrInvalidCurrentPIN})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin/change",
		strings.NewReader(`{"current_so_pin":"wrong","new_so_pin":"new123"}`))
	w := httptest.NewRecorder()

	h.ChangeSOPINHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- ChangeUserPINHandler ---

func TestChangeUserPINHandler_Success(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin/change",
		strings.NewReader(`{"current_user_pin":"old123","new_user_pin":"new123"}`))
	w := httptest.NewRecorder()

	h.ChangeUserPINHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestChangeUserPINHandler_NilManager(t *testing.T) {
	h := NewHandlerContext("test")

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin/change",
		strings.NewReader(`{"current_user_pin":"old","new_user_pin":"new"}`))
	w := httptest.NewRecorder()

	h.ChangeUserPINHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestChangeUserPINHandler_InvalidJSON(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin/change",
		strings.NewReader(`{`))
	w := httptest.NewRecorder()

	h.ChangeUserPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestChangeUserPINHandler_MissingCurrentPIN(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin/change",
		strings.NewReader(`{"current_user_pin":"","new_user_pin":"new123"}`))
	w := httptest.NewRecorder()

	h.ChangeUserPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestChangeUserPINHandler_MissingNewPIN(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin/change",
		strings.NewReader(`{"current_user_pin":"old123","new_user_pin":""}`))
	w := httptest.NewRecorder()

	h.ChangeUserPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestChangeUserPINHandler_Error(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{changeUserErr: pin.ErrPINLocked})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin/change",
		strings.NewReader(`{"current_user_pin":"old123","new_user_pin":"new123"}`))
	w := httptest.NewRecorder()

	h.ChangeUserPINHandler(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

// --- VerifySOPINHandler ---

func TestVerifySOPINHandler_Success(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin/verify",
		strings.NewReader(`{"pin":"123456"}`))
	w := httptest.NewRecorder()

	h.VerifySOPINHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestVerifySOPINHandler_NilManager(t *testing.T) {
	h := NewHandlerContext("test")

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin/verify",
		strings.NewReader(`{"pin":"123456"}`))
	w := httptest.NewRecorder()

	h.VerifySOPINHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestVerifySOPINHandler_InvalidJSON(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin/verify",
		strings.NewReader(`{`))
	w := httptest.NewRecorder()

	h.VerifySOPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifySOPINHandler_MissingPIN(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin/verify",
		strings.NewReader(`{"pin":""}`))
	w := httptest.NewRecorder()

	h.VerifySOPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifySOPINHandler_InvalidPIN(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{verifySOPINErr: pin.ErrPINInvalid})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin/verify",
		strings.NewReader(`{"pin":"wrong1"}`))
	w := httptest.NewRecorder()

	h.VerifySOPINHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- VerifyUserPINHandler ---

func TestVerifyUserPINHandler_Success(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin/verify",
		strings.NewReader(`{"pin":"123456"}`))
	w := httptest.NewRecorder()

	h.VerifyUserPINHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestVerifyUserPINHandler_NilManager(t *testing.T) {
	h := NewHandlerContext("test")

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin/verify",
		strings.NewReader(`{"pin":"123456"}`))
	w := httptest.NewRecorder()

	h.VerifyUserPINHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestVerifyUserPINHandler_InvalidJSON(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin/verify",
		strings.NewReader(`{`))
	w := httptest.NewRecorder()

	h.VerifyUserPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyUserPINHandler_MissingPIN(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin/verify",
		strings.NewReader(`{"pin":""}`))
	w := httptest.NewRecorder()

	h.VerifyUserPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyUserPINHandler_Error(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{verifyUserErr: pin.ErrPINNotSet})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin/verify",
		strings.NewReader(`{"pin":"123456"}`))
	w := httptest.NewRecorder()

	h.VerifyUserPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- GetLockoutStatusHandler ---

func TestGetLockoutStatusHandler_Success(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{
		lockoutStatus: &pin.LockoutStatus{
			FailedAttempts: 2,
			MaxAttempts:    10,
			IsLocked:       false,
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/pin/lockout", nil)
	w := httptest.NewRecorder()

	h.GetLockoutStatusHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp LockoutStatusResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.FailedAttempts)
	assert.Equal(t, 10, resp.MaxAttempts)
	assert.False(t, resp.IsLocked)
}

func TestGetLockoutStatusHandler_NilManager(t *testing.T) {
	h := NewHandlerContext("test")

	req := httptest.NewRequest(http.MethodGet, "/v1/pin/lockout", nil)
	w := httptest.NewRecorder()

	h.GetLockoutStatusHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// --- ResetLockoutHandler ---

func TestResetLockoutHandler_Success(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/lockout/reset",
		strings.NewReader(`{"so_pin":"123456"}`))
	w := httptest.NewRecorder()

	h.ResetLockoutHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestResetLockoutHandler_NilManager(t *testing.T) {
	h := NewHandlerContext("test")

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/lockout/reset",
		strings.NewReader(`{"so_pin":"123456"}`))
	w := httptest.NewRecorder()

	h.ResetLockoutHandler(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestResetLockoutHandler_InvalidJSON(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/lockout/reset",
		strings.NewReader(`{`))
	w := httptest.NewRecorder()

	h.ResetLockoutHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResetLockoutHandler_MissingSOPIN(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/lockout/reset",
		strings.NewReader(`{"so_pin":""}`))
	w := httptest.NewRecorder()

	h.ResetLockoutHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResetLockoutHandler_Error(t *testing.T) {
	h := NewHandlerContext("test")
	h.SetPINManager(&mockPINManager{resetErr: pin.ErrPINInvalid})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/lockout/reset",
		strings.NewReader(`{"so_pin":"wrong1"}`))
	w := httptest.NewRecorder()

	h.ResetLockoutHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- handlePINError ---

func TestHandlePINError_AllCases(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"PINNotSet", pin.ErrPINNotSet, http.StatusBadRequest},
		{"PINLocked", pin.ErrPINLocked, http.StatusTooManyRequests},
		{"PINInvalid", pin.ErrPINInvalid, http.StatusUnauthorized},
		{"SOPINRequired", pin.ErrSOPINRequired, http.StatusUnauthorized},
		{"PINTooShort", pin.ErrPINTooShort, http.StatusBadRequest},
		{"PINAlreadySet", pin.ErrPINAlreadySet, http.StatusConflict},
		{"InvalidCurrentPIN", pin.ErrInvalidCurrentPIN, http.StatusUnauthorized},
		{"StateCorrupted", pin.ErrStateCorrupted, http.StatusInternalServerError},
		{"Unknown", errors.New("unknown"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handlePINError(w, tt.err)
			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

// --- handleBarrierError additional coverage ---

func TestHandleBarrierError_AllCases(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"AlreadyInitialized", seal.ErrAlreadyInitialized, http.StatusConflict},
		{"AlreadyUnsealed", seal.ErrAlreadyUnsealed, http.StatusConflict},
		{"NotInitialized", seal.ErrNotInitialized, http.StatusBadRequest},
		{"InvalidCredentials", seal.ErrInvalidCredentials, http.StatusUnauthorized},
		{"Sealed", seal.ErrSealed, http.StatusConflict},
		{"NoAvailableStrategy", seal.ErrNoAvailableStrategy, http.StatusServiceUnavailable},
		{"StrategyNotFound", seal.ErrStrategyNotFound, http.StatusBadRequest},
		{"CorruptRootKey", seal.ErrCorruptRootKey, http.StatusInternalServerError},
		{"ShamirNotConfigured", seal.ErrShamirNotConfigured, http.StatusBadRequest},
		{"ShamirThresholdInvalid", seal.ErrShamirThresholdInvalid, http.StatusBadRequest},
		{"ShamirQuorumIncomplete", seal.ErrShamirQuorumIncomplete, http.StatusUnprocessableEntity},
		{"ShamirQuorumExpired", seal.ErrShamirQuorumExpired, http.StatusGone},
		{"ShamirDuplicateShare", seal.ErrShamirDuplicateShare, http.StatusConflict},
		{"ShamirCombineFailed", seal.ErrShamirCombineFailed, http.StatusInternalServerError},
		{"ShamirShareNotFound", seal.ErrShamirShareNotFound, http.StatusNotFound},
		{"ShamirNoSharesFound", seal.ErrShamirNoSharesFound, http.StatusNotFound},
		{"ShamirVerificationFailed", seal.ErrShamirVerificationFailed, http.StatusInternalServerError},
		{"ShamirStorageFailed", seal.ErrShamirStorageFailed, http.StatusInternalServerError},
		{"RecoveryKeysNotFound", seal.ErrRecoveryKeysNotFound, http.StatusNotFound},
		{"RootTokenVerificationFailed", seal.ErrRootTokenVerificationFailed, http.StatusUnauthorized},
		{"Unknown", errors.New("unknown"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handleBarrierError(w, tt.err)
			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}
