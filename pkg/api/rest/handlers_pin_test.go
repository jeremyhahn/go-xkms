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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPINManager implements qrdbsdk.PINBackend for testing.
type mockPINManager struct {
	strategy       qrdbsdk.PINStrategyID
	setSOPINErr    error
	setUserPINErr  error
	changeSOPINErr error
	changeUserErr  error
	verifySOPINErr error
	verifyUserErr  error
	resetErr       error
	lockoutStatus  *qrdbsdk.PINLockoutStatus
	initialized    bool
	soPINSet       bool
	userPINSet     bool
}

func (m *mockPINManager) Strategy() qrdbsdk.PINStrategyID             { return m.strategy }
func (m *mockPINManager) SetSOPIN(_, _ string) error                  { return m.setSOPINErr }
func (m *mockPINManager) SetUserPIN(_, _ string) error                { return m.setUserPINErr }
func (m *mockPINManager) ChangeSOPIN(_, _ string) error               { return m.changeSOPINErr }
func (m *mockPINManager) ChangeUserPIN(_, _ string) error             { return m.changeUserErr }
func (m *mockPINManager) VerifySOPIN(_ string) error                  { return m.verifySOPINErr }
func (m *mockPINManager) VerifyUserPIN(_ string) error                { return m.verifyUserErr }
func (m *mockPINManager) GetLockoutStatus() *qrdbsdk.PINLockoutStatus { return m.lockoutStatus }
func (m *mockPINManager) ResetLockout(_ string) error                 { return m.resetErr }
func (m *mockPINManager) IsInitialized() bool                         { return m.initialized }
func (m *mockPINManager) SOPINSet() bool                              { return m.soPINSet }
func (m *mockPINManager) UserPINSet() bool                            { return m.userPINSet }

// handlerOverPINManager returns a HandlerContext over an XKMSService composed
// with pm: the PIN handlers reach the PIN backend only through the service,
// which enforces its platform scope.
func handlerOverPINManager(pm qrdbsdk.PINBackend) *HandlerContext {
	svc := &xkms.XKMSService{}
	svc.SetPINManager(pm)
	h := NewHandlerContext("test")
	h.SetXKMSService(svc)
	return h
}

// --- SetSOPINHandler ---

func TestSetSOPINHandler_Success(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{})

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
	h := handlerOverPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin",
		strings.NewReader(`{bad`))
	w := httptest.NewRecorder()

	h.SetSOPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetSOPINHandler_MissingNewSOPIN(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin",
		strings.NewReader(`{"new_so_pin":""}`))
	w := httptest.NewRecorder()

	h.SetSOPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetSOPINHandler_PINError(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{setSOPINErr: qrdbsdk.ErrPINTooShort})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin",
		strings.NewReader(`{"new_so_pin":"123456"}`))
	w := httptest.NewRecorder()

	h.SetSOPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- SetUserPINHandler ---

func TestSetUserPINHandler_Success(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{})

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
	h := handlerOverPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin",
		strings.NewReader(`{bad`))
	w := httptest.NewRecorder()

	h.SetUserPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetUserPINHandler_MissingSOPIN(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin",
		strings.NewReader(`{"so_pin":"","new_user_pin":"123456"}`))
	w := httptest.NewRecorder()

	h.SetUserPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetUserPINHandler_MissingNewPIN(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin",
		strings.NewReader(`{"so_pin":"654321","new_user_pin":""}`))
	w := httptest.NewRecorder()

	h.SetUserPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetUserPINHandler_Error(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{setUserPINErr: qrdbsdk.ErrSOPINRequired})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin",
		strings.NewReader(`{"so_pin":"wrong","new_user_pin":"123456"}`))
	w := httptest.NewRecorder()

	h.SetUserPINHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- ChangeSOPINHandler ---

func TestChangeSOPINHandler_Success(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{})

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
	h := handlerOverPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin/change",
		strings.NewReader(`{`))
	w := httptest.NewRecorder()

	h.ChangeSOPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestChangeSOPINHandler_MissingCurrentSOPIN(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin/change",
		strings.NewReader(`{"current_so_pin":"","new_so_pin":"new123"}`))
	w := httptest.NewRecorder()

	h.ChangeSOPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestChangeSOPINHandler_MissingNewSOPIN(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin/change",
		strings.NewReader(`{"current_so_pin":"old123","new_so_pin":""}`))
	w := httptest.NewRecorder()

	h.ChangeSOPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestChangeSOPINHandler_Error(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{changeSOPINErr: qrdbsdk.ErrInvalidCurrentPIN})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin/change",
		strings.NewReader(`{"current_so_pin":"wrong","new_so_pin":"new123"}`))
	w := httptest.NewRecorder()

	h.ChangeSOPINHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- ChangeUserPINHandler ---

func TestChangeUserPINHandler_Success(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{})

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
	h := handlerOverPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin/change",
		strings.NewReader(`{`))
	w := httptest.NewRecorder()

	h.ChangeUserPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestChangeUserPINHandler_MissingCurrentPIN(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin/change",
		strings.NewReader(`{"current_user_pin":"","new_user_pin":"new123"}`))
	w := httptest.NewRecorder()

	h.ChangeUserPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestChangeUserPINHandler_MissingNewPIN(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin/change",
		strings.NewReader(`{"current_user_pin":"old123","new_user_pin":""}`))
	w := httptest.NewRecorder()

	h.ChangeUserPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestChangeUserPINHandler_Error(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{changeUserErr: qrdbsdk.ErrPINLocked})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin/change",
		strings.NewReader(`{"current_user_pin":"old123","new_user_pin":"new123"}`))
	w := httptest.NewRecorder()

	h.ChangeUserPINHandler(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

// --- VerifySOPINHandler ---

func TestVerifySOPINHandler_Success(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{})

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
	h := handlerOverPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin/verify",
		strings.NewReader(`{`))
	w := httptest.NewRecorder()

	h.VerifySOPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifySOPINHandler_MissingPIN(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin/verify",
		strings.NewReader(`{"pin":""}`))
	w := httptest.NewRecorder()

	h.VerifySOPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifySOPINHandler_InvalidPIN(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{verifySOPINErr: qrdbsdk.ErrPINInvalid})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/so-pin/verify",
		strings.NewReader(`{"pin":"wrong1"}`))
	w := httptest.NewRecorder()

	h.VerifySOPINHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- VerifyUserPINHandler ---

func TestVerifyUserPINHandler_Success(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{})

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
	h := handlerOverPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin/verify",
		strings.NewReader(`{`))
	w := httptest.NewRecorder()

	h.VerifyUserPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyUserPINHandler_MissingPIN(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin/verify",
		strings.NewReader(`{"pin":""}`))
	w := httptest.NewRecorder()

	h.VerifyUserPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestVerifyUserPINHandler_Error(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{verifyUserErr: qrdbsdk.ErrPINNotSet})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/user-pin/verify",
		strings.NewReader(`{"pin":"123456"}`))
	w := httptest.NewRecorder()

	h.VerifyUserPINHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- GetLockoutStatusHandler ---

func TestGetLockoutStatusHandler_Success(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{
		lockoutStatus: &qrdbsdk.PINLockoutStatus{
			FailedAttempts: 2,
			MaxAttempts:    10,
			IsLocked:       false,
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/pin/lockout", nil)
	w := httptest.NewRecorder()

	h.GetLockoutStatusHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp transport.LockoutStatusResponse
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
	h := handlerOverPINManager(&mockPINManager{})

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
	h := handlerOverPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/lockout/reset",
		strings.NewReader(`{`))
	w := httptest.NewRecorder()

	h.ResetLockoutHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResetLockoutHandler_MissingSOPIN(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{})

	req := httptest.NewRequest(http.MethodPost, "/v1/pin/lockout/reset",
		strings.NewReader(`{"so_pin":""}`))
	w := httptest.NewRecorder()

	h.ResetLockoutHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestResetLockoutHandler_Error(t *testing.T) {
	h := handlerOverPINManager(&mockPINManager{resetErr: qrdbsdk.ErrPINInvalid})

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
		{"PINNotSet", qrdbsdk.ErrPINNotSet, http.StatusBadRequest},
		{"PINLocked", qrdbsdk.ErrPINLocked, http.StatusTooManyRequests},
		{"PINInvalid", qrdbsdk.ErrPINInvalid, http.StatusUnauthorized},
		{"SOPINRequired", qrdbsdk.ErrSOPINRequired, http.StatusUnauthorized},
		{"PINTooShort", qrdbsdk.ErrPINTooShort, http.StatusBadRequest},
		{"PINAlreadySet", qrdbsdk.ErrPINAlreadySet, http.StatusConflict},
		{"InvalidCurrentPIN", qrdbsdk.ErrInvalidCurrentPIN, http.StatusUnauthorized},
		{"StateCorrupted", qrdbsdk.ErrPINStateCorrupted, http.StatusInternalServerError},
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
