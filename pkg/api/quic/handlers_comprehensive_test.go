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

package quic

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createBarrierTestServer creates a server with an initialized barrier.
func createBarrierTestServer(t *testing.T) *Server {
	t.Helper()
	server, _ := createTestServer(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	base := storage.New()
	strategy := seal.NewSoftwareStrategy()
	barrier, err := seal.NewBarrier(logger, base, seal.BarrierConfig{}, strategy)
	require.NoError(t, err)
	server.barrier = barrier
	return server
}

// mockPINManager implements pin.PINManager for testing.
type mockPINManager struct {
	soPINSet      bool
	userPINSet    bool
	initialized   bool
	setSOPINErr   error
	setUserPINErr error
	verifySOErr   error
	verifyUserErr error
	changeSOErr   error
	changeUserErr error
	resetErr      error
}

func (m *mockPINManager) Strategy() pin.StrategyID         { return "mock" }
func (m *mockPINManager) IsInitialized() bool              { return m.initialized }
func (m *mockPINManager) SOPINSet() bool                   { return m.soPINSet }
func (m *mockPINManager) UserPINSet() bool                 { return m.userPINSet }
func (m *mockPINManager) SetMaxAttempts(n int)             {}
func (m *mockPINManager) SetSOPIN(cur, new string) error   { return m.setSOPINErr }
func (m *mockPINManager) SetUserPIN(so, new string) error  { return m.setUserPINErr }
func (m *mockPINManager) ChangeSOPIN(cur, new string) error { return m.changeSOErr }
func (m *mockPINManager) ChangeUserPIN(cur, new string) error { return m.changeUserErr }
func (m *mockPINManager) VerifySOPIN(p string) error       { return m.verifySOErr }
func (m *mockPINManager) VerifyUserPIN(p string) error     { return m.verifyUserErr }
func (m *mockPINManager) ResetLockout(so string) error     { return m.resetErr }
func (m *mockPINManager) GetLockoutStatus() *pin.LockoutStatus {
	return &pin.LockoutStatus{
		FailedAttempts:  0,
		MaxAttempts:     10,
		IsLocked:        false,
		LockoutUntil:    time.Time{},
		RecoverySeconds: 300,
	}
}

// --- Barrier handler tests ---

func TestBarrierInitialize(t *testing.T) {
	server := createBarrierTestServer(t)
	defer xkms.Reset()

	t.Run("POST initializes barrier", func(t *testing.T) {
		body, _ := json.Marshal(BarrierInitializeRequest{Secret: "my-secret"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("POST fails without secret", func(t *testing.T) {
		body, _ := json.Marshal(BarrierInitializeRequest{Secret: ""})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/initialize", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("POST fails with invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize", bytes.NewReader([]byte(`{bad`)))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestBarrierUnseal(t *testing.T) {
	server := createBarrierTestServer(t)
	defer xkms.Reset()

	// Initialize first
	body, _ := json.Marshal(BarrierInitializeRequest{Secret: "unseal-secret"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	t.Run("POST unseals barrier", func(t *testing.T) {
		body, _ := json.Marshal(BarrierUnsealRequest{Secret: "unseal-secret"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		// May be already unsealed from init, which returns conflict
		assert.Contains(t, []int{http.StatusOK, http.StatusConflict}, w.Code)
	})

	t.Run("POST fails without secret", func(t *testing.T) {
		body, _ := json.Marshal(BarrierUnsealRequest{Secret: ""})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/unseal", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/unseal", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestBarrierSeal(t *testing.T) {
	server := createBarrierTestServer(t)
	defer xkms.Reset()

	// Initialize + unseal
	body, _ := json.Marshal(BarrierInitializeRequest{Secret: "seal-secret"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	t.Run("POST seals barrier", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/seal", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/seal", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestBarrierStatus(t *testing.T) {
	server := createBarrierTestServer(t)
	defer xkms.Reset()

	t.Run("GET returns status", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/status", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp BarrierStatusResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
	})

	t.Run("POST method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/status", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestBarrierNotConfigured(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	server.barrier = nil

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/barrier/initialize"},
		{http.MethodPost, "/api/v1/barrier/unseal"},
		{http.MethodPost, "/api/v1/barrier/seal"},
		{http.MethodGet, "/api/v1/barrier/status"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			var body io.Reader
			if ep.method == http.MethodPost {
				b, _ := json.Marshal(map[string]string{"secret": "x"})
				body = bytes.NewReader(b)
			}
			req := httptest.NewRequest(ep.method, ep.path, body)
			w := httptest.NewRecorder()
			server.handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		})
	}
}

func TestBarrierUnknownOperation(t *testing.T) {
	server := createBarrierTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/nonexistent", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- PIN handler tests ---

func TestPINHandlers(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	mock := &mockPINManager{initialized: true}
	server.pinManager = mock

	t.Run("SetSOPIN success", func(t *testing.T) {
		body, _ := json.Marshal(SetSOPINRequest{CurrentSOPIN: "old", NewSOPIN: "new"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("SetSOPIN missing new_so_pin", func(t *testing.T) {
		body, _ := json.Marshal(SetSOPINRequest{CurrentSOPIN: "old", NewSOPIN: ""})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("SetSOPIN GET not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/pin/so-pin", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("SetUserPIN success", func(t *testing.T) {
		body, _ := json.Marshal(SetUserPINRequest{SOPIN: "admin", NewUserPIN: "1234"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("SetUserPIN missing so_pin", func(t *testing.T) {
		body, _ := json.Marshal(SetUserPINRequest{SOPIN: "", NewUserPIN: "1234"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("SetUserPIN missing new_user_pin", func(t *testing.T) {
		body, _ := json.Marshal(SetUserPINRequest{SOPIN: "admin", NewUserPIN: ""})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("ChangeSOPIN success", func(t *testing.T) {
		body, _ := json.Marshal(ChangeSOPINRequest{CurrentSOPIN: "old", NewSOPIN: "new"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin/change", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("ChangeSOPIN missing current_so_pin", func(t *testing.T) {
		body, _ := json.Marshal(ChangeSOPINRequest{CurrentSOPIN: "", NewSOPIN: "new"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin/change", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("ChangeSOPIN missing new_so_pin", func(t *testing.T) {
		body, _ := json.Marshal(ChangeSOPINRequest{CurrentSOPIN: "old", NewSOPIN: ""})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin/change", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("ChangeUserPIN success", func(t *testing.T) {
		body, _ := json.Marshal(ChangeUserPINRequest{CurrentUserPIN: "old", NewUserPIN: "new"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin/change", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("ChangeUserPIN missing fields", func(t *testing.T) {
		body, _ := json.Marshal(ChangeUserPINRequest{CurrentUserPIN: "", NewUserPIN: "new"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin/change", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		body, _ = json.Marshal(ChangeUserPINRequest{CurrentUserPIN: "old", NewUserPIN: ""})
		req = httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin/change", bytes.NewReader(body))
		w = httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("VerifySOPIN success", func(t *testing.T) {
		body, _ := json.Marshal(VerifyPINRequest{PIN: "admin"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin/verify", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("VerifySOPIN missing pin", func(t *testing.T) {
		body, _ := json.Marshal(VerifyPINRequest{PIN: ""})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin/verify", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("VerifyUserPIN success", func(t *testing.T) {
		body, _ := json.Marshal(VerifyPINRequest{PIN: "1234"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin/verify", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("VerifyUserPIN missing pin", func(t *testing.T) {
		body, _ := json.Marshal(VerifyPINRequest{PIN: ""})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin/verify", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("GetLockoutStatus", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/pin/lockout", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp LockoutStatusResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, 10, resp.MaxAttempts)
	})

	t.Run("ResetLockout success", func(t *testing.T) {
		body, _ := json.Marshal(ResetLockoutRequest{SOPIN: "admin"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/lockout/reset", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("ResetLockout missing so_pin", func(t *testing.T) {
		body, _ := json.Marshal(ResetLockoutRequest{SOPIN: ""})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/lockout/reset", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("unknown PIN operation", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/nonexistent", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestPINNotConfigured(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	server.pinManager = nil

	pinEndpoints := []string{
		"/api/v1/pin/so-pin",
		"/api/v1/pin/user-pin",
		"/api/v1/pin/so-pin/change",
		"/api/v1/pin/user-pin/change",
		"/api/v1/pin/so-pin/verify",
		"/api/v1/pin/user-pin/verify",
		"/api/v1/pin/lockout/reset",
	}

	for _, path := range pinEndpoints {
		t.Run("POST "+path, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"pin": "x", "so_pin": "x", "new_so_pin": "x", "current_so_pin": "x", "new_user_pin": "x", "current_user_pin": "x"})
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
			w := httptest.NewRecorder()
			server.handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		})
	}

	t.Run("GET lockout not configured", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/pin/lockout", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestPINErrors(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	mock := &mockPINManager{
		initialized:   true,
		setSOPINErr:   pin.ErrPINInvalid,
		verifySOErr:   pin.ErrPINLocked,
		verifyUserErr: pin.ErrPINNotSet,
		changeSOErr:   pin.ErrSOPINRequired,
		changeUserErr: pin.ErrPINTooShort,
		setUserPINErr: pin.ErrPINAlreadySet,
		resetErr:      pin.ErrInvalidCurrentPIN,
	}
	server.pinManager = mock

	t.Run("SetSOPIN error maps to 401", func(t *testing.T) {
		body, _ := json.Marshal(SetSOPINRequest{CurrentSOPIN: "x", NewSOPIN: "y"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("VerifySOPIN locked maps to 429", func(t *testing.T) {
		body, _ := json.Marshal(VerifyPINRequest{PIN: "x"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin/verify", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusTooManyRequests, w.Code)
	})

	t.Run("VerifyUserPIN not set maps to 400", func(t *testing.T) {
		body, _ := json.Marshal(VerifyPINRequest{PIN: "x"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin/verify", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("SetUserPIN already set maps to 409", func(t *testing.T) {
		body, _ := json.Marshal(SetUserPINRequest{SOPIN: "x", NewUserPIN: "y"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("ResetLockout invalid current PIN", func(t *testing.T) {
		body, _ := json.Marshal(ResetLockoutRequest{SOPIN: "x"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/lockout/reset", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("sendPINError unknown error maps to 500", func(t *testing.T) {
		mock.setSOPINErr = errors.New("unexpected")
		body, _ := json.Marshal(SetSOPINRequest{CurrentSOPIN: "x", NewSOPIN: "y"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// --- Init/Credentials handler tests ---

func TestInitCredentialHandlers(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("GetInitStatus GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/init/status", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		// Service may not be configured, but handler should respond
		assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("GetInitStatus POST not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/init/status", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("ClaimCertBegin POST", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"officer_name": "test"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-cert/begin", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("ClaimCertBegin GET not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/init/claim-cert/begin", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("ClaimCertComplete POST", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"officer_name": "test"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-cert/complete", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("ClaimShare POST", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"officer_name": "test"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-share", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("SignCSRInit POST", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"csr_pem": "test"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/init/sign-csr", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("CredentialSubmit POST", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"name": "test", "value": "secret"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/submit", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("CredentialStrategy GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/credentials/strategy", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("mapInitErrorToStatus defaults to 500", func(t *testing.T) {
		status := mapInitErrorToStatus(errors.New("unknown"))
		assert.Equal(t, http.StatusInternalServerError, status)
	})

	t.Run("mapCredentialErrorToStatus defaults to 500", func(t *testing.T) {
		status := mapCredentialErrorToStatus(errors.New("unknown"))
		assert.Equal(t, http.StatusInternalServerError, status)
	})
}

// --- PIV handler tests ---

func TestPIVHandlers(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("ListPIVSlots GET without backend", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("ListPIVSlots POST not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("PIVSlotOperations missing slot", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("PIVSlotOperations unknown operation", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/9a/unknown", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("PIV certificate GET without backend", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/9a/certificate?backend=", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("PIV certificate DELETE without backend", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/piv/slots/9a/certificate?backend=", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("PIV certificate POST without backend in body", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"cert_pem": "test"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/certificate", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("PIV certificate PATCH not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/piv/slots/9a/certificate", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("PIV generate POST without backend", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"algorithm": "rsa"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/generate", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("PIV generate GET not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/9a/generate", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("PIV import POST without backend", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"cert_pem": "test"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/import", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("PIV import GET not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/9a/import", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("PIV export GET without backend", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/9a/export", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("PIV export POST not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/export", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("PIV CSR POST without backend", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"common_name": "test"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/csr", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("PIV CSR GET not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/9a/csr", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

// --- CA handler tests ---

func TestCAHandlers(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	caEndpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/ca/bundle"},
		{http.MethodGet, "/api/v1/ca/certificate"},
		
		{http.MethodGet, "/api/v1/ca/revoked/123"},
	}

	for _, ep := range caEndpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, nil)
			w := httptest.NewRecorder()
			server.handler.ServeHTTP(w, req)
			// Should not be method not allowed
			assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code)
		})
	}

	caPostEndpoints := []struct {
		path string
	}{
		{"/api/v1/ca/crl"},
		{"/api/v1/ca/sign-csr"},
		{"/api/v1/ca/issue"},
		{"/api/v1/ca/revoke"},
		{"/api/v1/ca/tcg/ek"},
		{"/api/v1/ca/tcg/ak"},
		{"/api/v1/ca/tcg/sign-csr"},
		{"/api/v1/ca/tcg/enroll"},
	}

	for _, ep := range caPostEndpoints {
		t.Run("POST "+ep.path, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"test": "value"})
			req := httptest.NewRequest(http.MethodPost, ep.path, bytes.NewReader(body))
			w := httptest.NewRecorder()
			server.handler.ServeHTTP(w, req)
			assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code)
		})
	}

	// Method not allowed tests for CA
	t.Run("CA sign-csr GET not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/sign-csr", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

// --- Server setter tests ---

func TestServerSetters(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("SetBarrier", func(t *testing.T) {
		assert.Nil(t, server.barrier)
		server.SetBarrier(nil)
		assert.Nil(t, server.barrier)
	})

	t.Run("SetPINManager", func(t *testing.T) {
		assert.Nil(t, server.pinManager)
		server.SetPINManager(nil)
		assert.Nil(t, server.pinManager)
	})

	t.Run("SetPasswordStore", func(t *testing.T) {
		server.SetPasswordStore(nil)
		assert.Nil(t, server.passwordStore)
	})

	t.Run("SetPasswordManager", func(t *testing.T) {
		server.SetPasswordManager(nil)
		assert.Nil(t, server.passwordManager)
	})
}

// --- TLS Certificate handler tests ---

func TestTLSCertificateHandler(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("GET without cert ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tls/my-cert", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("GET with invalid backend", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/my-cert?backend=invalid-backend", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("GET with nonexistent cert", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/nonexistent-cert", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// --- Copy Key handler test ---

func TestCopyKeyHandler(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("POST missing required fields", func(t *testing.T) {
		body, _ := json.Marshal(CopyKeyRequest{SourceBackend: "software"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/copy", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("POST with all required but invalid backends", func(t *testing.T) {
		body, _ := json.Marshal(CopyKeyRequest{
			SourceBackend: "nonexistent",
			SourceKeyID:   "key1",
			DestBackend:   "software",
			DestKeyID:     "key2",
			Algorithm:     "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// --- Import Parameters handler test ---

func TestGetImportParamsHandler(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("POST missing fields", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{Backend: "software"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/import-params", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

// --- sendBarrierError tests ---

func TestSendBarrierError(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	tests := []struct {
		name       string
		err        error
		statusCode int
	}{
		{"AlreadyInitialized", seal.ErrAlreadyInitialized, http.StatusConflict},
		{"AlreadyUnsealed", seal.ErrAlreadyUnsealed, http.StatusConflict},
		{"NotInitialized", seal.ErrNotInitialized, http.StatusBadRequest},
		{"InvalidCredentials", seal.ErrInvalidCredentials, http.StatusUnauthorized},
		{"Sealed", seal.ErrSealed, http.StatusConflict},
		{"NoAvailableStrategy", seal.ErrNoAvailableStrategy, http.StatusServiceUnavailable},
		{"StrategyNotFound", seal.ErrStrategyNotFound, http.StatusBadRequest},
		{"Unknown", errors.New("unknown"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			sendBarrierError(server, w, tt.err)
			assert.Equal(t, tt.statusCode, w.Code)
		})
	}
}
