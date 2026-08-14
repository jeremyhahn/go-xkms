//go:build codec_json

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

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	pkgca "github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// Setup service error types
// ==========================================================================

func TestSetupErrors(t *testing.T) {
	t.Run("SetupAlreadyCompleteError", func(t *testing.T) {
		err := &SetupAlreadyCompleteError{}
		assert.Contains(t, err.Error(), "already complete")
	})

	t.Run("SetupBarrierError wraps underlying error", func(t *testing.T) {
		inner := errors.New("barrier failed")
		err := &SetupBarrierError{Operation: "initialize", Err: inner}
		assert.Contains(t, err.Error(), "initialize")
		assert.Contains(t, err.Error(), "barrier failed")
		assert.Equal(t, inner, err.Unwrap())
	})

	t.Run("SetupError", func(t *testing.T) {
		err := &SetupError{Message: "missing field"}
		assert.Contains(t, err.Error(), "missing field")
	})

	t.Run("UnsupportedBarrierStrategyError", func(t *testing.T) {
		err := &UnsupportedBarrierStrategyError{Strategy: "hardware-tpm"}
		assert.Contains(t, err.Error(), "hardware-tpm")
		assert.Contains(t, err.Error(), "unsupported")
	})
}

// ==========================================================================
// stubSetupService implements SetupService for handler tests.
// ==========================================================================

type stubSetupService struct {
	statusResp  *SetupStatusResponse
	statusErr   error
	barrierResp *SetupBarrierResponse
	barrierErr  error
	caErr       error
	completeErr error
}

func newStubSetupService() *stubSetupService {
	return &stubSetupService{
		statusResp:  &SetupStatusResponse{Status: SetupStatusPending, Mode: BarrierModeEmbedded},
		barrierResp: &SetupBarrierResponse{},
	}
}

func (s *stubSetupService) Status(_ context.Context) (*SetupStatusResponse, error) {
	return s.statusResp, s.statusErr
}
func (s *stubSetupService) ConfigureBarrier(_ context.Context, _ *SetupBarrierRequest) (*SetupBarrierResponse, error) {
	return s.barrierResp, s.barrierErr
}
func (s *stubSetupService) ConfigureCA(_ context.Context, _ *SetupCARequest) error {
	return s.caErr
}
func (s *stubSetupService) Complete(_ context.Context) error {
	return s.completeErr
}

// Compile-time check.
var _ SetupService = (*stubSetupService)(nil)

// ==========================================================================
// SetupService implementation (NewSetupService + all operations)
// ==========================================================================

func TestSetupService_NewSetupService_NoKV(t *testing.T) {
	svc := NewSetupService(BarrierModeEmbedded, nil, nil, nil, slog.Default())
	assert.NotNil(t, svc)
}

func TestSetupService_NewSetupService_WithKV_PendingStatus(t *testing.T) {
	kv := newStubSetupKVClient()
	svc := NewSetupService(BarrierModeEmbedded, nil, nil, kv, slog.Default())
	assert.NotNil(t, svc)
}

func TestSetupService_NewSetupService_WithKV_RestoredComplete(t *testing.T) {
	kv := newStubSetupKVClient()
	// Pre-populate the "complete" status in the KV store.
	_ = kv.Put(context.Background(), kvKeySetupStatus, []byte(SetupStatusComplete))

	svc := NewSetupService(BarrierModeEmbedded, nil, nil, kv, slog.Default())
	assert.NotNil(t, svc)

	// Status should be restored as complete.
	resp, err := svc.Status(context.Background())
	require.NoError(t, err)
	assert.Equal(t, SetupStatusComplete, resp.Status)
}

func TestSetupService_Status_NilBarrierNilCA(t *testing.T) {
	svc := NewSetupService(BarrierModeEmbedded, nil, nil, nil, slog.Default())
	resp, err := svc.Status(context.Background())
	require.NoError(t, err)
	assert.Equal(t, SetupStatusPending, resp.Status)
	assert.False(t, resp.CAInitialized)
}

func TestSetupService_Status_BarrierInitialized(t *testing.T) {
	bc := newStubBarrierClient()
	bc.statusResp.InitializedAt = "2025-01-01T00:00:00Z"
	svc := NewSetupService(BarrierModeEmbedded, bc, nil, nil, slog.Default())

	resp, err := svc.Status(context.Background())
	require.NoError(t, err)
	assert.True(t, resp.CAInitialized)
}

func TestSetupService_ConfigureBarrier_AlreadyComplete(t *testing.T) {
	kv := newStubSetupKVClient()
	_ = kv.Put(context.Background(), kvKeySetupStatus, []byte(SetupStatusComplete))
	svc := NewSetupService(BarrierModeEmbedded, nil, nil, kv, slog.Default())

	_, err := svc.ConfigureBarrier(context.Background(), &SetupBarrierRequest{Strategy: "software", Secret: "s"})
	require.Error(t, err)
	var e *SetupAlreadyCompleteError
	assert.True(t, errors.As(err, &e))
}

func TestSetupService_ConfigureBarrier_StrategyNone(t *testing.T) {
	svc := NewSetupService(BarrierModeEmbedded, nil, nil, nil, slog.Default())
	resp, err := svc.ConfigureBarrier(context.Background(), &SetupBarrierRequest{Strategy: "none"})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSetupService_ConfigureBarrier_Software_NoBarrier(t *testing.T) {
	svc := NewSetupService(BarrierModeEmbedded, nil, nil, nil, slog.Default())
	_, err := svc.ConfigureBarrier(context.Background(), &SetupBarrierRequest{Strategy: "software", Secret: "secret"})
	require.Error(t, err)
	var e *BarrierNotEnabledError
	assert.True(t, errors.As(err, &e))
}

func TestSetupService_ConfigureBarrier_Software_RemoteMode(t *testing.T) {
	svc := NewSetupService(BarrierModeRemote, newStubBarrierClient(), nil, nil, slog.Default())
	_, err := svc.ConfigureBarrier(context.Background(), &SetupBarrierRequest{Strategy: "software", Secret: "secret"})
	require.Error(t, err)
	var e *BarrierRemoteModeError
	assert.True(t, errors.As(err, &e))
}

func TestSetupService_ConfigureBarrier_Software_EmptySecret(t *testing.T) {
	svc := NewSetupService(BarrierModeEmbedded, newStubBarrierClient(), nil, nil, slog.Default())
	_, err := svc.ConfigureBarrier(context.Background(), &SetupBarrierRequest{Strategy: "software", Secret: ""})
	require.Error(t, err)
	var e *SetupError
	assert.True(t, errors.As(err, &e))
}

func TestSetupService_ConfigureBarrier_Software_Success(t *testing.T) {
	svc := NewSetupService(BarrierModeEmbedded, newStubBarrierClient(), nil, nil, slog.Default())
	resp, err := svc.ConfigureBarrier(context.Background(), &SetupBarrierRequest{Strategy: "software", Secret: "my-secret"})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestSetupService_ConfigureBarrier_Software_BarrierError(t *testing.T) {
	bc := newStubBarrierClient()
	bc.initErr = errors.New("init failed")
	svc := NewSetupService(BarrierModeEmbedded, bc, nil, nil, slog.Default())
	_, err := svc.ConfigureBarrier(context.Background(), &SetupBarrierRequest{Strategy: "software", Secret: "s"})
	require.Error(t, err)
	var be *SetupBarrierError
	assert.True(t, errors.As(err, &be))
}

func TestSetupService_ConfigureBarrier_Shamir_NoConfig(t *testing.T) {
	svc := NewSetupService(BarrierModeEmbedded, newStubBarrierClient(), nil, nil, slog.Default())
	_, err := svc.ConfigureBarrier(context.Background(), &SetupBarrierRequest{Strategy: "shamir"})
	require.Error(t, err)
	var se *SetupError
	assert.True(t, errors.As(err, &se))
}

func TestSetupService_ConfigureBarrier_Shamir_BadThreshold(t *testing.T) {
	svc := NewSetupService(BarrierModeEmbedded, newStubBarrierClient(), nil, nil, slog.Default())
	_, err := svc.ConfigureBarrier(context.Background(), &SetupBarrierRequest{
		Strategy: "shamir",
		Shamir:   &SetupShamirConfig{Threshold: 0, Total: 3},
	})
	require.Error(t, err)
}

func TestSetupService_ConfigureBarrier_Shamir_TotalLessThanThreshold(t *testing.T) {
	svc := NewSetupService(BarrierModeEmbedded, newStubBarrierClient(), nil, nil, slog.Default())
	_, err := svc.ConfigureBarrier(context.Background(), &SetupBarrierRequest{
		Strategy: "shamir",
		Shamir:   &SetupShamirConfig{Threshold: 3, Total: 2},
	})
	require.Error(t, err)
}

func TestSetupService_ConfigureBarrier_Shamir_NoBarrier(t *testing.T) {
	svc := NewSetupService(BarrierModeEmbedded, nil, nil, nil, slog.Default())
	_, err := svc.ConfigureBarrier(context.Background(), &SetupBarrierRequest{
		Strategy: "shamir",
		Shamir:   &SetupShamirConfig{Threshold: 2, Total: 3},
	})
	require.Error(t, err)
	var e *BarrierNotEnabledError
	assert.True(t, errors.As(err, &e))
}

func TestSetupService_ConfigureBarrier_Shamir_RemoteMode(t *testing.T) {
	svc := NewSetupService(BarrierModeRemote, newStubBarrierClient(), nil, nil, slog.Default())
	_, err := svc.ConfigureBarrier(context.Background(), &SetupBarrierRequest{
		Strategy: "shamir",
		Shamir:   &SetupShamirConfig{Threshold: 2, Total: 3},
	})
	require.Error(t, err)
	var e *BarrierRemoteModeError
	assert.True(t, errors.As(err, &e))
}

func TestSetupService_ConfigureBarrier_Shamir_Success(t *testing.T) {
	svc := NewSetupService(BarrierModeEmbedded, newStubBarrierClient(), nil, nil, slog.Default())
	resp, err := svc.ConfigureBarrier(context.Background(), &SetupBarrierRequest{
		Strategy: "shamir",
		Shamir:   &SetupShamirConfig{Threshold: 2, Total: 3},
	})
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Threshold)
	assert.Equal(t, 3, resp.Total)
}

func TestSetupService_ConfigureBarrier_Shamir_BarrierError(t *testing.T) {
	bc := newStubBarrierClient()
	bc.initShamirErr = errors.New("shamir init failed")
	svc := NewSetupService(BarrierModeEmbedded, bc, nil, nil, slog.Default())
	_, err := svc.ConfigureBarrier(context.Background(), &SetupBarrierRequest{
		Strategy: "shamir",
		Shamir:   &SetupShamirConfig{Threshold: 2, Total: 3},
	})
	require.Error(t, err)
	var be *SetupBarrierError
	assert.True(t, errors.As(err, &be))
}

func TestSetupService_ConfigureBarrier_UnsupportedStrategy(t *testing.T) {
	svc := NewSetupService(BarrierModeEmbedded, nil, nil, nil, slog.Default())
	_, err := svc.ConfigureBarrier(context.Background(), &SetupBarrierRequest{Strategy: "quantum"})
	require.Error(t, err)
	var e *UnsupportedBarrierStrategyError
	assert.True(t, errors.As(err, &e))
}

func TestSetupService_ConfigureCA_AlreadyComplete(t *testing.T) {
	kv := newStubSetupKVClient()
	_ = kv.Put(context.Background(), kvKeySetupStatus, []byte(SetupStatusComplete))
	svc := NewSetupService(BarrierModeEmbedded, nil, nil, kv, slog.Default())

	err := svc.ConfigureCA(context.Background(), &SetupCARequest{
		RootCAName:         "Root",
		IntermediateCAName: "Intermediate",
		KeyAlgorithm:       "ecdsa",
		ValidityYears:      10,
	})
	require.Error(t, err)
	var e *SetupAlreadyCompleteError
	assert.True(t, errors.As(err, &e))
}

func TestSetupService_ConfigureCA_MissingFields(t *testing.T) {
	svc := NewSetupService(BarrierModeEmbedded, nil, nil, nil, slog.Default())
	ctx := context.Background()

	tests := []struct {
		name string
		req  *SetupCARequest
	}{
		{"missing root ca name", &SetupCARequest{RootCAName: ""}},
		{"missing intermediate ca name", &SetupCARequest{RootCAName: "Root"}},
		{"missing key algorithm", &SetupCARequest{RootCAName: "Root", IntermediateCAName: "Int"}},
		{"zero validity years", &SetupCARequest{RootCAName: "Root", IntermediateCAName: "Int", KeyAlgorithm: "ecdsa"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := svc.ConfigureCA(ctx, tt.req)
			require.Error(t, err)
			var se *SetupError
			assert.True(t, errors.As(err, &se))
		})
	}
}

func TestSetupService_ConfigureCA_CANotInitialized(t *testing.T) {
	// Use a stub CA that reports not initialized.
	caStub := &stubCAForSetup{initialized: false}
	svc := NewSetupService(BarrierModeEmbedded, nil, caStub, nil, slog.Default())
	err := svc.ConfigureCA(context.Background(), &SetupCARequest{
		RootCAName:         "Root",
		IntermediateCAName: "Intermediate",
		KeyAlgorithm:       "ecdsa",
		ValidityYears:      10,
	})
	require.Error(t, err)
	var se *SetupError
	assert.True(t, errors.As(err, &se))
	assert.Contains(t, se.Message, "not initialized")
}

func TestSetupService_ConfigureCA_WithKV_Success(t *testing.T) {
	kv := newStubSetupKVClient()
	caStub := &stubCAForSetup{initialized: true}
	svc := NewSetupService(BarrierModeEmbedded, nil, caStub, kv, slog.Default())
	err := svc.ConfigureCA(context.Background(), &SetupCARequest{
		RootCAName:         "Root CA",
		IntermediateCAName: "Intermediate CA",
		KeyAlgorithm:       "ecdsa",
		ValidityYears:      10,
		Organization:       "Test Org",
	})
	require.NoError(t, err)
}

func TestSetupService_ConfigureCA_KVPutError(t *testing.T) {
	kv := newFailingSetupKVClient()
	svc := NewSetupService(BarrierModeEmbedded, nil, nil, kv, slog.Default())
	err := svc.ConfigureCA(context.Background(), &SetupCARequest{
		RootCAName:         "Root",
		IntermediateCAName: "Intermediate",
		KeyAlgorithm:       "ecdsa",
		ValidityYears:      10,
	})
	require.Error(t, err)
	var se *SetupError
	assert.True(t, errors.As(err, &se))
}

func TestSetupService_Complete_Success(t *testing.T) {
	svc := NewSetupService(BarrierModeEmbedded, nil, nil, nil, slog.Default())
	err := svc.Complete(context.Background())
	require.NoError(t, err)

	// Subsequent call should return AlreadyComplete.
	err = svc.Complete(context.Background())
	require.Error(t, err)
	var e *SetupAlreadyCompleteError
	assert.True(t, errors.As(err, &e))
}

func TestSetupService_Complete_WithKV_Success(t *testing.T) {
	kv := newStubSetupKVClient()
	svc := NewSetupService(BarrierModeEmbedded, nil, nil, kv, slog.Default())
	err := svc.Complete(context.Background())
	require.NoError(t, err)
}

func TestSetupService_Complete_KVPutError(t *testing.T) {
	kv := newFailingSetupKVClient()
	svc := NewSetupService(BarrierModeEmbedded, nil, nil, kv, slog.Default())
	err := svc.Complete(context.Background())
	require.Error(t, err)
	var se *SetupError
	assert.True(t, errors.As(err, &se))
}

// ==========================================================================
// SetupHandlers — HTTP handlers
// ==========================================================================

func newSetupHandlerRouter(svc SetupService) *mux.Router {
	router := mux.NewRouter()
	h := NewSetupHandlers(svc, slog.Default())
	h.RegisterRoutes(router)
	return router
}

func TestSetupHandlers_Status_Success(t *testing.T) {
	router := newSetupHandlerRouter(newStubSetupService())
	req := httptest.NewRequest(http.MethodGet, "/admin/setup/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp SetupStatusResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, SetupStatusPending, resp.Status)
}

func TestSetupHandlers_Status_Error(t *testing.T) {
	svc := newStubSetupService()
	svc.statusErr = errors.New("status error")
	router := newSetupHandlerRouter(svc)
	req := httptest.NewRequest(http.MethodGet, "/admin/setup/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSetupHandlers_Barrier_Success(t *testing.T) {
	router := newSetupHandlerRouter(newStubSetupService())
	body, _ := json.Marshal(SetupBarrierRequest{Strategy: "software", Secret: "secret"})
	req := httptest.NewRequest(http.MethodPost, "/admin/setup/barrier", bytes.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSetupHandlers_Barrier_BadJSON(t *testing.T) {
	router := newSetupHandlerRouter(newStubSetupService())
	req := httptest.NewRequest(http.MethodPost, "/admin/setup/barrier", bytes.NewReader([]byte("bad")))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetupHandlers_Barrier_AlreadyCompleteError(t *testing.T) {
	svc := newStubSetupService()
	svc.barrierErr = &SetupAlreadyCompleteError{}
	router := newSetupHandlerRouter(svc)
	body, _ := json.Marshal(SetupBarrierRequest{Strategy: "software", Secret: "s"})
	req := httptest.NewRequest(http.MethodPost, "/admin/setup/barrier", bytes.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestSetupHandlers_Barrier_RemoteModeError(t *testing.T) {
	svc := newStubSetupService()
	svc.barrierErr = &BarrierRemoteModeError{Operation: "setup"}
	router := newSetupHandlerRouter(svc)
	body, _ := json.Marshal(SetupBarrierRequest{Strategy: "software", Secret: "s"})
	req := httptest.NewRequest(http.MethodPost, "/admin/setup/barrier", bytes.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestSetupHandlers_Barrier_UnsupportedStrategyError(t *testing.T) {
	svc := newStubSetupService()
	svc.barrierErr = &UnsupportedBarrierStrategyError{Strategy: "quantum"}
	router := newSetupHandlerRouter(svc)
	body, _ := json.Marshal(SetupBarrierRequest{Strategy: "quantum"})
	req := httptest.NewRequest(http.MethodPost, "/admin/setup/barrier", bytes.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetupHandlers_Barrier_SetupError(t *testing.T) {
	svc := newStubSetupService()
	svc.barrierErr = &SetupError{Message: "secret required"}
	router := newSetupHandlerRouter(svc)
	body, _ := json.Marshal(SetupBarrierRequest{Strategy: "software"})
	req := httptest.NewRequest(http.MethodPost, "/admin/setup/barrier", bytes.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetupHandlers_Barrier_SetupBarrierError(t *testing.T) {
	svc := newStubSetupService()
	svc.barrierErr = &SetupBarrierError{Operation: "initialize", Err: errors.New("rpc error")}
	router := newSetupHandlerRouter(svc)
	body, _ := json.Marshal(SetupBarrierRequest{Strategy: "software", Secret: "s"})
	req := httptest.NewRequest(http.MethodPost, "/admin/setup/barrier", bytes.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSetupHandlers_Barrier_InternalError(t *testing.T) {
	svc := newStubSetupService()
	svc.barrierErr = errors.New("unexpected error")
	router := newSetupHandlerRouter(svc)
	body, _ := json.Marshal(SetupBarrierRequest{Strategy: "software", Secret: "s"})
	req := httptest.NewRequest(http.MethodPost, "/admin/setup/barrier", bytes.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestSetupHandlers_CA_Success(t *testing.T) {
	router := newSetupHandlerRouter(newStubSetupService())
	body, _ := json.Marshal(SetupCARequest{
		RootCAName:         "Root CA",
		IntermediateCAName: "Intermediate CA",
		KeyAlgorithm:       "ecdsa",
		ValidityYears:      10,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/setup/ca", bytes.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSetupHandlers_CA_BadJSON(t *testing.T) {
	router := newSetupHandlerRouter(newStubSetupService())
	req := httptest.NewRequest(http.MethodPost, "/admin/setup/ca", bytes.NewReader([]byte("bad")))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetupHandlers_CA_Validations(t *testing.T) {
	router := newSetupHandlerRouter(newStubSetupService())

	tests := []struct {
		name string
		req  SetupCARequest
	}{
		{"missing root ca name", SetupCARequest{IntermediateCAName: "Int", KeyAlgorithm: "ecdsa", ValidityYears: 10}},
		{"missing intermediate ca name", SetupCARequest{RootCAName: "Root", KeyAlgorithm: "ecdsa", ValidityYears: 10}},
		{"missing key algorithm", SetupCARequest{RootCAName: "Root", IntermediateCAName: "Int", ValidityYears: 10}},
		{"zero validity years", SetupCARequest{RootCAName: "Root", IntermediateCAName: "Int", KeyAlgorithm: "ecdsa", ValidityYears: 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.req)
			req := httptest.NewRequest(http.MethodPost, "/admin/setup/ca", bytes.NewReader(body))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestSetupHandlers_CA_ServiceError(t *testing.T) {
	svc := newStubSetupService()
	svc.caErr = &SetupAlreadyCompleteError{}
	router := newSetupHandlerRouter(svc)
	body, _ := json.Marshal(SetupCARequest{
		RootCAName:         "Root",
		IntermediateCAName: "Int",
		KeyAlgorithm:       "ecdsa",
		ValidityYears:      10,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/setup/ca", bytes.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestSetupHandlers_Complete_Success(t *testing.T) {
	router := newSetupHandlerRouter(newStubSetupService())
	req := httptest.NewRequest(http.MethodPost, "/admin/setup/complete", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSetupHandlers_Complete_Error(t *testing.T) {
	svc := newStubSetupService()
	svc.completeErr = &SetupAlreadyCompleteError{}
	router := newSetupHandlerRouter(svc)
	req := httptest.NewRequest(http.MethodPost, "/admin/setup/complete", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestSetupHandlers_Defaults(t *testing.T) {
	router := newSetupHandlerRouter(newStubSetupService())
	req := httptest.NewRequest(http.MethodGet, "/admin/setup/defaults", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	// Should always return 200 (falls back to empty config if no OpenSSL config exists)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp SetupDefaultsResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
}

// ==========================================================================
// Tenant role/user handler coverage (0% functions)
// ==========================================================================

// newAuthedTenantRequest creates a tenant handler request with super-admin context.
func newAuthedTenantRequest(method, path string, body []byte) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	return addUserToRequest(req, createPlatformAdminUser())
}

func TestTenantHandlers_CreateTenantRole_Success(t *testing.T) {
	svc := &mockTenantService{
		createTenantRoleFunc: func(_ context.Context, _ string, _ *db.CreateRoleRequest) (*db.Role, error) {
			return &db.Role{ID: "role-1", Name: "admin"}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())

	body, _ := json.Marshal(db.CreateRoleRequest{Name: "admin"})
	req := newAuthedTenantRequest(http.MethodPost, "/api/v1/tenants/t1/roles", body)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.CreateTenantRole(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestTenantHandlers_CreateTenantRole_EmptyTenantID(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	body, _ := json.Marshal(db.CreateRoleRequest{Name: "admin"})
	req := newAuthedTenantRequest(http.MethodPost, "/api/v1/tenants//roles", body)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	w := httptest.NewRecorder()
	h.CreateTenantRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_CreateTenantRole_BadJSON(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodPost, "/api/v1/tenants/t1/roles", []byte("bad"))
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.CreateTenantRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_CreateTenantRole_ServiceError(t *testing.T) {
	svc := &mockTenantService{
		createTenantRoleFunc: func(_ context.Context, _ string, _ *db.CreateRoleRequest) (*db.Role, error) {
			return nil, errors.New("create failed")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	body, _ := json.Marshal(db.CreateRoleRequest{Name: "admin"})
	req := newAuthedTenantRequest(http.MethodPost, "/api/v1/tenants/t1/roles", body)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.CreateTenantRole(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTenantHandlers_GetTenantRole_Success(t *testing.T) {
	svc := &mockTenantService{
		getTenantRoleFunc: func(_ context.Context, _ string, _ string) (*db.Role, error) {
			return &db.Role{ID: "role-1", Name: "admin"}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/roles/role-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "roleID": "role-1"})
	w := httptest.NewRecorder()
	h.GetTenantRole(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_GetTenantRole_EmptyIDs(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants//roles/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "roleID": ""})
	w := httptest.NewRecorder()
	h.GetTenantRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_GetTenantRole_NotFound(t *testing.T) {
	svc := &mockTenantService{
		getTenantRoleFunc: func(_ context.Context, _ string, _ string) (*db.Role, error) {
			return nil, errors.New("not found")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/roles/role-x", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "roleID": "role-x"})
	w := httptest.NewRecorder()
	h.GetTenantRole(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestTenantHandlers_UpdateTenantRole_Success(t *testing.T) {
	svc := &mockTenantService{
		updateTenantRoleFunc: func(_ context.Context, _ string, _ *db.UpdateRoleRequest) (*db.Role, error) {
			return &db.Role{ID: "role-1", Name: "updated"}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	body, _ := json.Marshal(db.UpdateRoleRequest{Name: "updated"})
	req := newAuthedTenantRequest(http.MethodPut, "/api/v1/tenants/t1/roles/role-1", body)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "roleID": "role-1"})
	w := httptest.NewRecorder()
	h.UpdateTenantRole(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_UpdateTenantRole_EmptyIDs(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodPut, "/api/v1/tenants//roles/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "roleID": ""})
	w := httptest.NewRecorder()
	h.UpdateTenantRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_UpdateTenantRole_BadJSON(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodPut, "/api/v1/tenants/t1/roles/role-1", []byte("bad"))
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "roleID": "role-1"})
	w := httptest.NewRecorder()
	h.UpdateTenantRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_UpdateTenantRole_ServiceError(t *testing.T) {
	svc := &mockTenantService{
		updateTenantRoleFunc: func(_ context.Context, _ string, _ *db.UpdateRoleRequest) (*db.Role, error) {
			return nil, errors.New("update failed")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	body, _ := json.Marshal(db.UpdateRoleRequest{Name: "x"})
	req := newAuthedTenantRequest(http.MethodPut, "/api/v1/tenants/t1/roles/role-1", body)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "roleID": "role-1"})
	w := httptest.NewRecorder()
	h.UpdateTenantRole(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTenantHandlers_DeleteTenantRole_Success(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodDelete, "/api/v1/tenants/t1/roles/role-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "roleID": "role-1"})
	w := httptest.NewRecorder()
	h.DeleteTenantRole(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_DeleteTenantRole_EmptyIDs(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodDelete, "/api/v1/tenants//roles/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "roleID": ""})
	w := httptest.NewRecorder()
	h.DeleteTenantRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_DeleteTenantRole_ServiceError(t *testing.T) {
	svc := &mockTenantService{
		deleteTenantRoleFunc: func(_ context.Context, _ string, _ string) error {
			return errors.New("delete failed")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodDelete, "/api/v1/tenants/t1/roles/role-1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "roleID": "role-1"})
	w := httptest.NewRecorder()
	h.DeleteTenantRole(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTenantHandlers_ListTenantRoles_Success(t *testing.T) {
	svc := &mockTenantService{
		listTenantRolesFunc: func(_ context.Context, _ string, _ *db.ListRolesRequest) (*db.ListRolesResponse, error) {
			return &db.ListRolesResponse{Roles: []*db.Role{{ID: "r1", Name: "admin"}}}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/roles?page=1&page_size=20", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.ListTenantRoles(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_ListTenantRoles_EmptyTenantID(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants//roles", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	w := httptest.NewRecorder()
	h.ListTenantRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_ListTenantRoles_NilRoles(t *testing.T) {
	svc := &mockTenantService{
		listTenantRolesFunc: func(_ context.Context, _ string, _ *db.ListRolesRequest) (*db.ListRolesResponse, error) {
			return &db.ListRolesResponse{Roles: nil}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/roles", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.ListTenantRoles(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_ListTenantRoles_ServiceError(t *testing.T) {
	svc := &mockTenantService{
		listTenantRolesFunc: func(_ context.Context, _ string, _ *db.ListRolesRequest) (*db.ListRolesResponse, error) {
			return nil, errors.New("list failed")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/roles", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.ListTenantRoles(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTenantHandlers_DeleteTenantUser_Success(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodDelete, "/api/v1/tenants/t1/users/u1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "userID": "u1"})
	w := httptest.NewRecorder()
	h.DeleteTenantUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_DeleteTenantUser_EmptyIDs(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodDelete, "/api/v1/tenants//users/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "userID": ""})
	w := httptest.NewRecorder()
	h.DeleteTenantUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_DeleteTenantUser_ServiceError(t *testing.T) {
	svc := &mockTenantService{
		deleteTenantUserFunc: func(_ context.Context, _ string, _ string) error {
			return errors.New("delete failed")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodDelete, "/api/v1/tenants/t1/users/u1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "userID": "u1"})
	w := httptest.NewRecorder()
	h.DeleteTenantUser(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTenantHandlers_ListTenantUsers_Success(t *testing.T) {
	svc := &mockTenantService{
		listTenantUsersFunc: func(_ context.Context, _ string, _ *db.ListUsersRequest) (*db.ListUsersResponse, error) {
			return &db.ListUsersResponse{Users: []*db.User{{ID: 1, Username: "alice"}}}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/users?page=2&page_size=5", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.ListTenantUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_ListTenantUsers_EmptyTenantID(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants//users", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	w := httptest.NewRecorder()
	h.ListTenantUsers(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_ListTenantUsers_NilUsers(t *testing.T) {
	svc := &mockTenantService{
		listTenantUsersFunc: func(_ context.Context, _ string, _ *db.ListUsersRequest) (*db.ListUsersResponse, error) {
			return &db.ListUsersResponse{Users: nil}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/users", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.ListTenantUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_ListTenantUsers_ServiceError(t *testing.T) {
	svc := &mockTenantService{
		listTenantUsersFunc: func(_ context.Context, _ string, _ *db.ListUsersRequest) (*db.ListUsersResponse, error) {
			return nil, errors.New("list failed")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/users", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.ListTenantUsers(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTenantHandlers_CreateTenantUser_Success(t *testing.T) {
	svc := &mockTenantService{
		createTenantUserFunc: func(_ context.Context, _ string, _ *db.CreateUserRequest) (*db.User, error) {
			return &db.User{ID: 1, Username: "alice"}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	body, _ := json.Marshal(db.CreateUserRequest{Username: "alice"})
	req := newAuthedTenantRequest(http.MethodPost, "/api/v1/tenants/t1/users", body)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.CreateTenantUser(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestTenantHandlers_CreateTenantUser_EmptyTenantID(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	body, _ := json.Marshal(db.CreateUserRequest{Username: "alice"})
	req := newAuthedTenantRequest(http.MethodPost, "/api/v1/tenants//users", body)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	w := httptest.NewRecorder()
	h.CreateTenantUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_CreateTenantUser_BadJSON(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodPost, "/api/v1/tenants/t1/users", []byte("bad"))
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.CreateTenantUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_CreateTenantUser_ServiceError(t *testing.T) {
	svc := &mockTenantService{
		createTenantUserFunc: func(_ context.Context, _ string, _ *db.CreateUserRequest) (*db.User, error) {
			return nil, errors.New("create failed")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	body, _ := json.Marshal(db.CreateUserRequest{Username: "alice"})
	req := newAuthedTenantRequest(http.MethodPost, "/api/v1/tenants/t1/users", body)
	req = mux.SetURLVars(req, map[string]string{"id": "t1"})
	w := httptest.NewRecorder()
	h.CreateTenantUser(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTenantHandlers_GetTenantUser_Success(t *testing.T) {
	svc := &mockTenantService{
		getTenantUserFunc: func(_ context.Context, _ string, _ string) (*db.User, error) {
			return &db.User{ID: 1, Username: "alice"}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/users/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "userID": "1"})
	w := httptest.NewRecorder()
	h.GetTenantUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_GetTenantUser_EmptyIDs(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants//users/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "userID": ""})
	w := httptest.NewRecorder()
	h.GetTenantUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_GetTenantUser_NotFound(t *testing.T) {
	svc := &mockTenantService{
		getTenantUserFunc: func(_ context.Context, _ string, _ string) (*db.User, error) {
			return nil, errors.New("not found")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	req := newAuthedTenantRequest(http.MethodGet, "/api/v1/tenants/t1/users/99", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "userID": "99"})
	w := httptest.NewRecorder()
	h.GetTenantUser(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestTenantHandlers_UpdateTenantUser_Success(t *testing.T) {
	svc := &mockTenantService{
		updateTenantUserFunc: func(_ context.Context, _ string, _ *db.UpdateUserRequest) (*db.User, error) {
			return &db.User{ID: 1, Username: "updated"}, nil
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	body, _ := json.Marshal(db.UpdateUserRequest{Username: "updated"})
	req := newAuthedTenantRequest(http.MethodPut, "/api/v1/tenants/t1/users/1", body)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "userID": "1"})
	w := httptest.NewRecorder()
	h.UpdateTenantUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantHandlers_UpdateTenantUser_EmptyIDs(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodPut, "/api/v1/tenants//users/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "userID": ""})
	w := httptest.NewRecorder()
	h.UpdateTenantUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_UpdateTenantUser_BadJSON(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	req := newAuthedTenantRequest(http.MethodPut, "/api/v1/tenants/t1/users/1", []byte("bad"))
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "userID": "1"})
	w := httptest.NewRecorder()
	h.UpdateTenantUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_UpdateTenantUser_InvalidUserID(t *testing.T) {
	h := NewTenantHandlers(&mockTenantService{}, slog.Default())
	body, _ := json.Marshal(db.UpdateUserRequest{Username: "x"})
	req := newAuthedTenantRequest(http.MethodPut, "/api/v1/tenants/t1/users/not-a-number", body)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "userID": "not-a-number"})
	w := httptest.NewRecorder()
	h.UpdateTenantUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantHandlers_UpdateTenantUser_ServiceError(t *testing.T) {
	svc := &mockTenantService{
		updateTenantUserFunc: func(_ context.Context, _ string, _ *db.UpdateUserRequest) (*db.User, error) {
			return nil, errors.New("update failed")
		},
	}
	h := NewTenantHandlers(svc, slog.Default())
	body, _ := json.Marshal(db.UpdateUserRequest{Username: "x"})
	req := newAuthedTenantRequest(http.MethodPut, "/api/v1/tenants/t1/users/1", body)
	req = mux.SetURLVars(req, map[string]string{"id": "t1", "userID": "1"})
	w := httptest.NewRecorder()
	h.UpdateTenantUser(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestParsePagination_Defaults(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/path", nil)
	page, pageSize := parsePagination(req)
	assert.Equal(t, 1, page)
	assert.Equal(t, 20, pageSize)
}

func TestParsePagination_CustomValues(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/path?page=3&page_size=50", nil)
	page, pageSize := parsePagination(req)
	assert.Equal(t, 3, page)
	assert.Equal(t, 50, pageSize)
}

func TestParsePagination_InvalidValues(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/path?page=abc&page_size=-5", nil)
	page, pageSize := parsePagination(req)
	// Invalid values fall back to defaults
	assert.Equal(t, 1, page)
	assert.Equal(t, 20, pageSize)
}

// ==========================================================================
// Helpers — in-memory KV + CA stubs for setup service tests
// ==========================================================================

// stubSetupKVClient is a simple in-memory KV store for setup service tests.
type stubSetupKVClient struct {
	data map[string][]byte
}

func newStubSetupKVClient() *stubSetupKVClient {
	return &stubSetupKVClient{data: make(map[string][]byte)}
}

func (k *stubSetupKVClient) Get(_ context.Context, key string, _ ...db.ReadOption) ([]byte, error) {
	v, ok := k.data[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

func (k *stubSetupKVClient) Put(_ context.Context, key string, val []byte, _ ...db.WriteOption) error {
	k.data[key] = val
	return nil
}

func (k *stubSetupKVClient) Delete(_ context.Context, key string, _ ...db.WriteOption) error {
	delete(k.data, key)
	return nil
}

func (k *stubSetupKVClient) List(_ context.Context, prefix string, _ ...db.ReadOption) ([]string, error) {
	var keys []string
	for key := range k.data {
		if len(prefix) == 0 || len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (k *stubSetupKVClient) Scan(_ context.Context, _ string, _ ...db.ReadOption) (map[string][]byte, error) {
	return nil, nil
}

func (k *stubSetupKVClient) Exists(_ context.Context, key string, _ ...db.ReadOption) (bool, error) {
	_, ok := k.data[key]
	return ok, nil
}

// Compile-time check.
var _ db.KVClient = (*stubSetupKVClient)(nil)

// failingSetupKVClient always fails Put operations.
type failingSetupKVClient struct{}

func newFailingSetupKVClient() *failingSetupKVClient { return &failingSetupKVClient{} }

func (k *failingSetupKVClient) Get(_ context.Context, _ string, _ ...db.ReadOption) ([]byte, error) {
	return nil, errors.New("not found")
}
func (k *failingSetupKVClient) Put(_ context.Context, _ string, _ []byte, _ ...db.WriteOption) error {
	return errors.New("kv write error")
}
func (k *failingSetupKVClient) Delete(_ context.Context, _ string, _ ...db.WriteOption) error {
	return errors.New("not supported")
}
func (k *failingSetupKVClient) List(_ context.Context, _ string, _ ...db.ReadOption) ([]string, error) {
	return nil, errors.New("not supported")
}
func (k *failingSetupKVClient) Scan(_ context.Context, _ string, _ ...db.ReadOption) (map[string][]byte, error) {
	return nil, errors.New("not supported")
}
func (k *failingSetupKVClient) Exists(_ context.Context, _ string, _ ...db.ReadOption) (bool, error) {
	return false, errors.New("not supported")
}

// Compile-time check.
var _ db.KVClient = (*failingSetupKVClient)(nil)

// stubCAForSetup is a minimal ca.TCGCA stub that only implements IsInitialized.
// It embeds the ca.TCGCA interface so all non-overridden methods are nil (will
// panic if called — not an issue since the setup service only calls IsInitialized).
type stubCAForSetup struct {
	initialized bool
	pkgca.TCGCA // embed to satisfy interface without implementing all methods
}

func (s *stubCAForSetup) IsInitialized() bool { return s.initialized }
