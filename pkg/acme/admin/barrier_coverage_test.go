//go:build codec_json

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
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

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// stubBarrierClient is an in-memory BarrierClient for testing.
// ==========================================================================

type stubBarrierClient struct {
	statusResp          *db.BarrierStatusResponse
	statusErr           error
	initErr             error
	sealErr             error
	unsealErr           error
	initShamirResp      *db.BarrierInitializeShamirResponse
	initShamirErr       error
	unsealShareResp     *db.BarrierUnsealShareResponse
	unsealShareErr      error
	rekeyResp           *db.BarrierRekeyResponse
	rekeyErr            error
	genRecoveryResp     *db.BarrierRecoveryKeysResponse
	genRecoveryErr      error
	recoverErr          error
	hasKeysResp         *db.BarrierHasRecoveryKeysResponse
	hasKeysErr          error
	genRootTokenResp    *db.BarrierRootTokenResponse
	genRootTokenErr     error
}

func newStubBarrierClient() *stubBarrierClient {
	return &stubBarrierClient{
		statusResp: &db.BarrierStatusResponse{
			Sealed:   false,
			Strategy: "passphrase",
		},
		initShamirResp: &db.BarrierInitializeShamirResponse{
			Threshold:   2,
			TotalShares: 3,
			ShareCount:  3,
		},
		unsealShareResp: &db.BarrierUnsealShareResponse{
			Required:  2,
			Submitted: 1,
			Complete:  false,
		},
		rekeyResp: &db.BarrierRekeyResponse{
			Threshold:   2,
			TotalShares: 3,
			ShareCount:  3,
		},
		genRecoveryResp: &db.BarrierRecoveryKeysResponse{
			Threshold:  2,
			Total:      3,
			ShareCount: 3,
		},
		hasKeysResp: &db.BarrierHasRecoveryKeysResponse{
			HasKeys: true,
		},
		genRootTokenResp: &db.BarrierRootTokenResponse{
			Token:     "root-token-abc",
			CreatedAt: "2025-01-01T00:00:00Z",
		},
	}
}

func (s *stubBarrierClient) BarrierStatus(_ context.Context) (*db.BarrierStatusResponse, error) {
	return s.statusResp, s.statusErr
}
func (s *stubBarrierClient) BarrierInitialize(_ context.Context, _ *db.BarrierInitializeRequest) error {
	return s.initErr
}
func (s *stubBarrierClient) BarrierSeal(_ context.Context) error {
	return s.sealErr
}
func (s *stubBarrierClient) BarrierUnseal(_ context.Context, _ *db.BarrierUnsealRequest) error {
	return s.unsealErr
}
func (s *stubBarrierClient) BarrierInitializeShamir(_ context.Context, _ *db.BarrierInitializeShamirRequest) (*db.BarrierInitializeShamirResponse, error) {
	return s.initShamirResp, s.initShamirErr
}
func (s *stubBarrierClient) BarrierUnsealWithShare(_ context.Context, _ *db.BarrierUnsealShareRequest) (*db.BarrierUnsealShareResponse, error) {
	return s.unsealShareResp, s.unsealShareErr
}
func (s *stubBarrierClient) BarrierUnsealWithShares(_ context.Context, _ *db.BarrierUnsealSharesRequest) error {
	return nil
}
func (s *stubBarrierClient) BarrierRekey(_ context.Context, _ *db.BarrierRekeyRequest) (*db.BarrierRekeyResponse, error) {
	return s.rekeyResp, s.rekeyErr
}
func (s *stubBarrierClient) BarrierGenerateRecoveryKeys(_ context.Context, _ *db.BarrierGenerateRecoveryKeysRequest) (*db.BarrierRecoveryKeysResponse, error) {
	return s.genRecoveryResp, s.genRecoveryErr
}
func (s *stubBarrierClient) BarrierRecoverWithKeys(_ context.Context, _ *db.BarrierRecoverWithKeysRequest) error {
	return s.recoverErr
}
func (s *stubBarrierClient) BarrierDeleteRecoveryKeys(_ context.Context) error {
	return nil
}
func (s *stubBarrierClient) BarrierHasRecoveryKeys(_ context.Context) (*db.BarrierHasRecoveryKeysResponse, error) {
	return s.hasKeysResp, s.hasKeysErr
}
func (s *stubBarrierClient) BarrierGenerateRootToken(_ context.Context, _ *db.BarrierGenerateRootTokenRequest) (*db.BarrierRootTokenResponse, error) {
	return s.genRootTokenResp, s.genRootTokenErr
}
func (s *stubBarrierClient) OfficerRegister(_ context.Context, _ *db.OfficerRegisterRequest) (*db.OfficerRegisterResponse, error) {
	return nil, nil
}
func (s *stubBarrierClient) RecoveryOfficerRegister(_ context.Context, _ *db.OfficerRegisterRequest) (*db.OfficerRegisterResponse, error) {
	return nil, nil
}
func (s *stubBarrierClient) OfficerList(_ context.Context) ([]*db.OfficerStatus, error) {
	return nil, nil
}
func (s *stubBarrierClient) OfficerClaimStatus(_ context.Context) ([]*db.OfficerStatus, error) {
	return nil, nil
}
func (s *stubBarrierClient) ShareClaimBegin(_ context.Context, _ *db.ShareClaimBeginRequest) (*db.ShareClaimBeginResponse, error) {
	return nil, nil
}
func (s *stubBarrierClient) ShareClaimComplete(_ context.Context, _ *db.ShareClaimCompleteRequest) (*db.ShareClaimCompleteResponse, error) {
	return nil, nil
}
func (s *stubBarrierClient) ShamirSealVote(_ context.Context, _ *db.ShamirSealVoteRequest) (*db.ShamirSealVoteResponse, error) {
	return nil, nil
}
func (s *stubBarrierClient) RecoveryShareClaimBegin(_ context.Context, _ *db.ShareClaimBeginRequest) (*db.ShareClaimBeginResponse, error) {
	return nil, nil
}
func (s *stubBarrierClient) RecoveryShareClaimComplete(_ context.Context, _ *db.ShareClaimCompleteRequest) (*db.ShareClaimCompleteResponse, error) {
	return nil, nil
}

// Compile-time check.
var _ db.BarrierClient = (*stubBarrierClient)(nil)

// ==========================================================================
// barrierService error types
// ==========================================================================

func TestBarrierErrors(t *testing.T) {
	t.Run("BarrierRemoteModeError", func(t *testing.T) {
		err := &BarrierRemoteModeError{Operation: "seal"}
		assert.Contains(t, err.Error(), "seal")
		assert.Contains(t, err.Error(), "remote mode")
	})

	t.Run("BarrierNotInitializedError", func(t *testing.T) {
		err := &BarrierNotInitializedError{}
		assert.Contains(t, err.Error(), "not initialized")
	})

	t.Run("BarrierError wraps underlying error", func(t *testing.T) {
		inner := errors.New("connection refused")
		err := &BarrierError{Operation: "status", Err: inner}
		assert.Contains(t, err.Error(), "status")
		assert.Contains(t, err.Error(), "connection refused")
		assert.Equal(t, inner, err.Unwrap())
	})

	t.Run("BarrierNotEnabledError", func(t *testing.T) {
		err := &BarrierNotEnabledError{Operation: "initialize"}
		assert.Contains(t, err.Error(), "initialize")
		assert.Contains(t, err.Error(), "not enabled")
	})
}

// ==========================================================================
// barrierService — all operations
// ==========================================================================

func newEmbeddedBarrierService(b db.BarrierClient) BarrierService {
	return NewBarrierService(BarrierModeEmbedded, b, slog.Default())
}

func TestBarrierService_Status_NilClient(t *testing.T) {
	svc := NewBarrierService(BarrierModeEmbedded, nil, slog.Default())

	resp, err := svc.Status(context.Background())
	require.NoError(t, err)
	assert.False(t, resp.Enabled)
	assert.False(t, resp.Sealed)
}

func TestBarrierService_Status_Success(t *testing.T) {
	stub := newStubBarrierClient()
	svc := newEmbeddedBarrierService(stub)

	resp, err := svc.Status(context.Background())
	require.NoError(t, err)
	assert.True(t, resp.Enabled)
	assert.False(t, resp.Sealed)
	assert.Equal(t, "passphrase", resp.Strategy)
}

func TestBarrierService_Status_Error(t *testing.T) {
	stub := newStubBarrierClient()
	stub.statusErr = errors.New("rpc error")
	svc := newEmbeddedBarrierService(stub)

	_, err := svc.Status(context.Background())
	require.Error(t, err)
	var be *BarrierError
	assert.True(t, errors.As(err, &be))
	assert.Equal(t, "status", be.Operation)
}

func TestBarrierService_Initialize_RequireEmbedded(t *testing.T) {
	tests := []struct {
		name    string
		svc     BarrierService
		wantErr bool
		errType interface{}
	}{
		{
			name:    "nil barrier returns BarrierNotEnabledError",
			svc:     NewBarrierService(BarrierModeEmbedded, nil, slog.Default()),
			wantErr: true,
			errType: &BarrierNotEnabledError{},
		},
		{
			name:    "remote mode returns BarrierRemoteModeError",
			svc:     NewBarrierService(BarrierModeRemote, newStubBarrierClient(), slog.Default()),
			wantErr: true,
			errType: &BarrierRemoteModeError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.svc.Initialize(context.Background(), &BarrierInitializeRequest{Secret: "s"})
			require.Error(t, err)
		})
	}
}

func TestBarrierService_Initialize_Success(t *testing.T) {
	stub := newStubBarrierClient()
	svc := newEmbeddedBarrierService(stub)

	err := svc.Initialize(context.Background(), &BarrierInitializeRequest{Secret: "secret"})
	require.NoError(t, err)
}

func TestBarrierService_Initialize_Error(t *testing.T) {
	stub := newStubBarrierClient()
	stub.initErr = errors.New("already initialized")
	svc := newEmbeddedBarrierService(stub)

	err := svc.Initialize(context.Background(), &BarrierInitializeRequest{Secret: "secret"})
	require.Error(t, err)
	var be *BarrierError
	assert.True(t, errors.As(err, &be))
}

func TestBarrierService_Seal_Success(t *testing.T) {
	stub := newStubBarrierClient()
	svc := newEmbeddedBarrierService(stub)

	err := svc.Seal(context.Background())
	require.NoError(t, err)
}

func TestBarrierService_Seal_Error(t *testing.T) {
	stub := newStubBarrierClient()
	stub.sealErr = errors.New("seal failed")
	svc := newEmbeddedBarrierService(stub)

	err := svc.Seal(context.Background())
	require.Error(t, err)
	var be *BarrierError
	assert.True(t, errors.As(err, &be))
}

func TestBarrierService_Seal_RemoteMode(t *testing.T) {
	svc := NewBarrierService(BarrierModeRemote, newStubBarrierClient(), slog.Default())
	err := svc.Seal(context.Background())
	require.Error(t, err)
	var re *BarrierRemoteModeError
	assert.True(t, errors.As(err, &re))
}

func TestBarrierService_Unseal_Success(t *testing.T) {
	stub := newStubBarrierClient()
	svc := newEmbeddedBarrierService(stub)

	err := svc.Unseal(context.Background(), &BarrierUnsealRequest{Secret: "secret"})
	require.NoError(t, err)
}

func TestBarrierService_Unseal_Error(t *testing.T) {
	stub := newStubBarrierClient()
	stub.unsealErr = errors.New("wrong passphrase")
	svc := newEmbeddedBarrierService(stub)

	err := svc.Unseal(context.Background(), &BarrierUnsealRequest{Secret: "bad"})
	require.Error(t, err)
	var be *BarrierError
	assert.True(t, errors.As(err, &be))
}

func TestBarrierService_InitializeShamir_Success(t *testing.T) {
	stub := newStubBarrierClient()
	svc := newEmbeddedBarrierService(stub)

	resp, err := svc.InitializeShamir(context.Background(), &BarrierInitializeShamirRequest{
		Secret:      "secret",
		Threshold:   2,
		TotalShares: 3,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Threshold)
	assert.Equal(t, 3, resp.TotalShares)
}

func TestBarrierService_InitializeShamir_Error(t *testing.T) {
	stub := newStubBarrierClient()
	stub.initShamirErr = errors.New("shamir failed")
	svc := newEmbeddedBarrierService(stub)

	_, err := svc.InitializeShamir(context.Background(), &BarrierInitializeShamirRequest{
		Secret:      "x",
		Threshold:   2,
		TotalShares: 3,
	})
	require.Error(t, err)
	var be *BarrierError
	assert.True(t, errors.As(err, &be))
}

func TestBarrierService_InitializeShamir_RemoteMode(t *testing.T) {
	svc := NewBarrierService(BarrierModeRemote, newStubBarrierClient(), slog.Default())
	_, err := svc.InitializeShamir(context.Background(), &BarrierInitializeShamirRequest{
		Secret:      "x",
		Threshold:   2,
		TotalShares: 3,
	})
	require.Error(t, err)
}

func TestBarrierService_UnsealWithShare_Success(t *testing.T) {
	stub := newStubBarrierClient()
	svc := newEmbeddedBarrierService(stub)

	resp, err := svc.UnsealWithShare(context.Background(), &BarrierUnsealShareRequest{Share: "share-1"})
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Required)
	assert.Equal(t, 1, resp.Submitted)
	assert.False(t, resp.Complete)
}

func TestBarrierService_UnsealWithShare_Error(t *testing.T) {
	stub := newStubBarrierClient()
	stub.unsealShareErr = errors.New("invalid share")
	svc := newEmbeddedBarrierService(stub)

	_, err := svc.UnsealWithShare(context.Background(), &BarrierUnsealShareRequest{Share: "bad"})
	require.Error(t, err)
}

func TestBarrierService_Rekey_Success(t *testing.T) {
	stub := newStubBarrierClient()
	svc := newEmbeddedBarrierService(stub)

	resp, err := svc.Rekey(context.Background(), &BarrierRekeyRequest{Threshold: 3, Total: 5})
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Threshold)
}

func TestBarrierService_Rekey_Error(t *testing.T) {
	stub := newStubBarrierClient()
	stub.rekeyErr = errors.New("rekey failed")
	svc := newEmbeddedBarrierService(stub)

	_, err := svc.Rekey(context.Background(), &BarrierRekeyRequest{Threshold: 2, Total: 3})
	require.Error(t, err)
}

func TestBarrierService_GenerateRecoveryKeys_Success(t *testing.T) {
	stub := newStubBarrierClient()
	svc := newEmbeddedBarrierService(stub)

	resp, err := svc.GenerateRecoveryKeys(context.Background(), &BarrierGenerateRecoveryKeysRequest{
		Threshold: 2,
		Total:     3,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Threshold)
	assert.Equal(t, 3, resp.Total)
}

func TestBarrierService_GenerateRecoveryKeys_Error(t *testing.T) {
	stub := newStubBarrierClient()
	stub.genRecoveryErr = errors.New("recovery failed")
	svc := newEmbeddedBarrierService(stub)

	_, err := svc.GenerateRecoveryKeys(context.Background(), &BarrierGenerateRecoveryKeysRequest{Threshold: 2, Total: 3})
	require.Error(t, err)
}

func TestBarrierService_RecoverWithKeys_Success(t *testing.T) {
	stub := newStubBarrierClient()
	svc := newEmbeddedBarrierService(stub)

	err := svc.RecoverWithKeys(context.Background(), &BarrierRecoverWithKeysRequest{Keys: []string{"k1", "k2"}})
	require.NoError(t, err)
}

func TestBarrierService_RecoverWithKeys_Error(t *testing.T) {
	stub := newStubBarrierClient()
	stub.recoverErr = errors.New("recovery error")
	svc := newEmbeddedBarrierService(stub)

	err := svc.RecoverWithKeys(context.Background(), &BarrierRecoverWithKeysRequest{Keys: []string{"k1"}})
	require.Error(t, err)
}

func TestBarrierService_HasRecoveryKeys_Success(t *testing.T) {
	stub := newStubBarrierClient()
	svc := newEmbeddedBarrierService(stub)

	has, err := svc.HasRecoveryKeys(context.Background())
	require.NoError(t, err)
	assert.True(t, has)
}

func TestBarrierService_HasRecoveryKeys_Error(t *testing.T) {
	stub := newStubBarrierClient()
	stub.hasKeysErr = errors.New("has-keys error")
	svc := newEmbeddedBarrierService(stub)

	_, err := svc.HasRecoveryKeys(context.Background())
	require.Error(t, err)
}

func TestBarrierService_GenerateRootToken_Success(t *testing.T) {
	stub := newStubBarrierClient()
	svc := newEmbeddedBarrierService(stub)

	resp, err := svc.GenerateRootToken(context.Background(), &BarrierGenerateRootTokenRequest{
		Shares: []string{"s1", "s2"},
	})
	require.NoError(t, err)
	assert.Equal(t, "root-token-abc", resp.Token)
}

func TestBarrierService_GenerateRootToken_Error(t *testing.T) {
	stub := newStubBarrierClient()
	stub.genRootTokenErr = errors.New("root token error")
	svc := newEmbeddedBarrierService(stub)

	_, err := svc.GenerateRootToken(context.Background(), &BarrierGenerateRootTokenRequest{
		Shares: []string{"s1"},
	})
	require.Error(t, err)
}

// ==========================================================================
// BarrierHandlers — HTTP handler tests
// ==========================================================================

// stubBarrierService is a simple in-memory BarrierService for handler tests.
type stubBarrierService struct {
	statusResp       *BarrierStatusResponse
	statusErr        error
	initErr          error
	sealErr          error
	unsealErr        error
	shamirResp       *BarrierInitializeShamirResponse
	shamirErr        error
	shareResp        *BarrierUnsealShareResponse
	shareErr         error
	rekeyResp        *BarrierRekeyResponse
	rekeyErr         error
	genRecoveryResp  *BarrierRecoveryKeysResponse
	genRecoveryErr   error
	recoverErr       error
	hasKeysResult    bool
	hasKeysErr       error
	rootTokenResp    *BarrierRootTokenResponse
	rootTokenErr     error
}

func newStubBarrierService() *stubBarrierService {
	return &stubBarrierService{
		statusResp:  &BarrierStatusResponse{Mode: BarrierModeEmbedded, Enabled: true, Sealed: false, Strategy: "passphrase"},
		shamirResp:  &BarrierInitializeShamirResponse{Threshold: 2, TotalShares: 3, ShareCount: 3},
		shareResp:   &BarrierUnsealShareResponse{Required: 2, Submitted: 1, Complete: false},
		rekeyResp:   &BarrierRekeyResponse{Threshold: 2, TotalShares: 3, ShareCount: 3},
		genRecoveryResp: &BarrierRecoveryKeysResponse{Threshold: 2, Total: 3, ShareCount: 3},
		hasKeysResult: true,
		rootTokenResp: &BarrierRootTokenResponse{Token: "tok", CreatedAt: "2025-01-01T00:00:00Z"},
	}
}

func (s *stubBarrierService) Status(_ context.Context) (*BarrierStatusResponse, error) {
	return s.statusResp, s.statusErr
}
func (s *stubBarrierService) Initialize(_ context.Context, _ *BarrierInitializeRequest) error {
	return s.initErr
}
func (s *stubBarrierService) Seal(_ context.Context) error { return s.sealErr }
func (s *stubBarrierService) Unseal(_ context.Context, _ *BarrierUnsealRequest) error {
	return s.unsealErr
}
func (s *stubBarrierService) InitializeShamir(_ context.Context, _ *BarrierInitializeShamirRequest) (*BarrierInitializeShamirResponse, error) {
	return s.shamirResp, s.shamirErr
}
func (s *stubBarrierService) UnsealWithShare(_ context.Context, _ *BarrierUnsealShareRequest) (*BarrierUnsealShareResponse, error) {
	return s.shareResp, s.shareErr
}
func (s *stubBarrierService) Rekey(_ context.Context, _ *BarrierRekeyRequest) (*BarrierRekeyResponse, error) {
	return s.rekeyResp, s.rekeyErr
}
func (s *stubBarrierService) GenerateRecoveryKeys(_ context.Context, _ *BarrierGenerateRecoveryKeysRequest) (*BarrierRecoveryKeysResponse, error) {
	return s.genRecoveryResp, s.genRecoveryErr
}
func (s *stubBarrierService) RecoverWithKeys(_ context.Context, _ *BarrierRecoverWithKeysRequest) error {
	return s.recoverErr
}
func (s *stubBarrierService) HasRecoveryKeys(_ context.Context) (bool, error) {
	return s.hasKeysResult, s.hasKeysErr
}
func (s *stubBarrierService) GenerateRootToken(_ context.Context, _ *BarrierGenerateRootTokenRequest) (*BarrierRootTokenResponse, error) {
	return s.rootTokenResp, s.rootTokenErr
}

// Compile-time check.
var _ BarrierService = (*stubBarrierService)(nil)

// newBarrierHandlerRouter sets up a mux router with barrier routes.
// It injects a super-admin auth middleware so that RequireRole guards pass.
func newBarrierHandlerRouter(svc BarrierService) *mux.Router {
	router := mux.NewRouter()
	h := NewBarrierHandlers(svc, slog.Default())
	h.RegisterRoutes(router, newTestAuthMiddleware(RoleSuperAdmin))
	return router
}

// newAuthedBarrierRequest creates a request with the super-admin bearer token set.
func newAuthedBarrierRequest(method, path string, body interface{}) *http.Request {
	var req *http.Request
	if body != nil {
		if b, ok := body.([]byte); ok {
			req = httptest.NewRequest(method, path, bytes.NewReader(b))
		} else {
			b, _ := json.Marshal(body)
			req = httptest.NewRequest(method, path, bytes.NewReader(b))
		}
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Header.Set("Authorization", "Bearer test-super-admin-key")
	return req
}

func TestBarrierHandlers_Status_Success(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	req := newAuthedBarrierRequest(http.MethodGet, "/admin/barrier/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp BarrierStatusResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.False(t, resp.Sealed)
}

func TestBarrierHandlers_Status_Error(t *testing.T) {
	svc := newStubBarrierService()
	svc.statusErr = errors.New("backend error")
	router := newBarrierHandlerRouter(svc)

	req := newAuthedBarrierRequest(http.MethodGet, "/admin/barrier/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestBarrierHandlers_Initialize_Success(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	body, _ := json.Marshal(map[string]string{"secret": "mysecret"})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/initialize", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBarrierHandlers_Initialize_BadJSON(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/initialize", []byte("not-json"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBarrierHandlers_Initialize_EmptySecret(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	body, _ := json.Marshal(map[string]string{"secret": ""})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/initialize", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBarrierHandlers_Initialize_ServiceError(t *testing.T) {
	svc := newStubBarrierService()
	svc.initErr = &BarrierNotEnabledError{Operation: "initialize"}
	router := newBarrierHandlerRouter(svc)

	body, _ := json.Marshal(map[string]string{"secret": "s"})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/initialize", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestBarrierHandlers_Initialize_RemoteModeError(t *testing.T) {
	svc := newStubBarrierService()
	svc.initErr = &BarrierRemoteModeError{Operation: "initialize"}
	router := newBarrierHandlerRouter(svc)

	body, _ := json.Marshal(map[string]string{"secret": "s"})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/initialize", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestBarrierHandlers_Initialize_NotInitializedError(t *testing.T) {
	svc := newStubBarrierService()
	svc.initErr = &BarrierNotInitializedError{}
	router := newBarrierHandlerRouter(svc)

	body, _ := json.Marshal(map[string]string{"secret": "s"})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/initialize", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestBarrierHandlers_Initialize_InternalError(t *testing.T) {
	svc := newStubBarrierService()
	svc.initErr = errors.New("internal error")
	router := newBarrierHandlerRouter(svc)

	body, _ := json.Marshal(map[string]string{"secret": "s"})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/initialize", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestBarrierHandlers_Seal_Success(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/seal", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBarrierHandlers_Seal_Error(t *testing.T) {
	svc := newStubBarrierService()
	svc.sealErr = errors.New("seal failed")
	router := newBarrierHandlerRouter(svc)
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/seal", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestBarrierHandlers_Unseal_Success(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	body, _ := json.Marshal(map[string]string{"secret": "s"})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/unseal", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBarrierHandlers_Unseal_BadJSON(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/unseal", []byte("bad"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBarrierHandlers_Unseal_EmptySecret(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	body, _ := json.Marshal(map[string]string{"secret": ""})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/unseal", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBarrierHandlers_Unseal_Error(t *testing.T) {
	svc := newStubBarrierService()
	svc.unsealErr = errors.New("wrong")
	router := newBarrierHandlerRouter(svc)
	body, _ := json.Marshal(map[string]string{"secret": "wrong"})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/unseal", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestBarrierHandlers_ShamirInitialize_Success(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	body, _ := json.Marshal(BarrierInitializeShamirRequest{
		Secret:      "s",
		Threshold:   2,
		TotalShares: 3,
	})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/shamir/initialize", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBarrierHandlers_ShamirInitialize_Validations(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())

	tests := []struct {
		name    string
		rawBody []byte
	}{
		{"bad json", []byte("not-json")},
		{"empty secret", mustMarshal(BarrierInitializeShamirRequest{Secret: "", Threshold: 2, TotalShares: 3})},
		{"zero threshold", mustMarshal(BarrierInitializeShamirRequest{Secret: "s", Threshold: 0, TotalShares: 3})},
		{"total < threshold", mustMarshal(BarrierInitializeShamirRequest{Secret: "s", Threshold: 3, TotalShares: 2})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/shamir/initialize", tt.rawBody)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestBarrierHandlers_ShamirInitialize_Error(t *testing.T) {
	svc := newStubBarrierService()
	svc.shamirErr = errors.New("shamir error")
	router := newBarrierHandlerRouter(svc)
	body, _ := json.Marshal(BarrierInitializeShamirRequest{Secret: "s", Threshold: 2, TotalShares: 3})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/shamir/initialize", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestBarrierHandlers_ShamirUnsealShare_Success(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	body, _ := json.Marshal(map[string]string{"share": "share-1"})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/shamir/unseal-share", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBarrierHandlers_ShamirUnsealShare_BadJSON(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/shamir/unseal-share", []byte("bad"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBarrierHandlers_ShamirUnsealShare_EmptyShare(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	body, _ := json.Marshal(map[string]string{"share": ""})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/shamir/unseal-share", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBarrierHandlers_ShamirUnsealShare_Error(t *testing.T) {
	svc := newStubBarrierService()
	svc.shareErr = errors.New("bad share")
	router := newBarrierHandlerRouter(svc)
	body, _ := json.Marshal(map[string]string{"share": "s"})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/shamir/unseal-share", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestBarrierHandlers_Rekey_Success(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	body, _ := json.Marshal(BarrierRekeyRequest{Threshold: 2, Total: 3})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/rekey", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBarrierHandlers_Rekey_Validations(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())

	tests := []struct {
		name    string
		rawBody []byte
	}{
		{"bad json", []byte("bad")},
		{"zero threshold", mustMarshal(BarrierRekeyRequest{Threshold: 0, Total: 3})},
		{"total < threshold", mustMarshal(BarrierRekeyRequest{Threshold: 3, Total: 2})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/rekey", tt.rawBody)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestBarrierHandlers_Rekey_Error(t *testing.T) {
	svc := newStubBarrierService()
	svc.rekeyErr = errors.New("rekey error")
	router := newBarrierHandlerRouter(svc)
	body, _ := json.Marshal(BarrierRekeyRequest{Threshold: 2, Total: 3})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/rekey", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestBarrierHandlers_RecoveryGenerate_Success(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	body, _ := json.Marshal(BarrierGenerateRecoveryKeysRequest{Threshold: 2, Total: 3})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/recovery/generate", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBarrierHandlers_RecoveryGenerate_Validations(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())

	tests := []struct {
		name    string
		rawBody []byte
	}{
		{"bad json", []byte("bad")},
		{"zero threshold", mustMarshal(BarrierGenerateRecoveryKeysRequest{Threshold: 0, Total: 3})},
		{"total < threshold", mustMarshal(BarrierGenerateRecoveryKeysRequest{Threshold: 3, Total: 2})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/recovery/generate", tt.rawBody)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestBarrierHandlers_RecoveryGenerate_Error(t *testing.T) {
	svc := newStubBarrierService()
	svc.genRecoveryErr = errors.New("recovery gen error")
	router := newBarrierHandlerRouter(svc)
	body, _ := json.Marshal(BarrierGenerateRecoveryKeysRequest{Threshold: 2, Total: 3})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/recovery/generate", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestBarrierHandlers_RecoveryRecover_Success(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	body, _ := json.Marshal(BarrierRecoverWithKeysRequest{Keys: []string{"k1", "k2"}})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/recovery/recover", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBarrierHandlers_RecoveryRecover_BadJSON(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/recovery/recover", []byte("bad"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBarrierHandlers_RecoveryRecover_EmptyKeys(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	body, _ := json.Marshal(BarrierRecoverWithKeysRequest{Keys: []string{}})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/recovery/recover", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBarrierHandlers_RecoveryRecover_Error(t *testing.T) {
	svc := newStubBarrierService()
	svc.recoverErr = errors.New("recover error")
	router := newBarrierHandlerRouter(svc)
	body, _ := json.Marshal(BarrierRecoverWithKeysRequest{Keys: []string{"k1"}})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/recovery/recover", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestBarrierHandlers_RecoveryStatus_Success(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	req := newAuthedBarrierRequest(http.MethodGet, "/admin/barrier/recovery/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]bool
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["has_recovery_keys"])
}

func TestBarrierHandlers_RecoveryStatus_Error(t *testing.T) {
	svc := newStubBarrierService()
	svc.hasKeysErr = errors.New("status error")
	router := newBarrierHandlerRouter(svc)
	req := newAuthedBarrierRequest(http.MethodGet, "/admin/barrier/recovery/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestBarrierHandlers_RootToken_Success(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	body, _ := json.Marshal(BarrierGenerateRootTokenRequest{Shares: []string{"s1", "s2"}})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/root-token", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp BarrierRootTokenResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "tok", resp.Token)
}

func TestBarrierHandlers_RootToken_BadJSON(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/root-token", []byte("bad"))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBarrierHandlers_RootToken_EmptyShares(t *testing.T) {
	router := newBarrierHandlerRouter(newStubBarrierService())
	body, _ := json.Marshal(BarrierGenerateRootTokenRequest{Shares: []string{}})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/root-token", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBarrierHandlers_RootToken_Error(t *testing.T) {
	svc := newStubBarrierService()
	svc.rootTokenErr = errors.New("root token error")
	router := newBarrierHandlerRouter(svc)
	body, _ := json.Marshal(BarrierGenerateRootTokenRequest{Shares: []string{"s1"}})
	req := newAuthedBarrierRequest(http.MethodPost, "/admin/barrier/root-token", body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// mustMarshal is a test helper that panics if json.Marshal fails.
func mustMarshal(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
