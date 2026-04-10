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
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/bootstrap"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bootstrapTestLogger returns a slog.Logger for testing.
func bootstrapTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
}

// createBootstrapTestUserStore creates a user.Store backed by in-memory storage.
func createBootstrapTestUserStore(t *testing.T) user.Store {
	t.Helper()
	backend := storage.NewMemory()
	store, err := user.NewFileStore(backend, user.WithCleanupInterval(24*time.Hour))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}

// createBootstrapTestService creates a bootstrap.Service for testing.
func createBootstrapTestService(t *testing.T) (*bootstrap.Service, user.Store) {
	t.Helper()
	userStore := createBootstrapTestUserStore(t)
	svc, err := bootstrap.NewService(bootstrap.Config{
		TokenTTL: 10 * time.Minute,
	}, userStore, bootstrapTestLogger())
	require.NoError(t, err)
	return svc, userStore
}

// createBootstrapHandlersHelper creates BootstrapHandlers for testing.
func createBootstrapHandlersHelper(t *testing.T) (*BootstrapHandlers, *bootstrap.Service, user.Store) {
	t.Helper()
	svc, userStore := createBootstrapTestService(t)
	handlers := NewBootstrapHandlers(svc, bootstrapTestLogger())
	return handlers, svc, userStore
}

// TestBootstrapHandleGetStatusUninitialized verifies that the status endpoint
// returns the uninitialized state when no setup token has been generated.
func TestBootstrapHandleGetStatusUninitialized(t *testing.T) {
	handlers, _, _ := createBootstrapHandlersHelper(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/status", nil)
	rec := httptest.NewRecorder()

	handlers.HandleGetStatus(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp BootstrapStatusAPIResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, bootstrap.StateUninitialized, resp.State)
	assert.Contains(t, resp.Message, "initialization")
}

// TestBootstrapHandleGetStatusReady verifies that the status endpoint returns
// the ready state after a setup token has been generated.
func TestBootstrapHandleGetStatusReady(t *testing.T) {
	handlers, svc, _ := createBootstrapHandlersHelper(t)

	_, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/status", nil)
	rec := httptest.NewRecorder()

	handlers.HandleGetStatus(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp BootstrapStatusAPIResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, bootstrap.StateReady, resp.State)
	assert.Contains(t, resp.Message, "ready")
}

// TestBootstrapHandleGetStatusComplete verifies that the status endpoint returns
// the complete state after initialization.
func TestBootstrapHandleGetStatusComplete(t *testing.T) {
	handlers, svc, _ := createBootstrapHandlersHelper(t)

	// Generate token and initialize
	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	_, err = svc.Initialize(context.Background(), &bootstrap.InitRequest{
		SetupToken:       token.Token,
		Username:         "admin",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/status", nil)
	rec := httptest.NewRecorder()

	handlers.HandleGetStatus(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp BootstrapStatusAPIResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, bootstrap.StateComplete, resp.State)
	assert.Contains(t, resp.Message, "initialized")
}

// TestBootstrapHandleGetStatusCeremony verifies that the status endpoint returns
// the ceremony state during threshold initialization.
func TestBootstrapHandleGetStatusCeremony(t *testing.T) {
	userStore := createBootstrapTestUserStore(t)
	svc, err := bootstrap.NewService(bootstrap.Config{
		TokenTTL:       10 * time.Minute,
		ThresholdMode:  true,
		AdminThreshold: 2,
		AdminTotal:     3,
	}, userStore, bootstrapTestLogger())
	require.NoError(t, err)

	handlers := NewBootstrapHandlers(svc, bootstrapTestLogger())

	// Initialize first admin to enter ceremony state
	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)
	_, err = svc.Initialize(context.Background(), &bootstrap.InitRequest{
		SetupToken:       token.Token,
		Username:         "admin1",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/status", nil)
	rec := httptest.NewRecorder()

	handlers.HandleGetStatus(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp BootstrapStatusAPIResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, bootstrap.StateCeremony, resp.State)
	assert.Contains(t, resp.Message, "ceremony")
}

// TestBootstrapHandleInitSuccess verifies that the init endpoint succeeds
// with a valid request.
func TestBootstrapHandleInitSuccess(t *testing.T) {
	handlers, svc, _ := createBootstrapHandlersHelper(t)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	initReq := bootstrap.InitRequest{
		SetupToken:       token.Token,
		Username:         "admin",
		DisplayName:      "Admin User",
		FIDO2Attestation: json.RawMessage(`{"type":"public-key"}`),
	}
	body, err := json.Marshal(initReq)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleInit(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp bootstrap.InitResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, "admin", resp.Username)
	assert.NotEmpty(t, resp.UserID)
}

// TestBootstrapHandleInitInvalidJSON verifies that the init endpoint returns
// 400 for malformed JSON.
func TestBootstrapHandleInitInvalidJSON(t *testing.T) {
	handlers, svc, _ := createBootstrapHandlersHelper(t)

	_, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleInit(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestBootstrapHandleInitBadToken verifies that the init endpoint returns
// 401 for an invalid setup token.
func TestBootstrapHandleInitBadToken(t *testing.T) {
	handlers, svc, _ := createBootstrapHandlersHelper(t)

	_, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	initReq := bootstrap.InitRequest{
		SetupToken:       "wrong-token",
		Username:         "admin",
		FIDO2Attestation: json.RawMessage(`{"type":"public-key"}`),
	}
	body, err := json.Marshal(initReq)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleInit(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestBootstrapHandleInitAlreadyInitialized verifies that the init endpoint returns
// 409 when the system is already initialized.
func TestBootstrapHandleInitAlreadyInitialized(t *testing.T) {
	handlers, svc, _ := createBootstrapHandlersHelper(t)

	// Initialize the system first
	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	_, err = svc.Initialize(context.Background(), &bootstrap.InitRequest{
		SetupToken:       token.Token,
		Username:         "admin",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)

	// Try to initialize again
	initReq := bootstrap.InitRequest{
		SetupToken:       "any-token",
		Username:         "admin2",
		FIDO2Attestation: json.RawMessage(`{"type":"public-key"}`),
	}
	body, err := json.Marshal(initReq)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleInit(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

// TestBootstrapHandleInitEmptyUsername verifies that the init endpoint returns
// 400 when the username is empty.
func TestBootstrapHandleInitEmptyUsername(t *testing.T) {
	handlers, svc, _ := createBootstrapHandlersHelper(t)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	initReq := bootstrap.InitRequest{
		SetupToken:       token.Token,
		Username:         "",
		FIDO2Attestation: json.RawMessage(`{"type":"public-key"}`),
	}
	body, err := json.Marshal(initReq)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleInit(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestBootstrapHandleInitExpiredToken verifies that the init endpoint returns
// 410 (Gone) when the setup token has expired.
func TestBootstrapHandleInitExpiredToken(t *testing.T) {
	userStore := createBootstrapTestUserStore(t)
	svc, err := bootstrap.NewService(bootstrap.Config{
		TokenTTL: 1 * time.Nanosecond, // Ultra-short TTL
	}, userStore, bootstrapTestLogger())
	require.NoError(t, err)

	handlers := NewBootstrapHandlers(svc, bootstrapTestLogger())

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	initReq := bootstrap.InitRequest{
		SetupToken:       token.Token,
		Username:         "admin",
		FIDO2Attestation: json.RawMessage(`{"type":"public-key"}`),
	}
	body, err := json.Marshal(initReq)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleInit(rec, req)

	assert.Equal(t, http.StatusGone, rec.Code)
}

// TestBootstrapHandleThresholdInitWithSetupToken verifies that the threshold
// init endpoint works with a setup token (first admin).
func TestBootstrapHandleThresholdInitWithSetupToken(t *testing.T) {
	userStore := createBootstrapTestUserStore(t)
	svc, err := bootstrap.NewService(bootstrap.Config{
		TokenTTL:       10 * time.Minute,
		ThresholdMode:  true,
		AdminThreshold: 2,
		AdminTotal:     3,
	}, userStore, bootstrapTestLogger())
	require.NoError(t, err)

	handlers := NewBootstrapHandlers(svc, bootstrapTestLogger())

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	thresholdReq := bootstrap.ThresholdInitRequest{
		SetupToken:       token.Token,
		Username:         "admin1",
		DisplayName:      "First Admin",
		FIDO2Attestation: json.RawMessage(`{"type":"public-key"}`),
	}
	body, err := json.Marshal(thresholdReq)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/threshold", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleThresholdInit(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp bootstrap.InitResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "admin1", resp.Username)

	// Should be in ceremony state for threshold mode
	assert.Equal(t, bootstrap.StateCeremony, svc.State())
}

// TestBootstrapHandleThresholdInitWithSetupTokenError verifies that the threshold
// init endpoint returns the correct error when the setup token is invalid.
func TestBootstrapHandleThresholdInitWithSetupTokenError(t *testing.T) {
	userStore := createBootstrapTestUserStore(t)
	svc, err := bootstrap.NewService(bootstrap.Config{
		TokenTTL:       10 * time.Minute,
		ThresholdMode:  true,
		AdminThreshold: 2,
		AdminTotal:     3,
	}, userStore, bootstrapTestLogger())
	require.NoError(t, err)

	handlers := NewBootstrapHandlers(svc, bootstrapTestLogger())

	_, err = svc.GenerateSetupToken()
	require.NoError(t, err)

	thresholdReq := bootstrap.ThresholdInitRequest{
		SetupToken:       "wrong-token",
		Username:         "admin1",
		FIDO2Attestation: json.RawMessage(`{"type":"public-key"}`),
	}
	body, err := json.Marshal(thresholdReq)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/threshold", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleThresholdInit(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestBootstrapHandleThresholdInitWithInvitation verifies that the threshold
// init endpoint works with an invitation token (subsequent admins).
func TestBootstrapHandleThresholdInitWithInvitation(t *testing.T) {
	userStore := createBootstrapTestUserStore(t)
	svc, err := bootstrap.NewService(bootstrap.Config{
		TokenTTL:       10 * time.Minute,
		ThresholdMode:  true,
		AdminThreshold: 2,
		AdminTotal:     3,
	}, userStore, bootstrapTestLogger())
	require.NoError(t, err)

	handlers := NewBootstrapHandlers(svc, bootstrapTestLogger())

	// Initialize first admin
	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)
	_, err = svc.Initialize(context.Background(), &bootstrap.InitRequest{
		SetupToken:       token.Token,
		Username:         "admin1",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)

	// Generate invitations
	invitations, err := svc.GenerateInvitations(1)
	require.NoError(t, err)

	thresholdReq := bootstrap.ThresholdInitRequest{
		Invitation:       invitations[0].Token,
		Username:         "admin2",
		FIDO2Attestation: json.RawMessage(`{"type":"public-key"}`),
	}
	body, err := json.Marshal(thresholdReq)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/threshold", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleThresholdInit(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestBootstrapHandleThresholdInitInvalidInvitation verifies that the threshold
// init endpoint returns 401 for an invalid invitation token.
func TestBootstrapHandleThresholdInitInvalidInvitation(t *testing.T) {
	userStore := createBootstrapTestUserStore(t)
	svc, err := bootstrap.NewService(bootstrap.Config{
		TokenTTL:       10 * time.Minute,
		ThresholdMode:  true,
		AdminThreshold: 2,
		AdminTotal:     3,
	}, userStore, bootstrapTestLogger())
	require.NoError(t, err)

	handlers := NewBootstrapHandlers(svc, bootstrapTestLogger())

	// Initialize first admin to enter ceremony state
	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)
	_, err = svc.Initialize(context.Background(), &bootstrap.InitRequest{
		SetupToken:       token.Token,
		Username:         "admin1",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)

	thresholdReq := bootstrap.ThresholdInitRequest{
		Invitation:       "bad-invitation-token",
		Username:         "admin2",
		FIDO2Attestation: json.RawMessage(`{"type":"public-key"}`),
	}
	body, err := json.Marshal(thresholdReq)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/threshold", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleThresholdInit(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestBootstrapHandleThresholdInitUsedInvitation verifies that the threshold
// init endpoint returns 409 for an already-used invitation token.
func TestBootstrapHandleThresholdInitUsedInvitation(t *testing.T) {
	userStore := createBootstrapTestUserStore(t)
	svc, err := bootstrap.NewService(bootstrap.Config{
		TokenTTL:       10 * time.Minute,
		ThresholdMode:  true,
		AdminThreshold: 2,
		AdminTotal:     3,
	}, userStore, bootstrapTestLogger())
	require.NoError(t, err)

	handlers := NewBootstrapHandlers(svc, bootstrapTestLogger())

	// Initialize first admin
	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)
	_, err = svc.Initialize(context.Background(), &bootstrap.InitRequest{
		SetupToken:       token.Token,
		Username:         "admin1",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)

	// Generate and consume an invitation
	invitations, err := svc.GenerateInvitations(1)
	require.NoError(t, err)
	err = svc.ConsumeInvitation(invitations[0].Token)
	require.NoError(t, err)

	// Try to use the consumed invitation via the handler
	thresholdReq := bootstrap.ThresholdInitRequest{
		Invitation:       invitations[0].Token,
		Username:         "admin3",
		FIDO2Attestation: json.RawMessage(`{"type":"public-key"}`),
	}
	body, err := json.Marshal(thresholdReq)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/threshold", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleThresholdInit(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

// TestBootstrapHandleThresholdInitInvalidJSON verifies that the threshold init
// endpoint returns 400 for malformed JSON.
func TestBootstrapHandleThresholdInitInvalidJSON(t *testing.T) {
	handlers, _, _ := createBootstrapHandlersHelper(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/threshold", bytes.NewReader([]byte("{bad")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleThresholdInit(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestBootstrapHandleThresholdInitNoToken verifies that the threshold init
// endpoint returns 400 when neither a setup token nor invitation is provided.
func TestBootstrapHandleThresholdInitNoToken(t *testing.T) {
	handlers, _, _ := createBootstrapHandlersHelper(t)

	thresholdReq := bootstrap.ThresholdInitRequest{
		Username:         "admin",
		FIDO2Attestation: json.RawMessage(`{"type":"public-key"}`),
	}
	body, err := json.Marshal(thresholdReq)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/init/threshold", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleThresholdInit(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestBootstrapHandlersNilLogger verifies that NewBootstrapHandlers uses
// a default logger when nil is passed.
func TestBootstrapHandlersNilLogger(t *testing.T) {
	svc, _ := createBootstrapTestService(t)
	handlers := NewBootstrapHandlers(svc, nil)
	assert.NotNil(t, handlers)
	assert.NotNil(t, handlers.logger)
}

// TestBootstrapMapErrorUnknown verifies that unknown errors map to 500.
func TestBootstrapMapErrorUnknown(t *testing.T) {
	status := mapBootstrapError(assert.AnError)
	assert.Equal(t, http.StatusInternalServerError, status)
}

// TestBootstrapMapErrorKnownCodes verifies that known bootstrap errors map
// to the correct HTTP status codes.
func TestBootstrapMapErrorKnownCodes(t *testing.T) {
	tests := []struct {
		err      error
		expected int
	}{
		{bootstrap.ErrAlreadyInitialized, http.StatusConflict},
		{bootstrap.ErrNotReady, http.StatusServiceUnavailable},
		{bootstrap.ErrInvalidToken, http.StatusUnauthorized},
		{bootstrap.ErrTokenExpired, http.StatusGone},
		{bootstrap.ErrTokenUsed, http.StatusConflict},
		{bootstrap.ErrNoToken, http.StatusServiceUnavailable},
		{bootstrap.ErrInvalidRequest, http.StatusBadRequest},
		{bootstrap.ErrUsernameTaken, http.StatusConflict},
		{bootstrap.ErrEmptyUsername, http.StatusBadRequest},
		{bootstrap.ErrEmptyToken, http.StatusBadRequest},
		{bootstrap.ErrEmptyAttestation, http.StatusBadRequest},
		{bootstrap.ErrInvalidInvitation, http.StatusUnauthorized},
		{bootstrap.ErrInvitationExpired, http.StatusGone},
		{bootstrap.ErrInvitationUsed, http.StatusConflict},
		{bootstrap.ErrCeremonyNotStarted, http.StatusServiceUnavailable},
		{bootstrap.ErrCeremonyComplete, http.StatusConflict},
	}

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			status := mapBootstrapError(tt.err)
			assert.Equal(t, tt.expected, status)
		})
	}
}
