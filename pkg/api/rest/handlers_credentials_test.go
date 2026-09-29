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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// credTestService creates a manual-strategy credential service for tests.
func credTestService(t *testing.T) *credentials.Service {
	t.Helper()
	svc, err := credentials.New(
		&credentials.Config{Strategy: credentials.StrategyManual},
		nil, nil, initTestLogger(),
	)
	require.NoError(t, err)
	return svc
}

// credentialServiceOver returns an XKMSService composed with creds: the
// handlers reach the credential service only through it, which enforces its
// platform scope.
func credentialServiceOver(creds *credentials.Service) *xkms.XKMSService {
	svc := &xkms.XKMSService{}
	svc.SetCredentialService(creds)
	return svc
}

// credTestHandlers creates CredentialHandlers with a manual-strategy service.
func credTestHandlers(t *testing.T) *CredentialHandlers {
	t.Helper()
	return NewCredentialHandlers(credentialServiceOver(credTestService(t)), initTestLogger())
}

// ---------------------------------------------------------------------------
// HandleSubmit tests
// ---------------------------------------------------------------------------

// TestCredentialHandleSubmit_Success verifies that a valid credential
// submission returns 200 with status "accepted".
func TestCredentialHandleSubmit_Success(t *testing.T) {
	handlers := credTestHandlers(t)

	body, err := json.Marshal(CredentialSubmitRequest{
		Name:  "backend-password",
		Value: base64.StdEncoding.EncodeToString([]byte("s3cret")),
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/submit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleSubmit(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp CredentialSubmitResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "accepted", resp.Status)
}

// TestCredentialHandleSubmit_InvalidJSON verifies 400 for malformed JSON.
func TestCredentialHandleSubmit_InvalidJSON(t *testing.T) {
	handlers := credTestHandlers(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/submit", bytes.NewReader([]byte("{bad")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleSubmit(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestCredentialHandleSubmit_MissingName verifies 400 for empty name.
func TestCredentialHandleSubmit_MissingName(t *testing.T) {
	handlers := credTestHandlers(t)

	body, err := json.Marshal(CredentialSubmitRequest{
		Value: base64.StdEncoding.EncodeToString([]byte("s3cret")),
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/submit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleSubmit(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Error, "missing credential name")
}

// TestCredentialHandleSubmit_MissingValue verifies 400 for empty value.
func TestCredentialHandleSubmit_MissingValue(t *testing.T) {
	handlers := credTestHandlers(t)

	body, err := json.Marshal(CredentialSubmitRequest{
		Name: "backend-password",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/submit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleSubmit(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Error, "missing credential value")
}

// TestCredentialHandleSubmit_InvalidBase64 verifies 400 for invalid base64
// in the value field.
func TestCredentialHandleSubmit_InvalidBase64(t *testing.T) {
	handlers := credTestHandlers(t)

	body, err := json.Marshal(CredentialSubmitRequest{
		Name:  "backend-password",
		Value: "not-valid-base64!!!",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/submit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.HandleSubmit(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestCredentialHandleSubmit_AlreadySubmitted verifies 409 when the same
// credential name is submitted twice in manual mode.
func TestCredentialHandleSubmit_AlreadySubmitted(t *testing.T) {
	handlers := credTestHandlers(t)

	body, err := json.Marshal(CredentialSubmitRequest{
		Name:  "backend-password",
		Value: base64.StdEncoding.EncodeToString([]byte("s3cret")),
	})
	require.NoError(t, err)

	// First submission succeeds.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/submit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handlers.HandleSubmit(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Second submission returns 409.
	body, err = json.Marshal(CredentialSubmitRequest{
		Name:  "backend-password",
		Value: base64.StdEncoding.EncodeToString([]byte("other")),
	})
	require.NoError(t, err)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/credentials/submit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	handlers.HandleSubmit(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

// ---------------------------------------------------------------------------
// HandleGetStrategy tests
// ---------------------------------------------------------------------------

// TestCredentialHandleGetStrategy_Manual verifies that the strategy endpoint
// returns "manual" and auto_unseal=false for a manual-strategy service.
func TestCredentialHandleGetStrategy_Manual(t *testing.T) {
	handlers := credTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/credentials/strategy", nil)
	rec := httptest.NewRecorder()

	handlers.HandleGetStrategy(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp CredentialStrategyResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, credentials.StrategyManual, resp.Strategy)
	assert.False(t, resp.AutoUnseal)
}

// TestCredentialHandleGetStrategy_Barrier verifies that the strategy endpoint
// returns "barrier" and auto_unseal=true for a barrier-strategy service.
func TestCredentialHandleGetStrategy_Barrier(t *testing.T) {
	barrier := initTestBarrier(t)
	svc, err := credentials.New(
		&credentials.Config{Strategy: "barrier"},
		nil, barrier, initTestLogger(),
	)
	require.NoError(t, err)

	handlers := NewCredentialHandlers(credentialServiceOver(svc), initTestLogger())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/credentials/strategy", nil)
	rec := httptest.NewRecorder()

	handlers.HandleGetStrategy(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp CredentialStrategyResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "barrier", resp.Strategy)
	assert.True(t, resp.AutoUnseal)
}

// ---------------------------------------------------------------------------
// Constructor and error mapping tests
// ---------------------------------------------------------------------------

// TestNewCredentialHandlers_NilLogger verifies that NewCredentialHandlers
// uses a default logger when nil is passed.
func TestNewCredentialHandlers_NilLogger(t *testing.T) {
	handlers := NewCredentialHandlers(credentialServiceOver(credTestService(t)), nil)
	assert.NotNil(t, handlers)
	assert.NotNil(t, handlers.logger)
}

// TestMapCredentialError_UnknownError verifies that unknown errors map to 500.
func TestMapCredentialError_UnknownError(t *testing.T) {
	status := mapCredentialError(assert.AnError)
	assert.Equal(t, http.StatusInternalServerError, status)
}

// TestMapCredentialError_KnownCodes verifies that known credential errors
// map to the correct HTTP status codes.
func TestMapCredentialError_KnownCodes(t *testing.T) {
	tests := []struct {
		err      error
		expected int
	}{
		{credentials.ErrEmptyCredentialName, http.StatusBadRequest},
		{credentials.ErrEmptyCredentialValue, http.StatusBadRequest},
		{credentials.ErrCredentialNotFound, http.StatusNotFound},
		{credentials.ErrCredentialAlreadySubmitted, http.StatusConflict},
		{credentials.ErrInvalidStrategy, http.StatusBadRequest},
		{xkms.ErrInvalidEncoding, http.StatusBadRequest},
		{xkms.ErrNotConfigured, http.StatusServiceUnavailable},
		{&xkms.TenantBindingError{Op: "submit credential", CallerTenantID: "tenant-a"}, http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			status := mapCredentialError(tt.err)
			assert.Equal(t, tt.expected, status)
		})
	}
}

// ---------------------------------------------------------------------------
// HandleList tests
// ---------------------------------------------------------------------------

// TestCredentialHandleList_Empty verifies an empty store serializes as [] and
// not null, so a client can iterate the result without a nil check.
func TestCredentialHandleList_Empty(t *testing.T) {
	handlers := credTestHandlers(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/credentials", nil)
	w := httptest.NewRecorder()
	handlers.HandleList(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"names":[]`)

	var resp CredentialListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.Names)
	require.Empty(t, resp.Names)
}

// TestCredentialHandleList_ReportsSubmittedNames verifies submitted
// credentials appear in the listing.
func TestCredentialHandleList_ReportsSubmittedNames(t *testing.T) {
	svc := credTestService(t)
	handlers := NewCredentialHandlers(credentialServiceOver(svc), initTestLogger())

	require.NoError(t, svc.SubmitCredential(context.Background(), "pkcs11-user-pin", []byte("secret-value")))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/credentials", nil)
	w := httptest.NewRecorder()
	handlers.HandleList(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp CredentialListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Equal(t, []string{"pkcs11-user-pin"}, resp.Names)
}

// TestCredentialHandleList_NeverLeaksValues is the security property at the
// HTTP boundary: the response body must not contain the credential value.
func TestCredentialHandleList_NeverLeaksValues(t *testing.T) {
	svc := credTestService(t)
	handlers := NewCredentialHandlers(credentialServiceOver(svc), initTestLogger())

	const secret = "TOP-SECRET-PIN-VALUE"
	require.NoError(t, svc.SubmitCredential(context.Background(), "pkcs11-user-pin", []byte(secret)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/credentials", nil)
	w := httptest.NewRecorder()
	handlers.HandleList(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotContains(t, w.Body.String(), secret,
		"a credential value must never appear in a listing response")
}
