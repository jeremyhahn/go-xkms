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

package handlers

import (
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCABundleHandler_Success(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/acme/ca-bundle", nil)
	w := httptest.NewRecorder()

	service.CABundleHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/pem-certificate-chain", w.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))

	// Verify bundle content
	body := w.Body.Bytes()
	require.NotEmpty(t, body)
	assert.Equal(t, []byte("mock-bundle"), body)
}

func TestCABundleHandler_ContentType(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/acme/ca-bundle", nil)
	w := httptest.NewRecorder()

	service.CABundleHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/pem-certificate-chain", w.Header().Get("Content-Type"))
}

func TestCABundleHandler_CacheControl(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/acme/ca-bundle", nil)
	w := httptest.NewRecorder()

	service.CABundleHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

func TestCABundleHandler_ValidPEMBundle(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/acme/ca-bundle", nil)
	w := httptest.NewRecorder()

	service.CABundleHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify we got the bundle from the mock CA
	body := w.Body.Bytes()
	require.NotEmpty(t, body)
	assert.Equal(t, []byte("mock-bundle"), body)
}

func TestCABundleHandler_HTTPMethods(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	tests := []struct {
		name       string
		method     string
		expectCode int
	}{
		{"GET request", http.MethodGet, http.StatusOK},
		{"HEAD request", http.MethodHead, http.StatusOK},
		{"POST request", http.MethodPost, http.StatusOK},
		{"PUT request", http.MethodPut, http.StatusOK},
		{"DELETE request", http.MethodDelete, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/acme/ca-bundle", nil)
			w := httptest.NewRecorder()

			service.CABundleHandler(w, req)

			// All methods should succeed since there's no method checking in the handler
			assert.Equal(t, tt.expectCode, w.Code)
			if tt.method != http.MethodHead {
				assert.NotEmpty(t, w.Body.Bytes())
			}
		})
	}
}

// MockCAWithError is a mock CA that returns an error when fetching the bundle
type MockCAWithError struct {
	MockCA
}

func (m *MockCAWithError) CABundleFiltered(_ xkmssdk.StoreType, _ x509.PublicKeyAlgorithm) ([]byte, error) {
	return nil, errors.New("failed to get CA bundle")
}

func TestCABundleHandler_BundleError(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Replace the CA with one that returns an error
	service.ca = &MockCAWithError{}

	req := httptest.NewRequest(http.MethodGet, "/acme/ca-bundle", nil)
	w := httptest.NewRecorder()

	service.CABundleHandler(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "application/problem+json", w.Header().Get("Content-Type"))

	// Verify error response
	acmeError := parseErrorResponse(t, w)
	assert.Contains(t, acmeError.Type, "serverInternal")
	assert.Contains(t, acmeError.Detail, "Failed to get CA bundle")
}

// MockCAEmpty is a mock CA that returns an empty bundle
type MockCAEmpty struct {
	MockCA
}

func (m *MockCAEmpty) CABundleFiltered(_ xkmssdk.StoreType, _ x509.PublicKeyAlgorithm) ([]byte, error) {
	return []byte{}, nil
}

func TestCABundleHandler_EmptyBundle(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Replace with a mock CA that returns an empty bundle
	service.ca = &MockCAEmpty{}

	req := httptest.NewRequest(http.MethodGet, "/acme/ca-bundle", nil)
	w := httptest.NewRecorder()

	service.CABundleHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/pem-certificate-chain", w.Header().Get("Content-Type"))

	// Empty bundle should still return successfully
	body := w.Body.Bytes()
	assert.Empty(t, body)
}

func TestCABundleHandler_MultipleRequests(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Test multiple consecutive requests to ensure idempotency
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/acme/ca-bundle", nil)
		w := httptest.NewRecorder()

		service.CABundleHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/pem-certificate-chain", w.Header().Get("Content-Type"))
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))

		body := w.Body.Bytes()
		require.NotEmpty(t, body)
		assert.Equal(t, []byte("mock-bundle"), body)
	}
}

func TestCABundleHandler_WithHeaders(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/acme/ca-bundle", nil)
	req.Header.Set("User-Agent", "test-client/1.0")
	req.Header.Set("Accept", "application/pem-certificate-chain")
	w := httptest.NewRecorder()

	service.CABundleHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/pem-certificate-chain", w.Header().Get("Content-Type"))
	assert.NotEmpty(t, w.Body.Bytes())
}
