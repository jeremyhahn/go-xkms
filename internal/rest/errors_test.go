// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	err := errors.New("test error")

	writeError(w, err, http.StatusBadRequest)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Error != "test error" {
		t.Errorf("Expected error message 'test error', got %s", resp.Error)
	}

	if resp.Code != http.StatusBadRequest {
		t.Errorf("Expected code %d, got %d", http.StatusBadRequest, resp.Code)
	}
}

func TestWriteErrorWithMessage(t *testing.T) {
	w := httptest.NewRecorder()
	err := errors.New("test error")
	message := "custom message"

	writeErrorWithMessage(w, err, message, http.StatusInternalServerError)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Error != "test error" {
		t.Errorf("Expected error 'test error', got %s", resp.Error)
	}

	if resp.Message != message {
		t.Errorf("Expected message %s, got %s", message, resp.Message)
	}
}

func TestMapErrorToStatusCode(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{
			name:           "NotFound error",
			err:            storage.ErrNotFound,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "KeyNotFound error",
			err:            backend.ErrKeyNotFound,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "InvalidRequest error",
			err:            ErrInvalidRequest,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "InvalidBackend error",
			err:            ErrInvalidBackend,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "InvalidKeyType error",
			err:            ErrInvalidKeyType,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "MissingKeyID error",
			err:            ErrMissingKeyID,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "MissingBackend error",
			err:            ErrMissingBackend,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "InvalidKeyType backend error",
			err:            backend.ErrInvalidKeyType,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "InvalidKeyPartition error",
			err:            backend.ErrInvalidKeyPartition,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "AlreadyExists error",
			err:            storage.ErrAlreadyExists,
			expectedStatus: http.StatusConflict,
		},
		{
			name:           "Unknown error",
			err:            errors.New("unknown error"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := mapErrorToStatusCode(tt.err)
			if status != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, status)
			}
		})
	}
}

func TestHandleError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{
			name:           "NotFound",
			err:            storage.ErrNotFound,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "BadRequest",
			err:            ErrInvalidRequest,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Conflict",
			err:            storage.ErrAlreadyExists,
			expectedStatus: http.StatusConflict,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handleError(w, tt.err)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			var resp ErrorResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			if resp.Code != tt.expectedStatus {
				t.Errorf("Expected code %d, got %d", tt.expectedStatus, resp.Code)
			}
		})
	}
}

func TestWriteJSON(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		w := httptest.NewRecorder()
		data := map[string]string{"key": "value"}

		writeJSON(w, data, http.StatusOK)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}

		contentType := w.Header().Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", contentType)
		}

		var result map[string]string
		if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if result["key"] != "value" {
			t.Errorf("Expected key=value, got %s", result["key"])
		}
	})
}
