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
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

// createPasswordTestServer creates a test server with a password store configured
func createPasswordTestServer(t *testing.T) (*Server, staticpw.Store) {
	t.Helper()

	// Reset xkms state
	xkms.Reset()

	mockKS := xkmsmocks.NewMockKeyStore()

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software": mockKS,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	// Create an in-memory backend for the password store
	memBackend := storage.NewMemory()
	passwordStore := staticpw.NewStore(memBackend)

	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		PasswordStore: passwordStore,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	return server, passwordStore
}

// TestAddPasswordHandler tests the password add endpoint
func TestAddPasswordHandler(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	t.Run("success", func(t *testing.T) {
		reqBody := PasswordAddRequest{
			Name:     "test-password",
			Password: "secret123",
			Username: "testuser",
			URL:      "https://example.com",
			Notes:    "test notes",
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp PasswordAddResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "test-password", resp.Name)
		assert.NotEmpty(t, resp.ID)
		assert.Equal(t, "Password added successfully", resp.Message)
	})

	t.Run("success_with_folder", func(t *testing.T) {
		reqBody := PasswordAddRequest{
			Name:       "folder-password",
			Password:   "secret123",
			FolderPath: "work/projects",
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("missing_name", func(t *testing.T) {
		reqBody := PasswordAddRequest{
			Password: "secret123",
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Contains(t, resp["error"], "Name is required")
	})

	t.Run("missing_password", func(t *testing.T) {
		reqBody := PasswordAddRequest{
			Name: "test-password-2",
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Contains(t, resp["error"], "Password is required")
	})

	t.Run("invalid_json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestListPasswordsHandler tests the password list endpoint
func TestListPasswordsHandler(t *testing.T) {
	server, store := createPasswordTestServer(t)
	defer xkms.Reset()

	// Add some test passwords
	err := store.Add(&staticpw.StaticPassword{
		Name:       "password-1",
		Password:   "secret1",
		FolderPath: "work",
	})
	require.NoError(t, err)

	err = store.Add(&staticpw.StaticPassword{
		Name:       "password-2",
		Password:   "secret2",
		FolderPath: "personal",
	})
	require.NoError(t, err)

	t.Run("list_all", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PasswordListResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, 2, resp.Total)
		assert.Len(t, resp.Passwords, 2)
	})

	t.Run("list_by_folder", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords?folder=work", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PasswordListResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, 1, resp.Total)
		assert.Equal(t, "password-1", resp.Passwords[0].Name)
	})

	t.Run("list_empty_folder", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords?folder=nonexistent", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PasswordListResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, 0, resp.Total)
		assert.Empty(t, resp.Passwords)
	})
}

// TestGetPasswordHandler tests the password get endpoint
func TestGetPasswordHandler(t *testing.T) {
	server, store := createPasswordTestServer(t)
	defer xkms.Reset()

	// Add a test password
	pw := &staticpw.StaticPassword{
		Name:     "get-test-password",
		Password: "secret123",
		Username: "testuser",
		URL:      "https://example.com",
	}
	err := store.Add(pw)
	require.NoError(t, err)

	t.Run("success_by_id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/"+pw.ID, nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PasswordDetailResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "get-test-password", resp.Name)
		assert.Equal(t, "secret123", resp.Password)
		assert.Equal(t, "testuser", resp.Username)
	})

	t.Run("success_by_name", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/get-test-password", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PasswordDetailResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "get-test-password", resp.Name)
	})

	t.Run("not_found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/nonexistent", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestUpdatePasswordHandler tests the password update endpoint
func TestUpdatePasswordHandler(t *testing.T) {
	server, store := createPasswordTestServer(t)
	defer xkms.Reset()

	// Add a test password
	pw := &staticpw.StaticPassword{
		Name:     "update-test-password",
		Password: "original-secret",
	}
	err := store.Add(pw)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		newPassword := "updated-secret"
		newUsername := "updated-user"
		reqBody := PasswordUpdateRequest{
			Password: &newPassword,
			Username: &newUsername,
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/passwords/"+pw.ID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PasswordUpdateResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "Password updated successfully", resp.Message)

		// Verify the update
		updated, err := store.Get(pw.ID)
		require.NoError(t, err)
		assert.Equal(t, "updated-secret", updated.Password)
		assert.Equal(t, "updated-user", updated.Username)
	})

	t.Run("update_all_fields", func(t *testing.T) {
		// Add another password
		pw2 := &staticpw.StaticPassword{
			Name:     "update-all-fields",
			Password: "original",
		}
		err := store.Add(pw2)
		require.NoError(t, err)

		newPassword := "new-password"
		newUsername := "new-user"
		newURL := "https://new.example.com"
		newNotes := "new notes"
		newName := "updated-name"
		newFolder := "new-folder"

		reqBody := PasswordUpdateRequest{
			Password:   &newPassword,
			Username:   &newUsername,
			URL:        &newURL,
			Notes:      &newNotes,
			Name:       &newName,
			FolderPath: &newFolder,
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/passwords/"+pw2.ID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// ID is deterministic from name+folder, so renaming changes the ID.
		newID := staticpw.GenerateID("updated-name", "new-folder")
		updated, err := store.Get(newID)
		require.NoError(t, err)
		assert.Equal(t, "new-password", updated.Password)
		assert.Equal(t, "new-user", updated.Username)
		assert.Equal(t, "https://new.example.com", updated.URL)
		assert.Equal(t, "new notes", updated.Notes)
		assert.Equal(t, "updated-name", updated.Name)
		assert.Equal(t, "new-folder", updated.FolderPath)
	})

	t.Run("not_found", func(t *testing.T) {
		newPassword := "updated-secret"
		reqBody := PasswordUpdateRequest{
			Password: &newPassword,
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/passwords/nonexistent", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("invalid_json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/passwords/"+pw.ID, bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestDeletePasswordHandler tests the password delete endpoint
func TestDeletePasswordHandler(t *testing.T) {
	server, store := createPasswordTestServer(t)
	defer xkms.Reset()

	t.Run("success", func(t *testing.T) {
		// Add a test password
		pw := &staticpw.StaticPassword{
			Name:     "delete-test-password",
			Password: "secret123",
		}
		err := store.Add(pw)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/passwords/"+pw.ID, nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PasswordDeleteResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "Password deleted successfully", resp.Message)

		// Verify deletion
		_, err = store.Get(pw.ID)
		assert.ErrorIs(t, err, staticpw.ErrPasswordNotFound)
	})

	t.Run("not_found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/passwords/nonexistent", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("delete_by_name", func(t *testing.T) {
		// Add a test password
		pw := &staticpw.StaticPassword{
			Name:     "delete-by-name-password",
			Password: "secret123",
		}
		err := store.Add(pw)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/passwords/delete-by-name-password", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify deletion
		_, err = store.Get(pw.ID)
		assert.ErrorIs(t, err, staticpw.ErrPasswordNotFound)
	})
}

// TestGeneratePasswordHandler tests the password generation endpoint
func TestGeneratePasswordHandler(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	t.Run("default_parameters", func(t *testing.T) {
		reqBody := PasswordGenerateRequest{}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/generate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PasswordGenerateResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, staticpw.DefaultLength, resp.Length)
		assert.Len(t, resp.Password, staticpw.DefaultLength)
	})

	t.Run("custom_length", func(t *testing.T) {
		reqBody := PasswordGenerateRequest{
			Length: 16,
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/generate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PasswordGenerateResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, 16, resp.Length)
		assert.Len(t, resp.Password, 16)
	})

	t.Run("alphanumeric_charset", func(t *testing.T) {
		reqBody := PasswordGenerateRequest{
			Length:  20,
			Charset: "alphanumeric",
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/generate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PasswordGenerateResponse
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, 20, resp.Length)
	})

	t.Run("invalid_length_too_short", func(t *testing.T) {
		reqBody := PasswordGenerateRequest{
			Length: 5, // Less than MinLength (8)
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/generate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid_length_too_long", func(t *testing.T) {
		reqBody := PasswordGenerateRequest{
			Length: 200, // More than MaxLength (128)
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/generate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid_json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/generate", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestStatusHandler tests the password store status endpoint
func TestStatusHandler(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	t.Run("success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/status", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PasswordStoreStatusResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.True(t, resp.Available)
	})
}

// TestPasswordHandlersWithoutStore tests handlers when no store is configured
func TestPasswordHandlersWithoutStore(t *testing.T) {
	// Reset xkms state
	xkms.Reset()

	mockKS := xkmsmocks.NewMockKeyStore()

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software": mockKS,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)
	defer xkms.Reset()

	// Create server without password store
	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		// No PasswordStore configured
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	t.Run("list_without_store", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		// Should return service unavailable when no store is configured
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("add_without_store", func(t *testing.T) {
		reqBody := PasswordAddRequest{
			Name:     "test",
			Password: "secret",
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("get_without_store", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/some-id", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("update_without_store", func(t *testing.T) {
		newPassword := "updated"
		reqBody := PasswordUpdateRequest{
			Password: &newPassword,
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/passwords/some-id", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("delete_without_store", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/passwords/some-id", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("status_without_store", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/status", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PasswordStoreStatusResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		// StatusHandler returns Available: true as a system-level fallback
		// because the handler itself is always available, even if no store is configured
		assert.True(t, resp.Available)
	})
}

// TestPasswordHandlersMethodNotAllowed tests method not allowed responses
func TestPasswordHandlersMethodNotAllowed(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	testCases := []struct {
		name   string
		method string
		path   string
	}{
		{"patch_passwords", http.MethodPatch, "/api/v1/passwords"},
		{"delete_passwords", http.MethodDelete, "/api/v1/passwords"},
		{"post_status", http.MethodPost, "/api/v1/passwords/status"},
		{"get_unlock", http.MethodGet, "/api/v1/passwords/unlock"},
		{"get_lock", http.MethodGet, "/api/v1/passwords/lock"},
		{"get_generate", http.MethodGet, "/api/v1/passwords/generate"},
		{"patch_specific_password", http.MethodPatch, "/api/v1/passwords/some-id"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			w := httptest.NewRecorder()

			server.handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
		})
	}
}

// TestPasswordHandlersDuplicatePrevention tests that duplicate passwords are rejected
func TestPasswordHandlersDuplicatePrevention(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	// Add first password
	reqBody := PasswordAddRequest{
		Name:     "unique-password",
		Password: "secret123",
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	// Try to add duplicate
	body, err = json.Marshal(reqBody)
	require.NoError(t, err)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/passwords", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()

	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)

	var resp map[string]string
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "already exists")
}

// TestPasswordUnlockLockWithoutManager tests unlock/lock without manager configured
func TestPasswordUnlockLockWithoutManager(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	t.Run("unlock_without_manager", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/unlock", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotImplemented, w.Code)
	})

	t.Run("lock_without_manager", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/lock", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotImplemented, w.Code)
	})
}

// TestPasswordWithTenantIdentity tests password operations with tenant identity
func TestPasswordWithTenantIdentity(t *testing.T) {
	// This test verifies the tenant identity flow works correctly
	// when an authenticator provides tenant information

	// Reset xkms state
	xkms.Reset()

	mockKS := xkmsmocks.NewMockKeyStore()

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software": mockKS,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)
	defer xkms.Reset()

	// Create an in-memory backend for the password store
	memBackend := storage.NewMemory()
	passwordStore := staticpw.NewStore(memBackend)

	// Create a custom authenticator that provides tenant identity
	tenantAuth := &tenantTestAuthenticator{
		tenantID: "test-tenant",
		userID:   "test-user",
	}

	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: tenantAuth,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		PasswordStore: passwordStore,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	// Add a password
	reqBody := PasswordAddRequest{
		Name:     "tenant-password",
		Password: "secret123",
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handler.ServeHTTP(w, req)

	// Should succeed because we have a password store configured (falls back to system store)
	assert.Equal(t, http.StatusCreated, w.Code)
}

// tenantTestAuthenticator is a test authenticator that provides tenant identity
type tenantTestAuthenticator struct {
	tenantID string
	userID   string
}

func (a *tenantTestAuthenticator) Name() string {
	return "tenant-test"
}

func (a *tenantTestAuthenticator) AuthenticateHTTP(r *http.Request) (*auth.Identity, error) {
	return &auth.Identity{
		Subject:  a.userID,
		TenantID: a.tenantID,
	}, nil
}

func (a *tenantTestAuthenticator) AuthenticateGRPC(ctx context.Context, md metadata.MD) (*auth.Identity, error) {
	return &auth.Identity{
		Subject:  a.userID,
		TenantID: a.tenantID,
	}, nil
}

// TestOperationForMethod tests the operationForMethod helper function
func TestOperationForMethod(t *testing.T) {
	testCases := []struct {
		method   string
		expected string
	}{
		{http.MethodGet, "read"},
		{http.MethodHead, "read"},
		{http.MethodPost, "write"},
		{http.MethodPut, "write"},
		{http.MethodPatch, "write"},
		{http.MethodDelete, "delete"},
		{"OPTIONS", "read"}, // default case
	}

	for _, tc := range testCases {
		t.Run(tc.method, func(t *testing.T) {
			result := operationForMethod(tc.method)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestPasswordHandleStoreError tests the passwordHandleStoreError function
func TestPasswordHandleStoreError(t *testing.T) {
	testCases := []struct {
		name           string
		err            error
		expectedStatus int
		expectedMsg    string
	}{
		{
			name:           "store_locked",
			err:            staticpw.ErrStoreLocked,
			expectedStatus: http.StatusLocked,
			expectedMsg:    "Password store is locked",
		},
		{
			name:           "tenant_sealed",
			err:            seal.ErrTenantSealed,
			expectedStatus: http.StatusServiceUnavailable,
			expectedMsg:    "Tenant barrier is sealed",
		},
		{
			name:           "tenant_not_found",
			err:            seal.ErrTenantNotFound,
			expectedStatus: http.StatusNotFound,
			expectedMsg:    "Tenant not found",
		},
		{
			name:           "not_configured",
			err:            staticpw.ErrNotConfigured,
			expectedStatus: http.StatusServiceUnavailable,
			expectedMsg:    "Password store not configured",
		},
		{
			name:           "invalid_user_id",
			err:            staticpw.ErrInvalidUserID,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid user identity",
		},
		{
			name:           "not_owner",
			err:            staticpw.ErrNotOwner,
			expectedStatus: http.StatusForbidden,
			expectedMsg:    "Not the owner of this password",
		},
		{
			name:           "invalid_scope",
			err:            staticpw.ErrInvalidScope,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid scope",
		},
		{
			name:           "generic_error",
			err:            assert.AnError,
			expectedStatus: http.StatusInternalServerError,
			expectedMsg:    "Failed to access password store",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			passwordHandleStoreError(w, tc.err)

			assert.Equal(t, tc.expectedStatus, w.Code)

			var resp map[string]string
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedMsg, resp["error"])
		})
	}
}

// TestPasswordRouteEmptyPath tests the empty path case in password routes
func TestPasswordRouteEmptyPath(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	// Test the edge case where the path after /api/v1/passwords/ is empty
	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/", nil)
	w := httptest.NewRecorder()

	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNewPasswordHandlers tests the NewPasswordHandlers constructor
func TestNewPasswordHandlers(t *testing.T) {
	t.Run("with_store", func(t *testing.T) {
		memBackend := storage.NewMemory()
		store := staticpw.NewStore(memBackend)
		handlers := NewPasswordHandlers(store, nil)
		assert.NotNil(t, handlers)
		assert.NotNil(t, handlers.store)
		assert.Nil(t, handlers.manager)
	})

	t.Run("both_nil", func(t *testing.T) {
		handlers := NewPasswordHandlers(nil, nil)
		assert.NotNil(t, handlers)
		assert.Nil(t, handlers.store)
		assert.Nil(t, handlers.manager)
	})
}

// TestSetPasswordStore tests the SetPasswordStore setter method on Server
func TestSetPasswordStore(t *testing.T) {
	xkms.Reset()

	mockKS := xkmsmocks.NewMockKeyStore()

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software": mockKS,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)
	defer xkms.Reset()

	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	// Initially no store
	assert.Nil(t, server.passwordStore)

	// Set password store
	memBackend := storage.NewMemory()
	store := staticpw.NewStore(memBackend)
	server.SetPasswordStore(store)
	assert.NotNil(t, server.passwordStore)
}
