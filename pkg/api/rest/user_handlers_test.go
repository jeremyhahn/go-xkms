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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-keychain/pkg/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockUserStore implements user.Store for testing
type mockUserStore struct {
	mu           sync.RWMutex
	users        map[string]*user.User
	sessions     map[string][]byte
	createFunc   func(ctx context.Context, username, displayName string, role user.Role) (*user.User, error)
	getByIDFunc  func(ctx context.Context, id []byte) (*user.User, error)
	updateFunc   func(ctx context.Context, u *user.User) error
	deleteFunc   func(ctx context.Context, id []byte) error
	listFunc     func(ctx context.Context) ([]*user.User, error)
	countFunc    func(ctx context.Context) (int, error)
	hasUsersFunc func(ctx context.Context) (bool, error)
	countAdmins  func(ctx context.Context) (int, error)
}

func newMockUserStore() *mockUserStore {
	return &mockUserStore{
		users:    make(map[string]*user.User),
		sessions: make(map[string][]byte),
	}
}

func (m *mockUserStore) Create(ctx context.Context, username, displayName string, role user.Role) (*user.User, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, username, displayName, role)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	id := []byte(username) // Simple ID for testing
	u := &user.User{
		ID:          id,
		Username:    username,
		DisplayName: displayName,
		Role:        role,
		Enabled:     true,
		CreatedAt:   time.Now(),
	}
	m.users[username] = u
	return u, nil
}

func (m *mockUserStore) GetByID(ctx context.Context, id []byte) (*user.User, error) {
	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, id)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, u := range m.users {
		if string(u.ID) == string(id) {
			return u, nil
		}
	}
	return nil, user.ErrUserNotFound
}

func (m *mockUserStore) GetByUsername(ctx context.Context, username string) (*user.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if u, ok := m.users[username]; ok {
		return u, nil
	}
	return nil, user.ErrUserNotFound
}

func (m *mockUserStore) Update(ctx context.Context, u *user.User) error {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, u)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.users[u.Username] = u
	return nil
}

func (m *mockUserStore) Delete(ctx context.Context, id []byte) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, id)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	for username, u := range m.users {
		if string(u.ID) == string(id) {
			delete(m.users, username)
			return nil
		}
	}
	return user.ErrUserNotFound
}

func (m *mockUserStore) List(ctx context.Context) ([]*user.User, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	users := make([]*user.User, 0, len(m.users))
	for _, u := range m.users {
		users = append(users, u)
	}
	return users, nil
}

func (m *mockUserStore) Count(ctx context.Context) (int, error) {
	if m.countFunc != nil {
		return m.countFunc(ctx)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.users), nil
}

func (m *mockUserStore) HasAnyUsers(ctx context.Context) (bool, error) {
	if m.hasUsersFunc != nil {
		return m.hasUsersFunc(ctx)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.users) > 0, nil
}

func (m *mockUserStore) CountAdmins(ctx context.Context) (int, error) {
	if m.countAdmins != nil {
		return m.countAdmins(ctx)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, u := range m.users {
		if u.Role == user.RoleAdmin {
			count++
		}
	}
	return count, nil
}

func (m *mockUserStore) SaveSession(ctx context.Context, sessionID string, data []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[sessionID] = data
	return nil
}

func (m *mockUserStore) GetSession(ctx context.Context, sessionID string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if data, ok := m.sessions[sessionID]; ok {
		return data, nil
	}
	return nil, fmt.Errorf("session not found")
}

func (m *mockUserStore) DeleteSession(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, sessionID)
	return nil
}

func (m *mockUserStore) Close() error {
	return nil
}

// Helper to add a test user
func (m *mockUserStore) addUser(u *user.User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[u.Username] = u
}

// TestNewUserHandlers tests UserHandlers creation
func TestNewUserHandlers(t *testing.T) {
	store := newMockUserStore()
	handlers := NewUserHandlers(store)

	assert.NotNil(t, handlers)
	assert.Equal(t, store, handlers.userStore)
}

// TestBootstrapStatusHandler tests the bootstrap status endpoint
func TestBootstrapStatusHandler(t *testing.T) {
	t.Run("returns requires_setup when no users", func(t *testing.T) {
		store := newMockUserStore()
		handlers := NewUserHandlers(store)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/bootstrap/status", nil)
		w := httptest.NewRecorder()

		handlers.BootstrapStatusHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp BootstrapStatusResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.RequiresSetup)
		assert.Equal(t, 0, resp.UserCount)
		assert.Contains(t, resp.Message, "register the first administrator")
	})

	t.Run("returns configured when users exist", func(t *testing.T) {
		store := newMockUserStore()
		store.addUser(&user.User{
			ID:       []byte("test"),
			Username: "admin",
			Role:     user.RoleAdmin,
		})
		handlers := NewUserHandlers(store)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/bootstrap/status", nil)
		w := httptest.NewRecorder()

		handlers.BootstrapStatusHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp BootstrapStatusResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.False(t, resp.RequiresSetup)
		assert.Equal(t, 1, resp.UserCount)
		assert.Contains(t, resp.Message, "configured and ready")
	})

	t.Run("returns error when HasAnyUsers fails", func(t *testing.T) {
		store := newMockUserStore()
		store.hasUsersFunc = func(ctx context.Context) (bool, error) {
			return false, fmt.Errorf("database error")
		}
		handlers := NewUserHandlers(store)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/bootstrap/status", nil)
		w := httptest.NewRecorder()

		handlers.BootstrapStatusHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("returns error when Count fails", func(t *testing.T) {
		store := newMockUserStore()
		store.countFunc = func(ctx context.Context) (int, error) {
			return 0, fmt.Errorf("count error")
		}
		handlers := NewUserHandlers(store)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/bootstrap/status", nil)
		w := httptest.NewRecorder()

		handlers.BootstrapStatusHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestListUsersHandler tests listing users
func TestListUsersHandler(t *testing.T) {
	t.Run("returns empty list when no users", func(t *testing.T) {
		store := newMockUserStore()
		handlers := NewUserHandlers(store)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
		w := httptest.NewRecorder()

		handlers.ListUsersHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp UserListResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Empty(t, resp.Users)
		assert.Equal(t, 0, resp.Total)
	})

	t.Run("returns users when present", func(t *testing.T) {
		store := newMockUserStore()
		now := time.Now()
		loginTime := now.Add(-1 * time.Hour)
		store.addUser(&user.User{
			ID:          []byte("user1"),
			Username:    "admin",
			DisplayName: "Admin User",
			Role:        user.RoleAdmin,
			Enabled:     true,
			CreatedAt:   now,
			LastLoginAt: &loginTime,
			Credentials: []user.Credential{
				{ID: []byte("cred1"), Name: "Key 1"},
			},
		})
		handlers := NewUserHandlers(store)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
		w := httptest.NewRecorder()

		handlers.ListUsersHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp UserListResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Len(t, resp.Users, 1)
		assert.Equal(t, 1, resp.Total)
		assert.Equal(t, "admin", resp.Users[0].Username)
		assert.Equal(t, "Admin User", resp.Users[0].DisplayName)
		assert.Equal(t, string(user.RoleAdmin), resp.Users[0].Role)
		assert.True(t, resp.Users[0].Enabled)
		assert.Equal(t, 1, resp.Users[0].CredentialCount)
		assert.NotEmpty(t, resp.Users[0].LastLoginAt)
	})

	t.Run("returns error when List fails", func(t *testing.T) {
		store := newMockUserStore()
		store.listFunc = func(ctx context.Context) ([]*user.User, error) {
			return nil, fmt.Errorf("list error")
		}
		handlers := NewUserHandlers(store)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
		w := httptest.NewRecorder()

		handlers.ListUsersHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestGetUserHandler tests getting a specific user
func TestGetUserHandler(t *testing.T) {
	t.Run("returns error for missing ID", func(t *testing.T) {
		store := newMockUserStore()
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Get("/api/v1/users/{id}", handlers.GetUserHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code) // chi returns 404 for missing param
	})

	t.Run("returns error for invalid ID format", func(t *testing.T) {
		store := newMockUserStore()
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Get("/api/v1/users/{id}", handlers.GetUserHandler)

		// Invalid base64
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/!!!invalid!!!", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent user", func(t *testing.T) {
		store := newMockUserStore()
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Get("/api/v1/users/{id}", handlers.GetUserHandler)

		// Valid base64 but user doesn't exist
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/bm9uZXhpc3RlbnQ", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns user when found", func(t *testing.T) {
		store := newMockUserStore()
		now := time.Now()
		loginTime := now.Add(-1 * time.Hour)
		credTime := now.Add(-2 * time.Hour)
		store.addUser(&user.User{
			ID:          []byte("testuser"),
			Username:    "testuser",
			DisplayName: "Test User",
			Role:        user.RoleOperator,
			Enabled:     true,
			CreatedAt:   now,
			LastLoginAt: &loginTime,
			Credentials: []user.Credential{
				{ID: []byte("cred1"), Name: "Security Key", CreatedAt: credTime, LastUsedAt: &loginTime},
			},
		})
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Get("/api/v1/users/{id}", handlers.GetUserHandler)

		// Use base64url encoding of "testuser"
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/dGVzdHVzZXI", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp UserDetailResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "testuser", resp.Username)
		assert.Equal(t, "Test User", resp.DisplayName)
		assert.Equal(t, string(user.RoleOperator), resp.Role)
		assert.True(t, resp.Enabled)
		assert.Len(t, resp.Credentials, 1)
		assert.Equal(t, "Security Key", resp.Credentials[0].Name)
		assert.NotEmpty(t, resp.LastLoginAt)
	})

	t.Run("returns error when GetByID fails", func(t *testing.T) {
		store := newMockUserStore()
		store.getByIDFunc = func(ctx context.Context, id []byte) (*user.User, error) {
			return nil, fmt.Errorf("database error")
		}
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Get("/api/v1/users/{id}", handlers.GetUserHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/dGVzdA", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestUpdateUserHandler tests updating a user
func TestUpdateUserHandler(t *testing.T) {
	t.Run("returns error for missing ID", func(t *testing.T) {
		store := newMockUserStore()
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Put("/api/v1/users/{id}", handlers.UpdateUserHandler)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/users/", strings.NewReader(`{}`))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns error for invalid ID format", func(t *testing.T) {
		store := newMockUserStore()
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Put("/api/v1/users/{id}", handlers.UpdateUserHandler)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/users/!!!invalid!!!", strings.NewReader(`{}`))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		store := newMockUserStore()
		store.addUser(&user.User{
			ID:       []byte("testuser"),
			Username: "testuser",
			Role:     user.RoleUser,
		})
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Put("/api/v1/users/{id}", handlers.UpdateUserHandler)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/users/dGVzdHVzZXI", strings.NewReader("invalid json"))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent user", func(t *testing.T) {
		store := newMockUserStore()
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Put("/api/v1/users/{id}", handlers.UpdateUserHandler)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/users/bm9uZXhpc3RlbnQ", strings.NewReader(`{"display_name": "New Name"}`))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns error for invalid role", func(t *testing.T) {
		store := newMockUserStore()
		store.addUser(&user.User{
			ID:       []byte("testuser"),
			Username: "testuser",
			Role:     user.RoleUser,
		})
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Put("/api/v1/users/{id}", handlers.UpdateUserHandler)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/users/dGVzdHVzZXI", strings.NewReader(`{"role": "superuser"}`))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("updates display name successfully", func(t *testing.T) {
		store := newMockUserStore()
		store.addUser(&user.User{
			ID:          []byte("testuser"),
			Username:    "testuser",
			DisplayName: "Old Name",
			Role:        user.RoleUser,
		})
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Put("/api/v1/users/{id}", handlers.UpdateUserHandler)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/users/dGVzdHVzZXI", strings.NewReader(`{"display_name": "New Name"}`))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp UpdateUserResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "New Name", resp.DisplayName)
		assert.Contains(t, resp.Message, "successfully")
	})

	t.Run("updates role successfully", func(t *testing.T) {
		store := newMockUserStore()
		store.addUser(&user.User{
			ID:       []byte("testuser"),
			Username: "testuser",
			Role:     user.RoleUser,
		})
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Put("/api/v1/users/{id}", handlers.UpdateUserHandler)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/users/dGVzdHVzZXI", strings.NewReader(`{"role": "operator"}`))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp UpdateUserResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, string(user.RoleOperator), resp.Role)
	})

	t.Run("updates enabled status successfully", func(t *testing.T) {
		store := newMockUserStore()
		store.addUser(&user.User{
			ID:       []byte("testuser"),
			Username: "testuser",
			Role:     user.RoleUser,
			Enabled:  true,
		})
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Put("/api/v1/users/{id}", handlers.UpdateUserHandler)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/users/dGVzdHVzZXI", strings.NewReader(`{"enabled": false}`))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp UpdateUserResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.False(t, resp.Enabled)
	})

	t.Run("returns error when Update fails", func(t *testing.T) {
		store := newMockUserStore()
		store.addUser(&user.User{
			ID:       []byte("testuser"),
			Username: "testuser",
			Role:     user.RoleUser,
		})
		store.updateFunc = func(ctx context.Context, u *user.User) error {
			return fmt.Errorf("update error")
		}
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Put("/api/v1/users/{id}", handlers.UpdateUserHandler)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/users/dGVzdHVzZXI", strings.NewReader(`{"display_name": "New"}`))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestDeleteUserHandler tests deleting a user
func TestDeleteUserHandler(t *testing.T) {
	t.Run("returns error for missing ID", func(t *testing.T) {
		store := newMockUserStore()
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Delete("/api/v1/users/{id}", handlers.DeleteUserHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns error for invalid ID format", func(t *testing.T) {
		store := newMockUserStore()
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Delete("/api/v1/users/{id}", handlers.DeleteUserHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/!!!invalid!!!", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent user", func(t *testing.T) {
		store := newMockUserStore()
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Delete("/api/v1/users/{id}", handlers.DeleteUserHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/bm9uZXhpc3RlbnQ", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("prevents deletion of last admin", func(t *testing.T) {
		store := newMockUserStore()
		store.addUser(&user.User{
			ID:       []byte("admin"),
			Username: "admin",
			Role:     user.RoleAdmin,
		})
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Delete("/api/v1/users/{id}", handlers.DeleteUserHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/YWRtaW4", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("allows deletion of admin when others exist", func(t *testing.T) {
		store := newMockUserStore()
		store.addUser(&user.User{
			ID:       []byte("admin1"),
			Username: "admin1",
			Role:     user.RoleAdmin,
		})
		store.addUser(&user.User{
			ID:       []byte("admin2"),
			Username: "admin2",
			Role:     user.RoleAdmin,
		})
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Delete("/api/v1/users/{id}", handlers.DeleteUserHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/YWRtaW4x", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp DeleteUserResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "successfully")
	})

	t.Run("deletes non-admin user successfully", func(t *testing.T) {
		store := newMockUserStore()
		store.addUser(&user.User{
			ID:       []byte("testuser"),
			Username: "testuser",
			Role:     user.RoleUser,
		})
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Delete("/api/v1/users/{id}", handlers.DeleteUserHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/dGVzdHVzZXI", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp DeleteUserResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "successfully")
	})

	t.Run("returns error when CountAdmins fails", func(t *testing.T) {
		store := newMockUserStore()
		store.addUser(&user.User{
			ID:       []byte("admin"),
			Username: "admin",
			Role:     user.RoleAdmin,
		})
		store.countAdmins = func(ctx context.Context) (int, error) {
			return 0, fmt.Errorf("count error")
		}
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Delete("/api/v1/users/{id}", handlers.DeleteUserHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/YWRtaW4", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("returns error when Delete fails", func(t *testing.T) {
		store := newMockUserStore()
		store.addUser(&user.User{
			ID:       []byte("testuser"),
			Username: "testuser",
			Role:     user.RoleUser,
		})
		store.deleteFunc = func(ctx context.Context, id []byte) error {
			return fmt.Errorf("delete error")
		}
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Delete("/api/v1/users/{id}", handlers.DeleteUserHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/dGVzdHVzZXI", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("handles ErrLastAdmin from Delete", func(t *testing.T) {
		store := newMockUserStore()
		store.addUser(&user.User{
			ID:       []byte("admin"),
			Username: "admin",
			Role:     user.RoleUser, // Not admin so CountAdmins check passes
		})
		store.deleteFunc = func(ctx context.Context, id []byte) error {
			return user.ErrLastAdmin
		}
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Delete("/api/v1/users/{id}", handlers.DeleteUserHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/YWRtaW4", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

// TestEncodeUserID tests user ID encoding
func TestEncodeUserID(t *testing.T) {
	t.Run("encodes user ID to base64url", func(t *testing.T) {
		id := []byte("testuser")
		encoded := encodeUserID(id)
		assert.NotEmpty(t, encoded)
	})

	t.Run("encodes empty ID", func(t *testing.T) {
		id := []byte("")
		encoded := encodeUserID(id)
		assert.Empty(t, encoded)
	})
}

// TestDecodeUserID tests user ID decoding
func TestDecodeUserID(t *testing.T) {
	t.Run("decodes valid base64url", func(t *testing.T) {
		encoded := "dGVzdHVzZXI" // base64url of "testuser"
		decoded, err := decodeUserID(encoded)
		require.NoError(t, err)
		assert.Equal(t, []byte("testuser"), decoded)
	})

	t.Run("returns error for invalid base64", func(t *testing.T) {
		_, err := decodeUserID("!!!invalid!!!")
		assert.Error(t, err)
	})

	t.Run("decodes base64url with padding", func(t *testing.T) {
		encoded := "dGVzdHVzZXI=" // base64url with padding
		decoded, err := decodeUserID(encoded)
		require.NoError(t, err)
		assert.Equal(t, []byte("testuser"), decoded)
	})
}

// TestEncodeBase64URL tests base64url encoding
func TestEncodeBase64URL(t *testing.T) {
	t.Run("encodes data correctly", func(t *testing.T) {
		data := []byte("hello world")
		encoded := encodeBase64URL(data)
		assert.NotEmpty(t, encoded)
		// Should not contain padding or non-URL-safe characters
		assert.NotContains(t, encoded, "+")
		assert.NotContains(t, encoded, "/")
		assert.NotContains(t, encoded, "=")
	})

	t.Run("encodes empty data", func(t *testing.T) {
		encoded := encodeBase64URL([]byte{})
		assert.Empty(t, encoded)
	})

	t.Run("encodes binary data", func(t *testing.T) {
		data := []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}
		encoded := encodeBase64URL(data)
		assert.NotEmpty(t, encoded)
	})
}

// TestUserWriteJSONError tests error response writing
func TestUserWriteJSONError(t *testing.T) {
	t.Run("writes error response", func(t *testing.T) {
		w := httptest.NewRecorder()
		userWriteJSONError(w, "test error", http.StatusBadRequest)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var resp map[string]string
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "test error", resp["error"])
	})
}

// TestDeleteUserHandler_CountAdminsError tests error when CountAdmins fails
func TestDeleteUserHandler_CountAdminsError(t *testing.T) {
	t.Run("returns error when CountAdmins fails", func(t *testing.T) {
		store := newMockUserStore()
		store.addUser(&user.User{
			ID:       []byte("admin"),
			Username: "admin",
			Role:     user.RoleAdmin,
		})
		store.countAdmins = func(ctx context.Context) (int, error) {
			return 0, fmt.Errorf("database error")
		}
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Delete("/api/v1/users/{id}", handlers.DeleteUserHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/YWRtaW4", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "Failed to count admins")
	})
}

// TestDeleteUserHandler_GetByIDError tests error when GetByID fails
func TestDeleteUserHandler_GetByIDError(t *testing.T) {
	t.Run("returns error when GetByID fails with generic error", func(t *testing.T) {
		store := newMockUserStore()
		store.getByIDFunc = func(ctx context.Context, id []byte) (*user.User, error) {
			return nil, fmt.Errorf("database error")
		}
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Delete("/api/v1/users/{id}", handlers.DeleteUserHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/dGVzdA", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "Failed to get user")
	})
}

// TestDeleteUserHandler_DeleteLastAdminError tests when Delete returns ErrLastAdmin
func TestDeleteUserHandler_DeleteLastAdminError(t *testing.T) {
	t.Run("returns forbidden when Delete returns ErrLastAdmin", func(t *testing.T) {
		store := newMockUserStore()
		store.addUser(&user.User{
			ID:       []byte("regular"),
			Username: "regular",
			Role:     user.RoleUser,
		})
		store.deleteFunc = func(ctx context.Context, id []byte) error {
			return user.ErrLastAdmin
		}
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Delete("/api/v1/users/{id}", handlers.DeleteUserHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/cmVndWxhcg", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

// TestDeleteUserHandler_DeleteGenericError tests when Delete returns generic error
func TestDeleteUserHandler_DeleteGenericError(t *testing.T) {
	t.Run("returns error when Delete fails with generic error", func(t *testing.T) {
		store := newMockUserStore()
		store.addUser(&user.User{
			ID:       []byte("regular"),
			Username: "regular",
			Role:     user.RoleUser,
		})
		store.deleteFunc = func(ctx context.Context, id []byte) error {
			return fmt.Errorf("database error")
		}
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Delete("/api/v1/users/{id}", handlers.DeleteUserHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/cmVndWxhcg", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestUpdateUserHandler_UpdateError tests UpdateUserHandler when Update fails
func TestUpdateUserHandler_UpdateError(t *testing.T) {
	t.Run("returns error when Update fails", func(t *testing.T) {
		store := newMockUserStore()
		store.addUser(&user.User{
			ID:       []byte("testuser"),
			Username: "testuser",
			Role:     user.RoleUser,
		})
		store.updateFunc = func(ctx context.Context, u *user.User) error {
			return fmt.Errorf("update error")
		}
		handlers := NewUserHandlers(store)

		router := chi.NewRouter()
		router.Put("/api/v1/users/{id}", handlers.UpdateUserHandler)

		body := `{"display_name": "New Name"}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/users/dGVzdHVzZXI", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
