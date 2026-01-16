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

package cli

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/user"
	"github.com/spf13/cobra"
)

// MockUserStore implements user.Store for testing
type MockUserStore struct {
	// Users stored in memory
	users map[string]*user.User

	// Configuration for mock behavior
	createErr      error
	getByIDErr     error
	getByNameErr   error
	updateErr      error
	deleteErr      error
	listErr        error
	countErr       error
	hasAnyErr      error
	countAdminsErr error
	saveSessionErr error
	getSessionErr  error
	delSessionErr  error
	closeErr       error

	// Track calls
	closed bool
}

// NewMockUserStore creates a new mock user store
func NewMockUserStore() *MockUserStore {
	return &MockUserStore{
		users: make(map[string]*user.User),
	}
}

// Create implements user.Store
func (m *MockUserStore) Create(ctx context.Context, username, displayName string, role user.Role) (*user.User, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	u := &user.User{
		ID:          []byte("test-user-id-" + username),
		Username:    username,
		DisplayName: displayName,
		Role:        role,
		Credentials: []user.Credential{},
		CreatedAt:   time.Now().UTC(),
		Enabled:     true,
	}
	m.users[username] = u
	return u, nil
}

// GetByID implements user.Store
func (m *MockUserStore) GetByID(ctx context.Context, id []byte) (*user.User, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	for _, u := range m.users {
		if string(u.ID) == string(id) {
			return u, nil
		}
	}
	return nil, user.ErrUserNotFound
}

// GetByUsername implements user.Store
func (m *MockUserStore) GetByUsername(ctx context.Context, username string) (*user.User, error) {
	if m.getByNameErr != nil {
		return nil, m.getByNameErr
	}
	if u, ok := m.users[username]; ok {
		return u, nil
	}
	return nil, user.ErrUserNotFound
}

// Update implements user.Store
func (m *MockUserStore) Update(ctx context.Context, u *user.User) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.users[u.Username] = u
	return nil
}

// Delete implements user.Store
func (m *MockUserStore) Delete(ctx context.Context, id []byte) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	for name, u := range m.users {
		if string(u.ID) == string(id) {
			delete(m.users, name)
			return nil
		}
	}
	return user.ErrUserNotFound
}

// List implements user.Store
func (m *MockUserStore) List(ctx context.Context) ([]*user.User, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	var list []*user.User
	for _, u := range m.users {
		list = append(list, u)
	}
	return list, nil
}

// Count implements user.Store
func (m *MockUserStore) Count(ctx context.Context) (int, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	return len(m.users), nil
}

// HasAnyUsers implements user.Store
func (m *MockUserStore) HasAnyUsers(ctx context.Context) (bool, error) {
	if m.hasAnyErr != nil {
		return false, m.hasAnyErr
	}
	return len(m.users) > 0, nil
}

// CountAdmins implements user.Store
func (m *MockUserStore) CountAdmins(ctx context.Context) (int, error) {
	if m.countAdminsErr != nil {
		return 0, m.countAdminsErr
	}
	count := 0
	for _, u := range m.users {
		if u.Role == user.RoleAdmin {
			count++
		}
	}
	return count, nil
}

// SaveSession implements user.Store
func (m *MockUserStore) SaveSession(ctx context.Context, sessionID string, data []byte, ttl time.Duration) error {
	return m.saveSessionErr
}

// GetSession implements user.Store
func (m *MockUserStore) GetSession(ctx context.Context, sessionID string) ([]byte, error) {
	if m.getSessionErr != nil {
		return nil, m.getSessionErr
	}
	return nil, user.ErrSessionNotFound
}

// DeleteSession implements user.Store
func (m *MockUserStore) DeleteSession(ctx context.Context, sessionID string) error {
	return m.delSessionErr
}

// Close implements user.Store
func (m *MockUserStore) Close() error {
	m.closed = true
	return m.closeErr
}

// AddUser adds a user to the mock store for testing
func (m *MockUserStore) AddUser(u *user.User) {
	m.users[u.Username] = u
}

// Verify MockUserStore implements user.Store interface
var _ user.Store = (*MockUserStore)(nil)

// createMockUserStoreFactory creates a UserStoreFactory that returns a mock store
func createMockUserStoreFactory(mockStore *MockUserStore) UserStoreFactory {
	return func(storagePath string) (user.Store, error) {
		return mockStore, nil
	}
}

// createMockUserStoreFactoryWithError creates a UserStoreFactory that returns an error
func createMockUserStoreFactoryWithError(err error) UserStoreFactory {
	return func(storagePath string) (user.Store, error) {
		return nil, err
	}
}

// ============================================================================
// Test userCmd command structure
// ============================================================================

func TestUserCmd_Exists(t *testing.T) {
	if userCmd == nil {
		t.Fatal("userCmd should not be nil")
	}
}

func TestUserCmd_Properties(t *testing.T) {
	if userCmd.Use != "user" {
		t.Errorf("userCmd.Use = %v, want user", userCmd.Use)
	}

	if userCmd.Short == "" {
		t.Error("userCmd.Short should not be empty")
	}

	if userCmd.Long == "" {
		t.Error("userCmd.Long should not be empty")
	}
}

func TestUserCmd_HasSubcommands(t *testing.T) {
	subcommands := userCmd.Commands()

	expectedCmds := []string{
		"register",
		"login",
		"list",
		"get",
		"delete",
		"disable",
		"enable",
		"status",
		"credentials",
	}
	foundCmds := make(map[string]bool)

	for _, cmd := range subcommands {
		foundCmds[cmd.Name()] = true
	}

	for _, expected := range expectedCmds {
		if !foundCmds[expected] {
			t.Errorf("expected subcommand %q not found", expected)
		}
	}
}

func TestUserCmd_PersistentFlags(t *testing.T) {
	flags := userCmd.PersistentFlags()

	if flags.Lookup("storage-path") == nil {
		t.Error("expected persistent flag 'storage-path' not found on userCmd")
	}
}

// ============================================================================
// Test userRegisterCmd
// ============================================================================

func TestUserRegisterCmd_Exists(t *testing.T) {
	if userRegisterCmd == nil {
		t.Fatal("userRegisterCmd should not be nil")
	}
}

func TestUserRegisterCmd_Properties(t *testing.T) {
	if userRegisterCmd.Use != "register <username>" {
		t.Errorf("userRegisterCmd.Use = %v, want 'register <username>'", userRegisterCmd.Use)
	}

	if userRegisterCmd.Short == "" {
		t.Error("userRegisterCmd.Short should not be empty")
	}
}

func TestUserRegisterCmd_HasFlags(t *testing.T) {
	flags := userRegisterCmd.Flags()

	expectedFlags := []string{
		"display-name",
		"role",
		"rp-id",
		"rp-name",
		"timeout",
		"device",
		"user-verification",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on userRegisterCmd", flag)
		}
	}
}

func TestUserRegisterCmd_FlagDefaults(t *testing.T) {
	flags := userRegisterCmd.Flags()

	rpIDFlag := flags.Lookup("rp-id")
	if rpIDFlag.DefValue != "go-keychain" {
		t.Errorf("rp-id default = %v, want go-keychain", rpIDFlag.DefValue)
	}

	rpNameFlag := flags.Lookup("rp-name")
	if rpNameFlag.DefValue != "Go Keychain" {
		t.Errorf("rp-name default = %v, want 'Go Keychain'", rpNameFlag.DefValue)
	}

	timeoutFlag := flags.Lookup("timeout")
	if timeoutFlag.DefValue != "30s" {
		t.Errorf("timeout default = %v, want 30s", timeoutFlag.DefValue)
	}
}

// ============================================================================
// Test userLoginCmd
// ============================================================================

func TestUserLoginCmd_Exists(t *testing.T) {
	if userLoginCmd == nil {
		t.Fatal("userLoginCmd should not be nil")
	}
}

func TestUserLoginCmd_Properties(t *testing.T) {
	if userLoginCmd.Use != "login" {
		t.Errorf("userLoginCmd.Use = %v, want login", userLoginCmd.Use)
	}
}

func TestUserLoginCmd_HasFlags(t *testing.T) {
	flags := userLoginCmd.Flags()

	expectedFlags := []string{
		"credential-id",
		"salt",
		"rp-id",
		"timeout",
		"device",
		"user-verification",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on userLoginCmd", flag)
		}
	}
}

func TestUserLoginCmd_FlagDefaults(t *testing.T) {
	flags := userLoginCmd.Flags()

	rpIDFlag := flags.Lookup("rp-id")
	if rpIDFlag.DefValue != "go-keychain" {
		t.Errorf("rp-id default = %v, want go-keychain", rpIDFlag.DefValue)
	}

	timeoutFlag := flags.Lookup("timeout")
	if timeoutFlag.DefValue != "30s" {
		t.Errorf("timeout default = %v, want 30s", timeoutFlag.DefValue)
	}
}

// ============================================================================
// Test userListCmd
// ============================================================================

func TestUserListCmd_Exists(t *testing.T) {
	if userListCmd == nil {
		t.Fatal("userListCmd should not be nil")
	}
}

func TestUserListCmd_Properties(t *testing.T) {
	if userListCmd.Use != "list" {
		t.Errorf("userListCmd.Use = %v, want list", userListCmd.Use)
	}
}

func TestUserListCmd_Run_EmptyStore(t *testing.T) {
	mockStore := NewMockUserStore()

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	// Run the command - should succeed with empty list message
	userListCmd.Run(userListCmd, []string{})

	if mockStore.closed != true {
		t.Error("expected store to be closed after command")
	}
}

func TestUserListCmd_Run_WithUsers(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.AddUser(&user.User{
		ID:          []byte("user1-id"),
		Username:    "user1@example.com",
		DisplayName: "User One",
		Role:        user.RoleAdmin,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
		Credentials: []user.Credential{},
	})
	mockStore.AddUser(&user.User{
		ID:          []byte("user2-id"),
		Username:    "user2@example.com",
		DisplayName: "User Two",
		Role:        user.RoleUser,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
		Credentials: []user.Credential{},
	})

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	// Run the command
	userListCmd.Run(userListCmd, []string{})
}

func TestUserListCmd_Run_WithUsersJSON(t *testing.T) {
	mockStore := NewMockUserStore()
	lastLogin := time.Now().UTC()
	mockStore.AddUser(&user.User{
		ID:          []byte("user1-id"),
		Username:    "user1@example.com",
		DisplayName: "User One",
		Role:        user.RoleAdmin,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
		LastLoginAt: &lastLogin,
		Credentials: []user.Credential{
			{ID: []byte("cred1"), Name: "Key1"},
		},
	})

	cfg := &Config{
		OutputFormat:     "json",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	// Run the command
	userListCmd.Run(userListCmd, []string{})
}

func TestUserListCmd_Run_StoreError(t *testing.T) {
	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactoryWithError(errors.New("store creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userListCmd.Run(userListCmd, []string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserListCmd_Run_ListError(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.listErr = errors.New("list failed")

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userListCmd.Run(userListCmd, []string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

// ============================================================================
// Test userGetCmd
// ============================================================================

func TestUserGetCmd_Exists(t *testing.T) {
	if userGetCmd == nil {
		t.Fatal("userGetCmd should not be nil")
	}
}

func TestUserGetCmd_Properties(t *testing.T) {
	if userGetCmd.Use != "get <username>" {
		t.Errorf("userGetCmd.Use = %v, want 'get <username>'", userGetCmd.Use)
	}
}

func TestUserGetCmd_Run_Success(t *testing.T) {
	mockStore := NewMockUserStore()
	lastLogin := time.Now().UTC()
	lastUsed := time.Now().UTC()
	mockStore.AddUser(&user.User{
		ID:          []byte("user1-id"),
		Username:    "testuser",
		DisplayName: "Test User",
		Role:        user.RoleAdmin,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
		LastLoginAt: &lastLogin,
		Credentials: []user.Credential{
			{
				ID:         []byte("cred1"),
				Name:       "Key1",
				Salt:       []byte("salt123"),
				CreatedAt:  time.Now().UTC(),
				LastUsedAt: &lastUsed,
			},
		},
	})

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	userGetCmd.Run(userGetCmd, []string{"testuser"})
}

func TestUserGetCmd_Run_SuccessJSON(t *testing.T) {
	mockStore := NewMockUserStore()
	lastLogin := time.Now().UTC()
	lastUsed := time.Now().UTC()
	mockStore.AddUser(&user.User{
		ID:          []byte("user1-id"),
		Username:    "testuser",
		DisplayName: "Test User",
		Role:        user.RoleAdmin,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
		LastLoginAt: &lastLogin,
		Credentials: []user.Credential{
			{
				ID:         []byte("cred1"),
				Name:       "Key1",
				Salt:       []byte("salt123"),
				CreatedAt:  time.Now().UTC(),
				LastUsedAt: &lastUsed,
			},
		},
	})

	cfg := &Config{
		OutputFormat:     "json",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	userGetCmd.Run(userGetCmd, []string{"testuser"})
}

func TestUserGetCmd_Run_UserNotFound(t *testing.T) {
	mockStore := NewMockUserStore()

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userGetCmd.Run(userGetCmd, []string{"nonexistent"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserGetCmd_Run_StoreError(t *testing.T) {
	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactoryWithError(errors.New("store creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userGetCmd.Run(userGetCmd, []string{"testuser"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

// ============================================================================
// Test userDeleteCmd
// ============================================================================

func TestUserDeleteCmd_Exists(t *testing.T) {
	if userDeleteCmd == nil {
		t.Fatal("userDeleteCmd should not be nil")
	}
}

func TestUserDeleteCmd_Properties(t *testing.T) {
	if userDeleteCmd.Use != "delete <username>" {
		t.Errorf("userDeleteCmd.Use = %v, want 'delete <username>'", userDeleteCmd.Use)
	}
}

func TestUserDeleteCmd_Run_Success(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.AddUser(&user.User{
		ID:          []byte("user1-id"),
		Username:    "testuser",
		DisplayName: "Test User",
		Role:        user.RoleUser,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
	})
	// Add another admin to avoid last admin error
	mockStore.AddUser(&user.User{
		ID:          []byte("admin-id"),
		Username:    "admin",
		DisplayName: "Admin",
		Role:        user.RoleAdmin,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
	})

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	userDeleteCmd.Run(userDeleteCmd, []string{"testuser"})

	if _, ok := mockStore.users["testuser"]; ok {
		t.Error("expected user to be deleted")
	}
}

func TestUserDeleteCmd_Run_SuccessJSON(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.AddUser(&user.User{
		ID:          []byte("user1-id"),
		Username:    "testuser",
		DisplayName: "Test User",
		Role:        user.RoleUser,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
	})
	mockStore.AddUser(&user.User{
		ID:          []byte("admin-id"),
		Username:    "admin",
		DisplayName: "Admin",
		Role:        user.RoleAdmin,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
	})

	cfg := &Config{
		OutputFormat:     "json",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	userDeleteCmd.Run(userDeleteCmd, []string{"testuser"})
}

func TestUserDeleteCmd_Run_UserNotFound(t *testing.T) {
	mockStore := NewMockUserStore()

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userDeleteCmd.Run(userDeleteCmd, []string{"nonexistent"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserDeleteCmd_Run_DeleteError(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.AddUser(&user.User{
		ID:          []byte("user1-id"),
		Username:    "testuser",
		DisplayName: "Test User",
		Role:        user.RoleUser,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
	})
	mockStore.deleteErr = errors.New("delete failed")

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userDeleteCmd.Run(userDeleteCmd, []string{"testuser"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserDeleteCmd_Run_StoreError(t *testing.T) {
	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactoryWithError(errors.New("store creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userDeleteCmd.Run(userDeleteCmd, []string{"testuser"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

// ============================================================================
// Test userDisableCmd
// ============================================================================

func TestUserDisableCmd_Exists(t *testing.T) {
	if userDisableCmd == nil {
		t.Fatal("userDisableCmd should not be nil")
	}
}

func TestUserDisableCmd_Properties(t *testing.T) {
	if userDisableCmd.Use != "disable <username>" {
		t.Errorf("userDisableCmd.Use = %v, want 'disable <username>'", userDisableCmd.Use)
	}
}

func TestUserDisableCmd_Run_Success(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.AddUser(&user.User{
		ID:          []byte("user1-id"),
		Username:    "testuser",
		DisplayName: "Test User",
		Role:        user.RoleUser,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
	})

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	userDisableCmd.Run(userDisableCmd, []string{"testuser"})

	if mockStore.users["testuser"].Enabled {
		t.Error("expected user to be disabled")
	}
}

func TestUserDisableCmd_Run_SuccessJSON(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.AddUser(&user.User{
		ID:          []byte("user1-id"),
		Username:    "testuser",
		DisplayName: "Test User",
		Role:        user.RoleUser,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
	})

	cfg := &Config{
		OutputFormat:     "json",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	userDisableCmd.Run(userDisableCmd, []string{"testuser"})
}

func TestUserDisableCmd_Run_UserNotFound(t *testing.T) {
	mockStore := NewMockUserStore()

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userDisableCmd.Run(userDisableCmd, []string{"nonexistent"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserDisableCmd_Run_UpdateError(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.AddUser(&user.User{
		ID:          []byte("user1-id"),
		Username:    "testuser",
		DisplayName: "Test User",
		Role:        user.RoleUser,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
	})
	mockStore.updateErr = errors.New("update failed")

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userDisableCmd.Run(userDisableCmd, []string{"testuser"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserDisableCmd_Run_StoreError(t *testing.T) {
	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactoryWithError(errors.New("store creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userDisableCmd.Run(userDisableCmd, []string{"testuser"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

// ============================================================================
// Test userEnableCmd
// ============================================================================

func TestUserEnableCmd_Exists(t *testing.T) {
	if userEnableCmd == nil {
		t.Fatal("userEnableCmd should not be nil")
	}
}

func TestUserEnableCmd_Properties(t *testing.T) {
	if userEnableCmd.Use != "enable <username>" {
		t.Errorf("userEnableCmd.Use = %v, want 'enable <username>'", userEnableCmd.Use)
	}
}

func TestUserEnableCmd_Run_Success(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.AddUser(&user.User{
		ID:          []byte("user1-id"),
		Username:    "testuser",
		DisplayName: "Test User",
		Role:        user.RoleUser,
		Enabled:     false,
		CreatedAt:   time.Now().UTC(),
	})

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	userEnableCmd.Run(userEnableCmd, []string{"testuser"})

	if !mockStore.users["testuser"].Enabled {
		t.Error("expected user to be enabled")
	}
}

func TestUserEnableCmd_Run_SuccessJSON(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.AddUser(&user.User{
		ID:          []byte("user1-id"),
		Username:    "testuser",
		DisplayName: "Test User",
		Role:        user.RoleUser,
		Enabled:     false,
		CreatedAt:   time.Now().UTC(),
	})

	cfg := &Config{
		OutputFormat:     "json",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	userEnableCmd.Run(userEnableCmd, []string{"testuser"})
}

func TestUserEnableCmd_Run_UserNotFound(t *testing.T) {
	mockStore := NewMockUserStore()

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userEnableCmd.Run(userEnableCmd, []string{"nonexistent"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserEnableCmd_Run_UpdateError(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.AddUser(&user.User{
		ID:          []byte("user1-id"),
		Username:    "testuser",
		DisplayName: "Test User",
		Role:        user.RoleUser,
		Enabled:     false,
		CreatedAt:   time.Now().UTC(),
	})
	mockStore.updateErr = errors.New("update failed")

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userEnableCmd.Run(userEnableCmd, []string{"testuser"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserEnableCmd_Run_StoreError(t *testing.T) {
	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactoryWithError(errors.New("store creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userEnableCmd.Run(userEnableCmd, []string{"testuser"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

// ============================================================================
// Test userStatusCmd
// ============================================================================

func TestUserStatusCmd_Exists(t *testing.T) {
	if userStatusCmd == nil {
		t.Fatal("userStatusCmd should not be nil")
	}
}

func TestUserStatusCmd_Properties(t *testing.T) {
	if userStatusCmd.Use != "status" {
		t.Errorf("userStatusCmd.Use = %v, want status", userStatusCmd.Use)
	}
}

func TestUserStatusCmd_Run_NoUsers(t *testing.T) {
	mockStore := NewMockUserStore()

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	userStatusCmd.Run(userStatusCmd, []string{})
}

func TestUserStatusCmd_Run_NoUsersJSON(t *testing.T) {
	mockStore := NewMockUserStore()

	cfg := &Config{
		OutputFormat:     "json",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	userStatusCmd.Run(userStatusCmd, []string{})
}

func TestUserStatusCmd_Run_WithUsers(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.AddUser(&user.User{
		ID:          []byte("user1-id"),
		Username:    "admin",
		DisplayName: "Admin",
		Role:        user.RoleAdmin,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
	})
	mockStore.AddUser(&user.User{
		ID:          []byte("user2-id"),
		Username:    "user",
		DisplayName: "User",
		Role:        user.RoleUser,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
	})

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	userStatusCmd.Run(userStatusCmd, []string{})
}

func TestUserStatusCmd_Run_WithUsersJSON(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.AddUser(&user.User{
		ID:          []byte("user1-id"),
		Username:    "admin",
		DisplayName: "Admin",
		Role:        user.RoleAdmin,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
	})

	cfg := &Config{
		OutputFormat:     "json",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	userStatusCmd.Run(userStatusCmd, []string{})
}

func TestUserStatusCmd_Run_StoreError(t *testing.T) {
	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactoryWithError(errors.New("store creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userStatusCmd.Run(userStatusCmd, []string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserStatusCmd_Run_HasAnyUsersError(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.hasAnyErr = errors.New("has any users failed")

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userStatusCmd.Run(userStatusCmd, []string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserStatusCmd_Run_CountError(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.countErr = errors.New("count failed")

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userStatusCmd.Run(userStatusCmd, []string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserStatusCmd_Run_CountAdminsError(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.countAdminsErr = errors.New("count admins failed")

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userStatusCmd.Run(userStatusCmd, []string{})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

// ============================================================================
// Test userCredentialConfigCmd
// ============================================================================

func TestUserCredentialConfigCmd_Exists(t *testing.T) {
	if userCredentialConfigCmd == nil {
		t.Fatal("userCredentialConfigCmd should not be nil")
	}
}

func TestUserCredentialConfigCmd_Properties(t *testing.T) {
	if userCredentialConfigCmd.Use != "credentials <username>" {
		t.Errorf("userCredentialConfigCmd.Use = %v, want 'credentials <username>'", userCredentialConfigCmd.Use)
	}

	if userCredentialConfigCmd.Short == "" {
		t.Error("userCredentialConfigCmd.Short should not be empty")
	}
}

func TestUserCredentialConfigCmd_Run_Success(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.AddUser(&user.User{
		ID:          []byte("user1-id"),
		Username:    "testuser",
		DisplayName: "Test User",
		Role:        user.RoleUser,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
		Credentials: []user.Credential{
			{
				ID:        []byte("cred1"),
				Name:      "Key1",
				Salt:      []byte("salt123"),
				CreatedAt: time.Now().UTC(),
			},
		},
	})

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	userCredentialConfigCmd.Run(userCredentialConfigCmd, []string{"testuser"})
}

func TestUserCredentialConfigCmd_Run_SuccessJSON(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.AddUser(&user.User{
		ID:          []byte("user1-id"),
		Username:    "testuser",
		DisplayName: "Test User",
		Role:        user.RoleUser,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
		Credentials: []user.Credential{
			{
				ID:        []byte("cred1"),
				Name:      "Key1",
				Salt:      []byte("salt123"),
				CreatedAt: time.Now().UTC(),
			},
		},
	})

	cfg := &Config{
		OutputFormat:     "json",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	userCredentialConfigCmd.Run(userCredentialConfigCmd, []string{"testuser"})
}

func TestUserCredentialConfigCmd_Run_UserNotFound(t *testing.T) {
	mockStore := NewMockUserStore()

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userCredentialConfigCmd.Run(userCredentialConfigCmd, []string{"nonexistent"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserCredentialConfigCmd_Run_NoCredentials(t *testing.T) {
	mockStore := NewMockUserStore()
	mockStore.AddUser(&user.User{
		ID:          []byte("user1-id"),
		Username:    "testuser",
		DisplayName: "Test User",
		Role:        user.RoleUser,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
		Credentials: []user.Credential{}, // No credentials
	})

	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userCredentialConfigCmd.Run(userCredentialConfigCmd, []string{"testuser"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserCredentialConfigCmd_Run_StoreError(t *testing.T) {
	cfg := &Config{
		OutputFormat:     "text",
		UserStoreFactory: createMockUserStoreFactoryWithError(errors.New("store creation failed")),
	}
	cleanup := setupGlobalConfig(cfg)
	defer cleanup()

	code := captureExit(t, func() {
		userCredentialConfigCmd.Run(userCredentialConfigCmd, []string{"testuser"})
	})

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

// ============================================================================
// Test command argument requirements
// ============================================================================

func TestUserCmd_Arguments(t *testing.T) {
	// Verify argument requirements for commands using cobra.Command type
	argCmds := []struct {
		name    string
		cmd     *cobra.Command
		hasArgs bool
	}{
		{"register", userRegisterCmd, true},
		{"get", userGetCmd, true},
		{"delete", userDeleteCmd, true},
		{"disable", userDisableCmd, true},
		{"enable", userEnableCmd, true},
		{"credentials", userCredentialConfigCmd, true},
	}

	for _, tc := range argCmds {
		t.Run(tc.name, func(t *testing.T) {
			if tc.hasArgs && tc.cmd.Args == nil {
				t.Errorf("%s command should have Args set", tc.name)
			}
		})
	}
}

// ============================================================================
// Test UserStoreFactory injection
// ============================================================================

func TestUserStoreFactory_InjectedStore(t *testing.T) {
	mockStore := NewMockUserStore()

	cfg := &Config{
		UserStoreFactory: createMockUserStoreFactory(mockStore),
	}

	store, err := cfg.CreateUserStore("/tmp/test")
	if err != nil {
		t.Fatalf("CreateUserStore() error = %v", err)
	}

	if store != mockStore {
		t.Error("CreateUserStore() should return the injected mock store")
	}
}

func TestUserStoreFactory_InjectedError(t *testing.T) {
	expectedErr := errors.New("store creation failed")

	cfg := &Config{
		UserStoreFactory: createMockUserStoreFactoryWithError(expectedErr),
	}

	_, err := cfg.CreateUserStore("/tmp/test")
	if err == nil {
		t.Error("CreateUserStore() should return error from factory")
	}
	if err != expectedErr {
		t.Errorf("CreateUserStore() error = %v, want %v", err, expectedErr)
	}
}

// ============================================================================
// Verify MockUserStore implements user.Store interface
// ============================================================================

func TestMockUserStore_ImplementsInterface(t *testing.T) {
	var _ user.Store = (*MockUserStore)(nil)
}
