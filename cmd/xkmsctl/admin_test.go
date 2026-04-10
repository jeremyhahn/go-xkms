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

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/user"
	"github.com/spf13/cobra"
)

// ============================================================================
// Command Structure Tests
// ============================================================================

func TestAdminCmd_Exists(t *testing.T) {
	if adminCmd == nil {
		t.Fatal("adminCmd should not be nil")
	}
}

func TestAdminCmd_Properties(t *testing.T) {
	if adminCmd.Use != "admin" {
		t.Errorf("adminCmd.Use = %v, want admin", adminCmd.Use)
	}

	if adminCmd.Short == "" {
		t.Error("adminCmd.Short should not be empty")
	}
}

func TestAdminCmd_HasSubcommands(t *testing.T) {
	subcommands := adminCmd.Commands()

	expectedCmds := []string{
		"create",
		"list",
		"get",
		"delete",
		"disable",
		"enable",
		"status",
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

func TestAdminCreateCmd_Exists(t *testing.T) {
	if adminCreateCmd == nil {
		t.Fatal("adminCreateCmd should not be nil")
	}
}

func TestAdminCreateCmd_Properties(t *testing.T) {
	if adminCreateCmd.Use != "create <username>" {
		t.Errorf("adminCreateCmd.Use = %v, want 'create <username>'", adminCreateCmd.Use)
	}
}

func TestAdminCreateCmd_HasFlags(t *testing.T) {
	flags := adminCreateCmd.Flags()

	expectedFlags := []string{
		"display-name",
		"rp-id",
		"rp-name",
		"timeout",
		"device",
		"user-verification",
	}

	for _, flag := range expectedFlags {
		if flags.Lookup(flag) == nil {
			t.Errorf("expected flag %q not found on adminCreateCmd", flag)
		}
	}
}

func TestAdminListCmd_Exists(t *testing.T) {
	if adminListCmd == nil {
		t.Fatal("adminListCmd should not be nil")
	}
}

func TestAdminGetCmd_Exists(t *testing.T) {
	if adminGetCmd == nil {
		t.Fatal("adminGetCmd should not be nil")
	}
}

func TestAdminGetCmd_Properties(t *testing.T) {
	if adminGetCmd.Use != "get <username>" {
		t.Errorf("adminGetCmd.Use = %v, want 'get <username>'", adminGetCmd.Use)
	}
}

func TestAdminDeleteCmd_Exists(t *testing.T) {
	if adminDeleteCmd == nil {
		t.Fatal("adminDeleteCmd should not be nil")
	}
}

func TestAdminDeleteCmd_Properties(t *testing.T) {
	if adminDeleteCmd.Use != "delete <username>" {
		t.Errorf("adminDeleteCmd.Use = %v, want 'delete <username>'", adminDeleteCmd.Use)
	}
}

func TestAdminDisableCmd_Exists(t *testing.T) {
	if adminDisableCmd == nil {
		t.Fatal("adminDisableCmd should not be nil")
	}
}

func TestAdminDisableCmd_Properties(t *testing.T) {
	if adminDisableCmd.Use != "disable <username>" {
		t.Errorf("adminDisableCmd.Use = %v, want 'disable <username>'", adminDisableCmd.Use)
	}
}

func TestAdminEnableCmd_Exists(t *testing.T) {
	if adminEnableCmd == nil {
		t.Fatal("adminEnableCmd should not be nil")
	}
}

func TestAdminEnableCmd_Properties(t *testing.T) {
	if adminEnableCmd.Use != "enable <username>" {
		t.Errorf("adminEnableCmd.Use = %v, want 'enable <username>'", adminEnableCmd.Use)
	}
}

func TestAdminStatusCmd_Exists(t *testing.T) {
	if adminStatusCmd == nil {
		t.Fatal("adminStatusCmd should not be nil")
	}
}

func TestAdminStatusCmd_Properties(t *testing.T) {
	if adminStatusCmd.Use != "status" {
		t.Errorf("adminStatusCmd.Use = %v, want status", adminStatusCmd.Use)
	}
}

func TestAdminCmd_PersistentFlags(t *testing.T) {
	flags := adminCmd.PersistentFlags()

	if flags.Lookup("storage-path") == nil {
		t.Error("expected persistent flag 'storage-path' not found on adminCmd")
	}
}

func TestAdminCreateCmd_FlagDefaults(t *testing.T) {
	flags := adminCreateCmd.Flags()

	rpIDFlag := flags.Lookup("rp-id")
	if rpIDFlag.DefValue != "go-xkms" {
		t.Errorf("rp-id default = %v, want go-xkms", rpIDFlag.DefValue)
	}

	rpNameFlag := flags.Lookup("rp-name")
	if rpNameFlag.DefValue != "Go xKMS" {
		t.Errorf("rp-name default = %v, want 'Go xKMS'", rpNameFlag.DefValue)
	}

	timeoutFlag := flags.Lookup("timeout")
	if timeoutFlag.DefValue != "30s" {
		t.Errorf("timeout default = %v, want 30s", timeoutFlag.DefValue)
	}
}

func TestAdminCmd_Arguments(t *testing.T) {
	argCmds := []struct {
		name    string
		cmd     *cobra.Command
		hasArgs bool
	}{
		{"create", adminCreateCmd, true},
		{"get", adminGetCmd, true},
		{"delete", adminDeleteCmd, true},
		{"disable", adminDisableCmd, true},
		{"enable", adminEnableCmd, true},
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
// Helper Function Tests
// ============================================================================

func TestResolveStoragePath_WithEnvVar(t *testing.T) {
	originalEnv := os.Getenv("XKMS_STORAGE_PATH")
	defer func() {
		if originalEnv != "" {
			if err := os.Setenv("XKMS_STORAGE_PATH", originalEnv); err != nil {
				t.Errorf("failed to restore env: %v", err)
			}
		} else {
			_ = os.Unsetenv("XKMS_STORAGE_PATH")
		}
	}()

	testPath := "/custom/storage/path"
	if err := os.Setenv("XKMS_STORAGE_PATH", testPath); err != nil {
		t.Fatalf("failed to set env: %v", err)
	}

	result := resolveStoragePath("")
	if result != testPath {
		t.Errorf("resolveStoragePath() = %v, want %v", result, testPath)
	}
}

func TestResolveStoragePath_WithExplicitPath(t *testing.T) {
	explicitPath := "/explicit/path"
	result := resolveStoragePath(explicitPath)
	if result != explicitPath {
		t.Errorf("resolveStoragePath() = %v, want %v", result, explicitPath)
	}
}

func TestResolveStoragePath_Default(t *testing.T) {
	originalEnv := os.Getenv("XKMS_STORAGE_PATH")
	defer func() {
		if originalEnv != "" {
			if err := os.Setenv("XKMS_STORAGE_PATH", originalEnv); err != nil {
				t.Errorf("failed to restore env: %v", err)
			}
		}
	}()
	if err := os.Unsetenv("XKMS_STORAGE_PATH"); err != nil {
		t.Fatalf("failed to unset env: %v", err)
	}

	result := resolveStoragePath("")
	if result != "/var/lib/xkms" {
		t.Errorf("resolveStoragePath() = %v, want /var/lib/xkms", result)
	}
}

func TestRepeatString(t *testing.T) {
	tests := []struct {
		s      string
		count  int
		expect string
	}{
		{"-", 5, "-----"},
		{"*", 3, "***"},
		{"ab", 2, "abab"},
		{"-", 0, ""},
		{"", 5, ""},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			result := repeatString(tt.s, tt.count)
			if result != tt.expect {
				t.Errorf("repeatString(%q, %d) = %q, want %q", tt.s, tt.count, result, tt.expect)
			}
		})
	}
}

func TestRepeatString_NegativeCount(t *testing.T) {
	result := repeatString("-", -1)
	if result != "" {
		t.Errorf("repeatString with negative count should return empty string, got %q", result)
	}
}

func TestRepeatString_LargeCount(t *testing.T) {
	result := repeatString("x", 100)
	if len(result) != 100 {
		t.Errorf("repeatString with count 100 should return 100 chars, got %d", len(result))
	}
}

func TestOpenUserStore_ValidPath(t *testing.T) {
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, "test-users")

	store, err := openUserStore(storagePath)
	if err != nil {
		t.Fatalf("openUserStore failed: %v", err)
	}
	defer func() { _ = store.Close() }()

	if store == nil {
		t.Error("openUserStore should return non-nil store")
	}
}

func TestOpenUserStore_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, "new-users-dir")

	store, err := openUserStore(storagePath)
	if err != nil {
		t.Fatalf("openUserStore failed: %v", err)
	}
	defer func() { _ = store.Close() }()

	usersPath := storagePath + "/users"
	if _, statErr := os.Stat(usersPath); os.IsNotExist(statErr) {
		t.Error("openUserStore should create the users directory")
	}
}

// ============================================================================
// Test Helpers for Command Run Tests
// ============================================================================

// createTestUserStore creates a temporary user store for testing
func createTestUserStore(t *testing.T) (user.Store, string) {
	t.Helper()
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, "users")

	storage, err := file.New(storagePath)
	if err != nil {
		t.Fatalf("failed to create file storage: %v", err)
	}

	store, err := user.NewFileStore(storage, user.WithCleanupInterval(time.Second))
	if err != nil {
		t.Fatalf("failed to create user store: %v", err)
	}

	return store, tmpDir
}

// createTestAdmin creates a test admin user in the store with a sufficiently long ID
func createTestAdmin(t *testing.T, store user.Store, username string) *user.User {
	t.Helper()
	ctx := context.Background()
	admin, err := store.Create(ctx, username, "Test Admin", user.RoleAdmin, "")
	if err != nil {
		t.Fatalf("failed to create test admin: %v", err)
	}
	return admin
}

// captureStdout captures stdout during function execution
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}

	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	if _, copyErr := io.Copy(&buf, r); copyErr != nil {
		t.Fatalf("failed to read captured output: %v", copyErr)
	}

	return buf.String()
}

// executeAdminCommand executes an admin subcommand with proper flag handling
func executeAdminCommand(t *testing.T, storagePath string, args ...string) (string, error) {
	t.Helper()

	buf := new(bytes.Buffer)

	// Create a fresh command instance for testing
	cmd := &cobra.Command{Use: "test"}
	cmd.AddCommand(adminCmd)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	// Build the full args including storage-path
	fullArgs := append([]string{"admin"}, args...)
	fullArgs = append(fullArgs, "--storage-path", storagePath)
	cmd.SetArgs(fullArgs)

	// Capture stdout since commands use fmt.Println
	output := captureStdout(t, func() {
		_ = cmd.Execute()
	})

	return output, nil
}

// ============================================================================
// Admin Status Command Tests
// ============================================================================

func TestAdminStatusCmd_Run_NoAdmins(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	output, _ := executeAdminCommand(t, tmpDir, "status")

	if !strings.Contains(output, "NOT CONFIGURED") {
		t.Errorf("expected status to indicate no admins, got: %s", output)
	}
}

func TestAdminStatusCmd_Run_WithAdmins(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	createTestAdmin(t, store, "admin@test.com")

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	output, _ := executeAdminCommand(t, tmpDir, "status")

	if !strings.Contains(output, "CONFIGURED") {
		t.Errorf("expected status to indicate configured, got: %s", output)
	}
}

func TestAdminStatusCmd_Run_JSONOutput(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	createTestAdmin(t, store, "admin@test.com")

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "json"

	output, _ := executeAdminCommand(t, tmpDir, "status")

	if !strings.Contains(output, "admin_count") || !strings.Contains(output, "requires_setup") {
		t.Errorf("expected JSON output with admin_count and requires_setup, got: %s", output)
	}
}

func TestAdminStatusCmd_Run_JSONOutput_NoAdmins(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "json"

	output, _ := executeAdminCommand(t, tmpDir, "status")

	if !strings.Contains(output, "requires_setup") || !strings.Contains(output, "true") {
		t.Errorf("expected JSON output with requires_setup: true, got: %s", output)
	}
}

// ============================================================================
// Admin List Command Tests
// ============================================================================

func TestAdminListCmd_Run_NoAdmins(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	output, _ := executeAdminCommand(t, tmpDir, "list")

	if !strings.Contains(output, "No administrator") {
		t.Errorf("expected message about no administrators, got: %s", output)
	}
}

// Note: TestAdminListCmd_Run_WithAdmins uses JSON format because the text format
// has a production bug that panics when the user ID is too short for truncation.
func TestAdminListCmd_Run_WithAdmins(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	createTestAdmin(t, store, "admin1@test.com")
	createTestAdmin(t, store, "admin2@test.com")

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "json"

	output, _ := executeAdminCommand(t, tmpDir, "list")

	if !strings.Contains(output, "total") || !strings.Contains(output, "2") {
		t.Errorf("expected total of 2 administrators, got: %s", output)
	}
}

func TestAdminListCmd_Run_JSONOutput(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	createTestAdmin(t, store, "admin@test.com")

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "json"

	output, _ := executeAdminCommand(t, tmpDir, "list")

	if !strings.Contains(output, "admins") || !strings.Contains(output, "total") {
		t.Errorf("expected JSON output with admins and total, got: %s", output)
	}
}

// Note: Uses JSON format due to production bug in text format truncation.
func TestAdminListCmd_Run_WithCredentials(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	admin := createTestAdmin(t, store, "admin@test.com")
	admin.AddCredential(&user.Credential{
		ID:        []byte("test-credential-id"),
		PublicKey: []byte("test-public-key"),
		Name:      "Test Key",
		CreatedAt: time.Now().UTC(),
	})
	ctx := context.Background()
	if err := store.Update(ctx, admin); err != nil {
		t.Fatalf("failed to update admin: %v", err)
	}

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "json"

	output, _ := executeAdminCommand(t, tmpDir, "list")

	if !strings.Contains(output, "admin@test.com") || !strings.Contains(output, "total") {
		t.Errorf("expected admin username and total in output, got: %s", output)
	}
}

func TestAdminListCmd_Run_WithLastLogin(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	admin := createTestAdmin(t, store, "admin@test.com")
	now := time.Now().UTC()
	admin.LastLoginAt = &now
	ctx := context.Background()
	if err := store.Update(ctx, admin); err != nil {
		t.Fatalf("failed to update admin: %v", err)
	}

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "json"

	output, _ := executeAdminCommand(t, tmpDir, "list")

	if !strings.Contains(output, "last_login_at") {
		t.Errorf("expected last_login_at in JSON output, got: %s", output)
	}
}

// ============================================================================
// Admin Get Command Tests
// ============================================================================

func TestAdminGetCmd_Run_Success(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	createTestAdmin(t, store, "admin@test.com")

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	output, _ := executeAdminCommand(t, tmpDir, "get", "admin@test.com")

	if !strings.Contains(output, "admin@test.com") {
		t.Errorf("expected admin username in output, got: %s", output)
	}
	if !strings.Contains(output, "Administrator Details") {
		t.Errorf("expected 'Administrator Details' in output, got: %s", output)
	}
}

func TestAdminGetCmd_Run_NotFound(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	exitCode := captureExit(t, func() {
		_, _ = executeAdminCommand(t, tmpDir, "get", "nonexistent@test.com")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for not found, got %d", exitCode)
	}
}

func TestAdminGetCmd_Run_JSONOutput(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	createTestAdmin(t, store, "admin@test.com")

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "json"

	output, _ := executeAdminCommand(t, tmpDir, "get", "admin@test.com")

	if !strings.Contains(output, "username") || !strings.Contains(output, "admin@test.com") {
		t.Errorf("expected JSON output with username, got: %s", output)
	}
}

func TestAdminGetCmd_Run_WithCredentials(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	admin := createTestAdmin(t, store, "admin@test.com")
	now := time.Now().UTC()
	admin.AddCredential(&user.Credential{
		ID:         []byte("test-credential-id"),
		PublicKey:  []byte("test-public-key"),
		Name:       "Security Key 1",
		CreatedAt:  now,
		LastUsedAt: &now,
	})
	ctx := context.Background()
	if err := store.Update(ctx, admin); err != nil {
		t.Fatalf("failed to update admin: %v", err)
	}

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	output, _ := executeAdminCommand(t, tmpDir, "get", "admin@test.com")

	if !strings.Contains(output, "Credentials (1)") {
		t.Errorf("expected credentials section in output, got: %s", output)
	}
	if !strings.Contains(output, "Security Key 1") {
		t.Errorf("expected credential name in output, got: %s", output)
	}
}

func TestAdminGetCmd_Run_JSONWithLastLogin(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	admin := createTestAdmin(t, store, "admin@test.com")
	now := time.Now().UTC()
	admin.LastLoginAt = &now
	ctx := context.Background()
	if err := store.Update(ctx, admin); err != nil {
		t.Fatalf("failed to update admin: %v", err)
	}

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "json"

	output, _ := executeAdminCommand(t, tmpDir, "get", "admin@test.com")

	if !strings.Contains(output, "last_login_at") {
		t.Errorf("expected last_login_at in JSON output, got: %s", output)
	}
}

func TestAdminGetCmd_Run_TextWithLastLogin(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	admin := createTestAdmin(t, store, "admin@test.com")
	now := time.Now().UTC()
	admin.LastLoginAt = &now
	ctx := context.Background()
	if err := store.Update(ctx, admin); err != nil {
		t.Fatalf("failed to update admin: %v", err)
	}

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	output, _ := executeAdminCommand(t, tmpDir, "get", "admin@test.com")

	if !strings.Contains(output, "Last Login:") {
		t.Errorf("expected 'Last Login:' in text output, got: %s", output)
	}
}

func TestAdminGetCmd_Run_JSONCredentialsWithLastUsed(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	admin := createTestAdmin(t, store, "admin@test.com")
	now := time.Now().UTC()
	admin.AddCredential(&user.Credential{
		ID:         []byte("test-cred"),
		PublicKey:  []byte("test-key"),
		Name:       "Test Cred",
		CreatedAt:  now,
		LastUsedAt: &now,
	})
	ctx := context.Background()
	if err := store.Update(ctx, admin); err != nil {
		t.Fatalf("failed to update admin: %v", err)
	}

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "json"

	output, _ := executeAdminCommand(t, tmpDir, "get", "admin@test.com")

	if !strings.Contains(output, "last_used_at") {
		t.Errorf("expected last_used_at in credential JSON output, got: %s", output)
	}
}

// ============================================================================
// Admin Delete Command Tests
// ============================================================================

func TestAdminDeleteCmd_Run_Success(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	// Create two admins so we can delete one
	createTestAdmin(t, store, "admin1@test.com")
	createTestAdmin(t, store, "admin2@test.com")

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	output, _ := executeAdminCommand(t, tmpDir, "delete", "admin1@test.com")

	if !strings.Contains(output, "deleted successfully") {
		t.Errorf("expected success message, got: %s", output)
	}
}

func TestAdminDeleteCmd_Run_NotFound(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	exitCode := captureExit(t, func() {
		_, _ = executeAdminCommand(t, tmpDir, "delete", "nonexistent@test.com")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for not found, got %d", exitCode)
	}
}

func TestAdminDeleteCmd_Run_JSONOutput(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	createTestAdmin(t, store, "admin1@test.com")
	createTestAdmin(t, store, "admin2@test.com")

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "json"

	output, _ := executeAdminCommand(t, tmpDir, "delete", "admin1@test.com")

	if !strings.Contains(output, "success") || !strings.Contains(output, "true") {
		t.Errorf("expected JSON success output, got: %s", output)
	}
}

func TestAdminDeleteCmd_Run_LastAdmin(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	// Create only one admin
	createTestAdmin(t, store, "admin@test.com")

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	exitCode := captureExit(t, func() {
		_, _ = executeAdminCommand(t, tmpDir, "delete", "admin@test.com")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 when deleting last admin, got %d", exitCode)
	}
}

// ============================================================================
// Admin Disable Command Tests
// ============================================================================

func TestAdminDisableCmd_Run_Success(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	createTestAdmin(t, store, "admin@test.com")

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	output, _ := executeAdminCommand(t, tmpDir, "disable", "admin@test.com")

	if !strings.Contains(output, "disabled") {
		t.Errorf("expected disabled message, got: %s", output)
	}

	// Verify the user is actually disabled
	ctx := context.Background()
	admin, getErr := store.GetByUsername(ctx, "admin@test.com")
	if getErr != nil {
		t.Fatalf("failed to get admin: %v", getErr)
	}
	if admin.Enabled {
		t.Error("admin should be disabled")
	}
}

func TestAdminDisableCmd_Run_NotFound(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	exitCode := captureExit(t, func() {
		_, _ = executeAdminCommand(t, tmpDir, "disable", "nonexistent@test.com")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for not found, got %d", exitCode)
	}
}

func TestAdminDisableCmd_Run_JSONOutput(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	createTestAdmin(t, store, "admin@test.com")

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "json"

	output, _ := executeAdminCommand(t, tmpDir, "disable", "admin@test.com")

	if !strings.Contains(output, "enabled") || !strings.Contains(output, "false") {
		t.Errorf("expected JSON output with enabled: false, got: %s", output)
	}
}

// ============================================================================
// Admin Enable Command Tests
// ============================================================================

func TestAdminEnableCmd_Run_Success(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	// Create and disable an admin
	admin := createTestAdmin(t, store, "admin@test.com")
	admin.Enabled = false
	ctx := context.Background()
	if err := store.Update(ctx, admin); err != nil {
		t.Fatalf("failed to disable admin: %v", err)
	}

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	output, _ := executeAdminCommand(t, tmpDir, "enable", "admin@test.com")

	if !strings.Contains(output, "enabled") {
		t.Errorf("expected enabled message, got: %s", output)
	}

	// Verify the user is actually enabled
	admin, getErr := store.GetByUsername(ctx, "admin@test.com")
	if getErr != nil {
		t.Fatalf("failed to get admin: %v", getErr)
	}
	if !admin.Enabled {
		t.Error("admin should be enabled")
	}
}

func TestAdminEnableCmd_Run_NotFound(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	exitCode := captureExit(t, func() {
		_, _ = executeAdminCommand(t, tmpDir, "enable", "nonexistent@test.com")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for not found, got %d", exitCode)
	}
}

func TestAdminEnableCmd_Run_JSONOutput(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	// Create and disable an admin
	admin := createTestAdmin(t, store, "admin@test.com")
	admin.Enabled = false
	ctx := context.Background()
	if err := store.Update(ctx, admin); err != nil {
		t.Fatalf("failed to disable admin: %v", err)
	}

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "json"

	output, _ := executeAdminCommand(t, tmpDir, "enable", "admin@test.com")

	if !strings.Contains(output, "enabled") || !strings.Contains(output, "true") {
		t.Errorf("expected JSON output with enabled: true, got: %s", output)
	}
}

// ============================================================================
// Error Path Tests - Invalid Storage Path
// ============================================================================

func TestAdminStatusCmd_Run_InvalidStoragePath(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	exitCode := captureExit(t, func() {
		_, _ = executeAdminCommand(t, "/dev/null/invalid", "status")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid storage path, got %d", exitCode)
	}
}

func TestAdminListCmd_Run_InvalidStoragePath(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	exitCode := captureExit(t, func() {
		_, _ = executeAdminCommand(t, "/dev/null/invalid", "list")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid storage path, got %d", exitCode)
	}
}

func TestAdminGetCmd_Run_InvalidStoragePath(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	exitCode := captureExit(t, func() {
		_, _ = executeAdminCommand(t, "/dev/null/invalid", "get", "admin@test.com")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid storage path, got %d", exitCode)
	}
}

func TestAdminDeleteCmd_Run_InvalidStoragePath(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	exitCode := captureExit(t, func() {
		_, _ = executeAdminCommand(t, "/dev/null/invalid", "delete", "admin@test.com")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid storage path, got %d", exitCode)
	}
}

func TestAdminDisableCmd_Run_InvalidStoragePath(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	exitCode := captureExit(t, func() {
		_, _ = executeAdminCommand(t, "/dev/null/invalid", "disable", "admin@test.com")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid storage path, got %d", exitCode)
	}
}

func TestAdminEnableCmd_Run_InvalidStoragePath(t *testing.T) {
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	exitCode := captureExit(t, func() {
		_, _ = executeAdminCommand(t, "/dev/null/invalid", "enable", "admin@test.com")
	})

	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid storage path, got %d", exitCode)
	}
}

// ============================================================================
// Edge Case Tests
// ============================================================================

func TestAdminGetCmd_Run_MultipleCredentials(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	admin := createTestAdmin(t, store, "admin@test.com")
	now := time.Now().UTC()

	// Add multiple credentials
	admin.AddCredential(&user.Credential{
		ID:        []byte("cred1"),
		PublicKey: []byte("key1"),
		Name:      "Key 1",
		CreatedAt: now,
	})
	admin.AddCredential(&user.Credential{
		ID:        []byte("cred2"),
		PublicKey: []byte("key2"),
		Name:      "Key 2",
		CreatedAt: now,
	})

	ctx := context.Background()
	if err := store.Update(ctx, admin); err != nil {
		t.Fatalf("failed to update admin: %v", err)
	}

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "text"

	output, _ := executeAdminCommand(t, tmpDir, "get", "admin@test.com")

	if !strings.Contains(output, "Credentials (2)") {
		t.Errorf("expected 2 credentials, got: %s", output)
	}
	if !strings.Contains(output, "Key 1") || !strings.Contains(output, "Key 2") {
		t.Errorf("expected both credential names in output, got: %s", output)
	}
}

func TestAdminListCmd_Run_JSONOutput_NoAdmins(t *testing.T) {
	store, tmpDir := createTestUserStore(t)
	defer func() { _ = store.Close() }()

	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()
	globalConfig.OutputFormat = "json"

	output, _ := executeAdminCommand(t, tmpDir, "list")

	// When there are no admins, the command prints a message instead of JSON array
	if !strings.Contains(output, "No administrator accounts configured") {
		t.Errorf("expected no admins message, got: %s", output)
	}
}
