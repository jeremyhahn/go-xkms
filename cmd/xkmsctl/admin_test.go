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
	"io"
	"os"
	"strings"
	"testing"

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

// ============================================================================
// Test Helpers for Command Run Tests
// ============================================================================

// newTestStorageDir returns a temporary directory the admin command can use
// for its --storage-path flag. Identity lives in the embedded qrdb node, so the
// directory only needs to exist; nothing pre-populates a local user store.
func newTestStorageDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
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

// The binary's own bootstrap guidance must name the flags it now requires.
//
// FIDO2 admin enrollment began rejecting requests without --email, while the
// command's help examples and the `admin status` remediation text still told
// operators to run the old form. On a fresh system with no admins, following
// the binary's own instructions dead-ended on the FIRST-RUN setup path (Codex,
// go-xkms #190).
//
// Asserting on the strings is the point: nothing else fails when guidance goes
// stale, which is exactly why it did.
func TestBootstrapGuidance_NamesTheRequiredEmailFlag(t *testing.T) {
	// The FIDO2 example must carry --email; the mTLS ones must NOT, because
	// that admin is resolved by certificate thumbprint and has no login key.
	long := adminCreateCmd.Long
	fido2Line := ""
	for _, line := range strings.Split(long, "\n") {
		if strings.Contains(line, "admin create") && !strings.Contains(line, "--method mtls") {
			fido2Line = line
			break
		}
	}
	if fido2Line == "" {
		t.Fatal("no FIDO2 example found in `admin create` help")
	}
	if !strings.Contains(fido2Line, "--email") {
		t.Errorf("the FIDO2 example omits the flag the command now requires: %q", fido2Line)
	}
	for _, line := range strings.Split(long, "\n") {
		if strings.Contains(line, "--method mtls") && strings.Contains(line, "--email") {
			t.Errorf("an mTLS example demands --email, which that path does not use: %q", line)
		}
	}
}
