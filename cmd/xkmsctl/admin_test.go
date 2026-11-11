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

func TestAdminCreateCmd_FlagDefaults(t *testing.T) {
	flags := adminCreateCmd.Flags()

	methodFlag := flags.Lookup("method")
	if methodFlag.DefValue != "fido2" {
		t.Errorf("method default = %v, want fido2", methodFlag.DefValue)
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
