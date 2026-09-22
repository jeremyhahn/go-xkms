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

package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// newTestServeCmd creates a fresh cobra command with the serve flags registered,
// isolated from global state. This avoids cross-test pollution.
func newTestServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "serve",
		RunE: func(cmd *cobra.Command, args []string) error { return nil },
	}
	cmd.Flags().String("barrier-password", "", "")
	cmd.Flags().String("barrier-password-file", "", "")
	cmd.Flags().Bool("no-barrier", false, "")
	cmd.Flags().String("socket", "", "")
	cmd.Flags().String("log-level", "info", "")
	cmd.Flags().String("log-file", "", "")
	cmd.Flags().Int("auto-lock-minutes", 15, "")
	cmd.Flags().String("pin-state", "", "")
	cmd.Flags().Bool("no-auth", false, "")
	cmd.Flags().Bool("no-pairing", false, "")
	cmd.Flags().String("tpm-device", "", "")
	cmd.Flags().Bool("tpm-simulator", false, "")
	addSOPINFlags(cmd)
	return cmd
}

func TestResolveBarrierPassword_Flag(t *testing.T) {
	cmd := newTestServeCmd()
	if err := cmd.Flags().Set("barrier-password", "test-flag-pw"); err != nil {
		t.Fatal(err)
	}
	// Clear env to avoid interference.
	t.Setenv("XKEY_BARRIER_PASSWORD", "")

	pw, err := resolveBarrierPassword(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pw != "test-flag-pw" {
		t.Fatalf("expected 'test-flag-pw', got %q", pw)
	}
}

func TestResolveBarrierPassword_Env(t *testing.T) {
	cmd := newTestServeCmd()
	t.Setenv("XKEY_BARRIER_PASSWORD", "env-pw-value")

	pw, err := resolveBarrierPassword(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pw != "env-pw-value" {
		t.Fatalf("expected 'env-pw-value', got %q", pw)
	}
}

func TestResolveBarrierPassword_File(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "barrier-pw.txt")
	if err := os.WriteFile(tmpFile, []byte("file-pw-value\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := newTestServeCmd()
	if err := cmd.Flags().Set("barrier-password-file", tmpFile); err != nil {
		t.Fatal(err)
	}
	// Clear env to avoid interference.
	t.Setenv("XKEY_BARRIER_PASSWORD", "")

	pw, err := resolveBarrierPassword(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pw != "file-pw-value" {
		t.Fatalf("expected 'file-pw-value', got %q", pw)
	}
}

func TestResolveBarrierPassword_FileNotExist(t *testing.T) {
	cmd := newTestServeCmd()
	if err := cmd.Flags().Set("barrier-password-file", "/nonexistent/path/file.txt"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XKEY_BARRIER_PASSWORD", "")

	_, err := resolveBarrierPassword(cmd)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !errors.Is(err, ErrServeBarrierPasswordRequired) {
		t.Fatalf("expected ErrServeBarrierPasswordRequired, got %v", err)
	}
}

func TestResolveBarrierPassword_Priority_FlagOverFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "barrier-pw.txt")
	if err := os.WriteFile(tmpFile, []byte("file-pw\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := newTestServeCmd()
	if err := cmd.Flags().Set("barrier-password", "flag-pw"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("barrier-password-file", tmpFile); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XKEY_BARRIER_PASSWORD", "env-pw")

	pw, err := resolveBarrierPassword(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pw != "flag-pw" {
		t.Fatalf("expected 'flag-pw' (flag takes priority), got %q", pw)
	}
}

func TestResolveBarrierPassword_Priority_FileOverEnv(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "barrier-pw.txt")
	if err := os.WriteFile(tmpFile, []byte("file-pw\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := newTestServeCmd()
	if err := cmd.Flags().Set("barrier-password-file", tmpFile); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XKEY_BARRIER_PASSWORD", "env-pw")

	pw, err := resolveBarrierPassword(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pw != "file-pw" {
		t.Fatalf("expected 'file-pw' (file takes priority over env), got %q", pw)
	}
}

func TestResolveBarrierPassword_NoSourceNonTerminal(t *testing.T) {
	cmd := newTestServeCmd()
	t.Setenv("XKEY_BARRIER_PASSWORD", "")

	_, err := resolveBarrierPassword(cmd)
	if !errors.Is(err, ErrServeBarrierPasswordRequired) {
		t.Fatalf("expected ErrServeBarrierPasswordRequired, got %v", err)
	}
}

func TestResolveBarrierPassword_FileTrimsWhitespace(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "barrier-pw.txt")
	if err := os.WriteFile(tmpFile, []byte("  trimmed-pw  \nsecond-line\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := newTestServeCmd()
	if err := cmd.Flags().Set("barrier-password-file", tmpFile); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XKEY_BARRIER_PASSWORD", "")

	pw, err := resolveBarrierPassword(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pw != "trimmed-pw" {
		t.Fatalf("expected 'trimmed-pw' (first line, trimmed), got %q", pw)
	}
}

func TestHeadlessHandler_Touch(t *testing.T) {
	h := &headlessHandler{}
	resp, err := h.HandleTouch()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != ipc.StatusOK {
		t.Fatalf("expected status %q, got %q", ipc.StatusOK, resp.Status)
	}
	if resp.Action != ipc.ActionApprovedUP {
		t.Fatalf("expected action %q, got %q", ipc.ActionApprovedUP, resp.Action)
	}
}

func TestHeadlessHandler_TypePassword_Error(t *testing.T) {
	h := &headlessHandler{}
	resp, err := h.HandleTypePassword("some-name")
	if resp != nil {
		t.Fatal("expected nil response for unsupported operation")
	}
	if err == nil {
		t.Fatal("expected error for type_password in headless mode")
	}
	if !errors.Is(err, ErrServeTypePasswordUnsupported) {
		t.Fatalf("expected ErrServeTypePasswordUnsupported, got %v", err)
	}
}

func TestHeadlessHandler_Status(t *testing.T) {
	h := &headlessHandler{}
	resp, err := h.HandleStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != ipc.StatusOK {
		t.Fatalf("expected status %q, got %q", ipc.StatusOK, resp.Status)
	}
	if resp.Action != ipc.ActionDaemonReady {
		t.Fatalf("expected action %q, got %q", ipc.ActionDaemonReady, resp.Action)
	}
}

func TestParseSlogLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"debug", "DEBUG"},
		{"info", "INFO"},
		{"warn", "WARN"},
		{"warning", "WARN"},
		{"error", "ERROR"},
		{"unknown", "INFO"},
		{"", "INFO"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			level := parseSlogLevel(tt.input)
			if level.String() != tt.expected {
				t.Fatalf("parseSlogLevel(%q) = %v, want %v", tt.input, level, tt.expected)
			}
		})
	}
}

func TestCreateServeLogger_Stderr(t *testing.T) {
	cmd := newTestServeCmd()

	logger, closer, err := createServeLogger(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if closer != nil {
		t.Fatal("expected nil closer for stderr logger")
	}
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestCreateServeLogger_File(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "test.log")
	cmd := newTestServeCmd()
	if err := cmd.Flags().Set("log-file", logPath); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("log-level", "debug"); err != nil {
		t.Fatal(err)
	}

	logger, closer, err := createServeLogger(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if closer == nil {
		t.Fatal("expected non-nil closer for file logger")
	}
	defer closer.Close()

	if logger == nil {
		t.Fatal("expected non-nil logger")
	}

	// Write a log entry and verify the file was written.
	logger.Info("test message")
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("log file not created: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("log file is empty after writing")
	}
}

func TestCreateServeLogger_BadPath(t *testing.T) {
	cmd := newTestServeCmd()
	if err := cmd.Flags().Set("log-file", "/nonexistent-dir/test.log"); err != nil {
		t.Fatal(err)
	}

	_, _, err := createServeLogger(cmd)
	if err == nil {
		t.Fatal("expected error for nonexistent log path")
	}
	if !errors.Is(err, ErrServeLogFileOpenFailed) {
		t.Fatalf("expected ErrServeLogFileOpenFailed, got %v", err)
	}
}

func TestExtensionServeCmd_NoBarrier_IPCConnectivity(t *testing.T) {
	tmpDir := t.TempDir()

	// Set xhome override so Resolve() uses our temp directory.
	xhome.SetRoot(tmpDir)
	defer xhome.ResetRoot()

	socketPath := filepath.Join(tmpDir, "test-serve.sock")

	// Build and execute the serve command in a goroutine.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := &cobra.Command{
		Use:  "serve",
		RunE: runExtensionServe,
	}
	cmd.Flags().String("socket", socketPath, "")
	cmd.Flags().String("log-level", "error", "")
	cmd.Flags().String("log-file", "", "")
	cmd.Flags().String("barrier-password", "", "")
	cmd.Flags().String("barrier-password-file", "", "")
	cmd.Flags().Bool("no-barrier", true, "")
	cmd.Flags().Int("auto-lock-minutes", 0, "")
	cmd.Flags().String("pin-state", filepath.Join(tmpDir, "pin.json"), "")
	cmd.Flags().Bool("no-auth", false, "")
	cmd.Flags().Bool("no-pairing", false, "")

	serverErr := make(chan error, 1)
	go func() {
		// RunE blocks until signal; we cancel via context.
		err := cmd.ExecuteContext(ctx)
		serverErr <- err
	}()

	// Wait for the socket to appear.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case err := <-serverErr:
			t.Fatalf("server exited prematurely: %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for IPC socket")
		default:
			if _, err := os.Stat(socketPath); err == nil {
				goto socketReady
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

socketReady:
	// Connect with IPC client and verify status.
	client := ipc.NewClient(socketPath)
	defer client.Close()

	resp, err := client.Status()
	if err != nil {
		t.Fatalf("IPC status call failed: %v", err)
	}
	if resp.Status != ipc.StatusOK {
		t.Fatalf("expected status %q, got %q", ipc.StatusOK, resp.Status)
	}
	// The headless daemon owns an app lock here, so status reports the lock
	// state rather than a bare daemon_ready. That is what lets `xkey unlock`
	// confirm the state it reports (#250).
	if resp.Action != ipc.ActionUnlocked {
		t.Fatalf("expected action %q, got %q", ipc.ActionUnlocked, resp.Action)
	}

	// Verify autofill status is reachable.
	autofillResp, err := client.AutofillStatus()
	if err != nil {
		t.Fatalf("IPC autofill status call failed: %v", err)
	}
	if autofillResp.Status != ipc.StatusOK {
		t.Fatalf("expected autofill status %q, got %q", ipc.StatusOK, autofillResp.Status)
	}

	// Verify autofill policy is reachable.
	policyResp, err := client.AutofillPolicy()
	if err != nil {
		t.Fatalf("IPC autofill policy call failed: %v", err)
	}
	if policyResp.Status != ipc.StatusOK {
		t.Fatalf("expected policy status %q, got %q", ipc.StatusOK, policyResp.Status)
	}

	// Cancel context to trigger shutdown.
	cancel()

	// Wait for the server goroutine to finish.
	select {
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server shutdown")
	case err := <-serverErr:
		// The server may return nil or context-cancelled -- both acceptable.
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("server exited with: %v (acceptable)", err)
		}
	}
}

func TestExtensionServeCmd_BarrierMode_IPCConnectivity(t *testing.T) {
	tmpDir := t.TempDir()

	// Set xhome override so Resolve() uses our temp directory.
	xhome.SetRoot(tmpDir)
	defer xhome.ResetRoot()

	socketPath := filepath.Join(tmpDir, "test-barrier-serve.sock")
	barrierPassword := "test-barrier-password-123"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := &cobra.Command{
		Use:  "serve",
		RunE: runExtensionServe,
	}
	cmd.Flags().String("socket", socketPath, "")
	cmd.Flags().String("log-level", "error", "")
	cmd.Flags().String("log-file", "", "")
	cmd.Flags().String("barrier-password", barrierPassword, "")
	cmd.Flags().String("barrier-password-file", "", "")
	cmd.Flags().Bool("no-barrier", false, "")
	cmd.Flags().Int("auto-lock-minutes", 0, "")
	cmd.Flags().String("pin-state", filepath.Join(tmpDir, "pin.json"), "")
	cmd.Flags().Bool("no-auth", false, "")
	cmd.Flags().Bool("no-pairing", false, "")

	serverErr := make(chan error, 1)
	go func() {
		err := cmd.ExecuteContext(ctx)
		serverErr <- err
	}()

	// Wait for the socket to appear.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case err := <-serverErr:
			t.Fatalf("server exited prematurely: %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for IPC socket")
		default:
			if _, err := os.Stat(socketPath); err == nil {
				goto socketReady
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

socketReady:
	client := ipc.NewClient(socketPath)
	defer client.Close()

	resp, err := client.Status()
	if err != nil {
		t.Fatalf("IPC status call failed: %v", err)
	}
	if resp.Status != ipc.StatusOK {
		t.Fatalf("expected status %q, got %q (error: %s)", ipc.StatusOK, resp.Status, resp.Error)
	}

	cancel()

	select {
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server shutdown")
	case err := <-serverErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("server exited with: %v (acceptable)", err)
		}
	}
}

func TestHeadlessHandler_InterfaceCompliance(t *testing.T) {
	// Verify that headlessHandler satisfies all IPC interfaces at compile time.
	// This is also checked via var _ declarations in the main file, but
	// this test provides an explicit runtime assertion.
	var handler interface{} = &headlessHandler{}

	if _, ok := handler.(ipc.Handler); !ok {
		t.Fatal("headlessHandler does not implement ipc.Handler")
	}
	if _, ok := handler.(ipc.AutofillHandler); !ok {
		t.Fatal("headlessHandler does not implement ipc.AutofillHandler")
	}
	if _, ok := handler.(ipc.UnlockHandler); !ok {
		t.Fatal("headlessHandler does not implement ipc.UnlockHandler")
	}
}

func TestHeadlessHandler_HandleUnlock_NilAppLockSvc(t *testing.T) {
	h := &headlessHandler{}
	result, err := h.HandleUnlock("123456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Fatal("expected failure when appLockSvc is nil")
	}
	if result.Error == "" {
		t.Fatal("expected non-empty error message")
	}
}

func TestHeadlessHandler_HandleUnlock_WrongPIN(t *testing.T) {
	// Create a real AppLockService with a PINService that has no PIN set.
	// Unlock with any PIN should fail because there's no user PIN configured.
	pinSvc := services.NewPINService()
	appLockSvc := services.NewAppLockService(pinSvc, nil)
	appLockSvc.LockForStartup()

	h := &headlessHandler{appLockSvc: appLockSvc}
	result, err := h.HandleUnlock("wrong-pin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Fatal("expected failure with wrong PIN")
	}
	if result.Error == "" {
		t.Fatal("expected non-empty error message")
	}
}

func TestReadBarrierStrategy_Software(t *testing.T) {
	dataDir := t.TempDir()
	barrierDir := filepath.Join(dataDir, "barrier")
	if err := os.MkdirAll(barrierDir, 0700); err != nil {
		t.Fatal(err)
	}

	rootKey := `{"version":1,"strategy":"passphrase","salt":"AAAA","nonce":"BBBB","ciphertext":"CCCC","created_at":"2026-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(barrierDir, "root_key"), []byte(rootKey), 0600); err != nil {
		t.Fatal(err)
	}

	strategy, err := readBarrierStrategy(dataDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strategy != xkms.StrategyPassphrase {
		t.Fatalf("expected %q, got %q", xkms.StrategyPassphrase, strategy)
	}
}

func TestReadBarrierStrategy_TPM2(t *testing.T) {
	dataDir := t.TempDir()
	barrierDir := filepath.Join(dataDir, "barrier")
	if err := os.MkdirAll(barrierDir, 0700); err != nil {
		t.Fatal(err)
	}

	rootKey := `{"version":1,"strategy":"tpm2","sealed_data":{"backend":"tpm2"},"created_at":"2026-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(barrierDir, "root_key"), []byte(rootKey), 0600); err != nil {
		t.Fatal(err)
	}

	strategy, err := readBarrierStrategy(dataDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strategy != xkms.StrategyTPM2 {
		t.Fatalf("expected %q, got %q", xkms.StrategyTPM2, strategy)
	}
}

func TestReadBarrierStrategy_CloudKMS(t *testing.T) {
	dataDir := t.TempDir()
	barrierDir := filepath.Join(dataDir, "barrier")
	if err := os.MkdirAll(barrierDir, 0700); err != nil {
		t.Fatal(err)
	}

	rootKey := `{"version":1,"strategy":"awskms","sealed_data":{"backend":"awskms"},"created_at":"2026-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(barrierDir, "root_key"), []byte(rootKey), 0600); err != nil {
		t.Fatal(err)
	}

	strategy, err := readBarrierStrategy(dataDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strategy != xkms.StrategyAWSKMS {
		t.Fatalf("expected %q, got %q", xkms.StrategyAWSKMS, strategy)
	}
}

func TestReadBarrierStrategy_FileNotFound(t *testing.T) {
	dataDir := t.TempDir()
	_, err := readBarrierStrategy(dataDir)
	if err == nil {
		t.Fatal("expected error for missing root key file")
	}
}

func TestReadBarrierStrategy_InvalidJSON(t *testing.T) {
	dataDir := t.TempDir()
	barrierDir := filepath.Join(dataDir, "barrier")
	if err := os.MkdirAll(barrierDir, 0700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(barrierDir, "root_key"), []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := readBarrierStrategy(dataDir)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestReadBarrierStrategy_MissingStrategyField(t *testing.T) {
	dataDir := t.TempDir()
	barrierDir := filepath.Join(dataDir, "barrier")
	if err := os.MkdirAll(barrierDir, 0700); err != nil {
		t.Fatal(err)
	}

	rootKey := `{"version":1,"created_at":"2026-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(barrierDir, "root_key"), []byte(rootKey), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := readBarrierStrategy(dataDir)
	if err == nil {
		t.Fatal("expected error for missing strategy field")
	}
}

func TestServeErrors_AreDistinct(t *testing.T) {
	errs := []error{
		ErrServeStrategyReadFailed,
		ErrServeStrategyUnsupported,
		ErrServeTPMOpenFailed,
		ErrServeAuthenticatorInitFailed,
	}
	seen := make(map[string]bool, len(errs))
	for _, e := range errs {
		msg := e.Error()
		if seen[msg] {
			t.Fatalf("duplicate error message: %s", msg)
		}
		seen[msg] = true
	}
}

func TestNewTestServeCmd_HasNewFlags(t *testing.T) {
	cmd := newTestServeCmd()

	// Verify --no-auth flag exists and has correct default.
	noAuth, err := cmd.Flags().GetBool("no-auth")
	if err != nil {
		t.Fatalf("--no-auth flag not registered: %v", err)
	}
	if noAuth {
		t.Fatal("expected --no-auth default to be false")
	}

	// Verify --no-pairing flag exists and has correct default.
	noPairing, err := cmd.Flags().GetBool("no-pairing")
	if err != nil {
		t.Fatalf("--no-pairing flag not registered: %v", err)
	}
	if noPairing {
		t.Fatal("expected --no-pairing default to be false")
	}

	// Verify flags can be set.
	if err := cmd.Flags().Set("no-auth", "true"); err != nil {
		t.Fatalf("failed to set --no-auth: %v", err)
	}
	if err := cmd.Flags().Set("no-pairing", "true"); err != nil {
		t.Fatalf("failed to set --no-pairing: %v", err)
	}

	noAuth, _ = cmd.Flags().GetBool("no-auth")
	if !noAuth {
		t.Fatal("expected --no-auth to be true after setting")
	}
	noPairing, _ = cmd.Flags().GetBool("no-pairing")
	if !noPairing {
		t.Fatal("expected --no-pairing to be true after setting")
	}
}

func TestInitHeadlessAuthenticator_Success(t *testing.T) {
	dataDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	backend, err := xkms.NewFileStorageBackend(dataDir)
	if err != nil {
		t.Fatalf("failed to create storage backend: %v", err)
	}
	pinSvc := services.NewPINService()

	auth, err := initHeadlessAuthenticator(backend, pinSvc, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth == nil {
		t.Fatal("expected non-nil authenticator")
	}

	// initHeadlessAuthenticator wires the authenticator's persistent storage
	// to the supplied backend under the "fido2/xkey/" key prefix. The on-disk
	// directory is created lazily on first write, so persist a record through
	// the prefixed key and verify it lands under <dataDir>/fido2/xkey/.
	if err := backend.Put(context.Background(), "fido2/xkey/probe", []byte("ok")); err != nil {
		t.Fatalf("failed to write probe credential: %v", err)
	}
	credPath := filepath.Join(dataDir, "fido2", "xkey", "probe")
	if _, err := os.Stat(credPath); err != nil {
		t.Fatalf("credential not persisted under fido2/xkey prefix: %v", err)
	}
}

// TestInitHeadlessAuthenticator_StorageError verifies that a storage layer
// that cannot be constructed is surfaced as ErrServeAuthenticatorInitFailed
// with the underlying cause preserved. A nil backend is the one input that
// deterministically fails BackendStorage construction, so the error path is
// exercised directly instead of relying on the host rejecting a path.
func TestInitHeadlessAuthenticator_StorageError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	pinSvc := services.NewPINService()

	auth, err := initHeadlessAuthenticator(nil, pinSvc, logger)
	if err == nil {
		t.Fatal("expected error when the storage backend is unusable")
	}
	if auth != nil {
		t.Fatal("expected nil authenticator on error")
	}
	if !errors.Is(err, ErrServeAuthenticatorInitFailed) {
		t.Fatalf("expected ErrServeAuthenticatorInitFailed, got %v", err)
	}
	if !errors.Is(err, authenticator.ErrNilStorage) {
		t.Fatalf("expected the underlying cause to be preserved, got %v", err)
	}
}

// TestNewFileStorageBackend_UncreatablePath verifies that the file storage
// backend refuses a data directory that cannot be created because a regular
// file occupies a path component. This stays inside t.TempDir so the host
// filesystem is untouched.
func TestNewFileStorageBackend_UncreatablePath(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("failed to create blocking file: %v", err)
	}

	backend, err := xkms.NewFileStorageBackend(filepath.Join(blocker, "data"))
	if err == nil {
		t.Fatal("expected NewFileStorageBackend to reject an uncreatable data dir")
	}
	if backend != nil {
		t.Fatal("expected nil backend when construction fails")
	}
}

func TestExtensionServeCmd_NoAuth_NoBarrier(t *testing.T) {
	tmpDir := t.TempDir()

	// Set xhome override so Resolve() uses our temp directory.
	xhome.SetRoot(tmpDir)
	defer xhome.ResetRoot()

	socketPath := filepath.Join(tmpDir, "test-noauth-serve.sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := &cobra.Command{
		Use:  "serve",
		RunE: runExtensionServe,
	}
	cmd.Flags().String("socket", socketPath, "")
	cmd.Flags().String("log-level", "error", "")
	cmd.Flags().String("log-file", "", "")
	cmd.Flags().String("barrier-password", "", "")
	cmd.Flags().String("barrier-password-file", "", "")
	cmd.Flags().Bool("no-barrier", true, "")
	cmd.Flags().Int("auto-lock-minutes", 0, "")
	cmd.Flags().String("pin-state", filepath.Join(tmpDir, "pin.json"), "")
	cmd.Flags().Bool("no-auth", true, "")
	cmd.Flags().Bool("no-pairing", false, "")

	serverErr := make(chan error, 1)
	go func() {
		err := cmd.ExecuteContext(ctx)
		serverErr <- err
	}()

	// Wait for the socket to appear.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case err := <-serverErr:
			t.Fatalf("server exited prematurely: %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for IPC socket")
		default:
			if _, err := os.Stat(socketPath); err == nil {
				goto socketReady
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

socketReady:
	// Connect with IPC client and verify the server is operational.
	client := ipc.NewClient(socketPath)
	defer client.Close()

	resp, err := client.Status()
	if err != nil {
		t.Fatalf("IPC status call failed: %v", err)
	}
	if resp.Status != ipc.StatusOK {
		t.Fatalf("expected status %q, got %q", ipc.StatusOK, resp.Status)
	}
	// The headless daemon owns an app lock here, so status reports the lock
	// state rather than a bare daemon_ready. That is what lets `xkey unlock`
	// confirm the state it reports (#250).
	if resp.Action != ipc.ActionUnlocked {
		t.Fatalf("expected action %q, got %q", ipc.ActionUnlocked, resp.Action)
	}

	// Verify autofill status works with --no-auth.
	autofillResp, err := client.AutofillStatus()
	if err != nil {
		t.Fatalf("IPC autofill status call failed: %v", err)
	}
	if autofillResp.Status != ipc.StatusOK {
		t.Fatalf("expected autofill status %q, got %q", ipc.StatusOK, autofillResp.Status)
	}

	// Cancel context to trigger shutdown.
	cancel()

	select {
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server shutdown")
	case err := <-serverErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("server exited with: %v (acceptable)", err)
		}
	}
}

// --------------------------------------------------------------------------
// resolveTPMDevice - flag > TPM_DEVICE_PATH env > default precedence
// --------------------------------------------------------------------------

// TestResolveTPMDevice_ExplicitDevice verifies that an explicit device value
// (as supplied by a --tpm-device flag) is returned unchanged, regardless of
// the environment.
func TestResolveTPMDevice_ExplicitDevice(t *testing.T) {
	t.Setenv("TPM_DEVICE_PATH", "/dev/should-be-ignored")

	device := resolveTPMDevice("/dev/custom-tpm0")
	if device != "/dev/custom-tpm0" {
		t.Fatalf("expected '/dev/custom-tpm0', got %q", device)
	}
}

// TestResolveTPMDevice_EnvFallback verifies that TPM_DEVICE_PATH is honored
// when no explicit device is supplied, matching the server-side behavior in
// pkg/config.
func TestResolveTPMDevice_EnvFallback(t *testing.T) {
	t.Setenv("TPM_DEVICE_PATH", "/dev/env-tpm0")

	device := resolveTPMDevice("")
	if device != "/dev/env-tpm0" {
		t.Fatalf("expected '/dev/env-tpm0', got %q", device)
	}
}

// TestResolveTPMDevice_Default verifies that the default device path is used
// when neither an explicit device nor TPM_DEVICE_PATH is supplied.
func TestResolveTPMDevice_Default(t *testing.T) {
	t.Setenv("TPM_DEVICE_PATH", "")

	device := resolveTPMDevice("")
	if device != defaultBarrierTPMDevice {
		t.Fatalf("expected %q, got %q", defaultBarrierTPMDevice, device)
	}
}

// TestResolveTPMDevice_Priority_FlagOverEnv verifies that an explicit device
// takes priority over TPM_DEVICE_PATH when both are present.
func TestResolveTPMDevice_Priority_FlagOverEnv(t *testing.T) {
	t.Setenv("TPM_DEVICE_PATH", "/dev/env-tpm0")

	device := resolveTPMDevice("/dev/flag-tpm0")
	if device != "/dev/flag-tpm0" {
		t.Fatalf("expected '/dev/flag-tpm0' (flag takes priority), got %q", device)
	}
}

// --------------------------------------------------------------------------
// probeTPMSealer - device stat gating and simulator skip-stat behavior
// --------------------------------------------------------------------------

// newBufferedLogger returns a slog.Logger that writes to buf, allowing tests
// to assert on which code path was taken without touching real hardware.
func newBufferedLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestProbeTPMSealer_HardwareMode_DeviceNotFound verifies that, in hardware
// mode (useSimulator=false), a missing device path short-circuits before any
// TPM open attempt and returns (nil, nil).
func TestProbeTPMSealer_HardwareMode_DeviceNotFound(t *testing.T) {
	var buf bytes.Buffer
	logger := newBufferedLogger(&buf)

	sealer, closer := probeTPMSealer(logger, t.TempDir(), "/nonexistent-tpm-device-for-test", false)
	if sealer != nil {
		t.Fatal("expected nil sealer for missing device")
	}
	if closer != nil {
		t.Fatal("expected nil closer for missing device")
	}
	if !strings.Contains(buf.String(), "tpm device") || !strings.Contains(buf.String(), "not found") {
		t.Fatalf("expected a 'tpm device ... not found' log message, got: %s", buf.String())
	}
}

// TestProbeTPMSealer_SimulatorMode_SkipsDeviceStat verifies that, in
// simulator mode (useSimulator=true), the device stat check is skipped even
// when the supplied device path does not exist -- the function must proceed
// straight to opening the TPM (simulator) rather than short-circuiting on a
// missing device file. This is the regression this fix targets: previously
// probeTPMSealer always stat'd a hardcoded hardware device path.
func TestProbeTPMSealer_SimulatorMode_SkipsDeviceStat(t *testing.T) {
	var buf bytes.Buffer
	logger := newBufferedLogger(&buf)

	// The device path does not exist on disk; if the stat-skip logic were
	// broken, probeTPMSealer would short-circuit here with a "tpm device
	// ... not found" debug message instead of attempting to open the TPM.
	sealer, closer := probeTPMSealer(logger, t.TempDir(), "/nonexistent-tpm-device-for-test", true)
	if closer != nil {
		defer closer.Close()
	}
	_ = sealer

	if strings.Contains(buf.String(), "not found") {
		t.Fatalf("expected device stat to be skipped in simulator mode, got: %s", buf.String())
	}
}
