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
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
)

func TestFIDO2Cmd_Help(t *testing.T) {
	// Test via root command to properly route output
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"fido2", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("fido2 --help failed: %v", err)
	}

	output := buf.String()
	expectedStrings := []string{
		"FIDO2",
		"WebAuthn",
		"UHID",
		"--storage",
		"--backend",
		"--pin",
		"--interactive",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("FIDO2 help output missing %q", expected)
		}
	}
}

func TestFIDO2Cmd_HelpNewFlags(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"fido2", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("fido2 --help failed: %v", err)
	}

	output := buf.String()
	newFlags := []string{
		"--password-store",
		"--socket",
		"--default-password",
		"--notify-command",
	}

	for _, flag := range newFlags {
		if !strings.Contains(output, flag) {
			t.Errorf("FIDO2 help output missing new flag %q", flag)
		}
	}
}

func TestFIDO2Config_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *FIDO2Config
		wantErr error
	}{
		{
			name: "valid memory storage",
			cfg: &FIDO2Config{
				StorageType:       FIDO2StorageTypeMemory,
				Backend:           "software",
				AttestationFormat: "none",
			},
			wantErr: nil,
		},
		{
			name: "valid file storage",
			cfg: &FIDO2Config{
				StorageType:       FIDO2StorageTypeFile,
				StoragePath:       "/var/lib/xkey",
				Backend:           "software",
				AttestationFormat: "none",
			},
			wantErr: nil,
		},
		{
			name: "invalid storage type",
			cfg: &FIDO2Config{
				StorageType:       FIDO2StorageType("invalid"),
				Backend:           "software",
				AttestationFormat: "none",
			},
			wantErr: ErrFIDO2InvalidStorageType,
		},
		{
			name: "file storage without path",
			cfg: &FIDO2Config{
				StorageType:       FIDO2StorageTypeFile,
				StoragePath:       "",
				Backend:           "software",
				AttestationFormat: "none",
			},
			wantErr: ErrFIDO2StoragePathRequired,
		},
		{
			name: "invalid backend",
			cfg: &FIDO2Config{
				StorageType:       FIDO2StorageTypeMemory,
				Backend:           "invalid",
				AttestationFormat: "none",
			},
			wantErr: ErrFIDO2InvalidBackend,
		},
		{
			name: "invalid attestation format",
			cfg: &FIDO2Config{
				StorageType:       FIDO2StorageTypeMemory,
				Backend:           "software",
				AttestationFormat: "invalid",
			},
			wantErr: ErrFIDO2InvalidAttestationFormat,
		},
		{
			name: "TPM attestation with software backend",
			cfg: &FIDO2Config{
				StorageType:       FIDO2StorageTypeMemory,
				Backend:           "software",
				AttestationFormat: "tpm",
			},
			wantErr: ErrFIDO2TPMAttestationRequiresTPMBackend,
		},
		{
			name: "set-pin without pin enabled",
			cfg: &FIDO2Config{
				StorageType:       FIDO2StorageTypeMemory,
				Backend:           "software",
				AttestationFormat: "none",
				EnablePIN:         false,
				PIN:               "123456",
			},
			wantErr: ErrFIDO2SetPINRequiresPINEnabled,
		},
		{
			name: "valid TPM2 with TPM attestation",
			cfg: &FIDO2Config{
				StorageType:       FIDO2StorageTypeMemory,
				Backend:           "tpm2",
				AttestationFormat: "tpm",
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if err != tt.wantErr {
				t.Errorf("FIDO2Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFIDO2Config_ValidateWithNewFields(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *FIDO2Config
		wantErr error
	}{
		{
			name: "valid with password store path",
			cfg: &FIDO2Config{
				StorageType:       FIDO2StorageTypeMemory,
				Backend:           "software",
				AttestationFormat: "none",
				PasswordStorePath: "/var/lib/xkey/staticpw",
			},
			wantErr: nil,
		},
		{
			name: "valid with socket path",
			cfg: &FIDO2Config{
				StorageType:       FIDO2StorageTypeMemory,
				Backend:           "software",
				AttestationFormat: "none",
				SocketPath:        "/tmp/xkey.sock",
			},
			wantErr: nil,
		},
		{
			name: "valid with default password",
			cfg: &FIDO2Config{
				StorageType:       FIDO2StorageTypeMemory,
				Backend:           "software",
				AttestationFormat: "none",
				DefaultPassword:   "DatabaseProd",
			},
			wantErr: nil,
		},
		{
			name: "valid with notify command",
			cfg: &FIDO2Config{
				StorageType:       FIDO2StorageTypeMemory,
				Backend:           "software",
				AttestationFormat: "none",
				NotifyCommand:     "notify-send Xkey '%o'",
			},
			wantErr: nil,
		},
		{
			name: "valid with all new fields set",
			cfg: &FIDO2Config{
				StorageType:       FIDO2StorageTypeMemory,
				Backend:           "software",
				AttestationFormat: "none",
				PasswordStorePath: "/var/lib/xkey/staticpw",
				SocketPath:        "/tmp/xkey.sock",
				DefaultPassword:   "MyPassword",
				NotifyCommand:     "echo touch",
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if err != tt.wantErr {
				t.Errorf("FIDO2Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateFIDO2SerialNumber(t *testing.T) {
	// Test that serial numbers are generated
	serial1 := generateFIDO2SerialNumber()
	if serial1 == "" {
		t.Error("generateFIDO2SerialNumber() returned empty string")
	}

	// Test that serial numbers are unique
	serial2 := generateFIDO2SerialNumber()
	if serial1 == serial2 {
		t.Error("generateFIDO2SerialNumber() returned duplicate serial numbers")
	}

	// Test length (16 hex chars)
	if len(serial1) != 16 {
		t.Errorf("generateFIDO2SerialNumber() returned %d chars, want 16", len(serial1))
	}
}

func TestFormatCID(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		want   string
	}{
		{
			name:   "valid packet",
			packet: []byte{0x12, 0x34, 0x56, 0x78, 0x00},
			want:   "0x12345678",
		},
		{
			name:   "short packet",
			packet: []byte{0x12, 0x34},
			want:   "0x00000000",
		},
		{
			name:   "empty packet",
			packet: []byte{},
			want:   "0x00000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatCID(tt.packet)
			if got != tt.want {
				t.Errorf("formatCID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatCmd(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		want   string
	}{
		{
			name:   "valid packet",
			packet: []byte{0x00, 0x00, 0x00, 0x00, 0x83},
			want:   "0x83",
		},
		{
			name:   "short packet",
			packet: []byte{0x00, 0x00, 0x00, 0x00},
			want:   "0x00",
		},
		{
			name:   "empty packet",
			packet: []byte{},
			want:   "0x00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatCmd(tt.packet)
			if got != tt.want {
				t.Errorf("formatCmd() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFIDO2Errors_Prefixes(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		prefix string
	}{
		{"ErrFIDO2InvalidStorageType", ErrFIDO2InvalidStorageType, "fido2:"},
		{"ErrFIDO2StoragePathRequired", ErrFIDO2StoragePathRequired, "fido2:"},
		{"ErrFIDO2InvalidBackend", ErrFIDO2InvalidBackend, "fido2:"},
		{"ErrFIDO2InvalidAttestationFormat", ErrFIDO2InvalidAttestationFormat, "fido2:"},
		{"ErrFIDO2TPMAttestationRequiresTPMBackend", ErrFIDO2TPMAttestationRequiresTPMBackend, "fido2:"},
		{"ErrFIDO2SetPINRequiresPINEnabled", ErrFIDO2SetPINRequiresPINEnabled, "fido2:"},
		{"ErrFIDO2StorageCreationFailed", ErrFIDO2StorageCreationFailed, "fido2:"},
		{"ErrFIDO2AuthenticatorCreationFailed", ErrFIDO2AuthenticatorCreationFailed, "fido2:"},
		{"ErrFIDO2UHIDOpenFailed", ErrFIDO2UHIDOpenFailed, "fido2:"},
		{"ErrFIDO2UHIDCreateFailed", ErrFIDO2UHIDCreateFailed, "fido2:"},
		{"ErrFIDO2PINSetFailed", ErrFIDO2PINSetFailed, "fido2:"},
		{"ErrFIDO2TPMOpenFailed", ErrFIDO2TPMOpenFailed, "fido2:"},
		{"ErrFIDO2TPMBackendCreationFailed", ErrFIDO2TPMBackendCreationFailed, "fido2:"},
		{"ErrFIDO2DeviceAlreadyRunning", ErrFIDO2DeviceAlreadyRunning, "fido2:"},
		{"ErrFIDO2NotifierCreationFailed", ErrFIDO2NotifierCreationFailed, "fido2:"},
		{"ErrFIDO2IPCServerCreationFailed", ErrFIDO2IPCServerCreationFailed, "fido2:"},
		{"ErrFIDO2PasswordStoreOpenFailed", ErrFIDO2PasswordStoreOpenFailed, "fido2:"},
		{"ErrFIDO2KeyboardCreationFailed", ErrFIDO2KeyboardCreationFailed, "fido2:"},
		{"ErrFIDO2KeyboardUnavailable", ErrFIDO2KeyboardUnavailable, "fido2:"},
		{"ErrFIDO2PasswordStoreUnavailable", ErrFIDO2PasswordStoreUnavailable, "fido2:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.HasPrefix(tt.err.Error(), tt.prefix) {
				t.Errorf("%s.Error() = %q, want prefix %q", tt.name, tt.err.Error(), tt.prefix)
			}
		})
	}
}

func TestFIDO2Errors_Distinct(t *testing.T) {
	allErrors := []error{
		ErrFIDO2NotifierCreationFailed,
		ErrFIDO2IPCServerCreationFailed,
		ErrFIDO2PasswordStoreOpenFailed,
		ErrFIDO2KeyboardCreationFailed,
		ErrFIDO2KeyboardUnavailable,
		ErrFIDO2PasswordStoreUnavailable,
	}

	seen := make(map[string]bool)
	for _, err := range allErrors {
		msg := err.Error()
		if seen[msg] {
			t.Errorf("duplicate error message: %q", msg)
		}
		seen[msg] = true
	}
}

func TestCreateNotifier_EmptyCommand(t *testing.T) {
	logger := slog.Default()
	cfg := &FIDO2Config{
		NotifyCommand: "",
	}

	notifier := createNotifier(cfg, logger)
	if notifier == nil {
		t.Fatal("createNotifier returned nil")
	}

	// Verify it is a MultiNotifier (wraps at least the LogNotifier)
	multi, ok := notifier.(*notify.MultiNotifier)
	if !ok {
		t.Fatalf("createNotifier returned %T, want *notify.MultiNotifier", notifier)
	}

	// Should not panic and should be closeable
	err := multi.Close()
	if err != nil {
		t.Errorf("MultiNotifier.Close() returned error: %v", err)
	}
}

func TestCreateNotifier_WithCommand(t *testing.T) {
	logger := slog.Default()
	cfg := &FIDO2Config{
		NotifyCommand: "echo 'touch for %r'",
	}

	notifier := createNotifier(cfg, logger)
	if notifier == nil {
		t.Fatal("createNotifier returned nil")
	}

	multi, ok := notifier.(*notify.MultiNotifier)
	if !ok {
		t.Fatalf("createNotifier returned %T, want *notify.MultiNotifier", notifier)
	}

	err := multi.Close()
	if err != nil {
		t.Errorf("MultiNotifier.Close() returned error: %v", err)
	}
}

func TestCreateNotifier_InvalidCommand(t *testing.T) {
	logger := slog.Default()
	cfg := &FIDO2Config{
		NotifyCommand: "   ", // whitespace-only is invalid
	}

	notifier := createNotifier(cfg, logger)
	if notifier == nil {
		t.Fatal("createNotifier returned nil for invalid command")
	}

	// Should still return a valid notifier (falls back to log-only)
	multi, ok := notifier.(*notify.MultiNotifier)
	if !ok {
		t.Fatalf("createNotifier returned %T, want *notify.MultiNotifier", notifier)
	}

	err := multi.Close()
	if err != nil {
		t.Errorf("MultiNotifier.Close() returned error: %v", err)
	}
}

func TestCreateFIDO2UserPresenceHandler_Interactive(t *testing.T) {
	logger := slog.Default()
	cfg := &FIDO2Config{
		Interactive:       true,
		Backend:           "software",
		StorageType:       FIDO2StorageTypeMemory,
		AttestationFormat: "none",
	}

	handler, socketHandler, notifier, err := createFIDO2UserPresenceHandler(cfg, logger)
	// On CI/headless environments, NewInteractiveHandler may fail if no terminal.
	// That is acceptable; we verify error handling path.
	if err != nil {
		t.Skipf("interactive handler unavailable (no terminal): %v", err)
	}

	if handler == nil {
		t.Fatal("interactive handler is nil")
	}

	if socketHandler != nil {
		t.Error("socket handler should be nil in interactive mode")
	}

	if notifier != nil {
		t.Error("notifier should be nil in interactive mode")
	}
}

func TestCreateFIDO2UserPresenceHandler_NonInteractive(t *testing.T) {
	logger := slog.Default()
	cfg := &FIDO2Config{
		Interactive:       false,
		Backend:           "software",
		StorageType:       FIDO2StorageTypeMemory,
		AttestationFormat: "none",
	}

	handler, socketHandler, notifier, err := createFIDO2UserPresenceHandler(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if handler == nil {
		t.Fatal("handler is nil")
	}

	if socketHandler == nil {
		t.Fatal("socket handler should not be nil in non-interactive mode")
	}

	// The handler and socketHandler should be the same object
	if handler != socketHandler {
		t.Error("handler and socketHandler should be the same instance")
	}

	if notifier == nil {
		t.Fatal("notifier should not be nil in non-interactive mode")
	}
}

func TestFido2Device_HandleStatus(t *testing.T) {
	logger := slog.Default()
	device := &fido2Device{
		logger: logger,
	}

	resp, err := device.HandleStatus()
	if err != nil {
		t.Fatalf("HandleStatus() returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("HandleStatus() returned nil response")
	}
	if resp.Status != ipc.StatusOK {
		t.Errorf("HandleStatus() status = %q, want %q", resp.Status, ipc.StatusOK)
	}
	if resp.Action != ipc.ActionDaemonReady {
		t.Errorf("HandleStatus() action = %q, want %q", resp.Action, ipc.ActionDaemonReady)
	}
}

func TestFido2Device_HandleStatus_ErrorField(t *testing.T) {
	logger := slog.Default()
	device := &fido2Device{
		logger: logger,
	}

	resp, err := device.HandleStatus()
	if err != nil {
		t.Fatalf("HandleStatus() returned error: %v", err)
	}
	if resp.Error != "" {
		t.Errorf("HandleStatus() error field = %q, want empty", resp.Error)
	}
}

func TestFido2Device_HandleTouch_NoPending(t *testing.T) {
	logger := slog.Default()
	device := &fido2Device{
		logger: logger,
		// No socketHandler, no defaultPassword
	}

	resp, err := device.HandleTouch()
	if err != nil {
		t.Fatalf("HandleTouch() returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("HandleTouch() returned nil response")
	}
	if resp.Status != ipc.StatusOK {
		t.Errorf("HandleTouch() status = %q, want %q", resp.Status, ipc.StatusOK)
	}
	if resp.Action != ipc.ActionNoPending {
		t.Errorf("HandleTouch() action = %q, want %q", resp.Action, ipc.ActionNoPending)
	}
}

func TestFido2Device_HandleTouch_NoPendingNoDefault(t *testing.T) {
	logger := slog.Default()
	notifier := notify.NewMultiNotifier(notify.NewLogNotifier(logger))
	socketHandler := fakeSocketHandlerNoPending(notifier, logger)

	device := &fido2Device{
		logger:        logger,
		socketHandler: socketHandler,
	}

	resp, err := device.HandleTouch()
	if err != nil {
		t.Fatalf("HandleTouch() returned error: %v", err)
	}
	if resp.Action != ipc.ActionNoPending {
		t.Errorf("HandleTouch() action = %q, want %q", resp.Action, ipc.ActionNoPending)
	}
}

func TestFido2Device_HandleTypePassword_NilPwStore(t *testing.T) {
	logger := slog.Default()
	device := &fido2Device{
		logger: logger,
		// pwStore is nil
	}

	resp, err := device.HandleTypePassword("test")
	if resp != nil {
		t.Error("HandleTypePassword() returned non-nil response with nil pwStore")
	}
	if !errors.Is(err, ErrFIDO2PasswordStoreUnavailable) {
		t.Errorf("HandleTypePassword() error = %v, want %v", err, ErrFIDO2PasswordStoreUnavailable)
	}
}

func TestFido2Device_HandleTypePassword_NilKeyboard(t *testing.T) {
	logger := slog.Default()

	// Create a real but temporary password store to pass the pwStore nil check
	tmpDir := t.TempDir()
	store, err := openPasswordStore(tmpDir)
	if err != nil {
		t.Fatalf("failed to open temp password store: %v", err)
	}
	defer func() { _ = store.Close() }()

	device := &fido2Device{
		logger:  logger,
		pwStore: store,
		// keyboard is nil
	}

	resp, err := device.HandleTypePassword("test")
	if resp != nil {
		t.Error("HandleTypePassword() returned non-nil response with nil keyboard")
	}
	if !errors.Is(err, ErrFIDO2KeyboardUnavailable) {
		t.Errorf("HandleTypePassword() error = %v, want %v", err, ErrFIDO2KeyboardUnavailable)
	}
}

func TestFido2Device_HandleTouch_DefaultPassword_NilStore(t *testing.T) {
	logger := slog.Default()
	device := &fido2Device{
		logger:          logger,
		defaultPassword: "MyDefault",
		// pwStore is nil -> should return ErrFIDO2PasswordStoreUnavailable
	}

	resp, err := device.HandleTouch()
	if resp != nil {
		t.Error("HandleTouch() returned non-nil response with nil pwStore")
	}
	if !errors.Is(err, ErrFIDO2PasswordStoreUnavailable) {
		t.Errorf("HandleTouch() error = %v, want %v", err, ErrFIDO2PasswordStoreUnavailable)
	}
}

func TestFIDO2Config_NewFieldsPreserved(t *testing.T) {
	cfg := &FIDO2Config{
		StorageType:       FIDO2StorageTypeMemory,
		Backend:           "software",
		AttestationFormat: "none",
		PasswordStorePath: "/custom/pw/path",
		SocketPath:        "/custom/socket.sock",
		DefaultPassword:   "MyPassword",
		NotifyCommand:     "echo test",
	}

	if cfg.PasswordStorePath != "/custom/pw/path" {
		t.Errorf("PasswordStorePath = %q, want %q", cfg.PasswordStorePath, "/custom/pw/path")
	}
	if cfg.SocketPath != "/custom/socket.sock" {
		t.Errorf("SocketPath = %q, want %q", cfg.SocketPath, "/custom/socket.sock")
	}
	if cfg.DefaultPassword != "MyPassword" {
		t.Errorf("DefaultPassword = %q, want %q", cfg.DefaultPassword, "MyPassword")
	}
	if cfg.NotifyCommand != "echo test" {
		t.Errorf("NotifyCommand = %q, want %q", cfg.NotifyCommand, "echo test")
	}
}

func TestFido2Device_Close_NilSubsystems(t *testing.T) {
	// Close should handle all nil subsystems gracefully
	logger := slog.Default()
	device := &fido2Device{
		logger: logger,
	}

	err := device.Close()
	if err != nil {
		t.Errorf("Close() with nil subsystems returned error: %v", err)
	}
}

func TestFido2Device_Close_NilSubsystems_NoErrors(t *testing.T) {
	// Verify Close does not panic with a completely empty device
	logger := slog.Default()
	device := &fido2Device{
		logger: logger,
	}

	// Call Close twice to verify idempotent behavior
	err := device.Close()
	if err != nil {
		t.Errorf("first Close() returned error: %v", err)
	}

	err = device.Close()
	if err != nil {
		t.Errorf("second Close() returned error: %v", err)
	}
}

// fakeSocketHandlerNoPending creates a SocketHandler with no pending requests.
// This is used to test the HandleTouch path where the socket handler exists
// but has no pending user presence request.
func fakeSocketHandlerNoPending(n notify.Notifier, logger *slog.Logger) *authenticator.SocketHandler {
	return authenticator.NewSocketHandler(n, logger)
}
