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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/presence"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

func TestFIDO2Cmd_Help(t *testing.T) {
	resetCommandFlagsForTest(t, RootCmd)
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
	resetCommandFlagsForTest(t, RootCmd)
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
				PIN:               fido2PINSecret("123456"),
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
				NotifyCommand:     "notify-send Xkey",
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

// TestReadCryptoRandomFrom_HandlesShortReads proves readCryptoRandomFrom
// fully populates the destination buffer even when the source only
// returns a few bytes per Read call, rather than returning after the
// first short read the way a bare r.Read(b) would.
func TestReadCryptoRandomFrom_HandlesShortReads(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	r := iotest.OneByteReader(bytes.NewReader(data))

	buf := make([]byte, len(data))
	n, err := readCryptoRandomFrom(r, buf)
	if err != nil {
		t.Fatalf("readCryptoRandomFrom() error = %v", err)
	}
	if n != len(data) {
		t.Fatalf("readCryptoRandomFrom() n = %d, want %d", n, len(data))
	}
	if !bytes.Equal(buf, data) {
		t.Fatalf("readCryptoRandomFrom() buf = %v, want %v", buf, data)
	}
}

// TestReadCryptoRandomFrom_ShortSourcePropagatesError verifies that a
// source exhausted before the buffer is filled reports an error rather
// than silently returning fewer bytes than requested.
func TestReadCryptoRandomFrom_ShortSourcePropagatesError(t *testing.T) {
	r := iotest.OneByteReader(bytes.NewReader([]byte{1, 2, 3}))

	buf := make([]byte, 8)
	_, err := readCryptoRandomFrom(r, buf)
	if err == nil {
		t.Fatal("readCryptoRandomFrom() error = nil, want an error for a short source")
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
		{"ErrFIDO2PINAlreadySet", ErrFIDO2PINAlreadySet, "fido2:"},
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

	notifier, err := createNotifier(cfg, logger)
	if err != nil {
		t.Fatalf("createNotifier: %v", err)
	}
	if notifier == nil {
		t.Fatal("createNotifier returned nil")
	}

	// Verify it is a MultiNotifier (wraps at least the LogNotifier)
	multi, ok := notifier.(*notify.MultiNotifier)
	if !ok {
		t.Fatalf("createNotifier returned %T, want *notify.MultiNotifier", notifier)
	}

	// Should not panic and should be closeable
	err = multi.Close()
	if err != nil {
		t.Errorf("MultiNotifier.Close() returned error: %v", err)
	}
}

func TestCreateNotifier_WithCommand(t *testing.T) {
	logger := slog.Default()
	cfg := &FIDO2Config{
		NotifyCommand: "sh -c 'echo touch for $XKEY_RP_ID'",
	}

	notifier, err := createNotifier(cfg, logger)
	if err != nil {
		t.Fatalf("createNotifier: %v", err)
	}
	if notifier == nil {
		t.Fatal("createNotifier returned nil")
	}

	multi, ok := notifier.(*notify.MultiNotifier)
	if !ok {
		t.Fatalf("createNotifier returned %T, want *notify.MultiNotifier", notifier)
	}

	err = multi.Close()
	if err != nil {
		t.Errorf("MultiNotifier.Close() returned error: %v", err)
	}
}

func TestCreateNotifier_InvalidCommand(t *testing.T) {
	cfg := &FIDO2Config{
		NotifyCommand: "   ", // whitespace-only is invalid
	}

	notifier, err := createNotifier(cfg, slog.Default())
	if notifier != nil {
		t.Fatalf("createNotifier returned %T for an invalid command, want nil", notifier)
	}
	if !errors.Is(err, ErrFIDO2InvalidNotifyCommand) {
		t.Fatalf("err = %v, want ErrFIDO2InvalidNotifyCommand", err)
	}
	if !errors.Is(err, notify.ErrInvalidCommand) {
		t.Fatalf("err = %v, want notify.ErrInvalidCommand", err)
	}
}

// TestCreateNotifier_CommandWithPlaceholder_Refused verifies that a
// notify_command still using the removed %o/%r/%n/%u placeholders stops
// startup with ErrFIDO2InvalidNotifyCommand (wrapping
// notify.ErrTemplatePlaceholder) instead of running without touch
// notifications.
func TestCreateNotifier_CommandWithPlaceholder_Refused(t *testing.T) {
	cfg := &FIDO2Config{NotifyCommand: "notify-send xKey %u"}

	notifier, err := createNotifier(cfg, slog.Default())
	if notifier != nil {
		t.Fatalf("createNotifier returned %T, want nil", notifier)
	}
	if !errors.Is(err, ErrFIDO2InvalidNotifyCommand) {
		t.Fatalf("err = %v, want ErrFIDO2InvalidNotifyCommand", err)
	}
	if !errors.Is(err, notify.ErrTemplatePlaceholder) {
		t.Fatalf("err = %v, want notify.ErrTemplatePlaceholder", err)
	}
}

// withPTYStdin points os.Stdin at a freshly allocated pseudo-terminal for the
// duration of the test and restores the original stdin afterwards. This lets
// terminal-gated code paths run in-process on a headless machine without
// depending on how the test binary was launched. The PTY is private to the
// process and nothing is written to the host.
func withPTYStdin(t *testing.T) {
	t.Helper()

	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("failed to open /dev/ptmx: %v", err)
	}

	if err := unix.IoctlSetPointerInt(int(ptmx.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		_ = ptmx.Close()
		t.Fatalf("failed to unlock pty: %v", err)
	}

	ptyN, err := unix.IoctlGetInt(int(ptmx.Fd()), unix.TIOCGPTN)
	if err != nil {
		_ = ptmx.Close()
		t.Fatalf("failed to resolve pty number: %v", err)
	}

	pts, err := os.OpenFile(filepath.Join("/dev/pts", strconv.Itoa(ptyN)), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		_ = ptmx.Close()
		t.Fatalf("failed to open pty slave: %v", err)
	}

	orig := os.Stdin
	os.Stdin = pts
	t.Cleanup(func() {
		os.Stdin = orig
		_ = pts.Close()
		_ = ptmx.Close()
	})
}

// TestCreateFIDO2UserPresenceHandler_Interactive verifies that interactive mode
// yields a real interactive handler and deliberately no socket handler and no
// notifier, so daemon-only plumbing is not silently constructed.
func TestCreateFIDO2UserPresenceHandler_Interactive(t *testing.T) {
	withPTYStdin(t)

	logger := slog.Default()
	cfg := &FIDO2Config{
		Interactive:       true,
		Backend:           "software",
		StorageType:       FIDO2StorageTypeMemory,
		AttestationFormat: "none",
	}

	handler, socketHandler, notifier, err := createFIDO2UserPresenceHandler(cfg, logger)
	if err != nil {
		t.Fatalf("createFIDO2UserPresenceHandler returned error: %v", err)
	}

	if handler == nil {
		t.Fatal("interactive handler is nil")
	}

	if _, ok := handler.(*authenticator.InteractiveHandler); !ok {
		t.Fatalf("handler is %T, want *authenticator.InteractiveHandler", handler)
	}

	if socketHandler != nil {
		t.Error("socket handler should be nil in interactive mode")
	}

	if notifier != nil {
		t.Error("notifier should be nil in interactive mode")
	}
}

// TestCreateFIDO2UserPresenceHandler_InteractiveNoTerminal verifies that
// interactive mode fails loudly when stdin is not a terminal rather than
// silently degrading to the socket handler.
func TestCreateFIDO2UserPresenceHandler_InteractiveNoTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = orig
		_ = r.Close()
		_ = w.Close()
	})

	logger := slog.Default()
	cfg := &FIDO2Config{
		Interactive:       true,
		Backend:           "software",
		StorageType:       FIDO2StorageTypeMemory,
		AttestationFormat: "none",
	}

	handler, socketHandler, notifier, err := createFIDO2UserPresenceHandler(cfg, logger)
	if !errors.Is(err, authenticator.ErrTerminalUnavailable) {
		t.Fatalf("error = %v, want ErrTerminalUnavailable", err)
	}
	if handler != nil || socketHandler != nil || notifier != nil {
		t.Error("no handler, socket handler or notifier should be returned on failure")
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
func fakeSocketHandlerNoPending(n notify.Notifier, logger *slog.Logger) *presence.SocketHandler {
	return presence.NewSocketHandler(n, logger)
}

// --- resolveFIDO2StoragePath (go-xkms#929) ---

// TestResolveFIDO2StoragePath_ExplicitPathWins verifies that a caller-set
// StoragePath is returned unchanged, without consulting the shared xkey
// data-directory chain at all.
func TestResolveFIDO2StoragePath_ExplicitPathWins(t *testing.T) {
	cfg := &FIDO2Config{StoragePath: "/explicit/path"}

	got, err := resolveFIDO2StoragePath(cfg)
	if err != nil {
		t.Fatalf("resolveFIDO2StoragePath: %v", err)
	}
	if got != "/explicit/path" {
		t.Errorf("got %q, want %q", got, "/explicit/path")
	}
}

// TestResolveFIDO2StoragePath_DefaultsUnderXKEYHome verifies that an unset
// StoragePath resolves to an absolute path under the resolved xkey data
// directory (<XKEY_HOME>/data/fido2), never a path relative to the
// process's working directory, and that the resolved value is written back
// onto cfg for later readers (go-xkms#929).
func TestResolveFIDO2StoragePath_DefaultsUnderXKEYHome(t *testing.T) {
	isolateDataDirSources(t)
	root := t.TempDir()
	xhome.SetRoot(root)

	cfg := &FIDO2Config{}
	got, err := resolveFIDO2StoragePath(cfg)
	if err != nil {
		t.Fatalf("resolveFIDO2StoragePath: %v", err)
	}

	want := filepath.Join(root, "data", "fido2")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("got %q, want an absolute path", got)
	}
	if cfg.StoragePath != want {
		t.Errorf("cfg.StoragePath = %q, want it updated to %q", cfg.StoragePath, want)
	}
}

// TestResolveFIDO2StoragePath_ErrorWhenHomeUnresolvable verifies that
// resolution fails with a typed error, instead of falling back to a
// cwd-relative path, when the xkey home cannot be resolved or created
// (go-xkms#929).
func TestResolveFIDO2StoragePath_ErrorWhenHomeUnresolvable(t *testing.T) {
	isolateDataDirSources(t)

	// A regular file, not a directory: XKEY_HOME can neither be used nor
	// created as a directory.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv(xhome.EnvHome, blocker)

	if _, err := resolveFIDO2StoragePath(&FIDO2Config{}); err == nil {
		t.Error("resolveFIDO2StoragePath should fail when the xkey home cannot be resolved")
	}
}
