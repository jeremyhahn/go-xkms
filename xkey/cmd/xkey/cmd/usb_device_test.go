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
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pkcs11"
)

// --- Parent device command structure ---

func TestUSBDeviceCmd_Structure(t *testing.T) {
	assert.NotNil(t, usbDeviceCmd)
	assert.Equal(t, "device", usbDeviceCmd.Use)
	assert.NotEmpty(t, usbDeviceCmd.Short)
	assert.NotEmpty(t, usbDeviceCmd.Long)
}

func TestUSBDeviceCmd_RegisteredOnUSB(t *testing.T) {
	found := false
	for _, cmd := range usbCmd.Commands() {
		if cmd.Name() == "device" {
			found = true
			break
		}
	}
	assert.True(t, found, "device command should be registered on usb")
}

func TestUSBDeviceCmd_Subcommands(t *testing.T) {
	subcommands := usbDeviceCmd.Commands()

	names := make(map[string]bool)
	for _, cmd := range subcommands {
		names[cmd.Name()] = true
	}

	assert.True(t, names["start"], "device should have start subcommand")
	assert.True(t, names["stop"], "device should have stop subcommand")
	assert.True(t, names["status"], "device should have status subcommand")
}

// --- Start command structure ---

func TestUSBDeviceStartCmd_Structure(t *testing.T) {
	assert.NotNil(t, usbDeviceStartCmd)
	assert.Equal(t, "start", usbDeviceStartCmd.Use)
	assert.NotEmpty(t, usbDeviceStartCmd.Short)
	assert.NotEmpty(t, usbDeviceStartCmd.Long)
	assert.NotNil(t, usbDeviceStartCmd.RunE)
}

func TestUSBDeviceStartCmd_Flags(t *testing.T) {
	flag := usbDeviceStartCmd.Flags().Lookup("device-backend")
	require.NotNil(t, flag, "device-backend flag should exist")
	assert.Equal(t, defaultUSBDeviceBackend, flag.DefValue)
}

// --- Stop command structure ---

func TestUSBDeviceStopCmd_Structure(t *testing.T) {
	assert.NotNil(t, usbDeviceStopCmd)
	assert.Equal(t, "stop", usbDeviceStopCmd.Use)
	assert.NotEmpty(t, usbDeviceStopCmd.Short)
	assert.NotEmpty(t, usbDeviceStopCmd.Long)
	assert.NotNil(t, usbDeviceStopCmd.RunE)
}

func TestUSBDeviceStopCmd_Output(t *testing.T) {
	var buf bytes.Buffer
	usbDeviceStopCmd.SetOut(&buf)

	err := runUSBDeviceStop(usbDeviceStopCmd, nil)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "foreground")
	assert.Contains(t, output, "Ctrl+C")
	assert.Contains(t, output, "SIGTERM")
}

// --- Status command structure ---

func TestUSBDeviceStatusCmd_Structure(t *testing.T) {
	assert.NotNil(t, usbDeviceStatusCmd)
	assert.Equal(t, "status", usbDeviceStatusCmd.Use)
	assert.NotEmpty(t, usbDeviceStatusCmd.Short)
	assert.NotEmpty(t, usbDeviceStatusCmd.Long)
	assert.NotNil(t, usbDeviceStatusCmd.RunE)
}

func TestUSBDeviceStatusCmd_Output(t *testing.T) {
	var buf bytes.Buffer
	usbDeviceStatusCmd.SetOut(&buf)

	err := runUSBDeviceStatus(usbDeviceStatusCmd, nil)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Virtual CCID Device Status")
	assert.Contains(t, output, "UHID interface")
	assert.Contains(t, output, "CCID device")
	assert.Contains(t, output, "Device name")
	assert.Contains(t, output, "xKey CCID Smartcard Reader")
	assert.Contains(t, output, "XKEYCCID001")
	assert.Contains(t, output, "0xF1D0")
	assert.Contains(t, output, "0x0004")
}

// --- Sentinel error tests ---

func TestUSBDeviceSentinelErrors_NotNil(t *testing.T) {
	errs := []struct {
		name string
		err  error
	}{
		{"ErrUSBDeviceStartFailed", ErrUSBDeviceStartFailed},
		{"ErrUSBDeviceCCIDCreateFailed", ErrUSBDeviceCCIDCreateFailed},
		{"ErrUSBDeviceBridgeCreateFailed", ErrUSBDeviceBridgeCreateFailed},
		{"ErrUSBDeviceTransportCreateFailed", ErrUSBDeviceTransportCreateFailed},
	}

	for _, tt := range errs {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotNil(t, tt.err)
			assert.NotEmpty(t, tt.err.Error())
			assert.Contains(t, tt.err.Error(), "usb device:")
		})
	}
}

func TestUSBDeviceSentinelErrors_Distinct(t *testing.T) {
	errs := []error{
		ErrUSBDeviceStartFailed,
		ErrUSBDeviceCCIDCreateFailed,
		ErrUSBDeviceBridgeCreateFailed,
		ErrUSBDeviceTransportCreateFailed,
	}

	for i := 0; i < len(errs); i++ {
		for j := i + 1; j < len(errs); j++ {
			assert.NotEqual(t, errs[i].Error(), errs[j].Error(),
				"errors at index %d and %d should be distinct", i, j)
		}
	}
}

// --- LUKS exempt tests ---

// TestUSBDeviceCommandsAreLUKSExempt verifies `usb device ...` bypasses the
// LUKS unlock gate. It asserts on the real command objects rather than on
// bare leaf names: the previous version asserted `luksExemptCommands["device"]`,
// which is precisely the bug that exempted the unrelated top-level `device`
// group (device pair/enroll/attest/...).
func TestUSBDeviceCommandsAreLUKSExempt(t *testing.T) {
	for _, cmd := range []*cobra.Command{usbDeviceCmd, usbDeviceStartCmd, usbDeviceStopCmd} {
		t.Run(cmd.Name(), func(t *testing.T) {
			assert.True(t, isLUKSExempt(cmd),
				"%q must be LUKS-exempt", cmd.CommandPath())
		})
	}
}

// TestTopLevelDeviceGroupIsNotLUKSExempt is the regression guard: the
// top-level `device` group manages phone pairing/enrollment and must NOT
// bypass the unlock gate just because `usb device` shares its leaf name.
func TestTopLevelDeviceGroupIsNotLUKSExempt(t *testing.T) {
	assert.False(t, isLUKSExempt(deviceCmd),
		"top-level %q must not be LUKS-exempt", deviceCmd.CommandPath())
}

// --- Helper function tests ---

func TestCheckUHIDAvailable(t *testing.T) {
	// This is a best-effort test. The result depends on the host.
	// We just verify it does not panic and returns a boolean.
	result := checkUHIDAvailable()
	_ = result // Result is platform-dependent.
}

func TestCheckUSBDeviceRunning(t *testing.T) {
	// This is a best-effort test. The result depends on the host.
	// We just verify it does not panic and returns a boolean.
	result := checkUSBDeviceRunning()
	_ = result // Result is platform-dependent.
}

// --- Start command with uninitialized transport ---

func TestRunUSBDeviceStart_TransportNotInitialized(t *testing.T) {
	// The test's precondition is an uninitialized xkms singleton, so
	// NewEmbeddedTransport fails before any device starts. It establishes
	// that itself rather than trusting that no earlier test in the process
	// initialized xkms: with a live singleton this call would start a real
	// virtual CCID device and block until a signal.
	newPIVProcess()
	t.Cleanup(newPIVProcess)
	isolateGUISettings(t)
	err := runUSBDeviceStart(usbDeviceStartCmd, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUSBDeviceTransportCreateFailed),
		"should wrap ErrUSBDeviceTransportCreateFailed, got: %v", err)
}

// --- PKCS#11 transport selection ---

// listeningGUIHandler answers on the socket the way an unlocked xKey GUI
// does: its PKCS#11 side is the GUI's own handler. The transport's probe
// never reaches the base Handler methods.
type listeningGUIHandler struct {
	*services.PKCS11IPCHandler
}

func (listeningGUIHandler) HandleTouch() (*ipc.Response, error) { return nil, ipc.ErrHandlerFailed }
func (listeningGUIHandler) HandleTypePassword(string) (*ipc.Response, error) {
	return nil, ipc.ErrHandlerFailed
}
func (listeningGUIHandler) HandleStatus() (*ipc.Response, error) { return nil, ipc.ErrHandlerFailed }

// serveGUISocket runs a real IPC server at a private socket that the IPC
// transport resolves by default, and returns its path.
func serveGUISocket(t *testing.T) string {
	t.Helper()
	sockPath := filepath.Join(privateTempDir(t), "xkey.sock")
	t.Setenv(ipc.EnvSocketPath, sockPath)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := listeningGUIHandler{services.NewPKCS11IPCHandler(nil, logger, func() bool { return false })}
	srv, err := ipc.NewServer(sockPath, handler, logger)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, srv.Close())
	})
	return sockPath
}

func TestUSBDevicePKCS11Transport_OffOpensKeysInProcess(t *testing.T) {
	newPIVProcess()
	t.Cleanup(newPIVProcess)
	isolateGUISettings(t)
	serveGUISocket(t)

	transport, err := usbDevicePKCS11Transport(context.Background())

	assert.Nil(t, transport)
	assert.ErrorIs(t, err, pkcs11.ErrServiceNotInitialized,
		"with the setting off the in-process transport is chosen even while a GUI listens")
	assert.NotErrorIs(t, err, ErrUSBDeviceGUINotListening)
}

func TestUSBDevicePKCS11Transport_OnUsesListeningGUI(t *testing.T) {
	enableLocalAppAccessForTest(t)
	sockPath := serveGUISocket(t)

	transport, err := usbDevicePKCS11Transport(context.Background())

	require.NoError(t, err)
	ipcTransport, ok := transport.(*pkcs11.IPCTransport)
	require.True(t, ok, "with the setting on the device must use the IPC transport, got %T", transport)
	assert.Equal(t, sockPath, ipcTransport.SocketPath())
}

func TestUSBDevicePKCS11Transport_OnWithoutGUIFails(t *testing.T) {
	newPIVProcess()
	t.Cleanup(newPIVProcess)
	enableLocalAppAccessForTest(t)
	t.Setenv(ipc.EnvSocketPath, filepath.Join(privateTempDir(t), "xkey.sock"))

	transport, err := usbDevicePKCS11Transport(context.Background())

	assert.Nil(t, transport)
	assert.ErrorIs(t, err, ErrUSBDeviceGUINotListening)
	assert.ErrorIs(t, err, pkcs11.ErrIPCConnectionFailed)
	assert.NotErrorIs(t, err, pkcs11.ErrServiceNotInitialized, "no silent fallback to the in-process transport")
}

func TestUSBDevicePKCS11Transport_UnreadableSettings(t *testing.T) {
	writeGUISettings(t, []byte("{not json"))

	transport, err := usbDevicePKCS11Transport(context.Background())

	assert.Nil(t, transport)
	assert.ErrorIs(t, err, ErrAppAccessLoadFailed)
}

// --- Default backend constant ---

func TestDefaultUSBDeviceBackend(t *testing.T) {
	assert.Equal(t, "software", defaultUSBDeviceBackend)
}
