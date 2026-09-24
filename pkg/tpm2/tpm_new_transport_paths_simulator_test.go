// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewTPM2_CommandAddress_DerivesPlatformPort proves that when
// Config.CommandAddress is set and PlatformAddress is left empty, NewTPM2
// derives the platform (control) address by incrementing the command
// port -- the swtpm convention documented on the CommandAddress case --
// and that a refused connection at the derived address surfaces as a
// wrapped error instead of a transport that fails later on first use.
func TestNewTPM2_CommandAddress_DerivesPlatformPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedAddr := listener.Addr().String()
	require.NoError(t, listener.Close())

	params := &Params{
		Config: &Config{
			Hash:           "SHA-256",
			CommandAddress: closedAddr,
		},
		Logger: slog.Default(),
	}

	tpmIface, err := NewTPM2(params)
	require.Nil(t, tpmIface)
	require.Error(t, err, "connecting to a closed command port must fail, not silently proceed")
}

// TestNewTPM2_CommandAddress_MalformedFallsBackToRawAddress proves that
// when Config.CommandAddress carries no ":port" suffix, splitHostPort fails
// and NewTPM2 falls back to dialing the raw CommandAddress verbatim as the
// platform address too, rather than deriving a nonsense port or panicking.
func TestNewTPM2_CommandAddress_MalformedFallsBackToRawAddress(t *testing.T) {
	params := &Params{
		Config: &Config{
			Hash:           "SHA-256",
			CommandAddress: "not-a-host-port-pair",
		},
		Logger: slog.Default(),
	}

	tpmIface, err := NewTPM2(params)
	require.Nil(t, tpmIface)
	require.Error(t, err, "a malformed command address must fail to connect, not panic or hang")
}

// TestNewTPM2_UseSimulator_OpenerError proves NewTPM2 surfaces a
// simulator-open failure directly rather than continuing with a nil
// simulator or transport.
func TestNewTPM2_UseSimulator_OpenerError(t *testing.T) {
	original := simulatorOpener
	t.Cleanup(func() { simulatorOpener = original })
	openErr := errors.New("simulator: synthetic open failure")
	simulatorOpener = func() (SimulatorInterface, error) { return nil, openErr }

	params := &Params{
		Config: &Config{Hash: "SHA-256", UseSimulator: true},
		Logger: slog.Default(),
	}

	tpmIface, err := NewTPM2(params)
	require.Nil(t, tpmIface)
	require.ErrorIs(t, err, openErr)
}

// TestOpen_UseSimulator_OpenerError proves TPM2.Open, like NewTPM2, surfaces
// a simulator-open failure instead of leaving the instance with a stale or
// nil transport.
func TestOpen_UseSimulator_OpenerError(t *testing.T) {
	original := simulatorOpener
	t.Cleanup(func() { simulatorOpener = original })
	openErr := errors.New("simulator: synthetic open failure")
	simulatorOpener = func() (SimulatorInterface, error) { return nil, openErr }

	tpmObj := &TPM2{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		config: &Config{Hash: "SHA-256", UseSimulator: true},
	}

	err := tpmObj.Open()
	require.ErrorIs(t, err, openErr)
}

// TestNewTPM2_Device_UnixSocketOpenError proves NewTPM2's device branch
// surfaces a Unix-domain-socket dial failure for a ".sock"-suffixed Device
// path that has no listener behind it.
func TestNewTPM2_Device_UnixSocketOpenError(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "no-listener.sock")

	params := &Params{
		Config: &Config{Hash: "SHA-256", Device: sockPath},
		Logger: slog.Default(),
	}

	tpmIface, err := NewTPM2(params)
	require.Nil(t, tpmIface)
	require.Error(t, err, "dialing a socket path with no listener must fail")
}

// TestNewTPM2_Device_RegularFileOpenError proves NewTPM2's device branch
// maps an os.OpenFile failure for a non-socket Device path to the typed
// ErrOpeningDevice sentinel rather than leaking the raw os error.
func TestNewTPM2_Device_RegularFileOpenError(t *testing.T) {
	params := &Params{
		Config: &Config{Hash: "SHA-256", Device: filepath.Join(t.TempDir(), "missing", "tpm-device")},
		Logger: slog.Default(),
	}

	tpmIface, err := NewTPM2(params)
	require.Nil(t, tpmIface)
	require.ErrorIs(t, err, ErrOpeningDevice)
}

// TestNewTPM2_Device_RegularFileOpensThenReportsUnprovisioned proves
// NewTPM2's device branch, when os.OpenFile succeeds against a plain
// regular file standing in for a device node, wraps it with
// transport.FromReadWriter and proceeds into the normal
// "is this TPM provisioned" probe rather than short-circuiting. A file with
// no TPM behind it cannot answer TPM2_ReadPublic or TPM2_NV_ReadPublic
// coherently, so the probe must fail both ways and report ErrNotInitialized
// -- exactly as an unprovisioned real device would.
func TestNewTPM2_Device_RegularFileOpensThenReportsUnprovisioned(t *testing.T) {
	devicePath := filepath.Join(t.TempDir(), "fake-tpm-device")
	f, err := os.Create(devicePath)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	params := &Params{
		Config: &Config{Hash: "SHA-256", Device: devicePath},
		Logger: slog.Default(),
	}

	tpmIface, err := NewTPM2(params)
	require.NotNil(t, tpmIface, "the instance is still returned so the caller can Provision it")
	require.ErrorIs(t, err, ErrNotInitialized)
}
