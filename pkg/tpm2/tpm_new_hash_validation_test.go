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
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/require"
)

// TestNewTPM2_UnknownHashName proves NewTPM2 rejects a Config.Hash value
// that names no hash this process recognizes at all. A pre-supplied
// Transport takes the "already have a live connection" branch of the
// transport switch, so this exercises the hash validation in isolation
// from device/simulator opening; a missing check would fall through with
// a zero algID instead.
func TestNewTPM2_UnknownHashName(t *testing.T) {
	params := &Params{
		Config:    &Config{Hash: "not-a-real-hash-name"},
		Logger:    slog.Default(),
		Transport: &noopTransport{},
	}

	tpmIface, err := NewTPM2(params)
	require.Nil(t, tpmIface)
	require.ErrorIs(t, err, store.ErrInvalidHashFunction)
}

// TestNewTPM2_HashWithNoTPMAlgID proves NewTPM2 rejects a Config.Hash that
// names a real, linked crypto.Hash (so store.AvailableHashes accepts it)
// but has no corresponding TPM_ALG_ID (so ParseCryptoHashAlgID must
// reject it). SHA-224 is exactly that: available to the Go standard
// library but absent from the TPM 2.0 algorithm registry this package
// maps against, per store.AvailableHashes' own documented contract.
func TestNewTPM2_HashWithNoTPMAlgID(t *testing.T) {
	params := &Params{
		Config:    &Config{Hash: "SHA-224"},
		Logger:    slog.Default(),
		Transport: &noopTransport{},
	}

	tpmIface, err := NewTPM2(params)
	require.Nil(t, tpmIface)
	require.ErrorIs(t, err, ErrInvalidCryptoHashAlgID)
}

// TestForceClear_PPIPathUnavailable proves ForceClear surfaces the PPI
// sysfs write failure as a typed *errs.Detail wrapping ErrForceClear rather
// than a bare fmt.Errorf, and that it maps "tpmrm0" to the "tpm0" sysfs PPI
// node per the kernel's resource-manager naming convention. This process
// has no /sys/class/tpm/tpm0 node (no real TPM device is present, and this
// test writes nothing -- the write is expected to fail), so this exercises
// the error path deterministically; the success path (a real PPI write)
// requires kernel TPM sysfs support this test environment cannot provide.
func TestForceClear_PPIPathUnavailable(t *testing.T) {
	tpmObj := &TPM2{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		config: &Config{Device: "/dev/tpmrm0"},
	}

	err := tpmObj.ForceClear()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrForceClear)

	var detail *errs.Detail
	require.ErrorAs(t, err, &detail)
	require.NotEmpty(t, detail.Detail)
}

// TestClose_DeviceCloseErrorIsLoggedNotReturned proves Close tolerates a
// failing device.Close(): it must still clear the device/transport fields
// and return nil, matching Close's documented best-effort contract for
// every other cleanup step it performs.
func TestClose_DeviceCloseErrorIsLoggedNotReturned(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "tpm-device-*")
	require.NoError(t, err)
	require.NoError(t, f.Close()) // Closed once already; Close() must fail with os.ErrClosed the second time.

	tpmObj := &TPM2{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		device: f,
	}

	require.NoError(t, tpmObj.Close())
	require.Nil(t, tpmObj.device)
	require.Nil(t, tpmObj.transport)
}

// fakeCloseErrorSimulator implements SimulatorInterface and fails every
// Close() call, to exercise Close's simulator-cleanup branch without a real
// TPM simulator instance.
type fakeCloseErrorSimulator struct{ closeErr error }

func (f *fakeCloseErrorSimulator) Close() error              { return f.closeErr }
func (f *fakeCloseErrorSimulator) Transport() transport.TPM  { return nil }
func (f *fakeCloseErrorSimulator) ReadWriter() io.ReadWriter { return nil }

// TestClose_SimulatorCloseErrorIsLoggedNotReturned proves Close tolerates a
// failing simulator.Close() the same way it tolerates a failing
// device.Close(): the error is logged, not returned, and the simulator
// field is still cleared.
func TestClose_SimulatorCloseErrorIsLoggedNotReturned(t *testing.T) {
	tpmObj := &TPM2{
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		simulator: &fakeCloseErrorSimulator{closeErr: errors.New("simulator: synthetic close failure")},
	}

	require.NoError(t, tpmObj.Close())
	require.Nil(t, tpmObj.simulator)
}
