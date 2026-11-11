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
	"github.com/stretchr/testify/require"
)

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
