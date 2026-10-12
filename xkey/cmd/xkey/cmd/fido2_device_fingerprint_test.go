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

//go:build ble

package cmd

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// writeDevicesConfigForTest points HOME at a temp directory and writes a
// devices.yaml describing a single paired device with the given stored
// fingerprint.
func writeDevicesConfigForTest(t *testing.T, fingerprint string) {
	t.Helper()

	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	// getDevicesConfigPath prefers the invoking user's home when running under
	// sudo, which would send the lookup outside the temp directory.
	t.Setenv("SUDO_USER", "")

	cfg := &DevicesConfig{
		Devices: []PairedDevice{
			{
				Name:                 "Pixel 9",
				Address:              "AA:BB:CC:DD:EE:01",
				NoisePublicKey:       validNoisePublicKeyForTest(t),
				LocalNoisePrivateKey: validLocalNoisePrivateKeyForTest(t),
				DeviceFingerprint:    fingerprint,
				PairedAt:             time.Now().UTC(),
			},
		},
		DefaultDevice: "Pixel 9",
	}

	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, ".xkey"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, ".xkey", "devices.yaml"), data, 0600))
}

func quietTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// createFIDO2PhoneKeyBackend is a second, independent entry point into the
// fail-closed fingerprint decision (#38) — the CLI's, alongside the GUI
// service's. The decoder tests and the service tests would all still pass if
// this constructor stopped calling the decoder, swallowed its error, or moved
// the check back below the protected-key reconstruction, so the behaviour is
// asserted here too.
//
// Both malformed and wrong-length values are covered: the CLI must refuse a
// stored fingerprint it cannot use, whichever way it is unusable.
func TestCreateFIDO2PhoneKeyBackend_BadFingerprintIsRefused(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
	}{
		{"not hex", "not-valid-hex-!!!"},
		{"odd length", "aabbccdde"},
		{"too short for the wire contract", "aabbccdd11223344"},
		{"too long for the wire contract", strings.Repeat("aa", phone.DeviceFingerprintSize+1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeDevicesConfigForTest(t, tt.fingerprint)

			backend, err := createFIDO2PhoneKeyBackend(&FIDO2Config{}, quietTestLogger())

			require.Error(t, err, "a stored fingerprint that cannot be used must be refused")
			assert.Nil(t, backend, "no backend may be returned on the refusal path")
			assert.True(t, errors.Is(err, ErrFIDO2DeviceBackendCreationFailed),
				"want ErrFIDO2DeviceBackendCreationFailed, got %v", err)
			assert.True(t, errors.Is(err, phone.ErrInvalidDeviceFingerprint),
				"the decode cause must survive the wrap, got %v", err)

			// The refusal must happen before the backend is built. Reaching BLE
			// would mean the fingerprint was accepted and the handshake would
			// proceed with no identity binding at all — which is the defect.
			assert.False(t, errors.Is(err, phone.ErrBLEUnavailable),
				"the refusal must precede backend construction, got %v", err)
		})
	}
}
