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

package cmd

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setFIDO2PINViper sets one fido2 PIN source key for the test and restores
// it afterwards.
func setFIDO2PINViper(t *testing.T, key string, value any) {
	t.Helper()
	old := viper.Get(key)
	viper.Set(key, value)
	t.Cleanup(func() { viper.Set(key, old) })
}

// TestFIDO2PlatformSRKPINNamedSourceFails is ruling 998: a PIN source that
// was named but fails is an error naming the source, never a silent empty
// PIN, and createFIDO2TPM2KeyBackend stops before any TPM auth.
func TestFIDO2PlatformSRKPINNamedSourceFails(t *testing.T) {
	emptyFile := filepath.Join(t.TempDir(), "pin")
	require.NoError(t, os.WriteFile(emptyFile, []byte("\n"), 0o600))

	cases := []struct {
		name    string
		file    string
		stdin   bool
		setPIN  bool
		wantErr error
	}{
		{name: "unreadable pin-file", file: filepath.Join(t.TempDir(), "missing"), wantErr: ErrPINInputFileRead},
		{name: "empty pin-file", file: emptyFile, wantErr: ErrPINInputFileEmpty},
		{name: "pin-stdin with set-pin-stdin", stdin: true, setPIN: true, wantErr: ErrFIDO2PlatformSRKPINBothStdin},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(pinEnvVar, "")
			setFIDO2PINViper(t, "fido2.pin_file", tc.file)
			setFIDO2PINViper(t, "fido2.pin_stdin", tc.stdin)
			setFIDO2PINViper(t, "fido2.set_pin_stdin", tc.setPIN)

			pin, err := resolveFIDO2PlatformSRKPIN()
			require.ErrorIs(t, err, ErrFIDO2PlatformSRKPIN)
			require.ErrorIs(t, err, tc.wantErr)
			assert.Empty(t, pin)

			// The TPM device does not exist: reaching the TPM would fail
			// with ErrFIDO2TPMOpenFailed, so the PIN error proves no TPM
			// open or auth was attempted.
			cfg := &FIDO2Config{
				TPMDevice:         filepath.Join(t.TempDir(), "no-tpm"),
				PlatformSRKPINErr: err,
			}
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			_, backendErr := createFIDO2TPM2KeyBackend(cfg, logger)
			require.ErrorIs(t, backendErr, ErrFIDO2PlatformSRKPIN)
			require.ErrorIs(t, backendErr, tc.wantErr)
			assert.NotErrorIs(t, backendErr, ErrFIDO2TPMOpenFailed)
		})
	}
}

// TestFIDO2PlatformSRKPINNoSourceNamed keeps the no-source behaviour: no
// error and an empty PIN (empty-auth SRK).
func TestFIDO2PlatformSRKPINNoSourceNamed(t *testing.T) {
	t.Setenv(pinEnvVar, "")
	setFIDO2PINViper(t, "fido2.pin_file", "")
	setFIDO2PINViper(t, "fido2.pin_stdin", false)
	setFIDO2PINViper(t, "fido2.set_pin_stdin", false)

	pin, err := resolveFIDO2PlatformSRKPIN()
	require.NoError(t, err)
	assert.Empty(t, pin)
}
