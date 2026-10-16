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
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolateFIDO2Run gives runFIDO2 a clean viper and config directory with a
// memory store and no desktop notifier, so each test sets only the key under
// test.
func isolateFIDO2Run(t *testing.T) {
	t.Helper()
	resetViperForTest(t)
	isolateFIDO2ConfigDir(t)
	viper.Set("fido2.storage", string(FIDO2StorageTypeMemory))
	viper.Set("fido2.attestation", "none")
	viper.Set("fido2.notify", "none")
}

// TestRunFIDO2_RefusesAnUnknownStorageType pins the configuration gate:
// an unrecognised --storage is refused before any device is created.
func TestRunFIDO2_RefusesAnUnknownStorageType(t *testing.T) {
	isolateFIDO2Run(t)
	viper.Set("fido2.storage", "floppy")

	err := runFIDO2(fido2Cmd, nil)

	require.ErrorIs(t, err, ErrFIDO2InvalidStorageType)
}

// TestRunFIDO2_TPM2BackendWithoutATPMFailsToCreateTheDevice covers the
// device-construction failure: a valid configuration whose TPM cannot be
// opened returns that failure rather than starting the authenticator.
func TestRunFIDO2_TPM2BackendWithoutATPMFailsToCreateTheDevice(t *testing.T) {
	isolateFIDO2Run(t)
	viper.Set("fido2.backend", "tpm2")
	viper.Set("fido2.tpm_device", filepath.Join(t.TempDir(), "no-tpm"))

	err := runFIDO2(fido2Cmd, nil)

	require.ErrorIs(t, err, ErrFIDO2AuthenticatorCreationFailed)
	assert.ErrorIs(t, err, ErrFIDO2TPMOpenFailed)
}

// TestCreateFIDO2TPM2KeyBackend_RefusesAMissingDevice pins the TPM backend
// factory's own error: the open failure is typed, and no backend is returned.
func TestCreateFIDO2TPM2KeyBackend_RefusesAMissingDevice(t *testing.T) {
	cfg := &FIDO2Config{TPMDevice: filepath.Join(t.TempDir(), "no-tpm")}

	backend, err := createFIDO2TPM2KeyBackend(cfg, discardLogger())

	require.ErrorIs(t, err, ErrFIDO2TPMOpenFailed)
	assert.Nil(t, backend)
}
