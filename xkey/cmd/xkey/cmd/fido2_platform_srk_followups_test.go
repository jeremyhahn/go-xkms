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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// testFollowupPIN is a test-local literal; no real PIN is ever written.
const testFollowupPIN = "test-pin-2325"

// fakeSRKKeyStore is a Platform key store whose VerifyAuth returns
// verifyErr; every other method panics through the nil embedded interface.
type fakeSRKKeyStore struct {
	xkms.PlatformKeyStorer
	verifyErr error
	verified  string
}

func (f *fakeSRKKeyStore) VerifyAuth(pin string) error {
	f.verified = pin
	return f.verifyErr
}

func (f *fakeSRKKeyStore) SRKAttributes() *xkms.KeyAttributes { return nil }

// TestFIDO2PlatformSRKPINIsSealed is #2325 (3): the daemon's Platform SRK
// PIN is sealed into protected memory, as the set-PIN is, and destroyed
// once loadFIDO2PlatformSRKAuth has used it.
func TestFIDO2PlatformSRKPINIsSealed(t *testing.T) {
	t.Setenv(pinEnvVar, "")
	pinFile := filepath.Join(t.TempDir(), "pin")
	require.NoError(t, os.WriteFile(pinFile, []byte(testFollowupPIN+"\n"), 0o600))
	setFIDO2PINViper(t, "fido2.pin_file", pinFile)
	setFIDO2PINViper(t, "fido2.pin_stdin", false)
	setFIDO2PINViper(t, "fido2.set_pin_stdin", false)

	sealed, err := resolveFIDO2PlatformSRKPIN()
	require.NoError(t, err)
	require.NotNil(t, sealed)
	assert.Equal(t, testFollowupPIN, openSecretString(t, sealed))

	pks := &fakeSRKKeyStore{}
	cfg := &FIDO2Config{PlatformSRKPIN: sealed}
	_, err = loadFIDO2PlatformSRKAuth(cfg, func() (xkms.PlatformKeyStorer, error) { return pks, nil })
	require.NoError(t, err)
	assert.Equal(t, testFollowupPIN, pks.verified)
	assert.Nil(t, cfg.PlatformSRKPIN, "the sealed PIN is destroyed after use")
}

// TestFIDO2PlatformSRKAuthRejectedExitCode is #2325 (4): a PIN the TPM
// rejects stops the daemon with ExitCodePlatformSRKAuthRejected, which the
// unit lists in RestartPreventExitStatus, so restarts cannot walk the TPM
// into dictionary-attack lockout. Other failures keep exit code 1.
func TestFIDO2PlatformSRKAuthRejectedExitCode(t *testing.T) {
	sealed := mustSealPIN(t, testFollowupPIN)
	cfg := &FIDO2Config{PlatformSRKPIN: sealed}
	pks := &fakeSRKKeyStore{verifyErr: fmt.Errorf("%w: TPM_RC_AUTH_FAIL", xkms.ErrTPMAuthFailed)}
	_, err := loadFIDO2PlatformSRKAuth(cfg, func() (xkms.PlatformKeyStorer, error) { return pks, nil })
	require.ErrorIs(t, err, ErrFIDO2TPMPlatformSRKAuth)
	require.ErrorIs(t, err, ErrFIDO2TPMPlatformSRKAuthRejected)
	assert.NotContains(t, err.Error(), testFollowupPIN)
	assert.Equal(t, ExitCodePlatformSRKAuthRejected, ExitCode(fmt.Errorf("fido2: %w", err)))
	assert.Nil(t, cfg.PlatformSRKPIN, "the sealed PIN is destroyed after a failure too")

	attachCfg := &FIDO2Config{PlatformSRKPIN: mustSealPIN(t, testFollowupPIN)}
	_, attachErr := loadFIDO2PlatformSRKAuth(attachCfg, func() (xkms.PlatformKeyStorer, error) {
		return nil, errors.New("no key store")
	})
	require.ErrorIs(t, attachErr, ErrFIDO2TPMPlatformSRKAuth)
	assert.NotErrorIs(t, attachErr, ErrFIDO2TPMPlatformSRKAuthRejected)
	assert.Equal(t, 1, ExitCode(attachErr))
	assert.Equal(t, 0, ExitCode(nil))
}

// TestFIDO2PlatformSRKNonAuthErrorKeepsExit1 pins that only a TPM auth
// failure is the SRK-rejected sentinel: a not-enrolled SRK or a transport
// error exits 1, so systemd keeps restarting the service.
func TestFIDO2PlatformSRKNonAuthErrorKeepsExit1(t *testing.T) {
	for name, verifyErr := range map[string]error{
		"not enrolled": errors.New("platform SRK not enrolled"),
		"transport":    errors.New("tpm: session: transport closed"),
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &FIDO2Config{PlatformSRKPIN: mustSealPIN(t, testFollowupPIN)}
			pks := &fakeSRKKeyStore{verifyErr: verifyErr}
			_, err := loadFIDO2PlatformSRKAuth(cfg, func() (xkms.PlatformKeyStorer, error) { return pks, nil })
			require.ErrorIs(t, err, ErrFIDO2TPMPlatformSRKAuth)
			require.ErrorIs(t, err, verifyErr)
			assert.NotErrorIs(t, err, ErrFIDO2TPMPlatformSRKAuthRejected)
			assert.Equal(t, 1, ExitCode(fmt.Errorf("fido2: %w", err)))
		})
	}
}

// TestFIDO2PlatformSRKPromptedPINIsWiped pins that a PIN read at the
// terminal prompt is wiped once loadFIDO2PlatformSRKAuth returns.
func TestFIDO2PlatformSRKPromptedPINIsWiped(t *testing.T) {
	t.Setenv(pinEnvVar, "")
	prevTerminal, prevPrompt := pinInputIsTerminal, promptFIDO2PlatformSRKPIN
	t.Cleanup(func() { pinInputIsTerminal, promptFIDO2PlatformSRKPIN = prevTerminal, prevPrompt })
	prompted := []byte(testFollowupPIN)
	pinInputIsTerminal = func() bool { return true }
	promptFIDO2PlatformSRKPIN = func() ([]byte, error) { return prompted, nil }

	pks := &fakeSRKKeyStore{verifyErr: fmt.Errorf("%w: TPM_RC_AUTH_FAIL", xkms.ErrTPMAuthFailed)}
	_, err := loadFIDO2PlatformSRKAuth(&FIDO2Config{}, func() (xkms.PlatformKeyStorer, error) { return pks, nil })
	require.ErrorIs(t, err, ErrFIDO2TPMPlatformSRKAuthRejected)
	assert.Equal(t, testFollowupPIN, pks.verified, "the prompted PIN reaches VerifyAuth")
	assert.Equal(t, make([]byte, len(testFollowupPIN)), prompted, "the prompted PIN is wiped")
}

// TestXKeyUnitPreventsRestartOnSRKAuthRejected keeps the systemd unit and
// the exit code in step (#2325 (4)).
func TestXKeyUnitPreventsRestartOnSRKAuthRejected(t *testing.T) {
	unit, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "systemd", "xkey.service"))
	require.NoError(t, err)
	want := fmt.Sprintf("RestartPreventExitStatus=%d", ExitCodePlatformSRKAuthRejected)
	assert.True(t, strings.Contains(string(unit), want), "xkey.service lists %s", want)
}
