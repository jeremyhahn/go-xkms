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

package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// FactoryReset destroys the TPM hierarchy, the policy HMAC and the GUI config.
// Its only authorization is the SO PIN, so these tests pin the two ways that
// gate can fail to run: an unwired PIN service, and one that rejects the
// credential. Both must leave the device intact (#313).

// newFactoryResetFixture builds a SetupWizardService with a config directory, a
// policy HMAC file and a GUI config, and returns what a completed wipe removes.
func newFactoryResetFixture(t *testing.T) (svc *SetupWizardService, hmacFile string, configSaved *bool) {
	t.Helper()

	svc = NewSetupWizardService()
	svc.SetContext(context.Background())

	configDir := t.TempDir()
	svc.SetConfigDir(configDir)

	hmacFile = config.PolicyHMACPath(configDir)
	require.NoError(t, os.MkdirAll(filepath.Dir(hmacFile), 0700))
	require.NoError(t, os.WriteFile(hmacFile, []byte("policy-hmac"), 0600))
	require.FileExists(t, hmacFile)

	wrote := false
	configSaved = &wrote
	svc.SetConfigFunc(func() *GUIConfigData { return &GUIConfigData{SetupComplete: true} })
	svc.SetConfigSaveFunc(func(*GUIConfigData) error {
		wrote = true
		return nil
	})
	return svc, hmacFile, configSaved
}

// wireSOPIN gives svc a PIN service that accepts exactly soPIN.
func wireSOPIN(svc *SetupWizardService, soPIN string) *wizardMockPINBackend {
	backend := &wizardMockPINBackend{
		strategy: qrdbsdk.PINStrategySoftware,
		soPIN:    soPIN,
		soPINSet: true,
	}
	svc.SetPINService(newWizardPINService(backend))
	return backend
}

func TestFactoryReset_RefusesWhenPINServiceUnwired(t *testing.T) {
	// The regression guard for #313 site 4. SetPINService is a setter, so
	// FactoryReset can be reached with s.pinSvc still nil. The verification
	// used to sit inside "if s.pinSvc != nil", which turned an authorization
	// check that could not run into one that passed.
	svc, hmacFile, configSaved := newFactoryResetFixture(t)

	err := svc.FactoryReset("any-string-at-all")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSetupPINServiceUnavailable)
	assert.FileExists(t, hmacFile, "the policy HMAC must survive a refused wipe")
	assert.False(t, *configSaved, "the GUI config must not be rewritten by a refused wipe")
}

func TestFactoryReset_RefusesWrongSOPIN(t *testing.T) {
	svc, hmacFile, configSaved := newFactoryResetFixture(t)
	backend := wireSOPIN(svc, "correct-so-pin")

	err := svc.FactoryReset("wrong-so-pin")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSetupSOPINVerifyFailed)
	assert.Equal(t, 1, backend.verifySOPINCalls, "the SO PIN must actually be checked")
	assert.FileExists(t, hmacFile, "the policy HMAC must survive a refused wipe")
	assert.False(t, *configSaved, "the GUI config must not be rewritten by a refused wipe")
}

func TestFactoryReset_RefusesEmptySOPIN(t *testing.T) {
	svc, hmacFile, configSaved := newFactoryResetFixture(t)
	backend := wireSOPIN(svc, "correct-so-pin")

	err := svc.FactoryReset("")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSetupSOPINRequired)
	assert.Zero(t, backend.verifySOPINCalls, "an empty PIN is refused before the backend is consulted")
	assert.FileExists(t, hmacFile)
	assert.False(t, *configSaved)
}

func TestFactoryReset_ProceedsWithCorrectSOPIN(t *testing.T) {
	// The positive control. Without it, the refusal tests above would all still
	// pass if FactoryReset simply refused everything.
	svc, hmacFile, configSaved := newFactoryResetFixture(t)
	backend := wireSOPIN(svc, "correct-so-pin")

	err := svc.FactoryReset("correct-so-pin")

	// With no TPM service wired the wipe collects no fatal error; what matters
	// is that it cleared the gate and did the work available to it here.
	if err != nil {
		assert.NotErrorIs(t, err, ErrSetupPINServiceUnavailable)
		assert.NotErrorIs(t, err, ErrSetupSOPINVerifyFailed)
	}
	assert.Equal(t, 1, backend.verifySOPINCalls)
	assert.NoFileExists(t, hmacFile, "an authorized wipe removes the policy HMAC")
	assert.True(t, *configSaved, "an authorized wipe rewrites the GUI config")
}

func TestFactoryReset_PINServiceErrorIsNotMistakenForAbsence(t *testing.T) {
	// A PIN service that is wired but fails for an unrelated reason must report
	// a verification failure, not an unavailable service: otherwise the two
	// refusals are indistinguishable to the caller.
	svc, hmacFile, _ := newFactoryResetFixture(t)

	backend := &wizardMockPINBackend{
		strategy:    qrdbsdk.PINStrategySoftware,
		soPINSet:    true,
		verifySOErr: errors.New("pin backend unavailable"),
	}
	svc.SetPINService(newWizardPINService(backend))

	err := svc.FactoryReset("correct-so-pin")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSetupSOPINVerifyFailed)
	assert.NotErrorIs(t, err, ErrSetupPINServiceUnavailable)
	assert.FileExists(t, hmacFile)
}
