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

package gui

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

var errFakeTPMClose = errors.New("tpm: close failed")

// closingTPM is a TPM whose Close is observable and may fail.
type closingTPM struct {
	xkmssdk.TrustedPlatformModule
	closed   atomic.Bool
	closeErr error
	srk      *xkmssdk.KeyAttributes
}

func (c *closingTPM) Close() error {
	c.closed.Store(true)
	return c.closeErr
}

// PlatformSRKAttributes reports the SRK the TPM's keys are created under:
// srk if set, else ErrTPMNotInitialized, as for a TPM never provisioned.
func (c *closingTPM) PlatformSRKAttributes() (*xkmssdk.KeyAttributes, error) {
	if c.srk == nil {
		return nil, xkmssdk.ErrTPMNotInitialized
	}
	return c.srk, nil
}

// presentTPMDevice points app's TPM config at a file that exists, so getTPM
// gets past the device probe and opens the TPM through app.newTPM.
func presentTPMDevice(t *testing.T, app *App) string {
	t.Helper()
	device := filepath.Join(t.TempDir(), "tpmrm0")
	require.NoError(t, os.WriteFile(device, nil, 0o600))
	app.tpmConfigOnce.Do(func() {
		app.tpmCachedConfig = xkmssdk.TPMConfig{Device: device}
	})
	return device
}

func TestApp_GetTPM_OpensAndCachesTPM(t *testing.T) {
	tpm := &closingTPM{}
	var opened []*xkmssdk.TPMParams
	app := &App{log: lifecycleTestLogger(), config: DefaultGUIConfig()}
	app.newTPM = func(params *xkmssdk.TPMParams) (xkmssdk.TrustedPlatformModule, error) {
		opened = append(opened, params)
		return tpm, nil
	}
	device := presentTPMDevice(t, app)
	t.Cleanup(func() {
		if app.tpmStorageFactory != nil {
			assert.NoError(t, app.tpmStorageFactory.Close())
		}
	})

	assert.Same(t, tpm, app.getTPM())
	assert.Same(t, tpm, app.getTPM(), "the open TPM must be cached")

	require.Len(t, opened, 1, "a cached TPM must not be opened again")
	assert.Equal(t, device, opened[0].Config.Device)
	assert.NotNil(t, opened[0].Backend, "the TPM keys go to the storage factory's key backend")
	assert.NotNil(t, app.tpmStorageFactory)
}

func TestApp_Shutdown_ClosesOpenTPMEvenWhenCloseFails(t *testing.T) {
	app := newWiredApp(t)
	tpm := &closingTPM{closeErr: errFakeTPMClose}
	app.newTPM = func(*xkmssdk.TPMParams) (xkmssdk.TrustedPlatformModule, error) {
		return tpm, nil
	}
	// Forget any probe NewApp made of the host so the device below is used.
	app.tpmConfigOnce = sync.Once{}
	app.tpmUnavailable = false
	presentTPMDevice(t, app)
	require.Same(t, tpm, app.getTPM())

	app.shutdown(app.ctx)

	assert.True(t, tpm.closed.Load(), "shutdown must close the TPM it opened")
	assert.Nil(t, app.tpmInstance)
	assert.Nil(t, app.tpmStorageFactory, "shutdown must close the TPM storage factory")
}

// fakeTPMApp is a wired App whose TPM opens as tpm, with its data dir in a
// temporary directory.
func fakeTPMApp(t *testing.T, tpm xkmssdk.TrustedPlatformModule) *App {
	t.Helper()
	app := newWiredApp(t)
	app.newTPM = func(*xkmssdk.TPMParams) (xkmssdk.TrustedPlatformModule, error) {
		return tpm, nil
	}
	app.tpmConfigOnce = sync.Once{}
	app.tpmUnavailable = false
	presentTPMDevice(t, app)
	app.dataDir = t.TempDir()
	return app
}

func TestApp_EnsureLocalTPMPolicies_UnprovisionedTPMLeavesNoService(t *testing.T) {
	app := fakeTPMApp(t, &closingTPM{})
	logs := captureLog(app)
	t.Cleanup(func() { app.shutdown(app.ctx) })

	app.ensureLocalTPMPolicies()

	assert.Nil(t, app.tpmPolicyService.Local(), "a TPM with no Platform SRK cannot hold TPM policies")
	assert.True(t, logs.Contains("Platform SRK unavailable"))
}

func TestApp_EnsureLocalTPMPolicies_RegistryStoreFailureLeavesNoService(t *testing.T) {
	app := fakeTPMApp(t, &closingTPM{srk: &xkmssdk.KeyAttributes{CN: "srk"}})
	logs := captureLog(app)
	// A regular file where the policy registry's directory belongs.
	registry := filepath.Join(app.dataDir, "tpm-policies")
	require.NoError(t, os.WriteFile(registry, nil, 0o600))
	t.Cleanup(func() { app.shutdown(app.ctx) })

	app.ensureLocalTPMPolicies()

	assert.Nil(t, app.tpmPolicyService.Local(), "a policy registry that cannot open must leave no service")
	assert.True(t, logs.Contains("TPM policies: local service unavailable"))
	assert.True(t, logs.Contains(registry), "the SRK resolves; the registry is what fails")
}
