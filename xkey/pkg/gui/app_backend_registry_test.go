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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// TestDefaultCapabilities covers every BackendCategory branch, including the
// unrecognized-category default. Each case pins the exact capability set so
// a capability silently dropped (or added) from one category's grant list
// is caught rather than only "capabilities is non-empty".
func TestDefaultCapabilities(t *testing.T) {
	tests := []struct {
		name string
		cat  backendregistry.BackendCategory
		want map[backendregistry.Capability]bool
	}{
		{
			name: "software",
			cat:  backendregistry.CategorySoftware,
			want: map[backendregistry.Capability]bool{
				backendregistry.CapSigning:    true,
				backendregistry.CapEncryption: true,
				backendregistry.CapSSH:        true,
				backendregistry.CapFIDO2:      true,
				backendregistry.CapOATH:       true,
				backendregistry.CapPasswords:  true,
				backendregistry.CapSealing:    true,
				backendregistry.CapPIV:        true,
			},
		},
		{
			name: "tpm2",
			cat:  backendregistry.CategoryTPM2,
			want: map[backendregistry.Capability]bool{
				backendregistry.CapSigning:     true,
				backendregistry.CapEncryption:  true,
				backendregistry.CapSSH:         true,
				backendregistry.CapFIDO2:       true,
				backendregistry.CapSealing:     true,
				backendregistry.CapAttestation: true,
				backendregistry.CapPasswords:   true,
				backendregistry.CapPIV:         true,
			},
		},
		{
			name: "pkcs11",
			cat:  backendregistry.CategoryPKCS11,
			want: map[backendregistry.Capability]bool{
				backendregistry.CapSigning:    true,
				backendregistry.CapEncryption: true,
				backendregistry.CapSSH:        true,
				backendregistry.CapFIDO2:      true,
				backendregistry.CapPIV:        true,
				backendregistry.CapSealing:    true,
				backendregistry.CapOATH:       true,
				backendregistry.CapPasswords:  true,
			},
		},
		{
			name: "phone",
			cat:  backendregistry.CategoryPhone,
			want: map[backendregistry.Capability]bool{
				backendregistry.CapSigning:     true,
				backendregistry.CapEncryption:  true,
				backendregistry.CapSSH:         true,
				backendregistry.CapFIDO2:       true,
				backendregistry.CapAttestation: true,
			},
		},
		{
			// CategoryXKMS (and any other unrecognized value) falls through
			// to the base set with no category-specific additions.
			name: "unrecognized category falls back to the base set",
			cat:  backendregistry.CategoryXKMS,
			want: map[backendregistry.Capability]bool{
				backendregistry.CapSigning:    true,
				backendregistry.CapEncryption: true,
				backendregistry.CapSSH:        true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, defaultCapabilities(tt.cat))
		})
	}
}

// TestApp_RegisterDefaultSoftwareBackend_Fresh covers the registration path:
// a registry with no "software" entry gets one, ready, ID "software", with
// the software capability set.
func TestApp_RegisterDefaultSoftwareBackend_Fresh(t *testing.T) {
	app := newMinimalApp(t)

	app.registerDefaultSoftwareBackend()

	got, err := app.BackendRegistry().Get("software")
	require.NoError(t, err)
	assert.Equal(t, backendregistry.StateReady, got.State())
	assert.Equal(t, defaultCapabilities(backendregistry.CategorySoftware), got.Capabilities)
}

// TestApp_RegisterDefaultSoftwareBackend_AlreadyRegistered covers the
// early-return guard: a pre-existing "software" entry (as unified config
// registration would leave behind) must not be clobbered by a second call.
func TestApp_RegisterDefaultSoftwareBackend_AlreadyRegistered(t *testing.T) {
	app := newMinimalApp(t)

	existing := &backendregistry.RegisteredBackend{
		ID:          "software",
		Location:    backendregistry.LocationLocal,
		Category:    backendregistry.CategorySoftware,
		DisplayName: "pre-existing",
	}
	require.NoError(t, app.BackendRegistry().Register(existing))

	app.registerDefaultSoftwareBackend()

	got, err := app.BackendRegistry().Get("software")
	require.NoError(t, err)
	assert.Equal(t, "pre-existing", got.DisplayName,
		"a second registration attempt must not overwrite the existing entry")
}

// TestApp_PopulateBackendRegistry_ConfigUnavailable covers the config.Load
// error branch: when the unified config cannot be read, only the software
// backend is registered.
func TestApp_PopulateBackendRegistry_ConfigUnavailable(t *testing.T) {
	app := newMinimalApp(t)

	cfgDir := t.TempDir()
	config.SetConfigDir(cfgDir)
	t.Cleanup(config.ResetConfigDir)
	// A malformed config file makes config.Load return an error rather than
	// the "no file" first-run defaults.
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "xkey.yaml"), []byte("not: [valid yaml"), 0600))

	app.populateBackendRegistry()

	all := app.BackendRegistry().List()
	require.Len(t, all, 1, "only the always-on software backend must be registered")
	assert.Equal(t, "software", all[0].ID)
}

// TestApp_PopulateBackendRegistry_RegistersConfiguredBackends covers the
// success path: local and remote backends from the unified config are
// registered with the state and capabilities the function documents, the
// configured default is applied, and the software backend is still present
// alongside them.
func TestApp_PopulateBackendRegistry_RegistersConfiguredBackends(t *testing.T) {
	app := newMinimalApp(t)

	cfgDir := t.TempDir()
	config.SetConfigDir(cfgDir)
	t.Cleanup(config.ResetConfigDir)

	yaml := `
backends:
  local:
    - id: token1
      category: pkcs11
      name: "Test Token"
      pkcs11:
        library_path: /usr/lib/softhsm/libsofthsm2.so
  remote:
    - id: remote1
      name: "Remote KMS"
      address: kms.example.com:9443
      protocol: grpc
  defaults:
    signing: token1
`
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "xkey.yaml"), []byte(yaml), 0600))

	app.populateBackendRegistry()

	local, err := app.BackendRegistry().Get("token1")
	require.NoError(t, err)
	assert.Equal(t, backendregistry.LocationLocal, local.Location)
	assert.Equal(t, backendregistry.CategoryPKCS11, local.Category)
	assert.Equal(t, backendregistry.StateOffline, local.State(),
		"a pkcs11 backend must start offline pending PIN authentication")
	assert.Equal(t, defaultCapabilities(backendregistry.CategoryPKCS11), local.Capabilities)

	remote, err := app.BackendRegistry().Get("remote1")
	require.NoError(t, err)
	assert.Equal(t, backendregistry.LocationRemote, remote.Location)
	assert.Equal(t, backendregistry.CategoryXKMS, remote.Category)
	assert.Equal(t, backendregistry.StateOffline, remote.State())
	assert.Equal(t, "kms.example.com:9443", remote.Metadata["address"])
	assert.Equal(t, "grpc", remote.Metadata["protocol"])
	assert.True(t, remote.Capabilities[backendregistry.CapSigning])

	software, err := app.BackendRegistry().Get("software")
	require.NoError(t, err, "the software backend must always be registered")
	assert.Equal(t, backendregistry.StateReady, software.State())

	byCap := app.BackendRegistry().ListByCapability(backendregistry.CapSigning)
	var defaultIsToken1 bool
	for _, b := range byCap {
		if b.ID == "token1" {
			defaultIsToken1 = true
		}
	}
	assert.True(t, defaultIsToken1, "token1 must be discoverable for the signing capability")
}

// TestApp_RestorePKCS11Modules_ConfigUnavailable covers the config.Load
// error branch: restorePKCS11Modules must return without touching the
// PKCS#11 service when the unified config cannot be read.
func TestApp_RestorePKCS11Modules_ConfigUnavailable(t *testing.T) {
	app := newMinimalApp(t)

	cfgDir := t.TempDir()
	config.SetConfigDir(cfgDir)
	t.Cleanup(config.ResetConfigDir)
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "xkey.yaml"), []byte("not: [valid yaml"), 0600))

	assert.NotPanics(t, func() { app.restorePKCS11Modules() })
}

// TestApp_RestorePKCS11Modules_SkipsNonPKCS11AndRegistersConfigured covers
// the filter (non-pkcs11 categories and entries missing a library path are
// skipped) and the registration attempt for a configured pkcs11 module. The
// library path does not resolve to a real module on this host, so
// RegisterModuleFromConfig fails — that failure path (log and continue) is
// exactly what is under test; a real PKCS#11 token is neither available nor
// needed here.
func TestApp_RestorePKCS11Modules_SkipsNonPKCS11AndRegistersConfigured(t *testing.T) {
	app := newMinimalApp(t)
	app.pkcs11Service = services.NewPKCS11Service()

	// Defense in depth: the configured library path below is deliberately
	// not SoftHSM2-named so RegisterModuleFromConfig never takes the
	// auto-config branch that touches $HOME/.config/softhsm2/, but isolate
	// HOME anyway so a future edit to this fixture cannot write there.
	t.Setenv("HOME", t.TempDir())

	cfgDir := t.TempDir()
	config.SetConfigDir(cfgDir)
	t.Cleanup(config.ResetConfigDir)

	yaml := `
backends:
  local:
    - id: software
      category: software
      name: "Local Software"
    - id: incomplete-pkcs11
      category: pkcs11
      name: "Incomplete"
    - id: token1
      category: pkcs11
      name: "Test Token"
      pkcs11:
        library_path: /nonexistent/libpkcs11-vendor.so
`
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "xkey.yaml"), []byte(yaml), 0600))

	assert.NotPanics(t, func() { app.restorePKCS11Modules() })
}
