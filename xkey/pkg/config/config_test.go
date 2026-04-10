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

package config

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg)

	// All top-level sections should be populated (non-zero where defaults exist).
	assert.NotEmpty(t, cfg.Backend.Default)
	assert.NotEmpty(t, cfg.FIDO2.Storage)
	assert.NotEmpty(t, cfg.FIDO2.Attestation)
	assert.NotEmpty(t, cfg.FIDO2.DeviceName)
	assert.NotEmpty(t, cfg.TPM.Device)
	assert.NotEmpty(t, cfg.Log.Level)
	assert.NotEmpty(t, cfg.GUI.Theme)
	assert.Greater(t, cfg.GUI.WindowWidth, 0)
	assert.Greater(t, cfg.GUI.WindowHeight, 0)
	assert.Greater(t, cfg.GUI.ClipboardTimeout, 0)

	// Policy section should be populated via DefaultPolicy.
	assert.Greater(t, cfg.Policy.MinPINLength, 0)
	assert.Greater(t, cfg.Policy.PolicyVersion, 0)

	// DefaultConfig must pass Validate.
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestDefaultConfigFieldValues(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg)

	assert.Equal(t, "software", cfg.Backend.Default)
	assert.Equal(t, "system", cfg.GUI.Theme)
	assert.Equal(t, 1024, cfg.GUI.WindowWidth)
	assert.Equal(t, 768, cfg.GUI.WindowHeight)
	assert.Equal(t, "info", cfg.Log.Level)
	assert.Equal(t, "file", cfg.FIDO2.Storage)
	assert.Equal(t, "packed", cfg.FIDO2.Attestation)
	assert.Equal(t, "xKey", cfg.FIDO2.DeviceName)
	assert.Equal(t, "/dev/tpmrm0", cfg.TPM.Device)
	assert.True(t, cfg.TPM.EncryptSessions)
	assert.Equal(t, 30, cfg.GUI.ClipboardTimeout)
	assert.True(t, cfg.GUI.Notifications)
	assert.True(t, cfg.GUI.AutoTray)
	assert.True(t, cfg.GUI.FIDO2AuthEnabled)
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := DefaultConfig()
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestValidate_InvalidLogLevel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Log.Level = "invalid"

	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid))
	assert.Contains(t, err.Error(), "log.level")
}

func TestValidate_InvalidBackend(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backend.Default = "invalid"

	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid))
	assert.Contains(t, err.Error(), "backend.default")
}

func TestValidate_NegativeClipboardTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.GUI.ClipboardTimeout = -1

	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid))
	assert.Contains(t, err.Error(), "clipboard_timeout")
}

func TestValidate_ZeroWindowWidth(t *testing.T) {
	cfg := DefaultConfig()
	cfg.GUI.WindowWidth = 0

	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid))
	assert.Contains(t, err.Error(), "window_width")
}

func TestValidate_ZeroWindowHeight(t *testing.T) {
	cfg := DefaultConfig()
	cfg.GUI.WindowHeight = 0

	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid))
	assert.Contains(t, err.Error(), "window_height")
}

func TestValidate_EmptyLogLevel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Log.Level = ""

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestValidate_EmptyBackend(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backend.Default = ""

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestValidate_AllValidLogLevels(t *testing.T) {
	levels := []string{"trace", "debug", "info", "warn", "error"}
	for _, level := range levels {
		t.Run(level, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Log.Level = level

			err := cfg.Validate()
			assert.NoError(t, err)
		})
	}
}

func TestValidate_AllValidBackends(t *testing.T) {
	backends := []string{"software", "tpm2", "pkcs11", "phone"}
	for _, backend := range backends {
		t.Run(backend, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Backend.Default = backend

			err := cfg.Validate()
			assert.NoError(t, err)
		})
	}
}

func TestConfigYAMLRoundtrip(t *testing.T) {
	_ = t.TempDir() // prove we use tmpdir; marshaling is in-memory

	original := DefaultConfig()

	// Set some non-default fields to exercise more coverage.
	original.FIDO2.RPIDHash = true
	original.FIDO2.AlwaysUV = true
	original.FIDO2.ResidentKey = true
	original.FIDO2.ConformanceMode = true
	original.FIDO2.Extensions = map[string]bool{"hmac-secret": true}
	original.TPM.PlatformPCRBank = "sha256"
	original.TPM.SRKHandle = 0x81000001
	original.GUI.StartMinimized = true
	original.GUI.RememberPosition = true
	original.GUI.WindowX = 100
	original.GUI.WindowY = 200
	original.State.SetupComplete = true
	original.State.StorageType = "barrier"
	original.State.BarrierInitialized = true
	original.State.BarrierStrategy = "password"
	original.State.Mode = "personal"

	// Set backends config with local, remote, and defaults.
	original.Backends = BackendsConfig{
		Local: []LocalBackendConfig{
			{
				ID:       "sw-1",
				Category: "software",
				Name:     "Software Backend",
			},
			{
				ID:       "tpm-1",
				Category: "tpm2",
				Name:     "TPM Backend",
				TPM2: &TPM2BackendConfig{
					Device:    "/dev/tpmrm0",
					Simulator: false,
				},
			},
		},
		Remote: []RemoteBackendConfig{
			{
				ID:          "xkms-1",
				Name:        "Remote XKMS",
				Address:     "https://xkms.example.com:8443",
				Protocol:    "grpc",
				TLSEnabled:  true,
				SPKIPin:     "sha256//abc123",
				AutoConnect: true,
			},
		},
		Defaults: map[string]string{
			"fido2":     "sw-1",
			"passwords": "tpm-1",
		},
	}

	// Marshal to YAML.
	data, err := yaml.Marshal(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal back.
	var restored Config
	err = yaml.Unmarshal(data, &restored)
	require.NoError(t, err)

	// Compare all fields.
	assert.Equal(t, original.Backend.Default, restored.Backend.Default)
	assert.Equal(t, original.FIDO2.Storage, restored.FIDO2.Storage)
	assert.Equal(t, original.FIDO2.Attestation, restored.FIDO2.Attestation)
	assert.Equal(t, original.FIDO2.DeviceName, restored.FIDO2.DeviceName)
	assert.Equal(t, original.FIDO2.RPIDHash, restored.FIDO2.RPIDHash)
	assert.Equal(t, original.FIDO2.AlwaysUV, restored.FIDO2.AlwaysUV)
	assert.Equal(t, original.FIDO2.ResidentKey, restored.FIDO2.ResidentKey)
	assert.Equal(t, original.FIDO2.ConformanceMode, restored.FIDO2.ConformanceMode)
	assert.Equal(t, original.FIDO2.Extensions, restored.FIDO2.Extensions)
	assert.Equal(t, original.TPM.Device, restored.TPM.Device)
	assert.Equal(t, original.TPM.EncryptSessions, restored.TPM.EncryptSessions)
	assert.Equal(t, original.TPM.PlatformPCRBank, restored.TPM.PlatformPCRBank)
	assert.Equal(t, original.TPM.SRKHandle, restored.TPM.SRKHandle)
	assert.Equal(t, original.Log.Level, restored.Log.Level)
	assert.Equal(t, original.GUI.Theme, restored.GUI.Theme)
	assert.Equal(t, original.GUI.AutoTray, restored.GUI.AutoTray)
	assert.Equal(t, original.GUI.Notifications, restored.GUI.Notifications)
	assert.Equal(t, original.GUI.ClipboardTimeout, restored.GUI.ClipboardTimeout)
	assert.Equal(t, original.GUI.WindowWidth, restored.GUI.WindowWidth)
	assert.Equal(t, original.GUI.WindowHeight, restored.GUI.WindowHeight)
	assert.Equal(t, original.GUI.StartMinimized, restored.GUI.StartMinimized)
	assert.Equal(t, original.GUI.RememberPosition, restored.GUI.RememberPosition)
	assert.Equal(t, original.GUI.WindowX, restored.GUI.WindowX)
	assert.Equal(t, original.GUI.WindowY, restored.GUI.WindowY)
	assert.Equal(t, original.GUI.FIDO2AuthEnabled, restored.GUI.FIDO2AuthEnabled)
	assert.Equal(t, original.State.SetupComplete, restored.State.SetupComplete)
	assert.Equal(t, original.State.StorageType, restored.State.StorageType)
	assert.Equal(t, original.State.BarrierInitialized, restored.State.BarrierInitialized)
	assert.Equal(t, original.State.BarrierStrategy, restored.State.BarrierStrategy)
	assert.Equal(t, original.State.Mode, restored.State.Mode)

	// Backends fields survive the round-trip.
	require.Len(t, restored.Backends.Local, 2)
	assert.Equal(t, "sw-1", restored.Backends.Local[0].ID)
	assert.Equal(t, "software", restored.Backends.Local[0].Category)
	assert.Equal(t, "Software Backend", restored.Backends.Local[0].Name)
	assert.Equal(t, "tpm-1", restored.Backends.Local[1].ID)
	assert.Equal(t, "tpm2", restored.Backends.Local[1].Category)
	require.NotNil(t, restored.Backends.Local[1].TPM2)
	assert.Equal(t, "/dev/tpmrm0", restored.Backends.Local[1].TPM2.Device)
	assert.False(t, restored.Backends.Local[1].TPM2.Simulator)

	require.Len(t, restored.Backends.Remote, 1)
	assert.Equal(t, "xkms-1", restored.Backends.Remote[0].ID)
	assert.Equal(t, "https://xkms.example.com:8443", restored.Backends.Remote[0].Address)
	assert.Equal(t, "grpc", restored.Backends.Remote[0].Protocol)
	assert.True(t, restored.Backends.Remote[0].TLSEnabled)
	assert.Equal(t, "sha256//abc123", restored.Backends.Remote[0].SPKIPin)
	assert.True(t, restored.Backends.Remote[0].AutoConnect)

	assert.Equal(t, "sw-1", restored.Backends.Defaults["fido2"])
	assert.Equal(t, "tpm-1", restored.Backends.Defaults["passwords"])

	// Policy fields survive the round-trip.
	assert.Equal(t, original.Policy.MinPINLength, restored.Policy.MinPINLength)
	assert.Equal(t, original.Policy.RequireSOPIN, restored.Policy.RequireSOPIN)
	assert.Equal(t, original.Policy.RequireUserPIN, restored.Policy.RequireUserPIN)
	assert.Equal(t, original.Policy.RequireEncryptedStorage, restored.Policy.RequireEncryptedStorage)
	assert.Equal(t, original.Policy.StorageType, restored.Policy.StorageType)
	assert.Equal(t, original.Policy.PolicyVersion, restored.Policy.PolicyVersion)

	// Restored config must also pass validation.
	err = restored.Validate()
	assert.NoError(t, err)
}

func TestValidate_ValidMode(t *testing.T) {
	modes := []string{"personal", "enterprise"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.State.Mode = mode
			err := cfg.Validate()
			assert.NoError(t, err)
		})
	}
}

func TestValidate_InvalidMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.State.Mode = "invalid"
	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid))
	assert.Contains(t, err.Error(), "state.mode")
}

func TestValidate_EmptyMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.State.Mode = ""
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestValidate_BackendsLocal(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backends = BackendsConfig{
		Local: []LocalBackendConfig{
			{ID: "sw-1", Category: "software", Name: "Software 1"},
			{ID: "tpm-1", Category: "tpm2", Name: "TPM 1"},
		},
	}
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestValidate_BackendsLocalEmptyID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backends = BackendsConfig{
		Local: []LocalBackendConfig{
			{ID: "", Category: "software", Name: "No ID"},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid))
	assert.Contains(t, err.Error(), "id must not be empty")
}

func TestValidate_BackendsLocalDuplicateID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backends = BackendsConfig{
		Local: []LocalBackendConfig{
			{ID: "dup", Category: "software", Name: "First"},
			{ID: "dup", Category: "tpm2", Name: "Second"},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid))
	assert.Contains(t, err.Error(), "duplicate")
}

func TestValidate_BackendsLocalInvalidCategory(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backends = BackendsConfig{
		Local: []LocalBackendConfig{
			{ID: "bad-cat", Category: "invalid", Name: "Bad Category"},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid))
	assert.Contains(t, err.Error(), "category")
}

func TestValidate_BackendsPKCS11EmptyLibrary(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backends = BackendsConfig{
		Local: []LocalBackendConfig{
			{
				ID: "pkcs11-bad", Category: "pkcs11", Name: "Bad PKCS11",
				PKCS11: &PKCS11BackendConfig{LibraryPath: ""},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid))
	assert.Contains(t, err.Error(), "library_path")
}

func TestValidate_BackendsRemote(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backends = BackendsConfig{
		Remote: []RemoteBackendConfig{
			{ID: "xkms-1", Name: "Server 1", Address: "https://xkms.example.com:8443", Protocol: "rest"},
		},
	}
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestValidate_BackendsRemoteEmptyID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backends = BackendsConfig{
		Remote: []RemoteBackendConfig{
			{ID: "", Name: "No ID", Address: "https://example.com"},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid))
	assert.Contains(t, err.Error(), "id must not be empty")
}

func TestValidate_BackendsRemoteEmptyAddress(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backends = BackendsConfig{
		Remote: []RemoteBackendConfig{
			{ID: "no-addr", Name: "No Address", Address: ""},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid))
	assert.Contains(t, err.Error(), "address must not be empty")
}

func TestValidate_BackendsRemoteInvalidProtocol(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backends = BackendsConfig{
		Remote: []RemoteBackendConfig{
			{ID: "bad-proto", Name: "Bad Proto", Address: "https://example.com", Protocol: "ftp"},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid))
	assert.Contains(t, err.Error(), "protocol")
}

func TestValidate_BackendsDefaultsUnknownBackend(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backends = BackendsConfig{
		Local: []LocalBackendConfig{
			{ID: "sw-1", Category: "software", Name: "Software 1"},
		},
		Defaults: map[string]string{
			"fido2": "nonexistent",
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid))
	assert.Contains(t, err.Error(), "unknown backend")
}

func TestValidate_BackendsDefaultsValid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backends = BackendsConfig{
		Local: []LocalBackendConfig{
			{ID: "sw-1", Category: "software", Name: "Software 1"},
		},
		Defaults: map[string]string{
			"fido2":     "sw-1",
			"passwords": "sw-1",
		},
	}
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestValidate_BackendsCrossTypeDuplicate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backends = BackendsConfig{
		Local: []LocalBackendConfig{
			{ID: "dup-id", Category: "software", Name: "Local"},
		},
		Remote: []RemoteBackendConfig{
			{ID: "dup-id", Name: "Remote", Address: "https://example.com"},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrConfigInvalid))
	assert.Contains(t, err.Error(), "duplicate")
}

func TestAutoPopulateBackends_FromLegacy(t *testing.T) {
	cfg := DefaultConfig() // Backend.Default = "software"
	cfg.AutoPopulateBackends()

	require.Len(t, cfg.Backends.Local, 1)
	assert.Equal(t, "software", cfg.Backends.Local[0].ID)
	assert.Equal(t, "software", cfg.Backends.Local[0].Category)
	assert.Equal(t, "Local software", cfg.Backends.Local[0].Name)
	assert.NotNil(t, cfg.Backends.Defaults)
}

func TestAutoPopulateBackends_FromLegacyTPM2(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backend.Default = "tpm2"
	cfg.Backend.TPM2.Device = "/dev/tpmrm0"
	cfg.AutoPopulateBackends()

	require.Len(t, cfg.Backends.Local, 1)
	assert.Equal(t, "tpm2", cfg.Backends.Local[0].ID)
	assert.Equal(t, "tpm2", cfg.Backends.Local[0].Category)
	require.NotNil(t, cfg.Backends.Local[0].TPM2)
	assert.Equal(t, "/dev/tpmrm0", cfg.Backends.Local[0].TPM2.Device)
}

func TestAutoPopulateBackends_SkipsWhenPresent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backends = BackendsConfig{
		Local: []LocalBackendConfig{
			{ID: "already-there", Category: "software", Name: "Existing"},
		},
	}
	cfg.AutoPopulateBackends()

	// Should NOT add more entries.
	require.Len(t, cfg.Backends.Local, 1)
	assert.Equal(t, "already-there", cfg.Backends.Local[0].ID)
}

func TestAutoPopulateBackends_EmptyDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backend.Default = ""
	cfg.AutoPopulateBackends()

	require.Len(t, cfg.Backends.Local, 1)
	assert.Equal(t, "software", cfg.Backends.Local[0].ID)
	assert.Equal(t, "software", cfg.Backends.Local[0].Category)
}
