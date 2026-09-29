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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

func defaultTestConfig() *GUIConfigData {
	return &GUIConfigData{
		AutoTray:         true,
		Theme:            "system",
		StartMinimized:   false,
		Notifications:    true,
		WindowWidth:      1024,
		WindowHeight:     768,
		RememberPosition: true,
	}
}

func TestNewAppService(t *testing.T) {
	svc := NewAppService(defaultTestConfig())
	assert.NotNil(t, svc)
}

func TestNewAppService_NilConfig(t *testing.T) {
	svc := NewAppService(nil)
	assert.NotNil(t, svc)
	cfg := svc.GetConfig()
	assert.Equal(t, "system", cfg.Theme)
}

func TestAppService_SetContext(t *testing.T) {
	svc := NewAppService(defaultTestConfig())
	ctx := context.Background()
	svc.SetContext(ctx)
	// No panic means success; context is internal.
}

func TestAppService_GetStatus(t *testing.T) {
	svc := NewAppService(defaultTestConfig())
	status := svc.GetStatus()
	require.NotNil(t, status)
	assert.Equal(t, Version, status.Version)
	assert.NotEmpty(t, status.Platform)
	assert.NotEmpty(t, status.GoVersion)
	assert.NotEmpty(t, status.Uptime)
}

func TestAppService_GetConfig(t *testing.T) {
	cfg := defaultTestConfig()
	svc := NewAppService(cfg)
	got := svc.GetConfig()
	assert.Equal(t, cfg.Theme, got.Theme)
	assert.Equal(t, cfg.WindowWidth, got.WindowWidth)
}

func TestAppService_UpdateConfig(t *testing.T) {
	svc := NewAppService(defaultTestConfig())

	updated := defaultTestConfig()
	updated.Theme = "dark"

	err := svc.UpdateConfig(updated)
	assert.NoError(t, err)
	assert.Equal(t, "dark", svc.GetConfig().Theme)
}

func TestAppService_UpdateConfig_NilConfig(t *testing.T) {
	svc := NewAppService(defaultTestConfig())
	err := svc.UpdateConfig(nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAppConfigNil))
}

func TestAppService_UpdateConfig_WithUpdater(t *testing.T) {
	svc := NewAppService(defaultTestConfig())
	var called bool
	svc.SetConfigUpdater(func(cfg *GUIConfigData) error {
		called = true
		return nil
	})

	err := svc.UpdateConfig(defaultTestConfig())
	assert.NoError(t, err)
	assert.True(t, called)
}

func TestAppService_UpdateConfig_UpdaterError(t *testing.T) {
	svc := NewAppService(defaultTestConfig())
	errSave := errors.New("save failed")
	svc.SetConfigUpdater(func(cfg *GUIConfigData) error {
		return errSave
	})

	err := svc.UpdateConfig(defaultTestConfig())
	assert.Error(t, err)
	assert.Equal(t, errSave, err)
}

func TestAppService_GetTheme(t *testing.T) {
	svc := NewAppService(defaultTestConfig())
	assert.Equal(t, "system", svc.GetTheme())
}

func TestAppService_SetTheme(t *testing.T) {
	svc := NewAppService(defaultTestConfig())
	err := svc.SetTheme("dark")
	assert.NoError(t, err)
	assert.Equal(t, "dark", svc.GetTheme())
}

func TestAppService_SetTheme_WithValidator(t *testing.T) {
	svc := NewAppService(defaultTestConfig())
	errBad := errors.New("bad theme")
	svc.SetThemeValidator(func(theme string) error {
		if theme == "bad" {
			return errBad
		}
		return nil
	})

	err := svc.SetTheme("bad")
	assert.Error(t, err)
	assert.Equal(t, errBad, err)
	assert.Equal(t, "system", svc.GetTheme()) // Unchanged.

	err = svc.SetTheme("dark")
	assert.NoError(t, err)
	assert.Equal(t, "dark", svc.GetTheme())
}

func TestAppService_GetStatus_NewFields_Defaults(t *testing.T) {
	svc := NewAppService(nil)
	status := svc.GetStatus()
	assert.Equal(t, "standalone", status.Mode)
	assert.Zero(t, status.OATHAccountCount)
	assert.Zero(t, status.FIDO2CredCount)
	assert.Zero(t, status.PIVCertCount)
	assert.False(t, status.TPMAvailable)
	assert.False(t, status.TPMProvisioned)
	assert.False(t, status.StorageEncrypted)
	assert.False(t, status.StorageMounted)
	assert.False(t, status.Sealed)
	assert.False(t, status.PINConfigured)
	assert.False(t, status.PINLocked)
	assert.Empty(t, status.PINStrategy)
	assert.Empty(t, status.SealStrategy)
	assert.False(t, status.HardwareBacked)
}

func TestAppService_GetStatus_WithCallbacks(t *testing.T) {
	svc := NewAppService(nil)
	svc.SetOATHCountFunc(func() int { return 5 })
	svc.SetFIDO2CountFunc(func() int { return 3 })
	svc.SetPIVCertCountFunc(func() int { return 2 })
	svc.SetTPMStatusFunc(func() (bool, bool, bool) { return true, true, true })
	svc.SetStorageStatusFunc(func() (bool, bool) { return true, false })
	svc.SetServerConnectedFunc(func() bool { return true })

	status := svc.GetStatus()
	assert.Equal(t, 5, status.OATHAccountCount)
	assert.Equal(t, 3, status.FIDO2CredCount)
	assert.Equal(t, 2, status.PIVCertCount)
	assert.True(t, status.TPMDeviceExists)
	assert.True(t, status.TPMAvailable)
	assert.True(t, status.TPMProvisioned)
	assert.True(t, status.StorageEncrypted)
	assert.False(t, status.StorageMounted)
	assert.Equal(t, "xkmsd", status.Mode)
}

func TestAppService_Mode_Standalone(t *testing.T) {
	svc := NewAppService(nil)
	svc.SetServerConnectedFunc(func() bool { return false })
	status := svc.GetStatus()
	assert.Equal(t, "standalone", status.Mode)
}

// ---------------------------------------------------------------------------
// MinimizeToTray
// ---------------------------------------------------------------------------

func TestAppService_MinimizeToTray_WithFunc(t *testing.T) {
	svc := NewAppService(defaultTestConfig())
	called := false
	svc.SetWindowHideFunc(func() {
		called = true
	})

	svc.MinimizeToTray()
	assert.True(t, called)
}

func TestAppService_MinimizeToTray_NilFunc(t *testing.T) {
	svc := NewAppService(defaultTestConfig())
	// Do not set windowHideFunc.
	// Should not panic.
	svc.MinimizeToTray()
}

// ---------------------------------------------------------------------------
// AutoUnseal config fields
// ---------------------------------------------------------------------------

func TestAppService_SetWindowHideFunc(t *testing.T) {
	svc := NewAppService(defaultTestConfig())
	assert.Nil(t, svc.windowHideFunc)

	fn := func() {}
	svc.SetWindowHideFunc(fn)
	assert.NotNil(t, svc.windowHideFunc)
}

// ---------------------------------------------------------------------------
// Seal and PIN status callbacks
// ---------------------------------------------------------------------------

func TestAppService_GetStatus_WithSealAndPINCallbacks(t *testing.T) {
	svc := NewAppService(nil)
	svc.SetSealStatusFunc(func() (bool, string, bool) {
		return true, "tpm2", true
	})
	svc.SetPINStatusFunc(func() (bool, bool, string) {
		return true, false, "software"
	})

	status := svc.GetStatus()
	assert.True(t, status.Sealed)
	assert.Equal(t, "tpm2", status.SealStrategy)
	assert.True(t, status.HardwareBacked)
	assert.True(t, status.PINConfigured)
	assert.False(t, status.PINLocked)
	assert.Equal(t, "software", status.PINStrategy)
}

func TestAppService_GetStatus_SealAndPINDefaults(t *testing.T) {
	svc := NewAppService(nil)
	// No callbacks set, verify zero values.
	status := svc.GetStatus()
	assert.False(t, status.Sealed)
	assert.Empty(t, status.SealStrategy)
	assert.False(t, status.HardwareBacked)
	assert.False(t, status.PINConfigured)
	assert.False(t, status.PINLocked)
	assert.Empty(t, status.PINStrategy)
}

func TestAppService_GetStatus_PINLocked(t *testing.T) {
	svc := NewAppService(nil)
	svc.SetPINStatusFunc(func() (bool, bool, string) {
		return true, true, "pkcs11"
	})

	status := svc.GetStatus()
	assert.True(t, status.PINConfigured)
	assert.True(t, status.PINLocked)
	assert.Equal(t, "pkcs11", status.PINStrategy)
}

func TestAppService_SetSealStatusFunc(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.sealStatusFn)

	svc.SetSealStatusFunc(func() (bool, string, bool) {
		return false, "software", false
	})
	assert.NotNil(t, svc.sealStatusFn)
}

func TestAppService_SetPINStatusFunc(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.pinStatusFn)

	svc.SetPINStatusFunc(func() (bool, bool, string) {
		return false, false, "software"
	})
	assert.NotNil(t, svc.pinStatusFn)
}

// ---------------------------------------------------------------------------
// Phone status callbacks
// ---------------------------------------------------------------------------

func TestAppService_SetPhoneStatusFunc(t *testing.T) {
	svc := NewAppService(nil)
	assert.Nil(t, svc.phoneStatusFn)

	svc.SetPhoneStatusFunc(func() (bool, string) {
		return false, ""
	})
	assert.NotNil(t, svc.phoneStatusFn)
}

func TestAppService_GetStatus_PhoneConnected(t *testing.T) {
	svc := NewAppService(nil)
	svc.SetPhoneStatusFunc(func() (bool, string) {
		return true, "Pixel 8 Pro"
	})

	status := svc.GetStatus()
	assert.True(t, status.PhoneConnected)
	assert.Equal(t, "Pixel 8 Pro", status.PhoneDeviceName)
}

func TestAppService_GetStatus_PhoneDisconnected(t *testing.T) {
	svc := NewAppService(nil)
	svc.SetPhoneStatusFunc(func() (bool, string) {
		return false, ""
	})

	status := svc.GetStatus()
	assert.False(t, status.PhoneConnected)
	assert.Empty(t, status.PhoneDeviceName)
}

func TestAppService_GetStatus_PhoneDefaultNoCallback(t *testing.T) {
	svc := NewAppService(nil)
	// No phone status callback set.
	status := svc.GetStatus()
	assert.False(t, status.PhoneConnected)
	assert.Empty(t, status.PhoneDeviceName)
}

// ---------------------------------------------------------------------------
// ToggleFIDO2Authenticator
// ---------------------------------------------------------------------------

func TestAppService_ToggleFIDO2_NilFunc(t *testing.T) {
	svc := NewAppService(nil)
	err := svc.ToggleFIDO2Authenticator(true)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAppFIDO2ToggleUnavailable))
}

func TestAppService_ToggleFIDO2_WithFunc(t *testing.T) {
	svc := NewAppService(nil)
	var toggledTo bool
	svc.SetFIDO2ToggleFunc(func(enabled bool) error {
		toggledTo = enabled
		return nil
	})

	err := svc.ToggleFIDO2Authenticator(true)
	assert.NoError(t, err)
	assert.True(t, toggledTo)

	err = svc.ToggleFIDO2Authenticator(false)
	assert.NoError(t, err)
	assert.False(t, toggledTo)
}

// ---------------------------------------------------------------------------
// Identity configuration
// ---------------------------------------------------------------------------

func TestAppService_GetIdentity_Default(t *testing.T) {
	svc := NewAppService(defaultTestConfig())
	identity := svc.GetIdentity()
	assert.Equal(t, IdentityConfig{}, identity)
}

func TestAppService_UpdateIdentity(t *testing.T) {
	svc := NewAppService(defaultTestConfig())

	identity := IdentityConfig{
		CommonName:         "Alice Smith",
		Organization:       "Acme Corp",
		OrganizationalUnit: "Engineering",
		Country:            "US",
		Province:           "California",
		Locality:           "San Francisco",
	}

	err := svc.UpdateIdentity(identity)
	require.NoError(t, err)

	got := svc.GetIdentity()
	assert.Equal(t, identity, got)
}

func TestAppService_UpdateIdentity_PersistsViaConfig(t *testing.T) {
	svc := NewAppService(defaultTestConfig())

	identity := IdentityConfig{
		CommonName:   "Bob Jones",
		Organization: "WidgetCo",
		Country:      "GB",
	}

	err := svc.UpdateIdentity(identity)
	require.NoError(t, err)

	cfg := svc.GetConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, identity, cfg.Identity)
}

func TestAppService_ConfigChangedFields_Identity(t *testing.T) {
	base := defaultTestConfig()
	updated := defaultTestConfig()
	updated.Identity = IdentityConfig{
		CommonName:   "Changed",
		Organization: "NewOrg",
	}

	fields := configChangedFields(base, updated)
	assert.Contains(t, fields, "identity")

	// No change should not include identity.
	fields = configChangedFields(base, defaultTestConfig())
	assert.NotContains(t, fields, "identity")
}

// ---------------------------------------------------------------------------
// PolicySection capability-flag gating (#668).
// ---------------------------------------------------------------------------

func TestAppService_SetTheme_PolicyGate(t *testing.T) {
	tests := []struct {
		name    string
		policy  *config.PolicySection
		wantErr bool
	}{
		{"no policy (personal mode) allows", nil, false},
		{"UserCanConfigureTheme false denies", &config.PolicySection{UserCanConfigureTheme: false}, true},
		{"UserCanConfigureTheme true allows", &config.PolicySection{UserCanConfigureTheme: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewAppService(defaultTestConfig())
			logger := &recordingAuditLogger{}
			svc.SetAuditLogger(logger)
			svc.SetPolicy(tt.policy)

			err := svc.SetTheme("dark")

			if tt.wantErr {
				require.Error(t, err)
				var denied *PolicyDeniedError
				require.ErrorAs(t, err, &denied)
				assert.Equal(t, "user_can_configure_theme", denied.Field)
				assert.True(t, logger.hasPolicyDenial(), "denial must be audited")
				assert.Equal(t, "system", svc.GetTheme(), "the theme must not change when denied")
			} else {
				require.NoError(t, err)
				assert.Equal(t, "dark", svc.GetTheme())
				assert.False(t, logger.hasPolicyDenial())
			}
		})
	}
}

func TestAppService_SetDeveloperTools_PolicyGate(t *testing.T) {
	tests := []struct {
		name    string
		policy  *config.PolicySection
		enable  bool
		wantErr bool
		field   string
	}{
		{"no policy allows enabling", nil, true, false, ""},
		{"UserCanToggleDevTools false denies", &config.PolicySection{UserCanToggleDevTools: false, DeveloperToolsEnabled: true}, true, true, "user_can_toggle_dev_tools"},
		{"DeveloperToolsEnabled false denies enabling", &config.PolicySection{UserCanToggleDevTools: true, DeveloperToolsEnabled: false}, true, true, "developer_tools_enabled"},
		{"DeveloperToolsEnabled false allows disabling", &config.PolicySection{UserCanToggleDevTools: true, DeveloperToolsEnabled: false}, false, false, ""},
		{"both true allows enabling", &config.PolicySection{UserCanToggleDevTools: true, DeveloperToolsEnabled: true}, true, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewAppService(defaultTestConfig())
			logger := &recordingAuditLogger{}
			svc.SetAuditLogger(logger)
			svc.SetPolicy(tt.policy)

			err := svc.SetDeveloperTools(tt.enable)

			if tt.wantErr {
				require.Error(t, err)
				var denied *PolicyDeniedError
				require.ErrorAs(t, err, &denied)
				assert.Equal(t, tt.field, denied.Field)
				assert.True(t, logger.hasPolicyDenial())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.enable, svc.GetDeveloperTools())
				assert.False(t, logger.hasPolicyDenial())
			}
		})
	}
}

func TestAppService_ToggleBarrierAutoUnseal_PolicyGate(t *testing.T) {
	tests := []struct {
		name    string
		policy  *config.PolicySection
		enable  bool
		wantErr bool
		field   string
	}{
		{"no policy allows enabling", nil, true, false, ""},
		{"UserCanConfigureAutoUnseal false denies", &config.PolicySection{UserCanConfigureAutoUnseal: false, AllowAutoUnseal: true}, true, true, "user_can_configure_auto_unseal"},
		{"AllowAutoUnseal false denies enabling", &config.PolicySection{UserCanConfigureAutoUnseal: true, AllowAutoUnseal: false}, true, true, "allow_auto_unseal"},
		{"AllowAutoUnseal false allows disabling", &config.PolicySection{UserCanConfigureAutoUnseal: true, AllowAutoUnseal: false}, false, false, ""},
		{"both true allows enabling", &config.PolicySection{UserCanConfigureAutoUnseal: true, AllowAutoUnseal: true}, true, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewAppService(defaultTestConfig())
			logger := &recordingAuditLogger{}
			svc.SetAuditLogger(logger)
			svc.SetPolicy(tt.policy)

			err := svc.ToggleBarrierAutoUnseal(tt.enable)

			if tt.wantErr {
				require.Error(t, err)
				var denied *PolicyDeniedError
				require.ErrorAs(t, err, &denied)
				assert.Equal(t, tt.field, denied.Field)
				assert.True(t, logger.hasPolicyDenial())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.enable, svc.GetConfig().BarrierAutoUnsealEnabled)
				assert.False(t, logger.hasPolicyDenial())
			}
		})
	}
}
