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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock types for admin coverage tests
// ---------------------------------------------------------------------------

// mockPhoneProvider implements PhoneStatusProvider for testing.
type mockPhoneProvider struct {
	connected  bool
	deviceName string
	devices    []PairedDevice
	devicesErr error
}

func (m *mockPhoneProvider) IsConnected() bool           { return m.connected }
func (m *mockPhoneProvider) ConnectedDeviceName() string { return m.deviceName }
func (m *mockPhoneProvider) GetBackendDevices() ([]PairedDevice, error) {
	return m.devices, m.devicesErr
}

// mockPKCS11Tester implements PKCS11ConnectionTester for testing.
type mockPKCS11Tester struct {
	available   bool
	modules     []PKCS11ModuleInfo
	connections []PKCS11ConnectionInfo
	testErr     error
}

func (m *mockPKCS11Tester) TestConnection(_ string, _ uint, _ string) error {
	return m.testErr
}

func (m *mockPKCS11Tester) IsAvailable() bool                       { return m.available }
func (m *mockPKCS11Tester) ListModules() []PKCS11ModuleInfo         { return m.modules }
func (m *mockPKCS11Tester) ListConnections() []PKCS11ConnectionInfo { return m.connections }

// mockBackendRegistryWithPhone is a registry that returns a single phone
// registered backend from List(), enabling tests that exercise the
// enhancePhoneBackend path through dynamicBackends.
type mockBackendRegistryWithPhone struct {
	phoneBackend *backendregistry.RegisteredBackend
}

func newMockBackendRegistryWithPhone() *mockBackendRegistryWithPhone {
	backend := &backendregistry.RegisteredBackend{
		ID:          "phone-test",
		Category:    backendregistry.CategoryPhone,
		Location:    backendregistry.LocationLocal,
		DisplayName: "Test Phone",
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapSigning: true,
		},
		Metadata: map[string]string{},
	}
	backend.SetState(backendregistry.StateReady)
	return &mockBackendRegistryWithPhone{phoneBackend: backend}
}

func (m *mockBackendRegistryWithPhone) Register(_ *backendregistry.RegisteredBackend) error {
	return nil
}
func (m *mockBackendRegistryWithPhone) Unregister(_ string) error { return nil }

func (m *mockBackendRegistryWithPhone) Get(id string) (*backendregistry.RegisteredBackend, error) {
	if id == m.phoneBackend.ID {
		return m.phoneBackend, nil
	}
	return nil, errors.New("not found")
}

func (m *mockBackendRegistryWithPhone) List() []*backendregistry.RegisteredBackend {
	return []*backendregistry.RegisteredBackend{m.phoneBackend}
}

func (m *mockBackendRegistryWithPhone) ListByCapability(_ backendregistry.Capability) []*backendregistry.RegisteredBackend {
	return nil
}

func (m *mockBackendRegistryWithPhone) ListByCategory(cat backendregistry.BackendCategory) []*backendregistry.RegisteredBackend {
	if cat == backendregistry.CategoryPhone {
		return []*backendregistry.RegisteredBackend{m.phoneBackend}
	}
	return nil
}

func (m *mockBackendRegistryWithPhone) ListByLocation(_ backendregistry.BackendLocation) []*backendregistry.RegisteredBackend {
	return nil
}

func (m *mockBackendRegistryWithPhone) GetDefault(_ backendregistry.Capability) (*backendregistry.RegisteredBackend, error) {
	return nil, errors.New("no default")
}

func (m *mockBackendRegistryWithPhone) SetDefault(_ backendregistry.Capability, _ string) error {
	return nil
}

func (m *mockBackendRegistryWithPhone) Subscribe(_ backendregistry.EventHandler) int { return 0 }
func (m *mockBackendRegistryWithPhone) Unsubscribe(_ int)                            {}
func (m *mockBackendRegistryWithPhone) UpdateDisplayName(_ string, _ string) error   { return nil }
func (m *mockBackendRegistryWithPhone) Close() error                                 { return nil }

// ---------------------------------------------------------------------------
// TestBackendConnection tests
// ---------------------------------------------------------------------------

func TestAdminService_Coverage_TestBackendConnection(t *testing.T) {
	svc := NewAdminService()

	t.Run("unsupported backend type", func(t *testing.T) {
		result := svc.TestBackendConnection("unknown", nil)
		assert.False(t, result.Success)
		assert.Contains(t, result.Message, "not supported")
	})

	t.Run("pkcs11 missing library path", func(t *testing.T) {
		result := svc.TestBackendConnection("pkcs11", map[string]string{})
		assert.False(t, result.Success)
		assert.Contains(t, result.Message, "Library path")
	})

	t.Run("pkcs11 missing user pin", func(t *testing.T) {
		result := svc.TestBackendConnection("pkcs11", map[string]string{
			"library_path": "/usr/lib/libpkcs11.so",
		})
		assert.False(t, result.Success)
		assert.Contains(t, result.Message, "User PIN")
	})

	t.Run("pkcs11 no tester fallback", func(t *testing.T) {
		result := svc.TestBackendConnection("pkcs11", map[string]string{
			"library_path": "/usr/lib/libpkcs11.so",
			"user_pin":     "1234",
		})
		assert.True(t, result.Success)
		assert.Contains(t, result.Message, "configuration valid")
	})

	t.Run("pkcs11 with slot_id", func(t *testing.T) {
		result := svc.TestBackendConnection("pkcs11", map[string]string{
			"library_path": "/usr/lib/libpkcs11.so",
			"user_pin":     "1234",
			"slot_id":      "3",
		})
		assert.True(t, result.Success)
	})

	t.Run("pkcs11 tester success", func(t *testing.T) {
		svc.SetPKCS11Tester(&mockPKCS11Tester{available: true})
		result := svc.TestBackendConnection("pkcs11", map[string]string{
			"library_path": "/usr/lib/libpkcs11.so",
			"user_pin":     "1234",
			"slot_id":      "0",
		})
		assert.True(t, result.Success)
		assert.Contains(t, result.Message, "Successfully connected")
	})

	t.Run("pkcs11 tester failure", func(t *testing.T) {
		svc.SetPKCS11Tester(&mockPKCS11Tester{
			available: true,
			testErr:   errors.New("token not present"),
		})
		result := svc.TestBackendConnection("pkcs11", map[string]string{
			"library_path": "/usr/lib/libpkcs11.so",
			"user_pin":     "1234",
		})
		assert.False(t, result.Success)
		assert.Contains(t, result.Message, "token not present")
	})

	t.Run("awskms missing region", func(t *testing.T) {
		result := svc.TestBackendConnection("awskms", map[string]string{})
		assert.False(t, result.Success)
		assert.Contains(t, result.Message, "Region")
	})

	t.Run("awskms valid config", func(t *testing.T) {
		result := svc.TestBackendConnection("awskms", map[string]string{
			"region": "us-east-1",
		})
		assert.True(t, result.Success)
	})

	t.Run("gcpkms missing project", func(t *testing.T) {
		result := svc.TestBackendConnection("gcpkms", map[string]string{})
		assert.False(t, result.Success)
		assert.Contains(t, result.Message, "Project ID")
	})

	t.Run("gcpkms missing location", func(t *testing.T) {
		result := svc.TestBackendConnection("gcpkms", map[string]string{
			"project": "my-project",
		})
		assert.False(t, result.Success)
		assert.Contains(t, result.Message, "Location")
	})

	t.Run("gcpkms missing keyring", func(t *testing.T) {
		result := svc.TestBackendConnection("gcpkms", map[string]string{
			"project":  "my-project",
			"location": "us-central1",
		})
		assert.False(t, result.Success)
		assert.Contains(t, result.Message, "Key Ring")
	})

	t.Run("gcpkms valid config", func(t *testing.T) {
		result := svc.TestBackendConnection("gcpkms", map[string]string{
			"project":  "my-project",
			"location": "us-central1",
			"keyring":  "my-keyring",
		})
		assert.True(t, result.Success)
	})

	t.Run("azurekv missing vault_url", func(t *testing.T) {
		result := svc.TestBackendConnection("azurekv", map[string]string{})
		assert.False(t, result.Success)
		assert.Contains(t, result.Message, "Vault URL")
	})

	t.Run("azurekv valid config", func(t *testing.T) {
		result := svc.TestBackendConnection("azurekv", map[string]string{
			"vault_url": "https://myvault.vault.azure.net",
		})
		assert.True(t, result.Success)
	})

	t.Run("vault missing address", func(t *testing.T) {
		result := svc.TestBackendConnection("vault", map[string]string{})
		assert.False(t, result.Success)
		assert.Contains(t, result.Message, "Vault address")
	})

	t.Run("vault valid config", func(t *testing.T) {
		result := svc.TestBackendConnection("vault", map[string]string{
			"address": "https://vault.example.com:8200",
		})
		assert.True(t, result.Success)
	})
}

// ---------------------------------------------------------------------------
// isPKCS11Available / isXxxAvailable tests
// ---------------------------------------------------------------------------

func TestAdminService_Coverage_IsPKCS11Available(t *testing.T) {
	svc := NewAdminService()

	t.Run("nil tester returns false", func(t *testing.T) {
		assert.False(t, svc.isPKCS11Available())
	})

	t.Run("tester not available returns false", func(t *testing.T) {
		svc.SetPKCS11Tester(&mockPKCS11Tester{available: false})
		assert.False(t, svc.isPKCS11Available())
	})

	t.Run("tester available returns true", func(t *testing.T) {
		svc.SetPKCS11Tester(&mockPKCS11Tester{available: true})
		assert.True(t, svc.isPKCS11Available())
	})
}

func TestAdminService_Coverage_CloudAvailability(t *testing.T) {
	svc := NewAdminService()

	// These currently return true as placeholders.
	assert.True(t, svc.isAWSKMSAvailable())
	assert.True(t, svc.isGCPKMSAvailable())
	assert.True(t, svc.isAzureKVAvailable())
	assert.True(t, svc.isVaultAvailable())
}

// ---------------------------------------------------------------------------
// GetAvailableBackendTypes tests
// ---------------------------------------------------------------------------

func TestAdminService_Coverage_GetAvailableBackendTypes(t *testing.T) {
	t.Run("no registry no tester", func(t *testing.T) {
		svc := NewAdminService()
		types := svc.GetAvailableBackendTypes()
		require.NotEmpty(t, types)

		typeMap := make(map[string]AvailableBackendType)
		for _, bt := range types {
			typeMap[bt.Type] = bt
		}

		// PKCS#11 should be unavailable without tester.
		assert.False(t, typeMap["pkcs11"].Available)
		// Cloud backends are currently always available.
		assert.True(t, typeMap["awskms"].Available)
		assert.True(t, typeMap["gcpkms"].Available)
		assert.True(t, typeMap["azurekv"].Available)
		assert.True(t, typeMap["vault"].Available)
	})

	t.Run("with pkcs11 tester available", func(t *testing.T) {
		svc := NewAdminService()
		svc.SetPKCS11Tester(&mockPKCS11Tester{available: true})

		types := svc.GetAvailableBackendTypes()
		typeMap := make(map[string]AvailableBackendType)
		for _, bt := range types {
			typeMap[bt.Type] = bt
		}
		assert.True(t, typeMap["pkcs11"].Available)
	})

	t.Run("with registry populated", func(t *testing.T) {
		svc := NewAdminService()
		registry := newMockFullRegistry()
		registry.addBackend(newReadyBackend("software", backendregistry.CapSigning))
		svc.SetBackendRegistry(registry)

		types := svc.GetAvailableBackendTypes()
		require.NotEmpty(t, types)
		// Verify types have proper names and descriptions.
		for _, bt := range types {
			assert.NotEmpty(t, bt.Name)
			assert.NotEmpty(t, bt.Description)
		}
	})
}

// ---------------------------------------------------------------------------
// SetTPMStatusProvider / SetPhoneStatusProvider tests
// ---------------------------------------------------------------------------

func TestAdminService_Coverage_SetTPMStatusProvider(t *testing.T) {
	svc := NewAdminService()
	assert.Nil(t, svc.tpmProvider)

	provider := &mockTPMProvider{status: &TPMStatus{Available: true}}
	svc.SetTPMStatusProvider(provider)
	assert.NotNil(t, svc.tpmProvider)
}

func TestAdminService_Coverage_SetTPMStatusProvider_Nil(t *testing.T) {
	svc := NewAdminService()
	svc.SetTPMStatusProvider(nil)
	assert.Nil(t, svc.tpmProvider)
}

func TestAdminService_Coverage_SetPhoneStatusProvider(t *testing.T) {
	svc := NewAdminService()
	assert.Nil(t, svc.phoneProvider)

	provider := &mockPhoneProvider{connected: true, deviceName: "Pixel 8"}
	svc.SetPhoneStatusProvider(provider)
	assert.NotNil(t, svc.phoneProvider)
}

func TestAdminService_Coverage_SetPhoneStatusProvider_Nil(t *testing.T) {
	svc := NewAdminService()
	svc.SetPhoneStatusProvider(nil)
	assert.Nil(t, svc.phoneProvider)
}

// ---------------------------------------------------------------------------
// enhancePhoneBackend tests
// ---------------------------------------------------------------------------

func TestAdminService_Coverage_EnhancePhoneBackend(t *testing.T) {
	rb := &backendregistry.RegisteredBackend{
		ID:          "phone-test",
		Category:    backendregistry.CategoryPhone,
		DisplayName: "Phone Backend",
		Metadata:    map[string]string{},
	}

	t.Run("nil provider disables backend", func(t *testing.T) {
		svc := NewAdminService()
		backend := BackendInfo{ID: "phone-test", Type: "phone", Enabled: true, Connected: true}
		svc.enhancePhoneBackend(&backend, rb)
		assert.False(t, backend.Enabled)
		assert.False(t, backend.Connected)
	})

	t.Run("connected with device name", func(t *testing.T) {
		svc := NewAdminService()
		svc.SetPhoneStatusProvider(&mockPhoneProvider{
			connected:  true,
			deviceName: "Pixel 8",
			devices:    []PairedDevice{{Name: "Pixel 8", Address: "AA:BB:CC"}},
		})
		backend := BackendInfo{ID: "phone-test", Type: "phone"}
		svc.enhancePhoneBackend(&backend, rb)
		assert.True(t, backend.Connected)
		assert.True(t, backend.Enabled)
		assert.Equal(t, "Pixel 8", backend.DeviceName)
		assert.Equal(t, "Pixel 8", backend.DisplayName)
	})

	t.Run("connected with empty device name", func(t *testing.T) {
		svc := NewAdminService()
		svc.SetPhoneStatusProvider(&mockPhoneProvider{
			connected:  true,
			deviceName: "",
			devices:    []PairedDevice{{Name: "Phone", Address: "11:22:33"}},
		})
		backend := BackendInfo{ID: "phone-test", Type: "phone", DisplayName: "Original"}
		svc.enhancePhoneBackend(&backend, rb)
		assert.True(t, backend.Connected)
		// Empty device name should not override display name.
		assert.Equal(t, "Original", backend.DisplayName)
	})

	t.Run("not connected", func(t *testing.T) {
		svc := NewAdminService()
		svc.SetPhoneStatusProvider(&mockPhoneProvider{
			connected: false,
			devices:   []PairedDevice{{Name: "Phone", Address: "11:22:33"}},
		})
		backend := BackendInfo{ID: "phone-test", Type: "phone"}
		svc.enhancePhoneBackend(&backend, rb)
		assert.False(t, backend.Connected)
		assert.True(t, backend.Enabled)
	})

	t.Run("no devices disables backend", func(t *testing.T) {
		svc := NewAdminService()
		svc.SetPhoneStatusProvider(&mockPhoneProvider{
			connected: false,
			devices:   nil,
		})
		backend := BackendInfo{ID: "phone-test", Type: "phone", Enabled: true}
		svc.enhancePhoneBackend(&backend, rb)
		assert.False(t, backend.Enabled)
	})

	t.Run("devices error disables backend", func(t *testing.T) {
		svc := NewAdminService()
		svc.SetPhoneStatusProvider(&mockPhoneProvider{
			connected:  false,
			devicesErr: errors.New("BLE error"),
		})
		backend := BackendInfo{ID: "phone-test", Type: "phone", Enabled: true}
		svc.enhancePhoneBackend(&backend, rb)
		assert.False(t, backend.Enabled)
	})
}

// ---------------------------------------------------------------------------
// SetPKCS11Tester tests
// ---------------------------------------------------------------------------

func TestAdminService_Coverage_SetPKCS11Tester(t *testing.T) {
	svc := NewAdminService()
	assert.Nil(t, svc.pkcs11Tester)

	tester := &mockPKCS11Tester{available: true}
	svc.SetPKCS11Tester(tester)
	assert.NotNil(t, svc.pkcs11Tester)
}

func TestAdminService_Coverage_SetPKCS11Tester_Nil(t *testing.T) {
	svc := NewAdminService()
	svc.SetPKCS11Tester(nil)
	assert.Nil(t, svc.pkcs11Tester)
}

// ---------------------------------------------------------------------------
// algorithmsForCategory / descriptionForCategory tests
// ---------------------------------------------------------------------------

func TestAdminService_Coverage_AlgorithmsForCategory(t *testing.T) {
	svc := NewAdminService()

	t.Run("software", func(t *testing.T) {
		algs := svc.algorithmsForCategory(backendregistry.CategorySoftware)
		assert.Contains(t, algs, "RSA")
		assert.Contains(t, algs, "ECDSA")
		assert.Contains(t, algs, "Ed25519")
		assert.Contains(t, algs, "AES")
		assert.Contains(t, algs, "ML-KEM")
		assert.Contains(t, algs, "ML-DSA")
	})

	t.Run("tpm2", func(t *testing.T) {
		algs := svc.algorithmsForCategory(backendregistry.CategoryTPM2)
		assert.Contains(t, algs, "RSA")
		assert.Contains(t, algs, "ECDSA")
		assert.Contains(t, algs, "AES")
	})

	t.Run("pkcs11", func(t *testing.T) {
		algs := svc.algorithmsForCategory(backendregistry.CategoryPKCS11)
		assert.Contains(t, algs, "RSA")
	})

	t.Run("phone", func(t *testing.T) {
		algs := svc.algorithmsForCategory(backendregistry.CategoryPhone)
		assert.Equal(t, []string{"ECDSA"}, algs)
	})

	t.Run("xkms", func(t *testing.T) {
		algs := svc.algorithmsForCategory(backendregistry.CategoryXKMS)
		assert.Contains(t, algs, "RSA")
		assert.Contains(t, algs, "Ed25519")
	})

	t.Run("unknown falls back to default", func(t *testing.T) {
		algs := svc.algorithmsForCategory(backendregistry.BackendCategory("unknown"))
		assert.Equal(t, []string{"RSA", "ECDSA"}, algs)
	})
}

func TestAdminService_Coverage_DescriptionForCategory(t *testing.T) {
	svc := NewAdminService()

	t.Run("software", func(t *testing.T) {
		desc := svc.descriptionForCategory(backendregistry.CategorySoftware)
		assert.Contains(t, desc, "software")
	})

	t.Run("tpm2", func(t *testing.T) {
		desc := svc.descriptionForCategory(backendregistry.CategoryTPM2)
		assert.Contains(t, desc, "TPM")
	})

	t.Run("pkcs11", func(t *testing.T) {
		desc := svc.descriptionForCategory(backendregistry.CategoryPKCS11)
		assert.Contains(t, desc, "PKCS#11")
	})

	t.Run("phone", func(t *testing.T) {
		desc := svc.descriptionForCategory(backendregistry.CategoryPhone)
		assert.Contains(t, desc, "phone")
	})

	t.Run("xkms", func(t *testing.T) {
		desc := svc.descriptionForCategory(backendregistry.CategoryXKMS)
		assert.Contains(t, desc, "xkmsd")
	})

	t.Run("unknown falls back to default", func(t *testing.T) {
		desc := svc.descriptionForCategory(backendregistry.BackendCategory("unknown"))
		assert.Equal(t, "Key backend", desc)
	})
}

// ---------------------------------------------------------------------------
// convertRegisteredBackend additional coverage
// ---------------------------------------------------------------------------

func TestAdminService_Coverage_ConvertRegisteredBackend_ErrorState(t *testing.T) {
	svc := NewAdminService()

	rb := &backendregistry.RegisteredBackend{
		ID:           "errored",
		Category:     backendregistry.CategorySoftware,
		Location:     backendregistry.LocationLocal,
		DisplayName:  "Errored Backend",
		Capabilities: map[backendregistry.Capability]bool{},
		Metadata:     map[string]string{},
	}
	rb.SetState(backendregistry.StateError)

	info := svc.convertRegisteredBackend(rb)
	assert.False(t, info.Enabled, "errored backend must be disabled")
	assert.False(t, info.Connected)
}

func TestAdminService_Coverage_ConvertRegisteredBackend_OfflineState(t *testing.T) {
	svc := NewAdminService()

	rb := &backendregistry.RegisteredBackend{
		ID:           "offline",
		Category:     backendregistry.CategorySoftware,
		Location:     backendregistry.LocationLocal,
		DisplayName:  "Offline Backend",
		Capabilities: map[backendregistry.Capability]bool{},
		Metadata:     map[string]string{},
	}
	rb.SetState(backendregistry.StateOffline)

	info := svc.convertRegisteredBackend(rb)
	assert.False(t, info.Enabled, "offline backend must be disabled")
	assert.False(t, info.Connected)
}

func TestAdminService_Coverage_ConvertRegisteredBackend_XKMSCategory(t *testing.T) {
	svc := NewAdminService()

	rb := &backendregistry.RegisteredBackend{
		ID:          "remote-xkms",
		Category:    backendregistry.CategoryXKMS,
		Location:    backendregistry.LocationRemote,
		DisplayName: "Remote XKMS",
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapSigning:    true,
			backendregistry.CapEncryption: true,
		},
		Metadata: map[string]string{"server": "example.com"},
	}
	rb.SetState(backendregistry.StateReady)

	info := svc.convertRegisteredBackend(rb)
	assert.Equal(t, "remote-xkms", info.ID)
	assert.Equal(t, string(backendregistry.CategoryXKMS), info.Type)
	assert.True(t, info.Connected)
	assert.True(t, info.Enabled)
	assert.Contains(t, info.Description, "xkmsd")
	assert.NotEmpty(t, info.Algorithms)
	assert.Equal(t, "example.com", info.Metadata["server"])
}

// ---------------------------------------------------------------------------
// dynamicBackends with phone provider tests
// ---------------------------------------------------------------------------

func TestAdminService_Coverage_DynamicBackends_PhoneAutoDetect(t *testing.T) {
	svc := NewAdminService()
	svc.SetPhoneStatusProvider(&mockPhoneProvider{
		connected:  true,
		deviceName: "Pixel 8",
		devices: []PairedDevice{
			{Name: "Pixel 8", Address: "AA:BB:CC:DD"},
		},
	})

	backends := svc.dynamicBackends()
	var phoneBackend *BackendInfo
	for i := range backends {
		if backends[i].Type == "phone" {
			phoneBackend = &backends[i]
			break
		}
	}
	require.NotNil(t, phoneBackend, "phone backend must be auto-detected")
	assert.True(t, phoneBackend.Connected)
	assert.Equal(t, "Pixel 8", phoneBackend.DisplayName)
	assert.Equal(t, "phone-AA:BB:CC:DD", phoneBackend.ID)
}

func TestAdminService_Coverage_DynamicBackends_PhoneNotConnected(t *testing.T) {
	svc := NewAdminService()
	svc.SetPhoneStatusProvider(&mockPhoneProvider{
		connected:  false,
		deviceName: "",
		devices: []PairedDevice{
			{Name: "Phone A", Address: "11:22:33"},
		},
	})

	backends := svc.dynamicBackends()
	var phoneBackend *BackendInfo
	for i := range backends {
		if backends[i].Type == "phone" {
			phoneBackend = &backends[i]
			break
		}
	}
	require.NotNil(t, phoneBackend)
	assert.False(t, phoneBackend.Connected)
}

func TestAdminService_Coverage_DynamicBackends_PhoneNoDevices(t *testing.T) {
	svc := NewAdminService()
	svc.SetPhoneStatusProvider(&mockPhoneProvider{
		connected: false,
		devices:   nil,
	})

	backends := svc.dynamicBackends()
	for _, b := range backends {
		assert.NotEqual(t, "phone", b.Type, "phone backends should not appear with no devices")
	}
}

func TestAdminService_Coverage_DynamicBackends_PhoneInRegistry(t *testing.T) {
	svc := NewAdminService()
	registry := newMockBackendRegistryWithPhone()
	svc.SetBackendRegistry(registry)
	svc.SetPhoneStatusProvider(&mockPhoneProvider{
		connected:  true,
		deviceName: "Galaxy S24",
		devices:    []PairedDevice{{Name: "Galaxy S24", Address: "AA:BB"}},
	})

	backends := svc.dynamicBackends()
	phoneCount := 0
	for _, b := range backends {
		if b.Type == "phone" || b.ID == "phone-test" {
			phoneCount++
		}
	}
	// Should have exactly one phone entry (from registry), not auto-detected.
	assert.Equal(t, 1, phoneCount, "auto-detect must be skipped when registry has phone")
}

// ---------------------------------------------------------------------------
// dynamicBackends with PKCS#11 tester tests
// ---------------------------------------------------------------------------

func TestAdminService_Coverage_DynamicBackends_PKCS11Modules(t *testing.T) {
	svc := NewAdminService()
	svc.SetPKCS11Tester(&mockPKCS11Tester{
		available: true,
		modules: []PKCS11ModuleInfo{
			{
				ID:          "softhsm",
				DisplayName: "SoftHSM 2",
				LibraryPath: "/usr/lib/softhsm/libsofthsm2.so",
				State:       "loaded",
				Slots: []PKCS11SlotInfo{
					{SlotID: 0, Label: "test-token"},
				},
			},
		},
		connections: []PKCS11ConnectionInfo{
			{ModuleID: "softhsm", SlotID: 0, TokenLabel: "test-token"},
		},
	})

	backends := svc.dynamicBackends()
	var pkcs11Backend *BackendInfo
	for i := range backends {
		if backends[i].ID == "softhsm" {
			pkcs11Backend = &backends[i]
			break
		}
	}
	require.NotNil(t, pkcs11Backend, "PKCS#11 module must appear in backends")
	assert.Equal(t, "pkcs11", pkcs11Backend.Type)
	assert.True(t, pkcs11Backend.Connected)
	assert.True(t, pkcs11Backend.Enabled)
	assert.Contains(t, pkcs11Backend.DisplayName, "test-token")
	assert.Contains(t, pkcs11Backend.Description, "PKCS#11")
}

func TestAdminService_Coverage_DynamicBackends_PKCS11ModuleNotConnected(t *testing.T) {
	svc := NewAdminService()
	svc.SetPKCS11Tester(&mockPKCS11Tester{
		available: true,
		modules: []PKCS11ModuleInfo{
			{
				ID:          "yubihsm",
				DisplayName: "",
				LibraryPath: "/usr/lib/libyubihsm.so",
				State:       "loaded",
				Slots: []PKCS11SlotInfo{
					{SlotID: 0, Label: "yubi-slot"},
				},
			},
		},
		connections: nil, // No active connections.
	})

	backends := svc.dynamicBackends()
	var found *BackendInfo
	for i := range backends {
		if backends[i].ID == "yubihsm" {
			found = &backends[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.False(t, found.Connected)
	// DisplayName falls back to ID when empty.
	assert.Equal(t, "yubihsm", found.DisplayName)
}

func TestAdminService_Coverage_DynamicBackends_PKCS11NotAvailable(t *testing.T) {
	svc := NewAdminService()
	svc.SetPKCS11Tester(&mockPKCS11Tester{available: false})

	backends := svc.dynamicBackends()
	for _, b := range backends {
		assert.NotEqual(t, "pkcs11", b.Type, "PKCS#11 should not appear when not available")
	}
}

// ---------------------------------------------------------------------------
// fallbackBackends with phone provider tests
// ---------------------------------------------------------------------------

func TestAdminService_Coverage_FallbackBackends_WithPhoneDevices(t *testing.T) {
	svc := NewAdminService()
	svc.SetPhoneStatusProvider(&mockPhoneProvider{
		connected:  true,
		deviceName: "OnePlus 12",
		devices: []PairedDevice{
			{Name: "OnePlus 12", Address: "FF:EE:DD"},
			{Name: "Pixel 7", Address: "AA:BB:CC"},
		},
	})

	backends := svc.fallbackBackends()
	phoneCount := 0
	for _, b := range backends {
		if b.Type == "phone" {
			phoneCount++
		}
	}
	assert.Equal(t, 2, phoneCount, "two phone backends expected")

	// The connected phone should have Connected=true.
	found := findBackendByID(backends, "phone-FF:EE:DD")
	require.NotNil(t, found)
	assert.True(t, found.Connected)

	// The other phone should have Connected=false (device name doesn't match).
	other := findBackendByID(backends, "phone-AA:BB:CC")
	require.NotNil(t, other)
	assert.False(t, other.Connected)
}

func TestAdminService_Coverage_FallbackBackends_PhoneDevicesError(t *testing.T) {
	svc := NewAdminService()
	svc.SetPhoneStatusProvider(&mockPhoneProvider{
		connected:  false,
		devicesErr: errors.New("bluetooth off"),
	})

	backends := svc.fallbackBackends()
	for _, b := range backends {
		assert.NotEqual(t, "phone", b.Type, "no phone backends on error")
	}
}

// ---------------------------------------------------------------------------
// buildBackendConfig tests
// ---------------------------------------------------------------------------

func TestAdminService_Coverage_BuildBackendConfig(t *testing.T) {
	svc := NewAdminService()

	t.Run("missing id", func(t *testing.T) {
		_, _, err := svc.buildBackendConfig("pkcs11", map[string]string{})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAdminMissingField)
	})

	t.Run("pkcs11 missing library_path", func(t *testing.T) {
		_, _, err := svc.buildBackendConfig("pkcs11", map[string]string{"id": "test"})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAdminMissingField)
	})

	t.Run("pkcs11 invalid slot_id", func(t *testing.T) {
		_, _, err := svc.buildBackendConfig("pkcs11", map[string]string{
			"id":           "test",
			"library_path": "/usr/lib/test.so",
			"slot_id":      "notanumber",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAdminMissingField)
	})

	t.Run("pkcs11 valid", func(t *testing.T) {
		localCfg, rb, err := svc.buildBackendConfig("pkcs11", map[string]string{
			"id":           "softhsm",
			"name":         "SoftHSM",
			"library_path": "/usr/lib/softhsm2.so",
			"slot_id":      "2",
		})
		require.NoError(t, err)
		assert.Equal(t, "softhsm", localCfg.ID)
		assert.Equal(t, "SoftHSM", localCfg.Name)
		assert.Equal(t, "pkcs11", localCfg.Category)
		require.NotNil(t, localCfg.PKCS11)
		assert.Equal(t, "/usr/lib/softhsm2.so", localCfg.PKCS11.LibraryPath)
		assert.Equal(t, 2, localCfg.PKCS11.SlotID)
		assert.Equal(t, "softhsm", rb.ID)
		assert.Equal(t, backendregistry.CategoryPKCS11, rb.Category)
		assert.True(t, rb.HasCapability(backendregistry.CapSigning))
		assert.True(t, rb.HasCapability(backendregistry.CapEncryption))
	})

	t.Run("pkcs11 name defaults to id", func(t *testing.T) {
		localCfg, _, err := svc.buildBackendConfig("pkcs11", map[string]string{
			"id":           "myhsm",
			"library_path": "/usr/lib/test.so",
		})
		require.NoError(t, err)
		assert.Equal(t, "myhsm", localCfg.Name)
	})

	t.Run("tpm2 valid with defaults", func(t *testing.T) {
		localCfg, rb, err := svc.buildBackendConfig("tpm2", map[string]string{
			"id":   "tpm-test",
			"name": "My TPM",
		})
		require.NoError(t, err)
		assert.Equal(t, "tpm-test", localCfg.ID)
		require.NotNil(t, localCfg.TPM2)
		assert.Equal(t, "/dev/tpmrm0", localCfg.TPM2.Device)
		assert.Equal(t, backendregistry.CategoryTPM2, rb.Category)
		assert.True(t, rb.HasCapability(backendregistry.CapAttestation))
	})

	t.Run("tpm2 custom device", func(t *testing.T) {
		localCfg, _, err := svc.buildBackendConfig("tpm2", map[string]string{
			"id":     "tpm-custom",
			"device": "/dev/tpm1",
		})
		require.NoError(t, err)
		require.NotNil(t, localCfg.TPM2)
		assert.Equal(t, "/dev/tpm1", localCfg.TPM2.Device)
	})

	t.Run("unsupported type", func(t *testing.T) {
		_, _, err := svc.buildBackendConfig("faketype", map[string]string{"id": "x"})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAdminInvalidBackendType)
	})

	t.Run("metadata copies params excluding id and name", func(t *testing.T) {
		_, rb, err := svc.buildBackendConfig("tpm2", map[string]string{
			"id":     "tpm-meta",
			"name":   "TPM Meta",
			"device": "/dev/tpm0",
			"extra":  "value",
		})
		require.NoError(t, err)
		assert.Equal(t, "/dev/tpm0", rb.Metadata["device"])
		assert.Equal(t, "value", rb.Metadata["extra"])
		_, hasID := rb.Metadata["id"]
		assert.False(t, hasID, "id must not be in metadata")
		_, hasName := rb.Metadata["name"]
		assert.False(t, hasName, "name must not be in metadata")
	})
}

// ---------------------------------------------------------------------------
// ConfigureBackend tests (covers early validation paths only)
// ---------------------------------------------------------------------------

func TestAdminService_Coverage_ConfigureBackend_NoRegistry(t *testing.T) {
	svc := NewAdminService()
	err := svc.ConfigureBackend("pkcs11", map[string]string{"id": "test"})
	assert.ErrorIs(t, err, ErrAdminRegistryNotSet)
}

func TestAdminService_Coverage_ConfigureBackend_InvalidParams(t *testing.T) {
	svc := NewAdminService()
	svc.SetBackendRegistry(newMockFullRegistry())

	err := svc.ConfigureBackend("pkcs11", map[string]string{})
	assert.Error(t, err, "missing id should fail")
}

func TestAdminService_Coverage_ConfigureBackend_InvalidBackendType(t *testing.T) {
	svc := NewAdminService()
	svc.SetBackendRegistry(newMockFullRegistry())

	err := svc.ConfigureBackend("invalidtype", map[string]string{"id": "x"})
	assert.ErrorIs(t, err, ErrAdminInvalidBackendType)
}

// ---------------------------------------------------------------------------
// SetDefaultBackend with SetDefault error (warning path)
// ---------------------------------------------------------------------------

func TestAdminService_Coverage_SetDefaultBackend_SetDefaultError(t *testing.T) {
	svc := NewAdminService()
	registry := newMockFullRegistry()
	backend := newReadyBackend("software",
		backendregistry.CapSigning,
		backendregistry.CapEncryption,
	)
	registry.addBackend(backend)
	registry.setDefaultErr = errors.New("registry error")
	svc.SetBackendRegistry(registry)

	// SetDefault errors are logged but do not fail the overall operation.
	err := svc.SetDefaultBackend("software")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Error sentinels coverage for newer errors
// ---------------------------------------------------------------------------

func TestAdminService_Coverage_ErrorSentinels(t *testing.T) {
	sentinels := []struct {
		err     error
		message string
	}{
		{ErrAdminConfigLoadFailed, "admin_service: failed to load config"},
		{ErrAdminConfigSaveFailed, "admin_service: failed to save config"},
		{ErrAdminBackendDuplicate, "admin_service: backend ID already exists"},
		{ErrAdminInvalidBackendType, "admin_service: unsupported backend type"},
		{ErrAdminMissingField, "admin_service: required field missing"},
	}
	for _, s := range sentinels {
		assert.NotNil(t, s.err)
		assert.Equal(t, s.message, s.err.Error())
	}
}

// ---------------------------------------------------------------------------
// SetBackendRegistry coverage
// ---------------------------------------------------------------------------

func TestAdminService_Coverage_SetBackendRegistry(t *testing.T) {
	svc := NewAdminService()
	assert.Nil(t, svc.registry)

	registry := newMockFullRegistry()
	svc.SetBackendRegistry(registry)
	assert.NotNil(t, svc.registry)
}

func TestAdminService_Coverage_SetBackendRegistry_Nil(t *testing.T) {
	svc := NewAdminService()
	svc.SetBackendRegistry(nil)
	assert.Nil(t, svc.registry)
}

// ---------------------------------------------------------------------------
// fallbackBackends with TPM manufacturer info
// ---------------------------------------------------------------------------

func TestAdminService_Coverage_FallbackBackends_TPMWithManufacturer(t *testing.T) {
	svc := NewAdminService()
	svc.SetTPMStatusProvider(&mockTPMProvider{
		status: &TPMStatus{
			Available:    true,
			DeviceExists: true,
			Manufacturer: "Infineon",
			FirmwareVer:  "7.85",
			DevicePath:   "/dev/tpm0",
		},
	})

	backends := svc.fallbackBackends()
	tpm := findBackendByID(backends, "tpm2")
	require.NotNil(t, tpm)
	assert.Contains(t, tpm.Description, "Infineon")
	assert.Equal(t, "Infineon", tpm.Metadata["manufacturer"])
	assert.Equal(t, "7.85", tpm.Metadata["firmware"])
}

func TestAdminService_Coverage_FallbackBackends_TPMNoManufacturer(t *testing.T) {
	svc := NewAdminService()
	svc.SetTPMStatusProvider(&mockTPMProvider{
		status: &TPMStatus{
			Available:    true,
			DeviceExists: true,
			DevicePath:   "/dev/tpm0",
		},
	})

	backends := svc.fallbackBackends()
	tpm := findBackendByID(backends, "tpm2")
	require.NotNil(t, tpm)
	assert.Equal(t, "TPM 2.0 hardware key store", tpm.Description)
}

// ---------------------------------------------------------------------------
// TestPKCS11Connection with TestConnection method signature test
// ---------------------------------------------------------------------------

func TestAdminService_Coverage_TestPKCS11Connection_FullSignature(t *testing.T) {
	// Ensure mockPKCS11Tester.TestConnection receives correct arguments.
	var capturedLib string
	var capturedSlot uint
	var capturedPIN string

	tester := &mockPKCS11Tester{available: true}
	// Override via a custom type to capture args.
	captureTester := &capturingPKCS11Tester{
		capturedLib:  &capturedLib,
		capturedSlot: &capturedSlot,
		capturedPIN:  &capturedPIN,
	}

	svc := NewAdminService()
	svc.SetPKCS11Tester(captureTester)

	result := svc.TestBackendConnection("pkcs11", map[string]string{
		"library_path": "/usr/lib/test.so",
		"user_pin":     "secretpin",
		"slot_id":      "5",
	})
	assert.True(t, result.Success)
	assert.Equal(t, "/usr/lib/test.so", capturedLib)
	assert.Equal(t, uint(5), capturedSlot)
	assert.Equal(t, "secretpin", capturedPIN)

	_ = tester // silence unused
}

// capturingPKCS11Tester captures TestConnection arguments for verification.
type capturingPKCS11Tester struct {
	capturedLib  *string
	capturedSlot *uint
	capturedPIN  *string
}

func (c *capturingPKCS11Tester) TestConnection(lib string, slot uint, pin string) error {
	*c.capturedLib = lib
	*c.capturedSlot = slot
	*c.capturedPIN = pin
	return nil
}

func (c *capturingPKCS11Tester) IsAvailable() bool                       { return true }
func (c *capturingPKCS11Tester) ListModules() []PKCS11ModuleInfo         { return nil }
func (c *capturingPKCS11Tester) ListConnections() []PKCS11ConnectionInfo { return nil }
