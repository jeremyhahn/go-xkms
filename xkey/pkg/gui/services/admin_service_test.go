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
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAdminService(t *testing.T) {
	svc := NewAdminService()
	assert.NotNil(t, svc)
}

func TestAdminService_SetContext(t *testing.T) {
	svc := NewAdminService()
	svc.SetContext(context.Background())
	assert.Equal(t, context.Background(), svc.ctx)
}

func TestAdminService_IsAdmin(t *testing.T) {
	svc := NewAdminService()
	// In test environments we are typically not root.
	// Just verify it returns a bool without panicking.
	_ = svc.IsAdmin()
}

func TestAdminService_SetAuditStore(t *testing.T) {
	svc := NewAdminService()
	assert.Nil(t, svc.auditStore)

	store, storeErr := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, storeErr)
	svc.SetAuditStore(store)
	assert.NotNil(t, svc.auditStore)
}

// mockKeyCounter implements KeyCounter for testing.
type mockKeyCounter struct {
	count int
}

func (m *mockKeyCounter) KeyCount() int { return m.count }

func TestAdminService_SetKeyCounters(t *testing.T) {
	svc := NewAdminService()
	assert.Nil(t, svc.counters)

	c1 := &mockKeyCounter{count: 5}
	c2 := &mockKeyCounter{count: 3}
	svc.SetKeyCounters(c1, c2)
	require.Len(t, svc.counters, 2)
}

func TestAdminService_TotalKeyCount(t *testing.T) {
	svc := NewAdminService()

	t.Run("no counters", func(t *testing.T) {
		assert.Equal(t, 0, svc.totalKeyCount())
	})

	t.Run("with counters", func(t *testing.T) {
		svc.SetKeyCounters(&mockKeyCounter{count: 10}, &mockKeyCounter{count: 7})
		assert.Equal(t, 17, svc.totalKeyCount())
	})
}

func TestAdminService_SetConnectionInfoFunc(t *testing.T) {
	svc := NewAdminService()
	assert.Nil(t, svc.connInfoFn)

	info := &ConnectionInfo{State: "connected", Address: "localhost:9443"}
	svc.SetConnectionInfoFunc(func() *ConnectionInfo { return info })
	assert.NotNil(t, svc.connInfoFn)
	assert.Equal(t, info, svc.connInfoFn())
}

func TestAdminService_SetRemoteBackendsFunc(t *testing.T) {
	svc := NewAdminService()
	assert.Nil(t, svc.remoteBackendsFn)

	backends := []BackendInfo{{ID: "remote1", Type: "tpm2"}}
	svc.SetRemoteBackendsFunc(func() ([]BackendInfo, error) { return backends, nil })
	assert.NotNil(t, svc.remoteBackendsFn)
}

func TestAdminService_GetServerStatus(t *testing.T) {
	t.Run("not connected no callbacks", func(t *testing.T) {
		svc := NewAdminService()
		status, err := svc.GetServerStatus()
		require.NoError(t, err)
		assert.NotNil(t, status)
		assert.False(t, status.Running)
		assert.Equal(t, runtime.GOOS+"/"+runtime.GOARCH, status.Platform)
	})

	t.Run("connected with backend count", func(t *testing.T) {
		svc := NewAdminService()
		svc.SetConnectionInfoFunc(func() *ConnectionInfo {
			return &ConnectionInfo{
				State:   "connected",
				Address: "server:9443",
				Version: "1.0.0",
			}
		})
		svc.SetRemoteBackendsFunc(func() ([]BackendInfo, error) {
			return []BackendInfo{{ID: "sw"}, {ID: "tpm"}}, nil
		})

		status, err := svc.GetServerStatus()
		require.NoError(t, err)
		assert.True(t, status.Running)
		assert.Equal(t, "1.0.0", status.Version)
		assert.Equal(t, "server:9443", status.Address)
		assert.Equal(t, 2, status.BackendCount)
	})

	t.Run("connected without remote backends func", func(t *testing.T) {
		svc := NewAdminService()
		svc.SetConnectionInfoFunc(func() *ConnectionInfo {
			return &ConnectionInfo{State: "connected", Version: "2.0"}
		})

		status, err := svc.GetServerStatus()
		require.NoError(t, err)
		assert.True(t, status.Running)
		assert.Equal(t, 0, status.BackendCount)
	})

	t.Run("connected but remote backends error", func(t *testing.T) {
		svc := NewAdminService()
		svc.SetConnectionInfoFunc(func() *ConnectionInfo {
			return &ConnectionInfo{State: "connected"}
		})
		svc.SetRemoteBackendsFunc(func() ([]BackendInfo, error) {
			return nil, errors.New("unavailable")
		})

		status, err := svc.GetServerStatus()
		require.NoError(t, err)
		assert.True(t, status.Running)
		assert.Equal(t, 0, status.BackendCount)
	})

	t.Run("connInfoFn returns nil info", func(t *testing.T) {
		svc := NewAdminService()
		svc.SetConnectionInfoFunc(func() *ConnectionInfo { return nil })

		status, err := svc.GetServerStatus()
		require.NoError(t, err)
		assert.False(t, status.Running)
	})

	t.Run("connInfoFn returns disconnected", func(t *testing.T) {
		svc := NewAdminService()
		svc.SetConnectionInfoFunc(func() *ConnectionInfo {
			return &ConnectionInfo{State: "disconnected"}
		})

		status, err := svc.GetServerStatus()
		require.NoError(t, err)
		assert.False(t, status.Running)
	})
}

func TestAdminService_ListBackends(t *testing.T) {
	t.Run("local fallback when no remote func", func(t *testing.T) {
		svc := NewAdminService()
		backends, err := svc.ListBackends()
		require.NoError(t, err)
		assert.NotEmpty(t, backends)

		ids := make(map[string]bool)
		for _, b := range backends {
			ids[b.ID] = true
		}
		// Software is always present in fallback. Hardware backends (TPM,
		// PKCS#11, phone) only appear when their providers are set and
		// hardware is detected.
		assert.True(t, ids["software"])
	})

	t.Run("remote backends success", func(t *testing.T) {
		svc := NewAdminService()
		remoteBackends := []BackendInfo{
			{ID: "remote-sw", Type: "software", Enabled: true},
		}
		svc.SetRemoteBackendsFunc(func() ([]BackendInfo, error) {
			return remoteBackends, nil
		})

		backends, err := svc.ListBackends()
		require.NoError(t, err)
		require.Len(t, backends, 1)
		assert.Equal(t, "remote-sw", backends[0].ID)
	})

	t.Run("remote backends error falls back to local", func(t *testing.T) {
		svc := NewAdminService()
		svc.SetRemoteBackendsFunc(func() ([]BackendInfo, error) {
			return nil, errors.New("network error")
		})

		backends, err := svc.ListBackends()
		require.NoError(t, err)
		assert.NotEmpty(t, backends)
		assert.Equal(t, "software", backends[0].ID)
	})
}

// TestAdminService_ListBackends_RegistryPIVCapability verifies that when a
// software backend is registered in the backend registry with PIV capability,
// the ListBackends method returns it with PIV=true in its capabilities.
func TestAdminService_ListBackends_RegistryPIVCapability(t *testing.T) {
	svc := NewAdminService()
	registry := newMockBackendRegistryWithSoftware()
	svc.SetBackendRegistry(registry)

	backends, err := svc.ListBackends()
	require.NoError(t, err)
	require.NotEmpty(t, backends)

	sw := findBackendByID(backends, "software")
	require.NotNil(t, sw, "software backend must be present")

	assert.True(t, sw.Capabilities.PIV, "PIV capability must be true")
	assert.True(t, sw.Capabilities.Signing, "Signing capability must be true")
	assert.True(t, sw.Capabilities.Encryption, "Encryption capability must be true")
	assert.True(t, sw.Capabilities.FIDO2, "FIDO2 capability must be true")
	assert.True(t, sw.Capabilities.OATH, "OATH capability must be true")
	assert.True(t, sw.Capabilities.Passwords, "Passwords capability must be true")
	assert.True(t, sw.Capabilities.Sealing, "Sealing capability must be true")
	assert.False(t, sw.Capabilities.HardwareBacked, "software backend must not be hardware backed")
	assert.Equal(t, "software", sw.Type)
	assert.True(t, sw.Connected, "backend in StateReady must be connected")
	assert.True(t, sw.Enabled)
}

// TestAdminService_FallbackBackends_PIVCapability verifies that the fallback
// path (no registry, no providers) returns a software backend with PIV=true.
func TestAdminService_FallbackBackends_PIVCapability(t *testing.T) {
	svc := NewAdminService()

	// No registry and no providers set, so dynamicBackends falls back to
	// fallbackBackends which always includes a software backend.
	backends := svc.fallbackBackends()
	require.NotEmpty(t, backends)

	sw := findBackendByID(backends, "software")
	require.NotNil(t, sw, "fallback software backend must be present")

	assert.True(t, sw.Capabilities.PIV, "PIV capability must be true in fallback")
	assert.True(t, sw.Capabilities.Signing, "Signing capability must be true in fallback")
	assert.True(t, sw.Capabilities.Encryption, "Encryption capability must be true in fallback")
	assert.True(t, sw.Capabilities.Decryption, "Decryption capability must be true in fallback")
	assert.True(t, sw.Capabilities.KeyEncapsulation, "KeyEncapsulation capability must be true in fallback")
	assert.True(t, sw.Capabilities.FIDO2, "FIDO2 capability must be true in fallback")
	assert.True(t, sw.Capabilities.OATH, "OATH capability must be true in fallback")
	assert.True(t, sw.Capabilities.Passwords, "Passwords capability must be true in fallback")
	assert.True(t, sw.Capabilities.Sealing, "Sealing capability must be true in fallback")
	assert.False(t, sw.Capabilities.HardwareBacked, "software backend must not be hardware backed")
	assert.True(t, sw.Connected)
	assert.True(t, sw.Enabled)
}

func TestAdminService_GetBackendInfo_Valid(t *testing.T) {
	svc := NewAdminService()
	info, err := svc.GetBackendInfo("software")
	require.NoError(t, err)
	assert.Equal(t, "software", info.ID)
	assert.True(t, info.Enabled)
}

func TestAdminService_GetBackendInfo_NotFound(t *testing.T) {
	svc := NewAdminService()
	_, err := svc.GetBackendInfo("nonexistent")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAdminBackendNotFound))
}

func TestAdminService_GetBackendInfo_EmptyID(t *testing.T) {
	svc := NewAdminService()
	_, err := svc.GetBackendInfo("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrAdminBackendNotFound))
}

func TestAdminService_GetAuditLogs(t *testing.T) {
	t.Run("non admin returns error", func(t *testing.T) {
		svc := NewAdminService()
		svc.SetContext(context.Background())
		// We are typically not root in tests, so IsAdmin() returns false.
		if svc.IsAdmin() {
			t.Skip("test requires non-root user")
		}
		_, err := svc.GetAuditLogs(nil)
		assert.True(t, errors.Is(err, ErrAdminNotAuthorized))
	})
}

func TestAdminService_ExportAuditLogs_InvalidFormat(t *testing.T) {
	svc := NewAdminService()
	_, err := svc.ExportAuditLogs("yaml")
	// Non-admin gets ErrAdminNotAuthorized, admin gets ErrAdminInvalidFormat.
	assert.Error(t, err)
}

func TestAdminService_ExportAuditLogs_NotAuthorized(t *testing.T) {
	svc := NewAdminService()
	if svc.IsAdmin() {
		t.Skip("test requires non-root user")
	}
	_, err := svc.ExportAuditLogs("json")
	assert.True(t, errors.Is(err, ErrAdminNotAuthorized))
}

func TestAdminService_ExportAuditLogs_CSV_NotAuthorized(t *testing.T) {
	svc := NewAdminService()
	if svc.IsAdmin() {
		t.Skip("test requires non-root user")
	}
	_, err := svc.ExportAuditLogs("csv")
	assert.True(t, errors.Is(err, ErrAdminNotAuthorized))
}

func TestAdminService_ExportAuditLogs_WithStore(t *testing.T) {
	// This test exercises ExportAuditLogs logic beyond auth check.
	// Since we can't easily be admin in tests, we test the underlying
	// AuditService.ExportEntries which ExportAuditLogs delegates to.
	store, storeErr := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, storeErr)
	store.LogKeyOperation(audit.OpKeyCreated, "software", "test-key", true, nil, 42)

	auditSvc := NewAuditService(store)
	auditSvc.SetContext(context.Background())

	t.Run("json export", func(t *testing.T) {
		data, err := auditSvc.ExportEntries("json", nil)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		var entries []AuditEntry
		require.NoError(t, json.Unmarshal(data, &entries))
		require.Len(t, entries, 1)
		assert.Equal(t, "key_created", entries[0].Operation)
	})

	t.Run("csv export", func(t *testing.T) {
		data, err := auditSvc.ExportEntries("csv", nil)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		csvStr := string(data)
		assert.True(t, strings.HasPrefix(csvStr, "timestamp,"))
		assert.Contains(t, csvStr, "key_created")
		assert.Contains(t, csvStr, "test-key")
	})
}

func TestAdminService_ErrorSentinels(t *testing.T) {
	sentinels := []error{
		ErrAdminNotAuthorized,
		ErrAdminBackendNotFound,
		ErrAdminInvalidFormat,
	}
	for _, err := range sentinels {
		assert.NotNil(t, err)
		assert.NotEmpty(t, err.Error())
	}
}

func TestAdminService_GetDefaultBackend_NoRegistry(t *testing.T) {
	svc := NewAdminService()
	// Without a registry, it should return "software" as fallback.
	result := svc.GetDefaultBackend()
	assert.Equal(t, "software", result)
}

func TestAdminService_GetDefaultBackend_WithRegistry(t *testing.T) {
	svc := NewAdminService()

	// Create and populate a test registry.
	registry := newMockBackendRegistry()
	svc.SetBackendRegistry(registry)

	t.Run("no default set returns software", func(t *testing.T) {
		result := svc.GetDefaultBackend()
		assert.Equal(t, "software", result)
	})

	t.Run("with default set returns default", func(t *testing.T) {
		registry.setDefault("tpm2")
		result := svc.GetDefaultBackend()
		assert.Equal(t, "tpm2", result)
	})
}

// mockBackendRegistry is a minimal mock for testing GetDefaultBackend.
type mockBackendRegistry struct {
	defaultBackendID string
}

func newMockBackendRegistry() *mockBackendRegistry {
	return &mockBackendRegistry{}
}

func (m *mockBackendRegistry) setDefault(id string) {
	m.defaultBackendID = id
}

func (m *mockBackendRegistry) Register(backend *backendregistry.RegisteredBackend) error {
	return nil
}

func (m *mockBackendRegistry) Unregister(id string) error {
	return nil
}

func (m *mockBackendRegistry) Get(id string) (*backendregistry.RegisteredBackend, error) {
	if id == m.defaultBackendID {
		return &backendregistry.RegisteredBackend{ID: id}, nil
	}
	return nil, errors.New("not found")
}

func (m *mockBackendRegistry) List() []*backendregistry.RegisteredBackend {
	return nil
}

func (m *mockBackendRegistry) ListByCapability(cap backendregistry.Capability) []*backendregistry.RegisteredBackend {
	return nil
}

func (m *mockBackendRegistry) ListByCategory(cat backendregistry.BackendCategory) []*backendregistry.RegisteredBackend {
	return nil
}

func (m *mockBackendRegistry) ListByLocation(loc backendregistry.BackendLocation) []*backendregistry.RegisteredBackend {
	return nil
}

func (m *mockBackendRegistry) GetDefault(feature backendregistry.Capability) (*backendregistry.RegisteredBackend, error) {
	if m.defaultBackendID == "" {
		return nil, errors.New("no default set")
	}
	return &backendregistry.RegisteredBackend{ID: m.defaultBackendID}, nil
}

func (m *mockBackendRegistry) SetDefault(feature backendregistry.Capability, id string) error {
	m.defaultBackendID = id
	return nil
}

func (m *mockBackendRegistry) Subscribe(handler backendregistry.EventHandler) int {
	return 0
}

func (m *mockBackendRegistry) Unsubscribe(id int) {}

func (m *mockBackendRegistry) UpdateDisplayName(_ string, _ string) error { return nil }
func (m *mockBackendRegistry) Close() error {
	return nil
}

// ---------------------------------------------------------------------------
// TPM backend visibility regression tests
//
// These tests protect against the bug where a TPM device that exists on the
// filesystem but fails to initialize (transient error) was completely hidden
// from the UI. The fix ensures that:
//   - enhanceTPMBackend keeps Enabled=true when DeviceExists is true
//   - dynamicBackends auto-detect adds TPM when DeviceExists is true
//   - fallbackBackends includes TPM when DeviceExists is true
// ---------------------------------------------------------------------------

// mockTPMProvider implements TPMStatusProvider for testing.
type mockTPMProvider struct {
	status *TPMStatus
	err    error
}

func (m *mockTPMProvider) GetStatus() (*TPMStatus, error) {
	return m.status, m.err
}

// mockBackendRegistryWithTPM is a registry that returns a single TPM2
// registered backend from List(), enabling tests that exercise the
// enhanceTPMBackend path through dynamicBackends.
type mockBackendRegistryWithTPM struct {
	tpmBackend *backendregistry.RegisteredBackend
}

func newMockBackendRegistryWithTPM() *mockBackendRegistryWithTPM {
	backend := &backendregistry.RegisteredBackend{
		ID:          "tpm2",
		Category:    backendregistry.CategoryTPM2,
		Location:    backendregistry.LocationLocal,
		DisplayName: "TPM 2.0",
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapSigning:     true,
			backendregistry.CapEncryption:  true,
			backendregistry.CapSealing:     true,
			backendregistry.CapAttestation: true,
		},
		Metadata: map[string]string{},
	}
	backend.SetState(backendregistry.StateReady)
	return &mockBackendRegistryWithTPM{tpmBackend: backend}
}

func (m *mockBackendRegistryWithTPM) Register(_ *backendregistry.RegisteredBackend) error {
	return nil
}

func (m *mockBackendRegistryWithTPM) Unregister(_ string) error {
	return nil
}

func (m *mockBackendRegistryWithTPM) Get(id string) (*backendregistry.RegisteredBackend, error) {
	if id == m.tpmBackend.ID {
		return m.tpmBackend, nil
	}
	return nil, errors.New("not found")
}

func (m *mockBackendRegistryWithTPM) List() []*backendregistry.RegisteredBackend {
	return []*backendregistry.RegisteredBackend{m.tpmBackend}
}

func (m *mockBackendRegistryWithTPM) ListByCapability(_ backendregistry.Capability) []*backendregistry.RegisteredBackend {
	return nil
}

func (m *mockBackendRegistryWithTPM) ListByCategory(cat backendregistry.BackendCategory) []*backendregistry.RegisteredBackend {
	if cat == backendregistry.CategoryTPM2 {
		return []*backendregistry.RegisteredBackend{m.tpmBackend}
	}
	return nil
}

func (m *mockBackendRegistryWithTPM) ListByLocation(_ backendregistry.BackendLocation) []*backendregistry.RegisteredBackend {
	return nil
}

func (m *mockBackendRegistryWithTPM) GetDefault(_ backendregistry.Capability) (*backendregistry.RegisteredBackend, error) {
	return nil, errors.New("no default")
}

func (m *mockBackendRegistryWithTPM) SetDefault(_ backendregistry.Capability, _ string) error {
	return nil
}

func (m *mockBackendRegistryWithTPM) Subscribe(_ backendregistry.EventHandler) int {
	return 0
}

func (m *mockBackendRegistryWithTPM) Unsubscribe(_ int) {}

func (m *mockBackendRegistryWithTPM) UpdateDisplayName(_ string, _ string) error { return nil }

func (m *mockBackendRegistryWithTPM) Close() error {
	return nil
}

// mockBackendRegistryWithSoftware is a registry that returns a single
// software backend from List(), enabling tests that exercise the
// registry-based convertRegisteredBackend path with PIV capability.
type mockBackendRegistryWithSoftware struct {
	softwareBackend *backendregistry.RegisteredBackend
}

func newMockBackendRegistryWithSoftware() *mockBackendRegistryWithSoftware {
	backend := &backendregistry.RegisteredBackend{
		ID:          "software",
		Category:    backendregistry.CategorySoftware,
		Location:    backendregistry.LocationLocal,
		DisplayName: "Local Software",
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapSigning:    true,
			backendregistry.CapEncryption: true,
			backendregistry.CapFIDO2:      true,
			backendregistry.CapOATH:       true,
			backendregistry.CapPasswords:  true,
			backendregistry.CapSealing:    true,
			backendregistry.CapPIV:        true,
		},
		Metadata: map[string]string{},
	}
	backend.SetState(backendregistry.StateReady)
	return &mockBackendRegistryWithSoftware{softwareBackend: backend}
}

func (m *mockBackendRegistryWithSoftware) Register(_ *backendregistry.RegisteredBackend) error {
	return nil
}

func (m *mockBackendRegistryWithSoftware) Unregister(_ string) error {
	return nil
}

func (m *mockBackendRegistryWithSoftware) Get(id string) (*backendregistry.RegisteredBackend, error) {
	if id == m.softwareBackend.ID {
		return m.softwareBackend, nil
	}
	return nil, errors.New("not found")
}

func (m *mockBackendRegistryWithSoftware) List() []*backendregistry.RegisteredBackend {
	return []*backendregistry.RegisteredBackend{m.softwareBackend}
}

func (m *mockBackendRegistryWithSoftware) ListByCapability(_ backendregistry.Capability) []*backendregistry.RegisteredBackend {
	return nil
}

func (m *mockBackendRegistryWithSoftware) ListByCategory(cat backendregistry.BackendCategory) []*backendregistry.RegisteredBackend {
	if cat == backendregistry.CategorySoftware {
		return []*backendregistry.RegisteredBackend{m.softwareBackend}
	}
	return nil
}

func (m *mockBackendRegistryWithSoftware) ListByLocation(_ backendregistry.BackendLocation) []*backendregistry.RegisteredBackend {
	return nil
}

func (m *mockBackendRegistryWithSoftware) GetDefault(_ backendregistry.Capability) (*backendregistry.RegisteredBackend, error) {
	return nil, errors.New("no default")
}

func (m *mockBackendRegistryWithSoftware) SetDefault(_ backendregistry.Capability, _ string) error {
	return nil
}

func (m *mockBackendRegistryWithSoftware) Subscribe(_ backendregistry.EventHandler) int {
	return 0
}

func (m *mockBackendRegistryWithSoftware) Unsubscribe(_ int) {}

func (m *mockBackendRegistryWithSoftware) UpdateDisplayName(_ string, _ string) error { return nil }

func (m *mockBackendRegistryWithSoftware) Close() error {
	return nil
}

// findBackendByID is a test helper that locates a backend in a slice by ID.
func findBackendByID(backends []BackendInfo, id string) *BackendInfo {
	for i := range backends {
		if backends[i].ID == id {
			return &backends[i]
		}
	}
	return nil
}

// TestAdminService_EnhanceTPMBackend_DeviceExistsButUnavailable verifies that
// when a TPM device node exists but the TPM cannot be initialized (transient
// error), the backend remains Enabled=true so it stays visible in the UI.
// This is the core regression test for the TPM visibility bug.
func TestAdminService_EnhanceTPMBackend_DeviceExistsButUnavailable(t *testing.T) {
	svc := NewAdminService()
	svc.tpmProvider = &mockTPMProvider{
		status: &TPMStatus{
			Available:    false,
			DeviceExists: true,
			DevicePath:   "/dev/tpm0",
			InitError:    "device busy: resource temporarily unavailable",
		},
	}

	backend := BackendInfo{
		ID:       "tpm2",
		Type:     "tpm2",
		Enabled:  false,
		Metadata: nil,
	}
	svc.enhanceTPMBackend(&backend)

	assert.True(t, backend.Enabled, "backend must remain enabled when device exists")
	assert.False(t, backend.Connected, "backend must not be connected when unavailable")
	require.NotNil(t, backend.Metadata)
	assert.Equal(t, "/dev/tpm0", backend.Metadata["device_path"])
	assert.Equal(t, "device busy: resource temporarily unavailable", backend.Metadata["init_error"])
}

// TestAdminService_EnhanceTPMBackend_NoDeviceNoTPM verifies that when no TPM
// device node exists and the TPM is not available, the backend is disabled.
func TestAdminService_EnhanceTPMBackend_NoDeviceNoTPM(t *testing.T) {
	svc := NewAdminService()
	svc.tpmProvider = &mockTPMProvider{
		status: &TPMStatus{
			Available:    false,
			DeviceExists: false,
		},
	}

	backend := BackendInfo{
		ID:      "tpm2",
		Type:    "tpm2",
		Enabled: true,
	}
	svc.enhanceTPMBackend(&backend)

	assert.False(t, backend.Enabled, "backend must be disabled when no device exists")
	assert.False(t, backend.Connected, "backend must not be connected")
}

// TestAdminService_EnhanceTPMBackend_FullyAvailable verifies that when the TPM
// is fully available, the backend is enabled, connected, and description
// includes the manufacturer string.
func TestAdminService_EnhanceTPMBackend_FullyAvailable(t *testing.T) {
	svc := NewAdminService()
	svc.tpmProvider = &mockTPMProvider{
		status: &TPMStatus{
			Available:    true,
			DeviceExists: true,
			Provisioned:  true,
			Manufacturer: "Infineon",
			FirmwareVer:  "7.85",
			DevicePath:   "/dev/tpm0",
		},
	}

	backend := BackendInfo{
		ID:   "tpm2",
		Type: "tpm2",
	}
	svc.enhanceTPMBackend(&backend)

	assert.True(t, backend.Enabled, "backend must be enabled when fully available")
	assert.True(t, backend.Connected, "backend must be connected when available")
	assert.Contains(t, backend.Description, "Infineon", "description must include manufacturer")
	require.NotNil(t, backend.Metadata)
	assert.Equal(t, "Infineon", backend.Metadata["manufacturer"])
	assert.Equal(t, "7.85", backend.Metadata["firmware"])
	assert.Equal(t, "/dev/tpm0", backend.Metadata["device_path"])
	_, hasInitError := backend.Metadata["init_error"]
	assert.False(t, hasInitError, "init_error must not be set when no error occurred")
}

// TestAdminService_EnhanceTPMBackend_NilProvider verifies that when no TPM
// provider is configured, the backend is left unchanged.
func TestAdminService_EnhanceTPMBackend_NilProvider(t *testing.T) {
	svc := NewAdminService()
	// Explicitly nil provider.
	svc.tpmProvider = nil

	backend := BackendInfo{
		ID:          "tpm2",
		Type:        "tpm2",
		Enabled:     true,
		Connected:   true,
		Description: "original description",
	}
	svc.enhanceTPMBackend(&backend)

	// Backend must be completely unchanged.
	assert.True(t, backend.Enabled)
	assert.True(t, backend.Connected)
	assert.Equal(t, "original description", backend.Description)
}

// TestAdminService_EnhanceTPMBackend_ProviderError verifies that when
// GetStatus returns an error, the backend is disabled and disconnected.
func TestAdminService_EnhanceTPMBackend_ProviderError(t *testing.T) {
	svc := NewAdminService()
	svc.tpmProvider = &mockTPMProvider{
		status: nil,
		err:    errors.New("permission denied"),
	}

	backend := BackendInfo{
		ID:      "tpm2",
		Type:    "tpm2",
		Enabled: true,
	}
	svc.enhanceTPMBackend(&backend)

	assert.False(t, backend.Enabled, "backend must be disabled on provider error")
	assert.False(t, backend.Connected, "backend must not be connected on provider error")
}

// TestAdminService_DynamicBackends_TPMDeviceExistsNotAvailable verifies that
// when there is no registry but the TPM device node exists (with initialization
// failure), the TPM still appears in the backend list with Enabled=true.
// This is the auto-detect path regression test.
func TestAdminService_DynamicBackends_TPMDeviceExistsNotAvailable(t *testing.T) {
	svc := NewAdminService()
	svc.tpmProvider = &mockTPMProvider{
		status: &TPMStatus{
			Available:    false,
			DeviceExists: true,
			DevicePath:   "/dev/tpmrm0",
			InitError:    "no such device or address",
		},
	}

	backends, err := svc.ListBackends()
	require.NoError(t, err)

	tpmBackend := findBackendByID(backends, "tpm2")
	require.NotNil(t, tpmBackend, "TPM must appear in list when device exists")
	assert.True(t, tpmBackend.Enabled, "TPM must be enabled when device exists")
	assert.False(t, tpmBackend.Connected, "TPM must not be connected when unavailable")
	require.NotNil(t, tpmBackend.Metadata)
	assert.Equal(t, "no such device or address", tpmBackend.Metadata["init_error"])
	assert.Equal(t, "/dev/tpmrm0", tpmBackend.Metadata["device_path"])
}

// TestAdminService_DynamicBackends_TPMDeviceNotExists verifies that when the
// TPM device node does not exist and the TPM is not available, the TPM does
// NOT appear in the auto-detected backend list.
func TestAdminService_DynamicBackends_TPMDeviceNotExists(t *testing.T) {
	svc := NewAdminService()
	svc.tpmProvider = &mockTPMProvider{
		status: &TPMStatus{
			Available:    false,
			DeviceExists: false,
		},
	}

	backends, err := svc.ListBackends()
	require.NoError(t, err)

	tpmBackend := findBackendByID(backends, "tpm2")
	assert.Nil(t, tpmBackend, "TPM must NOT appear in list when device does not exist")
}

// TestAdminService_DynamicBackends_TPMFullyAvailable verifies that when the
// TPM is fully available via auto-detect, it appears as enabled and connected.
func TestAdminService_DynamicBackends_TPMFullyAvailable(t *testing.T) {
	svc := NewAdminService()
	svc.tpmProvider = &mockTPMProvider{
		status: &TPMStatus{
			Available:    true,
			DeviceExists: true,
			Provisioned:  true,
			Manufacturer: "STMicroelectronics",
			FirmwareVer:  "3.22",
			DevicePath:   "/dev/tpm0",
		},
	}

	backends, err := svc.ListBackends()
	require.NoError(t, err)

	tpmBackend := findBackendByID(backends, "tpm2")
	require.NotNil(t, tpmBackend, "TPM must appear in list when fully available")
	assert.True(t, tpmBackend.Enabled, "TPM must be enabled")
	assert.True(t, tpmBackend.Connected, "TPM must be connected when available")
	assert.Contains(t, tpmBackend.Description, "STMicroelectronics")
	require.NotNil(t, tpmBackend.Metadata)
	assert.Equal(t, "STMicroelectronics", tpmBackend.Metadata["manufacturer"])
	assert.Equal(t, "3.22", tpmBackend.Metadata["firmware"])
}

// TestAdminService_DynamicBackends_TPMInRegistry verifies that when the
// registry already contains a TPM2 backend, the auto-detect path is skipped
// and the registry entry is enhanced with live TPM status. When the device
// exists but is unavailable, the backend stays Enabled=true.
func TestAdminService_DynamicBackends_TPMInRegistry(t *testing.T) {
	svc := NewAdminService()
	registry := newMockBackendRegistryWithTPM()
	svc.SetBackendRegistry(registry)
	svc.tpmProvider = &mockTPMProvider{
		status: &TPMStatus{
			Available:    false,
			DeviceExists: true,
			DevicePath:   "/dev/tpm0",
			InitError:    "device in use",
		},
	}

	backends, err := svc.ListBackends()
	require.NoError(t, err)

	tpmBackend := findBackendByID(backends, "tpm2")
	require.NotNil(t, tpmBackend, "TPM must appear from registry")
	assert.True(t, tpmBackend.Enabled, "registry TPM must stay enabled when device exists")
	assert.False(t, tpmBackend.Connected, "registry TPM must not be connected when unavailable")
	require.NotNil(t, tpmBackend.Metadata)
	assert.Equal(t, "device in use", tpmBackend.Metadata["init_error"])
	assert.Equal(t, "/dev/tpm0", tpmBackend.Metadata["device_path"])

	// Verify only one TPM entry exists (auto-detect was skipped).
	tpmCount := 0
	for _, b := range backends {
		if b.ID == "tpm2" {
			tpmCount++
		}
	}
	assert.Equal(t, 1, tpmCount, "auto-detect must be skipped when registry has TPM")
}

// TestAdminService_FallbackBackends_TPMDeviceExists verifies that the
// fallback path (no registry, no providers except TPM) includes the TPM
// backend when DeviceExists=true, even if Available=false.
func TestAdminService_FallbackBackends_TPMDeviceExists(t *testing.T) {
	svc := NewAdminService()
	svc.tpmProvider = &mockTPMProvider{
		status: &TPMStatus{
			Available:    false,
			DeviceExists: true,
			DevicePath:   "/dev/tpmrm0",
			InitError:    "tpm2: open: permission denied",
		},
	}
	// No registry, no remote func, no phone provider -- triggers fallbackBackends.

	backends := svc.fallbackBackends()
	require.NotEmpty(t, backends)

	// First entry must always be software.
	assert.Equal(t, "software", backends[0].ID)

	// TPM must be present because DeviceExists=true.
	tpmBackend := findBackendByID(backends, "tpm2")
	require.NotNil(t, tpmBackend, "fallback must include TPM when device exists")
	assert.True(t, tpmBackend.Enabled, "fallback TPM must be enabled")
	assert.False(t, tpmBackend.Connected, "fallback TPM must not be connected when unavailable")
	require.NotNil(t, tpmBackend.Metadata)
	assert.Equal(t, "tpm2: open: permission denied", tpmBackend.Metadata["init_error"])
	assert.Equal(t, "/dev/tpmrm0", tpmBackend.Metadata["device_path"])
}

// ---------------------------------------------------------------------------
// SetDefaultBackend and GetSystemDefaultBackend tests
// ---------------------------------------------------------------------------

// mockFullRegistry is a test registry that stores multiple backends with
// state and capability tracking, used for SetDefaultBackend tests.
type mockFullRegistry struct {
	backends      map[string]*backendregistry.RegisteredBackend
	defaults      map[backendregistry.Capability]string
	setDefaultErr error
}

func newMockFullRegistry() *mockFullRegistry {
	return &mockFullRegistry{
		backends: make(map[string]*backendregistry.RegisteredBackend),
		defaults: make(map[backendregistry.Capability]string),
	}
}

func (m *mockFullRegistry) addBackend(b *backendregistry.RegisteredBackend) {
	m.backends[b.ID] = b
}

func (m *mockFullRegistry) Register(_ *backendregistry.RegisteredBackend) error { return nil }
func (m *mockFullRegistry) Unregister(_ string) error                           { return nil }

func (m *mockFullRegistry) Get(id string) (*backendregistry.RegisteredBackend, error) {
	if b, ok := m.backends[id]; ok {
		return b, nil
	}
	return nil, errors.New("not found")
}

func (m *mockFullRegistry) List() []*backendregistry.RegisteredBackend {
	var out []*backendregistry.RegisteredBackend
	for _, b := range m.backends {
		out = append(out, b)
	}
	return out
}

func (m *mockFullRegistry) ListByCapability(_ backendregistry.Capability) []*backendregistry.RegisteredBackend {
	return nil
}

func (m *mockFullRegistry) ListByCategory(_ backendregistry.BackendCategory) []*backendregistry.RegisteredBackend {
	return nil
}

func (m *mockFullRegistry) ListByLocation(_ backendregistry.BackendLocation) []*backendregistry.RegisteredBackend {
	return nil
}

func (m *mockFullRegistry) GetDefault(feature backendregistry.Capability) (*backendregistry.RegisteredBackend, error) {
	if id, ok := m.defaults[feature]; ok {
		if b, ok2 := m.backends[id]; ok2 {
			return b, nil
		}
	}
	return nil, errors.New("no default set")
}

func (m *mockFullRegistry) SetDefault(feature backendregistry.Capability, id string) error {
	if m.setDefaultErr != nil {
		return m.setDefaultErr
	}
	m.defaults[feature] = id
	return nil
}

func (m *mockFullRegistry) Subscribe(_ backendregistry.EventHandler) int { return 0 }
func (m *mockFullRegistry) Unsubscribe(_ int)                            {}
func (m *mockFullRegistry) UpdateDisplayName(_ string, _ string) error   { return nil }
func (m *mockFullRegistry) Close() error                                 { return nil }

// newReadyBackend creates a RegisteredBackend in StateReady with the given capabilities.
func newReadyBackend(id string, caps ...backendregistry.Capability) *backendregistry.RegisteredBackend {
	capMap := make(map[backendregistry.Capability]bool)
	for _, c := range caps {
		capMap[c] = true
	}
	b := &backendregistry.RegisteredBackend{
		ID:           id,
		Category:     backendregistry.CategorySoftware,
		Location:     backendregistry.LocationLocal,
		DisplayName:  id,
		Capabilities: capMap,
		Metadata:     map[string]string{},
	}
	b.SetState(backendregistry.StateReady)
	return b
}

// newOfflineBackend creates a RegisteredBackend in StateOffline.
func newOfflineBackend(id string) *backendregistry.RegisteredBackend {
	b := &backendregistry.RegisteredBackend{
		ID:           id,
		Category:     backendregistry.CategorySoftware,
		Location:     backendregistry.LocationLocal,
		DisplayName:  id,
		Capabilities: map[backendregistry.Capability]bool{},
		Metadata:     map[string]string{},
	}
	b.SetState(backendregistry.StateOffline)
	return b
}

func TestAdminService_SetSealService(t *testing.T) {
	svc := NewAdminService()
	assert.Nil(t, svc.sealSvc)

	sealSvc := NewSealService(t.TempDir())
	svc.SetSealService(sealSvc)
	assert.Equal(t, sealSvc, svc.sealSvc)
}

func TestAdminService_SetSealService_Nil(t *testing.T) {
	svc := NewAdminService()
	svc.SetSealService(nil)
	assert.Nil(t, svc.sealSvc)
}

func TestAdminService_SetConfigUpdateFunc(t *testing.T) {
	svc := NewAdminService()
	assert.Nil(t, svc.configUpdateFunc)

	called := false
	svc.SetConfigUpdateFunc(func(id string) error {
		called = true
		return nil
	})
	assert.NotNil(t, svc.configUpdateFunc)

	err := svc.configUpdateFunc("test")
	require.NoError(t, err)
	assert.True(t, called)
}

func TestAdminService_SetConfigUpdateFunc_Nil(t *testing.T) {
	svc := NewAdminService()
	svc.SetConfigUpdateFunc(nil)
	assert.Nil(t, svc.configUpdateFunc)
}

func TestAdminService_SetDefaultBackend_Success(t *testing.T) {
	svc := NewAdminService()
	registry := newMockFullRegistry()
	backend := newReadyBackend("software",
		backendregistry.CapSigning,
		backendregistry.CapEncryption,
		backendregistry.CapSealing,
	)
	registry.addBackend(backend)
	svc.SetBackendRegistry(registry)

	err := svc.SetDefaultBackend("software")
	require.NoError(t, err)

	// Verify capabilities with matching support were set.
	assert.Equal(t, "software", registry.defaults[backendregistry.CapSigning])
	assert.Equal(t, "software", registry.defaults[backendregistry.CapEncryption])
	assert.Equal(t, "software", registry.defaults[backendregistry.CapSealing])

	// Attestation was NOT a capability, so it should not be in defaults.
	_, hasAttestation := registry.defaults[backendregistry.CapAttestation]
	assert.False(t, hasAttestation)
}

func TestAdminService_SetDefaultBackend_NoRegistry(t *testing.T) {
	svc := NewAdminService()
	err := svc.SetDefaultBackend("software")
	assert.ErrorIs(t, err, ErrAdminRegistryNotSet)
}

func TestAdminService_SetDefaultBackend_BackendNotFound(t *testing.T) {
	svc := NewAdminService()
	registry := newMockFullRegistry()
	svc.SetBackendRegistry(registry)

	err := svc.SetDefaultBackend("nonexistent")
	assert.ErrorIs(t, err, ErrAdminBackendNotFound)
}

func TestAdminService_SetDefaultBackend_BackendNotConnected(t *testing.T) {
	svc := NewAdminService()
	registry := newMockFullRegistry()
	registry.addBackend(newOfflineBackend("tpm2"))
	svc.SetBackendRegistry(registry)

	err := svc.SetDefaultBackend("tpm2")
	assert.ErrorIs(t, err, ErrAdminBackendNotConnected)
}

func TestAdminService_SetDefaultBackend_SyncsSealService(t *testing.T) {
	svc := NewAdminService()
	registry := newMockFullRegistry()
	registry.addBackend(newReadyBackend("tpm2", backendregistry.CapSealing))
	svc.SetBackendRegistry(registry)

	sealSvc := NewSealService(t.TempDir())
	sealSvc.SetDefaultBackend("software")
	svc.SetSealService(sealSvc)

	err := svc.SetDefaultBackend("tpm2")
	require.NoError(t, err)

	assert.Equal(t, "tpm2", sealSvc.DefaultBackend())
}

func TestAdminService_SetDefaultBackend_NoSealService(t *testing.T) {
	svc := NewAdminService()
	registry := newMockFullRegistry()
	registry.addBackend(newReadyBackend("software", backendregistry.CapSigning))
	svc.SetBackendRegistry(registry)

	// No seal service set -- should not panic.
	err := svc.SetDefaultBackend("software")
	require.NoError(t, err)
}

func TestAdminService_SetDefaultBackend_PersistsToConfig(t *testing.T) {
	svc := NewAdminService()
	registry := newMockFullRegistry()
	registry.addBackend(newReadyBackend("software", backendregistry.CapSigning))
	svc.SetBackendRegistry(registry)

	var persisted string
	svc.SetConfigUpdateFunc(func(id string) error {
		persisted = id
		return nil
	})

	err := svc.SetDefaultBackend("software")
	require.NoError(t, err)
	assert.Equal(t, "software", persisted)
}

func TestAdminService_SetDefaultBackend_ConfigPersistError(t *testing.T) {
	svc := NewAdminService()
	registry := newMockFullRegistry()
	registry.addBackend(newReadyBackend("software", backendregistry.CapSigning))
	svc.SetBackendRegistry(registry)

	persistErr := errors.New("disk full")
	svc.SetConfigUpdateFunc(func(id string) error {
		return persistErr
	})

	err := svc.SetDefaultBackend("software")
	assert.Equal(t, persistErr, err)
}

func TestAdminService_SetDefaultBackend_NoConfigFunc(t *testing.T) {
	svc := NewAdminService()
	registry := newMockFullRegistry()
	registry.addBackend(newReadyBackend("software", backendregistry.CapSigning))
	svc.SetBackendRegistry(registry)

	// No config update func -- should succeed without error.
	err := svc.SetDefaultBackend("software")
	require.NoError(t, err)
}

func TestAdminService_SetDefaultBackend_AllCapabilities(t *testing.T) {
	svc := NewAdminService()
	registry := newMockFullRegistry()
	backend := newReadyBackend("tpm2",
		backendregistry.CapSigning,
		backendregistry.CapEncryption,
		backendregistry.CapSealing,
		backendregistry.CapAttestation,
	)
	registry.addBackend(backend)
	svc.SetBackendRegistry(registry)

	err := svc.SetDefaultBackend("tpm2")
	require.NoError(t, err)

	// All four capabilities should be set.
	assert.Equal(t, "tpm2", registry.defaults[backendregistry.CapSigning])
	assert.Equal(t, "tpm2", registry.defaults[backendregistry.CapEncryption])
	assert.Equal(t, "tpm2", registry.defaults[backendregistry.CapSealing])
	assert.Equal(t, "tpm2", registry.defaults[backendregistry.CapAttestation])
}

func TestAdminService_GetSystemDefaultBackend_WithSealService(t *testing.T) {
	svc := NewAdminService()
	sealSvc := NewSealService(t.TempDir())
	sealSvc.SetDefaultBackend("tpm2")
	svc.SetSealService(sealSvc)

	result := svc.GetSystemDefaultBackend()
	assert.Equal(t, "tpm2", result)
}

func TestAdminService_GetSystemDefaultBackend_SealServiceEmpty(t *testing.T) {
	svc := NewAdminService()
	sealSvc := NewSealService(t.TempDir())
	sealSvc.SetDefaultBackend("")
	svc.SetSealService(sealSvc)

	// Empty seal service default falls through to registry/software.
	result := svc.GetSystemDefaultBackend()
	assert.Equal(t, "software", result)
}

func TestAdminService_GetSystemDefaultBackend_NoSealService(t *testing.T) {
	svc := NewAdminService()
	// No seal service set -- falls through to GetDefaultBackend.
	result := svc.GetSystemDefaultBackend()
	assert.Equal(t, "software", result)
}

func TestAdminService_GetSystemDefaultBackend_NoSealServiceWithRegistry(t *testing.T) {
	svc := NewAdminService()
	registry := newMockBackendRegistry()
	registry.setDefault("tpm2")
	svc.SetBackendRegistry(registry)

	// No seal service, but registry has a default.
	result := svc.GetSystemDefaultBackend()
	assert.Equal(t, "tpm2", result)
}

func TestAdminService_GetSystemDefaultBackend_SealServiceOverridesRegistry(t *testing.T) {
	svc := NewAdminService()

	// Registry says tpm2.
	registry := newMockBackendRegistry()
	registry.setDefault("tpm2")
	svc.SetBackendRegistry(registry)

	// Seal service says pkcs11.
	sealSvc := NewSealService(t.TempDir())
	sealSvc.SetDefaultBackend("pkcs11")
	svc.SetSealService(sealSvc)

	// Seal service takes priority.
	result := svc.GetSystemDefaultBackend()
	assert.Equal(t, "pkcs11", result)
}

func TestAdminService_NewErrorSentinels(t *testing.T) {
	// Verify the new error sentinels are distinct and have meaningful messages.
	sentinels := []struct {
		err     error
		message string
	}{
		{ErrAdminBackendNotConnected, "admin_service: backend not connected"},
		{ErrAdminRegistryNotSet, "admin_service: backend registry not configured"},
	}
	for _, s := range sentinels {
		assert.NotNil(t, s.err)
		assert.Equal(t, s.message, s.err.Error())
	}

	// Verify they are distinct from existing errors.
	assert.NotErrorIs(t, ErrAdminBackendNotConnected, ErrAdminBackendNotFound)
	assert.NotErrorIs(t, ErrAdminRegistryNotSet, ErrAdminNotAuthorized)
}

// ---------------------------------------------------------------------------
// BackendCapability new field tests
// ---------------------------------------------------------------------------

func TestBackendCapability_FIDO2Field(t *testing.T) {
	svc := NewAdminService()

	t.Run("FIDO2 capability present", func(t *testing.T) {
		rb := &backendregistry.RegisteredBackend{
			ID:          "fido2-backend",
			Category:    backendregistry.CategorySoftware,
			Location:    backendregistry.LocationLocal,
			DisplayName: "FIDO2 Backend",
			Capabilities: map[backendregistry.Capability]bool{
				backendregistry.CapFIDO2:   true,
				backendregistry.CapSigning: true,
			},
			Metadata: map[string]string{},
		}
		rb.SetState(backendregistry.StateReady)

		info := svc.convertRegisteredBackend(rb)
		assert.True(t, info.Capabilities.FIDO2)
		assert.True(t, info.Capabilities.Signing)
	})

	t.Run("FIDO2 capability absent", func(t *testing.T) {
		rb := &backendregistry.RegisteredBackend{
			ID:          "no-fido2",
			Category:    backendregistry.CategorySoftware,
			Location:    backendregistry.LocationLocal,
			DisplayName: "No FIDO2",
			Capabilities: map[backendregistry.Capability]bool{
				backendregistry.CapSigning: true,
			},
			Metadata: map[string]string{},
		}
		rb.SetState(backendregistry.StateReady)

		info := svc.convertRegisteredBackend(rb)
		assert.False(t, info.Capabilities.FIDO2)
		assert.True(t, info.Capabilities.Signing)
	})
}

func TestBackendCapability_PIVField(t *testing.T) {
	svc := NewAdminService()

	t.Run("PIV capability present", func(t *testing.T) {
		rb := &backendregistry.RegisteredBackend{
			ID:          "pkcs11-piv",
			Category:    backendregistry.CategoryPKCS11,
			Location:    backendregistry.LocationLocal,
			DisplayName: "PKCS#11 with PIV",
			Capabilities: map[backendregistry.Capability]bool{
				backendregistry.CapPIV:        true,
				backendregistry.CapSigning:    true,
				backendregistry.CapEncryption: true,
			},
			Metadata: map[string]string{},
		}
		rb.SetState(backendregistry.StateReady)

		info := svc.convertRegisteredBackend(rb)
		assert.True(t, info.Capabilities.PIV)
		assert.True(t, info.Capabilities.HardwareBacked)
	})

	t.Run("PIV capability absent", func(t *testing.T) {
		rb := &backendregistry.RegisteredBackend{
			ID:          "pkcs11-no-piv",
			Category:    backendregistry.CategoryPKCS11,
			Location:    backendregistry.LocationLocal,
			DisplayName: "PKCS#11 without PIV",
			Capabilities: map[backendregistry.Capability]bool{
				backendregistry.CapSigning:    true,
				backendregistry.CapEncryption: true,
			},
			Metadata: map[string]string{},
		}
		rb.SetState(backendregistry.StateReady)

		info := svc.convertRegisteredBackend(rb)
		assert.False(t, info.Capabilities.PIV)
	})
}

func TestBackendCapability_OATHField(t *testing.T) {
	svc := NewAdminService()

	t.Run("OATH capability present", func(t *testing.T) {
		rb := &backendregistry.RegisteredBackend{
			ID:          "oath-backend",
			Category:    backendregistry.CategorySoftware,
			Location:    backendregistry.LocationLocal,
			DisplayName: "OATH Backend",
			Capabilities: map[backendregistry.Capability]bool{
				backendregistry.CapOATH:    true,
				backendregistry.CapSigning: true,
			},
			Metadata: map[string]string{},
		}
		rb.SetState(backendregistry.StateReady)

		info := svc.convertRegisteredBackend(rb)
		assert.True(t, info.Capabilities.OATH)
	})

	t.Run("OATH capability absent", func(t *testing.T) {
		rb := &backendregistry.RegisteredBackend{
			ID:          "no-oath",
			Category:    backendregistry.CategorySoftware,
			Location:    backendregistry.LocationLocal,
			DisplayName: "No OATH",
			Capabilities: map[backendregistry.Capability]bool{
				backendregistry.CapSigning: true,
			},
			Metadata: map[string]string{},
		}
		rb.SetState(backendregistry.StateReady)

		info := svc.convertRegisteredBackend(rb)
		assert.False(t, info.Capabilities.OATH)
	})
}

func TestBackendCapability_PasswordsField(t *testing.T) {
	svc := NewAdminService()

	t.Run("Passwords capability present", func(t *testing.T) {
		rb := &backendregistry.RegisteredBackend{
			ID:          "pw-backend",
			Category:    backendregistry.CategorySoftware,
			Location:    backendregistry.LocationLocal,
			DisplayName: "Passwords Backend",
			Capabilities: map[backendregistry.Capability]bool{
				backendregistry.CapPasswords: true,
				backendregistry.CapSigning:   true,
			},
			Metadata: map[string]string{},
		}
		rb.SetState(backendregistry.StateReady)

		info := svc.convertRegisteredBackend(rb)
		assert.True(t, info.Capabilities.Passwords)
	})

	t.Run("Passwords capability absent", func(t *testing.T) {
		rb := &backendregistry.RegisteredBackend{
			ID:          "no-pw",
			Category:    backendregistry.CategorySoftware,
			Location:    backendregistry.LocationLocal,
			DisplayName: "No Passwords",
			Capabilities: map[backendregistry.Capability]bool{
				backendregistry.CapSigning: true,
			},
			Metadata: map[string]string{},
		}
		rb.SetState(backendregistry.StateReady)

		info := svc.convertRegisteredBackend(rb)
		assert.False(t, info.Capabilities.Passwords)
	})
}

func TestBackendCapability_FiltersByCapability(t *testing.T) {
	svc := NewAdminService()

	// Software backend with FIDO2, OATH, Passwords, Signing, Encryption, Sealing.
	swBackend := &backendregistry.RegisteredBackend{
		ID:          "software",
		Category:    backendregistry.CategorySoftware,
		Location:    backendregistry.LocationLocal,
		DisplayName: "Software",
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapFIDO2:      true,
			backendregistry.CapOATH:       true,
			backendregistry.CapPasswords:  true,
			backendregistry.CapSigning:    true,
			backendregistry.CapEncryption: true,
			backendregistry.CapSealing:    true,
		},
		Metadata: map[string]string{},
	}
	swBackend.SetState(backendregistry.StateReady)

	// PKCS#11 backend with FIDO2, PIV, Signing, Encryption, Sealing.
	p11Backend := &backendregistry.RegisteredBackend{
		ID:          "pkcs11",
		Category:    backendregistry.CategoryPKCS11,
		Location:    backendregistry.LocationLocal,
		DisplayName: "PKCS#11",
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapFIDO2:      true,
			backendregistry.CapPIV:        true,
			backendregistry.CapSigning:    true,
			backendregistry.CapEncryption: true,
			backendregistry.CapSealing:    true,
		},
		Metadata: map[string]string{},
	}
	p11Backend.SetState(backendregistry.StateReady)

	// TPM2 backend with FIDO2, Passwords, Signing, Encryption, Sealing, Attestation.
	tpm2Backend := &backendregistry.RegisteredBackend{
		ID:          "tpm2",
		Category:    backendregistry.CategoryTPM2,
		Location:    backendregistry.LocationLocal,
		DisplayName: "TPM 2.0",
		Capabilities: map[backendregistry.Capability]bool{
			backendregistry.CapFIDO2:       true,
			backendregistry.CapSigning:     true,
			backendregistry.CapEncryption:  true,
			backendregistry.CapSealing:     true,
			backendregistry.CapAttestation: true,
			backendregistry.CapPasswords:   true,
		},
		Metadata: map[string]string{},
	}
	tpm2Backend.SetState(backendregistry.StateReady)

	// Convert all backends.
	swInfo := svc.convertRegisteredBackend(swBackend)
	p11Info := svc.convertRegisteredBackend(p11Backend)
	tpm2Info := svc.convertRegisteredBackend(tpm2Backend)

	// Software backend assertions.
	t.Run("software capabilities", func(t *testing.T) {
		assert.True(t, swInfo.Capabilities.FIDO2)
		assert.True(t, swInfo.Capabilities.OATH)
		assert.True(t, swInfo.Capabilities.Passwords)
		assert.True(t, swInfo.Capabilities.Signing)
		assert.True(t, swInfo.Capabilities.Encryption)
		assert.True(t, swInfo.Capabilities.Sealing)
		assert.False(t, swInfo.Capabilities.PIV)
		assert.False(t, swInfo.Capabilities.Attestation)
		assert.False(t, swInfo.Capabilities.HardwareBacked)
	})

	// PKCS#11 backend assertions.
	t.Run("pkcs11 capabilities", func(t *testing.T) {
		assert.True(t, p11Info.Capabilities.PIV)
		assert.True(t, p11Info.Capabilities.Signing)
		assert.True(t, p11Info.Capabilities.Encryption)
		assert.True(t, p11Info.Capabilities.Sealing)
		assert.True(t, p11Info.Capabilities.HardwareBacked)
		assert.True(t, p11Info.Capabilities.FIDO2)
		assert.False(t, p11Info.Capabilities.OATH)
		assert.False(t, p11Info.Capabilities.Passwords)
		assert.False(t, p11Info.Capabilities.Attestation)
	})

	// TPM2 backend assertions.
	t.Run("tpm2 capabilities", func(t *testing.T) {
		assert.True(t, tpm2Info.Capabilities.FIDO2)
		assert.True(t, tpm2Info.Capabilities.Signing)
		assert.True(t, tpm2Info.Capabilities.Encryption)
		assert.True(t, tpm2Info.Capabilities.Sealing)
		assert.True(t, tpm2Info.Capabilities.Attestation)
		assert.True(t, tpm2Info.Capabilities.HardwareBacked)
		assert.False(t, tpm2Info.Capabilities.PIV)
		assert.False(t, tpm2Info.Capabilities.OATH)
		assert.True(t, tpm2Info.Capabilities.Passwords)
	})
}

// ---------------------------------------------------------------------------
// PIV backend selector data flow tests
//
// These tests verify that the PIV capability field is correctly propagated
// through all code paths that produce BackendInfo slices. The frontend
// BackendSelector component filters backends by Capabilities.PIV to decide
// which backends to show in the PIV management view. If any path omits the
// PIV field, the selector shows an empty list -- a silent, hard-to-diagnose
// failure.
// ---------------------------------------------------------------------------

// TestAdminService_DynamicBackends_AutoDetectedTPM_HasPIV verifies that the
// auto-detected TPM backend (no registry, TPM provider returns Available=true
// and DeviceExists=true) includes PIV=true and FIDO2=true in its capabilities.
func TestAdminService_DynamicBackends_AutoDetectedTPM_HasPIV(t *testing.T) {
	svc := NewAdminService()
	svc.tpmProvider = &mockTPMProvider{
		status: &TPMStatus{
			Available:    true,
			DeviceExists: true,
			Manufacturer: "TestCorp",
			FirmwareVer:  "1.0",
			DevicePath:   "/dev/tpm0",
		},
	}
	// No registry -- forces auto-detect path in dynamicBackends.

	backends, err := svc.ListBackends()
	require.NoError(t, err)

	tpmBackend := findBackendByID(backends, "tpm2")
	require.NotNil(t, tpmBackend, "auto-detected TPM must appear in backend list")

	assert.True(t, tpmBackend.Capabilities.PIV,
		"auto-detected TPM must have PIV=true for frontend filtering")
	assert.True(t, tpmBackend.Capabilities.FIDO2,
		"auto-detected TPM must have FIDO2=true for frontend filtering")
	assert.True(t, tpmBackend.Capabilities.HardwareBacked,
		"auto-detected TPM must be hardware backed")
	assert.True(t, tpmBackend.Capabilities.Signing)
	assert.True(t, tpmBackend.Capabilities.Encryption)
	assert.True(t, tpmBackend.Capabilities.Sealing)
	assert.True(t, tpmBackend.Capabilities.Attestation)
}

// TestAdminService_FallbackBackends_SoftwareHasPIV verifies that the fallback
// software backend (no registry, no providers) includes PIV=true, FIDO2=true,
// OATH=true, and Passwords=true. This is the minimum viable state for the
// frontend BackendSelector to show at least one backend.
func TestAdminService_FallbackBackends_SoftwareHasPIV(t *testing.T) {
	svc := NewAdminService()
	// No registry, no providers -- triggers fallbackBackends.

	backends, err := svc.ListBackends()
	require.NoError(t, err)
	require.NotEmpty(t, backends)

	sw := findBackendByID(backends, "software")
	require.NotNil(t, sw, "software fallback backend must be present")

	assert.True(t, sw.Capabilities.PIV,
		"fallback software must have PIV=true for frontend filtering")
	assert.True(t, sw.Capabilities.FIDO2,
		"fallback software must have FIDO2=true for frontend filtering")
	assert.True(t, sw.Capabilities.OATH,
		"fallback software must have OATH=true for frontend filtering")
	assert.True(t, sw.Capabilities.Passwords,
		"fallback software must have Passwords=true for frontend filtering")
}

// TestAdminService_ListBackends_AllPathsIncludePIV is the key regression test
// for the PIV backend selector. It creates an AdminService with both a
// registry (containing a software backend with CapPIV) and a TPM
// provider (Available=true). It then verifies that ALL returned backends
// have Capabilities.PIV == true. If any code path forgets to set PIV, this
// test catches it.
func TestAdminService_ListBackends_AllPathsIncludePIV(t *testing.T) {
	svc := NewAdminService()

	// Registry path: software backend with PIV capability.
	registry := newMockBackendRegistryWithSoftware()
	svc.SetBackendRegistry(registry)

	// Auto-detect path: TPM provider returning available.
	svc.tpmProvider = &mockTPMProvider{
		status: &TPMStatus{
			Available:    true,
			DeviceExists: true,
			Manufacturer: "RegressionCorp",
			FirmwareVer:  "2.0",
			DevicePath:   "/dev/tpm0",
		},
	}

	backends, err := svc.ListBackends()
	require.NoError(t, err)
	require.NotEmpty(t, backends, "must return at least one backend")

	for _, b := range backends {
		assert.True(t, b.Capabilities.PIV,
			"backend %q (type=%s) must have PIV=true, but got false", b.ID, b.Type)
	}
}

// TestAdminService_ListBackends_PIVFilterSimulation simulates exactly what the
// frontend BackendSelector component does: call ListBackends, then filter to
// only those where Capabilities.PIV == true. The filtered list must be
// non-empty. This directly tests the data the frontend would receive.
func TestAdminService_ListBackends_PIVFilterSimulation(t *testing.T) {
	svc := NewAdminService()
	// Bare service with no registry and no providers uses fallbackBackends.

	backends, err := svc.ListBackends()
	require.NoError(t, err)
	require.NotEmpty(t, backends)

	// Simulate frontend filter: keep only backends with PIV capability.
	var pivBackends []BackendInfo
	for _, b := range backends {
		if b.Capabilities.PIV {
			pivBackends = append(pivBackends, b)
		}
	}

	assert.NotEmpty(t, pivBackends,
		"frontend PIV filter must find at least one backend; got 0 out of %d total backends",
		len(backends))

	// Verify at least one filtered backend is enabled and connected.
	hasConnected := false
	for _, b := range pivBackends {
		if b.Enabled && b.Connected {
			hasConnected = true
			break
		}
	}
	assert.True(t, hasConnected,
		"at least one PIV-capable backend must be enabled and connected")
}

// TestAdminService_DynamicBackends_RegistryBackendHasPIV verifies the
// convertRegisteredBackend path: a software backend registered with
// CapPIV=true in the registry must appear with Capabilities.PIV=true in the
// ListBackends result.
func TestAdminService_DynamicBackends_RegistryBackendHasPIV(t *testing.T) {
	svc := NewAdminService()
	registry := newMockBackendRegistryWithSoftware()
	svc.SetBackendRegistry(registry)

	backends, err := svc.ListBackends()
	require.NoError(t, err)
	require.NotEmpty(t, backends)

	sw := findBackendByID(backends, "software")
	require.NotNil(t, sw, "software backend from registry must be present")

	assert.True(t, sw.Capabilities.PIV,
		"registry backend with CapPIV must have Capabilities.PIV=true")
	assert.True(t, sw.Capabilities.FIDO2,
		"registry backend with CapFIDO2 must have Capabilities.FIDO2=true")
	assert.True(t, sw.Capabilities.OATH,
		"registry backend with CapOATH must have Capabilities.OATH=true")
	assert.True(t, sw.Capabilities.Passwords,
		"registry backend with CapPasswords must have Capabilities.Passwords=true")
	assert.True(t, sw.Capabilities.Signing,
		"registry backend with CapSigning must have Capabilities.Signing=true")
	assert.True(t, sw.Capabilities.Encryption,
		"registry backend with CapEncryption must have Capabilities.Encryption=true")
	assert.True(t, sw.Capabilities.Sealing,
		"registry backend with CapSealing must have Capabilities.Sealing=true")
	assert.False(t, sw.Capabilities.HardwareBacked,
		"software category must not be hardware backed")
	assert.Equal(t, "software", sw.Type)
}

// --- RenameBackend tests ---

func TestAdminService_RenameBackend_Success(t *testing.T) {
	t.Parallel()

	svc := NewAdminService()
	registry := backendregistry.NewMemoryRegistry()
	backend := &backendregistry.RegisteredBackend{
		ID:           "pkcs11-hsm",
		Category:     backendregistry.CategoryPKCS11,
		Location:     backendregistry.LocationLocal,
		DisplayName:  "Old Name",
		Capabilities: map[backendregistry.Capability]bool{backendregistry.CapSigning: true},
		Metadata:     map[string]string{},
	}
	backend.SetState(backendregistry.StateReady)
	require.NoError(t, registry.Register(backend))
	svc.SetBackendRegistry(registry)

	err := svc.RenameBackend("pkcs11-hsm", "My Secure HSM")
	require.NoError(t, err)

	// Verify registry was updated.
	got, getErr := registry.Get("pkcs11-hsm")
	require.NoError(t, getErr)
	assert.Equal(t, "My Secure HSM", got.DisplayName)

	// Verify ListBackends returns the new name.
	backends, listErr := svc.ListBackends()
	require.NoError(t, listErr)
	found := findBackendByID(backends, "pkcs11-hsm")
	require.NotNil(t, found)
	assert.Equal(t, "My Secure HSM", found.DisplayName)
}

func TestAdminService_RenameBackend_NotFound(t *testing.T) {
	t.Parallel()

	svc := NewAdminService()
	registry := backendregistry.NewMemoryRegistry()
	svc.SetBackendRegistry(registry)

	err := svc.RenameBackend("nonexistent", "New Name")
	assert.ErrorIs(t, err, ErrAdminBackendNotFound)
}

func TestAdminService_RenameBackend_EmptyName(t *testing.T) {
	t.Parallel()

	svc := NewAdminService()
	registry := backendregistry.NewMemoryRegistry()
	svc.SetBackendRegistry(registry)

	err := svc.RenameBackend("some-id", "")
	assert.ErrorIs(t, err, ErrAdminEmptyDisplayName)
}

func TestAdminService_RenameBackend_EmptyID(t *testing.T) {
	t.Parallel()

	svc := NewAdminService()
	registry := backendregistry.NewMemoryRegistry()
	svc.SetBackendRegistry(registry)

	err := svc.RenameBackend("", "New Name")
	assert.ErrorIs(t, err, ErrAdminBackendNotFound)
}

func TestAdminService_RenameBackend_NoRegistry(t *testing.T) {
	t.Parallel()

	svc := NewAdminService()
	err := svc.RenameBackend("some-id", "New Name")
	assert.ErrorIs(t, err, ErrAdminRegistryNotSet)
}

// --- DisplayName fallback tests ---

func TestAdminService_ConvertRegisteredBackend_FallbackDisplayName(t *testing.T) {
	t.Parallel()

	svc := NewAdminService()
	registry := backendregistry.NewMemoryRegistry()

	// Register a backend with an empty DisplayName.
	backend := &backendregistry.RegisteredBackend{
		ID:           "software-test",
		Category:     backendregistry.CategorySoftware,
		Location:     backendregistry.LocationLocal,
		DisplayName:  "",
		Capabilities: map[backendregistry.Capability]bool{backendregistry.CapSigning: true},
		Metadata:     map[string]string{},
	}
	backend.SetState(backendregistry.StateReady)
	require.NoError(t, registry.Register(backend))
	svc.SetBackendRegistry(registry)

	backends, err := svc.ListBackends()
	require.NoError(t, err)

	found := findBackendByID(backends, "software-test")
	require.NotNil(t, found)
	assert.Equal(t, "Software", found.DisplayName,
		"empty DisplayName should fall back to category name")
}

func TestAdminService_ListBackends_DisplayNameAlwaysSet(t *testing.T) {
	t.Parallel()

	svc := NewAdminService()
	registry := backendregistry.NewMemoryRegistry()

	// Register backends with and without display names.
	for _, tc := range []struct {
		id      string
		cat     backendregistry.BackendCategory
		display string
	}{
		{"sw", backendregistry.CategorySoftware, ""},
		{"tpm", backendregistry.CategoryTPM2, ""},
		{"hsm", backendregistry.CategoryPKCS11, "My HSM"},
	} {
		b := &backendregistry.RegisteredBackend{
			ID:           tc.id,
			Category:     tc.cat,
			Location:     backendregistry.LocationLocal,
			DisplayName:  tc.display,
			Capabilities: map[backendregistry.Capability]bool{backendregistry.CapSigning: true},
			Metadata:     map[string]string{},
		}
		b.SetState(backendregistry.StateReady)
		require.NoError(t, registry.Register(b))
	}
	svc.SetBackendRegistry(registry)

	backends, err := svc.ListBackends()
	require.NoError(t, err)

	for _, b := range backends {
		assert.NotEmpty(t, b.DisplayName,
			"backend %s must have a non-empty display_name", b.ID)
	}
}
