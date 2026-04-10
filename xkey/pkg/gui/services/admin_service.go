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
	"strings"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/user"
	"runtime"
	"sort"
	"strconv"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// Admin service errors.
var (
	ErrAdminNotAuthorized       = errors.New("admin_service: not authorized")
	ErrAdminBackendNotFound     = errors.New("admin_service: backend not found")
	ErrAdminInvalidFormat       = errors.New("admin_service: invalid export format")
	ErrAdminBackendNotConnected = errors.New("admin_service: backend not connected")
	ErrAdminRegistryNotSet      = errors.New("admin_service: backend registry not configured")
	ErrAdminConfigLoadFailed    = errors.New("admin_service: failed to load config")
	ErrAdminConfigSaveFailed    = errors.New("admin_service: failed to save config")
	ErrAdminBackendDuplicate    = errors.New("admin_service: backend ID already exists")
	ErrAdminInvalidBackendType  = errors.New("admin_service: unsupported backend type")
	ErrAdminMissingField        = errors.New("admin_service: required field missing")
	ErrAdminEmptyDisplayName    = errors.New("admin_service: display name must not be empty")
)

// ServerStatus describes the xkmsd server state.
type ServerStatus struct {
	Running      bool   `json:"running"`
	Version      string `json:"version"`
	Address      string `json:"address"`
	Uptime       string `json:"uptime"`
	Platform     string `json:"platform"`
	BackendCount int    `json:"backend_count"`
}

// BackendInfo describes a registered key backend.
type BackendInfo struct {
	ID           string            `json:"id"`
	Type         string            `json:"type"`
	Enabled      bool              `json:"enabled"`
	Connected    bool              `json:"connected"`
	KeyCount     int               `json:"key_count"`
	Algorithms   []string          `json:"algorithms"`
	Description  string            `json:"description"`
	DisplayName  string            `json:"display_name,omitempty"`
	DeviceName   string            `json:"device_name,omitempty"`
	Capabilities BackendCapability `json:"capabilities,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// BackendCapability describes the cryptographic capabilities of a backend.
type BackendCapability struct {
	Signing          bool `json:"signing"`
	Encryption       bool `json:"encryption"`
	Decryption       bool `json:"decryption"`
	KeyEncapsulation bool `json:"key_encapsulation"`
	Sealing          bool `json:"sealing"`
	Attestation      bool `json:"attestation"`
	HardwareBacked   bool `json:"hardware_backed"`
	QuantumSigning   bool `json:"quantum_signing"`
	FIDO2            bool `json:"fido2"`
	PIV              bool `json:"piv"`
	OATH             bool `json:"oath"`
	Passwords        bool `json:"passwords"`
}

// BackendStatusProvider provides status information for a specific backend type.
type BackendStatusProvider interface {
	GetBackendStatus() (*BackendStatusInfo, error)
}

// BackendStatusInfo contains status details for a backend.
type BackendStatusInfo struct {
	Available    bool
	Connected    bool
	DeviceName   string
	Manufacturer string
	Firmware     string
	KeyCount     int
}

// KeyCounter provides a count of stored items.
type KeyCounter interface {
	KeyCount() int
}

// RemoteBackendListFunc returns backend info from the remote server.
type RemoteBackendListFunc func() ([]BackendInfo, error)

// TPMStatusProvider provides TPM status information.
type TPMStatusProvider interface {
	GetStatus() (*TPMStatus, error)
}

// PhoneStatusProvider provides phone device status information.
type PhoneStatusProvider interface {
	IsConnected() bool
	ConnectedDeviceName() string
	GetBackendDevices() ([]PairedDevice, error)
}

// AdminService exposes server administration operations to the frontend.
// The admin panel is hidden by default and only accessible to users with
// appropriate system privileges.
type AdminService struct {
	ctx              context.Context
	counters         []KeyCounter
	connInfoFn       func() *ConnectionInfo
	remoteBackendsFn RemoteBackendListFunc
	auditStore       audit.Store
	registry         backendregistry.Registry
	tpmProvider      TPMStatusProvider
	phoneProvider    PhoneStatusProvider
	pkcs11Tester     PKCS11ConnectionTester
	sealSvc          *SealService
	configUpdateFunc func(backendID string) error
	pivRegisterFn    func(backendID, category string)
}

// NewAdminService creates a new AdminService.
func NewAdminService() *AdminService {
	return &AdminService{}
}

// SetAuditStore sets the queryable audit store for admin operations.
func (s *AdminService) SetAuditStore(store audit.Store) {
	s.auditStore = store
}

// SetKeyCounters sets the services that can report key counts.
func (s *AdminService) SetKeyCounters(counters ...KeyCounter) {
	s.counters = counters
}

// SetConnectionInfoFunc sets the callback to retrieve connection state.
func (s *AdminService) SetConnectionInfoFunc(fn func() *ConnectionInfo) {
	s.connInfoFn = fn
}

// SetRemoteBackendsFunc sets the callback to list remote backends.
func (s *AdminService) SetRemoteBackendsFunc(fn RemoteBackendListFunc) {
	s.remoteBackendsFn = fn
}

// SetBackendRegistry sets the backend registry for dynamic backend discovery.
func (s *AdminService) SetBackendRegistry(registry backendregistry.Registry) {
	s.registry = registry
}

// SetPIVRegisterFunc sets the callback invoked when a new PIV-capable backend
// is configured. The callback registers the backend's PIV store in the global
// PIV manager so it can participate in PIV operations without a restart.
func (s *AdminService) SetPIVRegisterFunc(fn func(backendID, category string)) {
	s.pivRegisterFn = fn
}

// SetTPMStatusProvider sets the TPM status provider for TPM backend detection.
func (s *AdminService) SetTPMStatusProvider(provider TPMStatusProvider) {
	s.tpmProvider = provider
}

// SetPhoneStatusProvider sets the phone status provider for device backend detection.
func (s *AdminService) SetPhoneStatusProvider(provider PhoneStatusProvider) {
	s.phoneProvider = provider
}

// totalKeyCount sums key counts from all registered counters.
func (s *AdminService) totalKeyCount() int {
	total := 0
	for _, c := range s.counters {
		total += c.KeyCount()
	}
	return total
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *AdminService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// IsAdmin returns true if the current user has administrative privileges.
func (s *AdminService) IsAdmin() bool {
	u, err := user.Current()
	if err != nil {
		return false
	}
	// On Unix, root (uid 0) is admin. On Windows, check group membership.
	return u.Uid == "0"
}

// GetServerStatus returns the xkmsd server status.
func (s *AdminService) GetServerStatus() (*ServerStatus, error) {
	if s.connInfoFn != nil {
		info := s.connInfoFn()
		if info != nil && info.State == "connected" {
			backendCount := 0
			if s.remoteBackendsFn != nil {
				if backends, err := s.remoteBackendsFn(); err == nil {
					backendCount = len(backends)
				}
			}
			return &ServerStatus{
				Running:      true,
				Version:      info.Version,
				Address:      info.Address,
				Uptime:       "",
				Platform:     runtime.GOOS + "/" + runtime.GOARCH,
				BackendCount: backendCount,
			}, nil
		}
	}
	return &ServerStatus{
		Running:      false,
		Version:      Version,
		Address:      "",
		Uptime:       "",
		Platform:     runtime.GOOS + "/" + runtime.GOARCH,
		BackendCount: 0,
	}, nil
}

// ListBackends returns all registered key backends. When connected
// to a remote server, the server's backends are returned. Otherwise
// dynamic local backends are returned based on available hardware.
func (s *AdminService) ListBackends() ([]BackendInfo, error) {
	if s.remoteBackendsFn != nil {
		backends, err := s.remoteBackendsFn()
		if err == nil {
			return backends, nil
		}
		// Fall through to dynamic local backends on error.
	}
	backends := s.dynamicBackends()
	// Sort alphabetically by display name for consistent UI ordering.
	sort.Slice(backends, func(i, j int) bool {
		return backends[i].DisplayName < backends[j].DisplayName
	})
	return backends, nil
}

// dynamicBackends returns backends based on registry and live status queries.
// It also auto-detects hardware backends (TPM, phones) not in the registry.
func (s *AdminService) dynamicBackends() []BackendInfo {
	var backends []BackendInfo
	hasTPM := false
	hasPhone := false

	// Query registry if available.
	if s.registry != nil {
		registeredBackends := s.registry.List()
		slog.Debug("admin: dynamicBackends registry query",
			"count", len(registeredBackends),
			"registry_available", true)
		for _, rb := range registeredBackends {
			backend := s.convertRegisteredBackend(rb)
			slog.Debug("admin: registry backend",
				"id", backend.ID,
				"type", backend.Type,
				"enabled", backend.Enabled,
				"connected", backend.Connected,
				"piv", backend.Capabilities.PIV)

			// Enhance with live status from providers.
			switch rb.Category {
			case backendregistry.CategoryTPM2:
				s.enhanceTPMBackend(&backend)
				hasTPM = true
			case backendregistry.CategoryPhone:
				s.enhancePhoneBackend(&backend, rb)
				hasPhone = true
			}

			backends = append(backends, backend)
		}
	}

	// Auto-detect TPM if not already in registry. The TPM backend is shown
	// whenever the device node exists, even if TPM initialization fails.
	// This prevents the TPM from silently disappearing from the UI.
	if !hasTPM && s.tpmProvider != nil {
		if status, err := s.tpmProvider.GetStatus(); err == nil && status != nil && (status.Available || status.DeviceExists) {
			desc := "TPM 2.0 hardware key store"
			if status.Manufacturer != "" {
				desc = "TPM 2.0 - " + status.Manufacturer
			}
			metadata := map[string]string{
				"device_path": status.DevicePath,
			}
			if status.Manufacturer != "" {
				metadata["manufacturer"] = status.Manufacturer
				metadata["firmware"] = status.FirmwareVer
			}
			if status.InitError != "" {
				metadata["init_error"] = status.InitError
			}
			backends = append(backends, BackendInfo{
				ID:          "tpm2",
				Type:        "tpm2",
				DisplayName: "TPM 2.0",
				Enabled:     true,
				Connected:   status.Available,
				KeyCount:    0,
				Algorithms:  []string{"RSA", "ECDSA", "AES"},
				Description: desc,
				Capabilities: BackendCapability{
					Signing:        true,
					Encryption:     true,
					Decryption:     true,
					Sealing:        true,
					Attestation:    true,
					HardwareBacked: true,
					Passwords:      true,
					PIV:            true,
					FIDO2:          true,
				},
				Metadata: metadata,
			})
		}
	}

	// Auto-detect phone backends if not already in registry.
	if !hasPhone && s.phoneProvider != nil {
		devices, err := s.phoneProvider.GetBackendDevices()
		if err == nil && len(devices) > 0 {
			for _, device := range devices {
				connected := s.phoneProvider.IsConnected() && s.phoneProvider.ConnectedDeviceName() == device.Name
				backends = append(backends, BackendInfo{
					ID:          "phone-" + device.Address,
					Type:        "phone",
					DisplayName: device.Name,
					DeviceName:  device.Name,
					Enabled:     true,
					Connected:   connected,
					KeyCount:    0,
					Algorithms:  []string{"ECDSA"},
					Description: "Android phone BLE key backend",
					Capabilities: BackendCapability{
						Signing:        true,
						Attestation:    true,
						HardwareBacked: true,
					},
				})
			}
		}
	}

	// Add PKCS#11 backends from connected modules
	if s.pkcs11Tester != nil && s.pkcs11Tester.IsAvailable() {
		modules := s.pkcs11Tester.ListModules()
		connections := s.pkcs11Tester.ListConnections()

		// Create a map of connected slots
		connectedSlots := make(map[string]bool)
		for _, conn := range connections {
			key := fmt.Sprintf("%s:%d", conn.ModuleID, conn.SlotID)
			connectedSlots[key] = true
		}

		// Add each module with connection status
		for _, mod := range modules {
			// Check if any slot in this module is connected
			connected := false
			var connectedSlot string
			for _, slot := range mod.Slots {
				key := fmt.Sprintf("%s:%d", mod.ID, slot.SlotID)
				if connectedSlots[key] {
					connected = true
					connectedSlot = slot.Label
					break
				}
			}

			displayName := mod.DisplayName
			if displayName == "" {
				displayName = mod.ID
			}
			if connectedSlot != "" {
				displayName = fmt.Sprintf("%s (%s)", displayName, connectedSlot)
			}

			// YubiKey has its own native FIDO2 applet (HID USB) that browsers
			// talk to directly. The PIV applet does not — and cannot — proxy
			// FIDO2 credentials, so we suppress the FIDO2 capability for it.
			isYubiKey := strings.Contains(mod.LibraryPath, "libykcs11") || strings.Contains(mod.LibraryPath, "ykcs11")
			fido2Capable := !isYubiKey

			backends = append(backends, BackendInfo{
				ID:          mod.ID,
				Type:        "pkcs11",
				DisplayName: displayName,
				Enabled:     mod.State == "loaded",
				Connected:   connected,
				KeyCount:    0,
				Algorithms:  []string{"RSA", "ECDSA", "AES"},
				Description: fmt.Sprintf("PKCS#11 HSM - %s", mod.LibraryPath),
				Capabilities: BackendCapability{
					Signing:        true,
					Encryption:     true,
					Decryption:     true,
					Sealing:        true,
					HardwareBacked: true,
					FIDO2:          fido2Capable,
					PIV:            true,
					OATH:           true,
					Passwords:      true,
				},
				Metadata: map[string]string{
					"library_path": mod.LibraryPath,
					"slot_count":   fmt.Sprintf("%d", len(mod.Slots)),
				},
			})
		}
	}

	// If still empty, return minimal defaults with live status.
	if len(backends) == 0 {
		slog.Debug("admin: dynamicBackends empty, using fallback")
		backends = s.fallbackBackends()
	}

	slog.Debug("admin: dynamicBackends result", "count", len(backends))
	return backends
}

// convertRegisteredBackend converts a registry backend to BackendInfo.
func (s *AdminService) convertRegisteredBackend(rb *backendregistry.RegisteredBackend) BackendInfo {
	state := rb.State()
	connected := state == backendregistry.StateReady

	caps := BackendCapability{
		Signing:          rb.HasCapability(backendregistry.CapSigning),
		Encryption:       rb.HasCapability(backendregistry.CapEncryption),
		Decryption:       rb.HasCapability(backendregistry.CapEncryption), // Decryption implies encryption
		KeyEncapsulation: rb.HasCapability(backendregistry.CapEncryption), // For KEMs
		Sealing:          rb.HasCapability(backendregistry.CapSealing),
		Attestation:      rb.HasCapability(backendregistry.CapAttestation),
		HardwareBacked:   rb.Category != backendregistry.CategorySoftware,
		FIDO2:            rb.HasCapability(backendregistry.CapFIDO2),
		PIV:              rb.HasCapability(backendregistry.CapPIV),
		OATH:             rb.HasCapability(backendregistry.CapOATH),
		Passwords:        rb.HasCapability(backendregistry.CapPasswords),
	}

	displayName := rb.DisplayName
	if displayName == "" {
		displayName = s.defaultDisplayName(rb.Category, rb.ID)
	}

	return BackendInfo{
		ID:           rb.ID,
		Type:         string(rb.Category),
		DisplayName:  displayName,
		Enabled:      state != backendregistry.StateError && state != backendregistry.StateOffline,
		Connected:    connected,
		KeyCount:     0,
		Algorithms:   s.algorithmsForCategory(rb.Category),
		Description:  s.descriptionForCategory(rb.Category),
		Capabilities: caps,
		Metadata:     rb.Metadata,
	}
}

// enhanceTPMBackend updates a TPM backend with live status from TPMService.
// The backend remains Enabled (visible in the UI) as long as the TPM device
// node exists on the filesystem, even when the TPM cannot be opened. Only
// the Connected flag reflects whether the TPM is fully operational.
func (s *AdminService) enhanceTPMBackend(backend *BackendInfo) {
	if s.tpmProvider == nil {
		return
	}
	status, err := s.tpmProvider.GetStatus()
	if err != nil || status == nil {
		backend.Enabled = false
		backend.Connected = false
		return
	}
	// Keep the backend enabled (visible) when the device exists, even if
	// TPM initialization failed. This prevents the TPM from disappearing
	// from the UI due to transient init errors.
	backend.Enabled = status.Available || status.DeviceExists
	backend.Connected = status.Available
	if backend.Metadata == nil {
		backend.Metadata = make(map[string]string)
	}
	if status.Manufacturer != "" {
		backend.Description = "TPM 2.0 - " + status.Manufacturer
		backend.Metadata["manufacturer"] = status.Manufacturer
		backend.Metadata["firmware"] = status.FirmwareVer
	}
	backend.Metadata["device_path"] = status.DevicePath
	if status.InitError != "" {
		backend.Metadata["init_error"] = status.InitError
	}
}

// enhancePhoneBackend updates a phone backend with live status from PhoneService.
func (s *AdminService) enhancePhoneBackend(backend *BackendInfo, rb *backendregistry.RegisteredBackend) {
	if s.phoneProvider == nil {
		backend.Enabled = false
		backend.Connected = false
		return
	}
	backend.Connected = s.phoneProvider.IsConnected()
	if backend.Connected {
		backend.DeviceName = s.phoneProvider.ConnectedDeviceName()
		if backend.DeviceName != "" {
			backend.DisplayName = backend.DeviceName
		}
	}
	// Only show phone backend if there are devices marked as backends.
	devices, err := s.phoneProvider.GetBackendDevices()
	if err != nil || len(devices) == 0 {
		backend.Enabled = false
	} else {
		backend.Enabled = true
	}
}

// categoryDisplayNames maps backend categories to human-readable default names.
var categoryDisplayNames = map[backendregistry.BackendCategory]string{
	backendregistry.CategorySoftware: "Software",
	backendregistry.CategoryTPM2:     "TPM 2.0",
	backendregistry.CategoryPKCS11:   "PKCS#11",
	backendregistry.CategoryPhone:    "Phone",
	backendregistry.CategoryXKMS:     "Remote Server",
}

// defaultDisplayName returns a human-readable fallback display name for a
// backend based on its category. If the category has no mapping, the backend
// ID is returned as-is.
func (s *AdminService) defaultDisplayName(cat backendregistry.BackendCategory, id string) string {
	if name, ok := categoryDisplayNames[cat]; ok {
		return name
	}
	return id
}

// RenameBackend updates the display name of an existing backend. The new name
// is updated in the in-memory registry and persisted to the config file.
func (s *AdminService) RenameBackend(backendID string, newName string) error {
	if backendID == "" {
		return ErrAdminBackendNotFound
	}
	if newName == "" {
		return ErrAdminEmptyDisplayName
	}
	if s.registry == nil {
		return ErrAdminRegistryNotSet
	}

	// Update in-memory registry.
	if err := s.registry.UpdateDisplayName(backendID, newName); err != nil {
		return ErrAdminBackendNotFound
	}

	// Persist to config file.
	ucfg, loadErr := config.Load()
	if loadErr != nil {
		return fmt.Errorf("%w: %v", ErrAdminConfigLoadFailed, loadErr)
	}

	for i, existing := range ucfg.Backends.Local {
		if existing.ID == backendID {
			ucfg.Backends.Local[i].Name = newName
			if saveErr := config.Save(ucfg); saveErr != nil {
				return fmt.Errorf("%w: %v", ErrAdminConfigSaveFailed, saveErr)
			}
			return nil
		}
	}

	// Backend was in registry but not in config file (e.g., auto-detected).
	// The in-memory update succeeded, which is sufficient.
	return nil
}

// algorithmsForCategory returns the supported algorithms for a backend category.
func (s *AdminService) algorithmsForCategory(cat backendregistry.BackendCategory) []string {
	algorithms := map[backendregistry.BackendCategory][]string{
		backendregistry.CategorySoftware: {"RSA", "ECDSA", "Ed25519", "AES", "ML-KEM", "ML-DSA"},
		backendregistry.CategoryTPM2:     {"RSA", "ECDSA", "AES"},
		backendregistry.CategoryPKCS11:   {"RSA", "ECDSA", "AES"},
		backendregistry.CategoryPhone:    {"ECDSA"},
		backendregistry.CategoryXKMS:     {"RSA", "ECDSA", "Ed25519", "AES"},
	}
	if algs, ok := algorithms[cat]; ok {
		return algs
	}
	return []string{"RSA", "ECDSA"}
}

// descriptionForCategory returns the description for a backend category.
func (s *AdminService) descriptionForCategory(cat backendregistry.BackendCategory) string {
	descriptions := map[backendregistry.BackendCategory]string{
		backendregistry.CategorySoftware: "In-memory and file-backed software key store",
		backendregistry.CategoryTPM2:     "TPM 2.0 hardware key store",
		backendregistry.CategoryPKCS11:   "PKCS#11 hardware security module",
		backendregistry.CategoryPhone:    "Android phone BLE key backend",
		backendregistry.CategoryXKMS:     "Remote xkmsd server",
	}
	if desc, ok := descriptions[cat]; ok {
		return desc
	}
	return "Key backend"
}

// fallbackBackends returns default backends when registry is unavailable.
func (s *AdminService) fallbackBackends() []BackendInfo {
	backends := []BackendInfo{
		{
			ID:          "software",
			Type:        "software",
			DisplayName: "Software",
			Enabled:     true,
			Connected:   true,
			KeyCount:    0,
			Algorithms:  []string{"RSA", "ECDSA", "Ed25519", "AES", "ML-KEM"},
			Description: "In-memory and file-backed software key store",
			Capabilities: BackendCapability{
				Signing:          true,
				Encryption:       true,
				Decryption:       true,
				KeyEncapsulation: true,
				Sealing:          true,
				FIDO2:            true,
				PIV:              true,
				OATH:             true,
				Passwords:        true,
			},
		},
	}

	// Add TPM when the device node exists, even if init fails.
	if s.tpmProvider != nil {
		if status, err := s.tpmProvider.GetStatus(); err == nil && status != nil && (status.Available || status.DeviceExists) {
			desc := "TPM 2.0 hardware key store"
			if status.Manufacturer != "" {
				desc = "TPM 2.0 - " + status.Manufacturer
			}
			metadata := map[string]string{
				"device_path": status.DevicePath,
			}
			if status.Manufacturer != "" {
				metadata["manufacturer"] = status.Manufacturer
				metadata["firmware"] = status.FirmwareVer
			}
			if status.InitError != "" {
				metadata["init_error"] = status.InitError
			}
			backends = append(backends, BackendInfo{
				ID:          "tpm2",
				Type:        "tpm2",
				DisplayName: "TPM 2.0",
				Enabled:     true,
				Connected:   status.Available,
				KeyCount:    0,
				Algorithms:  []string{"RSA", "ECDSA", "AES"},
				Description: desc,
				Capabilities: BackendCapability{
					Signing:        true,
					Encryption:     true,
					Decryption:     true,
					Sealing:        true,
					Attestation:    true,
					HardwareBacked: true,
					Passwords:      true,
					PIV:            true,
					FIDO2:          true,
				},
				Metadata: metadata,
			})
		}
	}

	// Add phone backends that are marked as backends.
	if s.phoneProvider != nil {
		devices, err := s.phoneProvider.GetBackendDevices()
		if err == nil && len(devices) > 0 {
			for _, device := range devices {
				connected := s.phoneProvider.IsConnected() && s.phoneProvider.ConnectedDeviceName() == device.Name
				backends = append(backends, BackendInfo{
					ID:          "phone-" + device.Address,
					Type:        "phone",
					DisplayName: device.Name,
					DeviceName:  device.Name,
					Enabled:     true,
					Connected:   connected,
					KeyCount:    0,
					Algorithms:  []string{"ECDSA"},
					Description: "Android phone BLE key backend",
					Capabilities: BackendCapability{
						Signing:        true,
						Attestation:    true,
						HardwareBacked: true,
					},
				})
			}
		}
	}

	return backends
}

// GetBackendInfo returns details about a specific backend.
// TODO: wire to xkmsd backend info endpoint.
func (s *AdminService) GetBackendInfo(id string) (*BackendInfo, error) {
	if id == "" {
		return nil, ErrAdminBackendNotFound
	}
	backends, err := s.ListBackends()
	if err != nil {
		return nil, err
	}
	for i := range backends {
		if backends[i].ID == id {
			return &backends[i], nil
		}
	}
	return nil, ErrAdminBackendNotFound
}

// GetAuditLogs returns audit entries via the admin interface.
// This delegates to the AuditService but adds an authorization check.
// TODO: wire to a shared queryable audit store.
func (s *AdminService) GetAuditLogs(filter *AuditFilter) ([]AuditEntry, error) {
	if !s.IsAdmin() {
		return nil, ErrAdminNotAuthorized
	}
	// Delegate to shared audit query logic.
	auditSvc := NewAuditService(s.auditStore)
	auditSvc.SetContext(s.ctx)
	return auditSvc.GetEntries(filter)
}

// GetDefaultBackend returns the default backend ID from the registry.
// If no default is set, returns "software" as the fallback.
func (s *AdminService) GetDefaultBackend() string {
	if s.registry != nil {
		// Try to get default for the primary capability (signing).
		if backend, err := s.registry.GetDefault(backendregistry.CapSigning); err == nil && backend != nil {
			return backend.ID
		}
	}
	return "software"
}

// SetDefaultBackend sets the system-wide default backend. The backend must exist
// in the registry and be connected. This updates the registry defaults for all
// supported capabilities, syncs the seal service, and persists to config.
func (s *AdminService) SetDefaultBackend(backendID string) error {
	if s.registry == nil {
		return ErrAdminRegistryNotSet
	}

	// Validate backend exists in registry.
	backend, err := s.registry.Get(backendID)
	if err != nil {
		return ErrAdminBackendNotFound
	}

	// Verify the backend is connected.
	if backend.State() != backendregistry.StateReady {
		return ErrAdminBackendNotConnected
	}

	// Update registry defaults for all capabilities the backend supports.
	capabilities := []backendregistry.Capability{
		backendregistry.CapSigning,
		backendregistry.CapEncryption,
		backendregistry.CapSealing,
		backendregistry.CapAttestation,
		backendregistry.CapFIDO2,
		backendregistry.CapPIV,
		backendregistry.CapOATH,
		backendregistry.CapPasswords,
	}
	for _, cap := range capabilities {
		if backend.HasCapability(cap) {
			if setErr := s.registry.SetDefault(cap, backendID); setErr != nil {
				slog.Warn("failed to set default for capability",
					"capability", cap, "backend", backendID, "error", setErr)
			}
		}
	}

	// Sync seal service default.
	if s.sealSvc != nil {
		s.sealSvc.SetDefaultBackend(backendID)
	}

	// Persist to config.
	if s.configUpdateFunc != nil {
		if persistErr := s.configUpdateFunc(backendID); persistErr != nil {
			return persistErr
		}
	}

	return nil
}

// GetSystemDefaultBackend returns the system-wide default backend ID.
// If a seal service is configured, its default takes priority since it
// reflects the most recent explicit or auto-selected backend.
// Falls back to the registry signing default, then "software".
func (s *AdminService) GetSystemDefaultBackend() string {
	if s.sealSvc != nil {
		if backend := s.sealSvc.DefaultBackend(); backend != "" {
			return backend
		}
	}
	return s.GetDefaultBackend()
}

// ExportAuditLogs exports audit entries in the specified format.
// Supported formats: "json", "csv".
func (s *AdminService) ExportAuditLogs(format string) ([]byte, error) {
	if !s.IsAdmin() {
		return nil, ErrAdminNotAuthorized
	}
	validFormats := map[string]struct{}{
		"json": {},
		"csv":  {},
	}
	if _, ok := validFormats[format]; !ok {
		return nil, ErrAdminInvalidFormat
	}

	auditSvc := NewAuditService(s.auditStore)
	auditSvc.SetContext(s.ctx)

	entries, err := auditSvc.GetEntries(nil)
	if err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		return nil, ErrAuditNoEntries
	}

	switch format {
	case "json":
		return json.MarshalIndent(entries, "", "  ")
	case "csv":
		return auditSvc.exportCSV(entries)
	default:
		return nil, ErrAdminInvalidFormat
	}
}

// ConnectionTestResult describes the result of a backend connection test.
type ConnectionTestResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// TestBackendConnection tests connectivity to a backend with the given configuration.
// This allows the user to verify their configuration before adding the backend.
func (s *AdminService) TestBackendConnection(backendType string, config map[string]string) *ConnectionTestResult {
	testHandlers := map[string]func(map[string]string) *ConnectionTestResult{
		"pkcs11":  s.testPKCS11Connection,
		"yubikey": s.testYubiKeyConnection,
		"awskms":  s.testAWSKMSConnection,
		"gcpkms":  s.testGCPKMSConnection,
		"azurekv": s.testAzureKVConnection,
		"vault":   s.testVaultConnection,
	}

	handler, ok := testHandlers[backendType]
	if !ok {
		return &ConnectionTestResult{
			Success: false,
			Message: "Connection test not supported for this backend type",
		}
	}

	return handler(config)
}

// PKCS11ConnectionTester provides PKCS#11 connection testing and listing.
type PKCS11ConnectionTester interface {
	TestConnection(libraryPath string, slotID uint, userPIN string) error
	IsAvailable() bool
	ListModules() []PKCS11ModuleInfo
	ListConnections() []PKCS11ConnectionInfo
}

// SetPKCS11Tester sets the PKCS#11 connection tester.
func (s *AdminService) SetPKCS11Tester(tester PKCS11ConnectionTester) {
	s.pkcs11Tester = tester
}

// SetSealService sets the seal service for default backend synchronization.
func (s *AdminService) SetSealService(svc *SealService) {
	s.sealSvc = svc
}

// SetConfigUpdateFunc sets the callback to persist the default backend to config.
func (s *AdminService) SetConfigUpdateFunc(fn func(backendID string) error) {
	s.configUpdateFunc = fn
}

// testPKCS11Connection tests connectivity to a PKCS#11 module.
func (s *AdminService) testPKCS11Connection(config map[string]string) *ConnectionTestResult {
	libraryPath := config["library_path"]
	if libraryPath == "" {
		return &ConnectionTestResult{
			Success: false,
			Message: "Library path is required",
		}
	}

	userPIN := config["user_pin"]
	if userPIN == "" {
		return &ConnectionTestResult{
			Success: false,
			Message: "User PIN is required to test connection",
		}
	}

	// Parse slot ID (default to 0)
	var slotID uint
	if slotStr := config["slot_id"]; slotStr != "" {
		var slotVal uint64
		_, err := fmt.Sscanf(slotStr, "%d", &slotVal)
		if err == nil {
			slotID = uint(slotVal)
		}
	}

	// Use the tester if available
	if s.pkcs11Tester != nil {
		if err := s.pkcs11Tester.TestConnection(libraryPath, slotID, userPIN); err != nil {
			return &ConnectionTestResult{
				Success: false,
				Message: "Connection failed: " + err.Error(),
			}
		}
		return &ConnectionTestResult{
			Success: true,
			Message: fmt.Sprintf("Successfully connected to PKCS#11 token (slot %d)", slotID),
		}
	}

	// Fallback: just validate the config
	return &ConnectionTestResult{
		Success: true,
		Message: "PKCS#11 configuration valid (connection test requires PKCS#11 service)",
	}
}

// testYubiKeyConnection tests connectivity to a YubiKey via libykcs11.
// YubiKey uses the PKCS#11 interface, so this delegates to the PKCS#11 handler.
func (s *AdminService) testYubiKeyConnection(config map[string]string) *ConnectionTestResult {
	return s.testPKCS11Connection(config)
}

// testAWSKMSConnection tests connectivity to AWS KMS.
func (s *AdminService) testAWSKMSConnection(config map[string]string) *ConnectionTestResult {
	region := config["region"]
	if region == "" {
		return &ConnectionTestResult{
			Success: false,
			Message: "Region is required",
		}
	}

	// TODO: Implement actual AWS KMS connection test using AWS SDK
	// This should:
	// 1. Create a KMS client with the provided credentials
	// 2. Call ListKeys or similar to verify access
	// 3. Return success/failure with appropriate message
	return &ConnectionTestResult{
		Success: true,
		Message: "AWS KMS configuration valid (connection test not implemented)",
	}
}

// testGCPKMSConnection tests connectivity to GCP Cloud KMS.
func (s *AdminService) testGCPKMSConnection(config map[string]string) *ConnectionTestResult {
	project := config["project"]
	if project == "" {
		return &ConnectionTestResult{
			Success: false,
			Message: "Project ID is required",
		}
	}

	location := config["location"]
	if location == "" {
		return &ConnectionTestResult{
			Success: false,
			Message: "Location is required",
		}
	}

	keyring := config["keyring"]
	if keyring == "" {
		return &ConnectionTestResult{
			Success: false,
			Message: "Key Ring is required",
		}
	}

	// TODO: Implement actual GCP KMS connection test
	// This should:
	// 1. Create a KMS client with the provided credentials
	// 2. Try to get the keyring or list keys
	// 3. Return success/failure with appropriate message
	return &ConnectionTestResult{
		Success: true,
		Message: "GCP KMS configuration valid (connection test not implemented)",
	}
}

// testAzureKVConnection tests connectivity to Azure Key Vault.
func (s *AdminService) testAzureKVConnection(config map[string]string) *ConnectionTestResult {
	vaultURL := config["vault_url"]
	if vaultURL == "" {
		return &ConnectionTestResult{
			Success: false,
			Message: "Vault URL is required",
		}
	}

	// TODO: Implement actual Azure Key Vault connection test
	// This should:
	// 1. Create a Key Vault client with the provided credentials
	// 2. Try to list keys or get vault properties
	// 3. Return success/failure with appropriate message
	return &ConnectionTestResult{
		Success: true,
		Message: "Azure Key Vault configuration valid (connection test not implemented)",
	}
}

// testVaultConnection tests connectivity to HashiCorp Vault.
func (s *AdminService) testVaultConnection(config map[string]string) *ConnectionTestResult {
	address := config["address"]
	if address == "" {
		return &ConnectionTestResult{
			Success: false,
			Message: "Vault address is required",
		}
	}

	// TODO: Implement actual Vault connection test
	// This should:
	// 1. Create a Vault client with the provided address and token
	// 2. Try to authenticate or check health
	// 3. Return success/failure with appropriate message
	return &ConnectionTestResult{
		Success: true,
		Message: "HashiCorp Vault configuration valid (connection test not implemented)",
	}
}

// ConfigureBackend adds or updates a backend configuration.
// The backend is registered with the backend registry and persisted
// to the unified config file so it survives application restarts.
func (s *AdminService) ConfigureBackend(backendType string, params map[string]string) error {
	if s.registry == nil {
		return ErrAdminRegistryNotSet
	}

	// Build the LocalBackendConfig and RegisteredBackend from the params.
	localCfg, rb, err := s.buildBackendConfig(backendType, params)
	if err != nil {
		return err
	}

	// Load the unified config from disk.
	ucfg, loadErr := config.Load()
	if loadErr != nil {
		return fmt.Errorf("%w: %v", ErrAdminConfigLoadFailed, loadErr)
	}

	// Check for duplicate IDs and replace if updating.
	replaced := false
	for i, existing := range ucfg.Backends.Local {
		if existing.ID == localCfg.ID {
			ucfg.Backends.Local[i] = *localCfg
			replaced = true
			break
		}
	}
	if !replaced {
		ucfg.Backends.Local = append(ucfg.Backends.Local, *localCfg)
	}

	// Persist the updated config to disk.
	if saveErr := config.Save(ucfg); saveErr != nil {
		return fmt.Errorf("%w: %v", ErrAdminConfigSaveFailed, saveErr)
	}

	// Register the backend in the in-memory registry.
	if regErr := s.registry.Register(rb); regErr != nil {
		// Config is saved but in-memory registration failed.
		// Log the error — the backend will load on next restart.
		slog.Warn("backend saved to config but in-memory registration failed",
			"id", rb.ID, "error", regErr)
	}

	// Register the PIV store for newly configured PIV-capable backends
	// so they can participate in PIV operations without a restart.
	if rb.HasCapability(backendregistry.CapPIV) && s.pivRegisterFn != nil {
		s.pivRegisterFn(rb.ID, string(rb.Category))
	}

	return nil
}

// buildBackendConfig validates the params and constructs a LocalBackendConfig
// and a RegisteredBackend for the given backend type.
func (s *AdminService) buildBackendConfig(backendType string, params map[string]string) (*config.LocalBackendConfig, *backendregistry.RegisteredBackend, error) {
	id := params["id"]
	name := params["name"]
	if id == "" {
		return nil, nil, fmt.Errorf("%w: id", ErrAdminMissingField)
	}
	if name == "" {
		name = id
	}

	localCfg := &config.LocalBackendConfig{
		ID:       id,
		Category: backendType,
		Name:     name,
	}

	var category backendregistry.BackendCategory
	caps := map[backendregistry.Capability]bool{}

	switch backendType {
	case "pkcs11":
		libPath := params["library_path"]
		if libPath == "" {
			return nil, nil, fmt.Errorf("%w: library_path", ErrAdminMissingField)
		}
		slotID := 0
		if s, ok := params["slot_id"]; ok && s != "" {
			parsed, parseErr := strconv.Atoi(s)
			if parseErr != nil {
				return nil, nil, fmt.Errorf("%w: slot_id must be a number", ErrAdminMissingField)
			}
			slotID = parsed
		}
		localCfg.PKCS11 = &config.PKCS11BackendConfig{
			LibraryPath: libPath,
			SlotID:      slotID,
		}
		category = backendregistry.CategoryPKCS11
		caps[backendregistry.CapSigning] = true
		caps[backendregistry.CapEncryption] = true
		caps[backendregistry.CapSealing] = true

	case "tpm2":
		device := params["device"]
		if device == "" {
			device = "/dev/tpmrm0"
		}
		localCfg.TPM2 = &config.TPM2BackendConfig{
			Device: device,
		}
		category = backendregistry.CategoryTPM2
		caps[backendregistry.CapSigning] = true
		caps[backendregistry.CapEncryption] = true
		caps[backendregistry.CapSealing] = true
		caps[backendregistry.CapAttestation] = true

	default:
		return nil, nil, fmt.Errorf("%w: %s", ErrAdminInvalidBackendType, backendType)
	}

	rb := &backendregistry.RegisteredBackend{
		ID:           id,
		Location:     backendregistry.LocationLocal,
		Category:     category,
		DisplayName:  name,
		Capabilities: caps,
		Metadata:     make(map[string]string),
	}

	// Copy relevant params into metadata for display.
	for k, v := range params {
		if k != "id" && k != "name" {
			rb.Metadata[k] = v
		}
	}

	rb.SetState(backendregistry.StateReady)

	return localCfg, rb, nil
}

// AvailableBackendType describes a backend type that can be configured.
type AvailableBackendType struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Available   bool   `json:"available"`
}

// GetAvailableBackendTypes returns the list of backend types that are
// compiled into the binary and can be configured.
func (s *AdminService) GetAvailableBackendTypes() []AvailableBackendType {
	pkcs11Available := s.isPKCS11Available()
	slog.Info("GetAvailableBackendTypes called",
		"pkcs11_tester_nil", s.pkcs11Tester == nil,
		"pkcs11_available", pkcs11Available)

	// Get the list of available backends from the registry
	availableTypes := make(map[string]bool)

	if s.registry != nil {
		for _, backend := range s.registry.List() {
			availableTypes[string(backend.Category)] = true
		}
	}

	// Also check what backends are compiled in based on build tags
	// This is determined by the backend packages that are imported
	backendTypes := []AvailableBackendType{
		{
			Type:        "pkcs11",
			Name:        "PKCS#11 / HSM",
			Description: "Hardware Security Module via PKCS#11",
			Available:   s.isPKCS11Available(),
		},
		{
			Type:        "yubikey",
			Name:        "YubiKey",
			Description: "YubiKey PIV via PKCS#11 (libykcs11)",
			Available:   s.isPKCS11Available(),
		},
		{
			Type:        "awskms",
			Name:        "AWS KMS",
			Description: "Amazon Web Services Key Management Service",
			Available:   s.isAWSKMSAvailable(),
		},
		{
			Type:        "gcpkms",
			Name:        "GCP Cloud KMS",
			Description: "Google Cloud Platform Key Management Service",
			Available:   s.isGCPKMSAvailable(),
		},
		{
			Type:        "azurekv",
			Name:        "Azure Key Vault",
			Description: "Microsoft Azure Key Vault",
			Available:   s.isAzureKVAvailable(),
		},
		{
			Type:        "vault",
			Name:        "HashiCorp Vault",
			Description: "HashiCorp Vault Transit Secrets Engine",
			Available:   s.isVaultAvailable(),
		},
	}

	return backendTypes
}

// isPKCS11Available checks if PKCS#11 support is compiled in.
func (s *AdminService) isPKCS11Available() bool {
	// Check if the PKCS11 tester is available and reports itself as available
	if s.pkcs11Tester == nil {
		return false
	}
	return s.pkcs11Tester.IsAvailable()
}

// isAWSKMSAvailable checks if AWS KMS support is compiled in.
func (s *AdminService) isAWSKMSAvailable() bool {
	// TODO: Check if AWS KMS backend is compiled in
	// For now, return true as a placeholder
	return true
}

// isGCPKMSAvailable checks if GCP KMS support is compiled in.
func (s *AdminService) isGCPKMSAvailable() bool {
	// TODO: Check if GCP KMS backend is compiled in
	// For now, return true as a placeholder
	return true
}

// isAzureKVAvailable checks if Azure Key Vault support is compiled in.
func (s *AdminService) isAzureKVAvailable() bool {
	// TODO: Check if Azure KV backend is compiled in
	// For now, return true as a placeholder
	return true
}

// isVaultAvailable checks if HashiCorp Vault support is compiled in.
func (s *AdminService) isVaultAvailable() bool {
	// TODO: Check if Vault backend is compiled in
	// For now, return true as a placeholder
	return true
}
