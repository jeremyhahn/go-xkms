// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package grpc

import (
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// BackendRegistry manages multiple keystore backends
type BackendRegistry struct {
	mu        sync.RWMutex
	keystores map[string]keychain.KeyStore
}

// NewBackendRegistry creates a new backend registry
func NewBackendRegistry() *BackendRegistry {
	return &BackendRegistry{
		keystores: make(map[string]keychain.KeyStore),
	}
}

// Register registers a keystore backend with the given name
func (m *BackendRegistry) Register(name string, ks keychain.KeyStore) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.keystores[name]; exists {
		return fmt.Errorf("backend %s already registered", name)
	}

	m.keystores[name] = ks
	return nil
}

// Get retrieves a keystore by backend name
func (m *BackendRegistry) Get(name string) (keychain.KeyStore, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ks, exists := m.keystores[name]
	if !exists {
		return nil, fmt.Errorf("backend %s not found", name)
	}

	return ks, nil
}

// List returns information about all registered backends
func (m *BackendRegistry) List() []BackendInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	infos := make([]BackendInfo, 0, len(m.keystores))
	for name, ks := range m.keystores {
		backend := ks.Backend()
		caps := backend.Capabilities()

		infos = append(infos, BackendInfo{
			Name:               name,
			Type:               string(backend.Type()),
			Description:        getBackendDescription(backend.Type()),
			HardwareBacked:     caps.HardwareBacked,
			SupportsSigning:    caps.Signing,
			SupportsDecryption: caps.Decryption,
			SupportsRotation:   caps.KeyRotation,
		})
	}

	return infos
}

// Close closes all registered keystores
func (m *BackendRegistry) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	for name, ks := range m.keystores {
		if err := ks.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close backend %s: %w", name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing backends: %v", errs)
	}

	return nil
}

// BackendInfo contains information about a backend
type BackendInfo struct {
	Name               string
	Type               string
	Description        string
	HardwareBacked     bool
	SupportsSigning    bool
	SupportsDecryption bool
	SupportsRotation   bool
}

// getBackendDescription returns a human-readable description for a backend type
func getBackendDescription(bt types.BackendType) string {
	descriptions := map[types.BackendType]string{
		types.BackendTypePKCS8:   "Software-based PKCS#8 key storage",
		types.BackendTypePKCS11:  "Hardware Security Module (PKCS#11)",
		types.BackendTypeTPM2:    "Trusted Platform Module 2.0",
		types.BackendTypeAWSKMS:  "AWS Key Management Service",
		types.BackendTypeGCPKMS:  "Google Cloud Key Management Service",
		types.BackendTypeAzureKV: "Azure Key Vault",
		types.BackendTypeVault:   "HashiCorp Vault",
	}

	if desc, ok := descriptions[bt]; ok {
		return desc
	}

	return string(bt)
}
