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

package server

import (
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/backend/aes"
	"github.com/jeremyhahn/go-keychain/pkg/backend/pkcs8"
	"github.com/jeremyhahn/go-keychain/pkg/backend/software"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// BackendConfig contains configuration for a single backend
type BackendConfig struct {
	Name    string                 // Backend name (pkcs8, pkcs11, tpm2, etc.)
	Type    string                 // Backend type identifier
	Enabled bool                   // Whether this backend is enabled
	Config  map[string]interface{} // Backend-specific configuration
}

// BackendFactoryConfig contains configuration for backend initialization
type BackendFactoryConfig struct {
	DefaultBackend string          // Default backend to use if not specified
	Backends       []BackendConfig // List of backend configurations
}

// Initialize creates backends from configuration and initializes the keychain.
// If config is nil, it will initialize all compiled-in backends with defaults.
// Returns error if no backends could be initialized.
func Initialize(config *BackendFactoryConfig) error {
	if config == nil {
		// Auto-detect and initialize all compiled-in backends with defaults
		config = &BackendFactoryConfig{
			DefaultBackend: "pkcs8",
			Backends:       getDefaultBackendConfigs(),
		}
	}

	// Create shared certificate storage (certs are always stored externally)
	certDir := "/tmp/keystore/certs"
	certStorage, err := createCertStorage(certDir)
	if err != nil {
		return fmt.Errorf("failed to create certificate storage: %w", err)
	}

	keystores := make(map[string]keychain.KeyStore)

	// Initialize each enabled backend
	for _, bc := range config.Backends {
		if !bc.Enabled {
			continue
		}

		backend, err := createBackend(bc)
		if err != nil {
			// Log warning but continue - some backends may not be available
			// in certain environments (e.g., no TPM, no HSM)
			fmt.Printf("Warning: Failed to initialize backend '%s': %v\n", bc.Name, err)
			continue
		}

		// Wrap backend in KeyStore with shared cert storage
		ks, err := keychain.New(&keychain.Config{
			Backend:     backend,
			CertStorage: certStorage,
		})
		if err != nil {
			fmt.Printf("Warning: Failed to create keystore for backend '%s': %v\n", bc.Name, err)
			continue
		}
		keystores[bc.Name] = ks
	}

	// Ensure at least one backend is available
	if len(keystores) == 0 {
		return fmt.Errorf("no backends available - at least one backend must be initialized")
	}

	// Determine default backend
	defaultBackend := config.DefaultBackend
	if _, ok := keystores[defaultBackend]; !ok {
		// Fall back to first available backend
		for name := range keystores {
			defaultBackend = name
			break
		}
	}

	// Initialize the facade
	facadeConfig := &keychain.FacadeConfig{
		Backends:       keystores,
		DefaultBackend: defaultBackend,
	}

	return keychain.Initialize(facadeConfig)
}

// getDefaultBackendConfigs returns default configurations for all compiled-in backends.
// Backends that aren't compiled in (due to build tags) will fail gracefully during initialization.
func getDefaultBackendConfigs() []BackendConfig {
	return []BackendConfig{
		{
			Name:    "pkcs8",
			Type:    "pkcs8",
			Enabled: true,
			Config: map[string]interface{}{
				"key_dir": "/tmp/keystore/pkcs8",
			},
		},
		{
			Name:    "software",
			Type:    "software",
			Enabled: true,
			Config: map[string]interface{}{
				"key_dir": "/tmp/keystore/software",
			},
		},
		{
			Name:    "aes",
			Type:    "aes",
			Enabled: true,
			Config: map[string]interface{}{
				"key_dir": "/tmp/keystore/aes",
			},
		},
		// Hardware backends (may not be available in all environments)
		{
			Name:    "pkcs11",
			Type:    "pkcs11",
			Enabled: true,
			Config: map[string]interface{}{
				"library_path": "/usr/lib/softhsm/libsofthsm2.so",
				"token_label":  "keychain",
				"pin":          "1234",
			},
		},
		{
			Name:    "smartcardhsm",
			Type:    "smartcardhsm",
			Enabled: true,
			Config: map[string]interface{}{
				"library_path":   "/usr/lib/opensc-pkcs11.so",
				"token_label":    "SmartCard-HSM",
				"pin":            "648219",
				"dkek_shares":    5,
				"dkek_threshold": 3,
			},
		},
		{
			Name:    "tpm2",
			Type:    "tpm2",
			Enabled: true,
			Config: map[string]interface{}{
				"device": "/dev/tpmrm0",
			},
		},
		// Cloud backends (will fail if credentials not available)
		{
			Name:    "awskms",
			Type:    "awskms",
			Enabled: true,
			Config: map[string]interface{}{
				"region": "us-east-1",
			},
		},
		{
			Name:    "gcpkms",
			Type:    "gcpkms",
			Enabled: true,
			Config: map[string]interface{}{
				"project_id":  "my-project",
				"location_id": "us-east1",
				"key_ring_id": "keychain",
			},
		},
		{
			Name:    "azurekv",
			Type:    "azurekv",
			Enabled: true,
			Config:  map[string]interface{}{
				// Will use environment variables for Azure authentication
			},
		},
		{
			Name:    "vault",
			Type:    "vault",
			Enabled: true,
			Config: map[string]interface{}{
				"address": "http://localhost:8200",
				"token":   "", // Will use VAULT_TOKEN env var
			},
		},
	}
}

// createBackend creates a backend instance from configuration.
// Returns error if backend type is not compiled in or configuration is invalid.
func createBackend(config BackendConfig) (types.Backend, error) {
	switch config.Type {
	case "pkcs8":
		return createPKCS8Backend(config)
	case "software":
		return createSoftwareBackend(config)
	case "aes":
		return createAESBackend(config)
	case "pkcs11":
		return createPKCS11Backend(config)
	case "smartcardhsm":
		return createSmartCardHSMBackend(config)
	case "tpm2":
		return createTPM2Backend(config)
	case "awskms":
		return createAWSKMSBackend(config)
	case "gcpkms":
		return createGCPKMSBackend(config)
	case "azurekv":
		return createAzureKVBackend(config)
	case "vault":
		return createVaultBackend(config)
	default:
		return nil, fmt.Errorf("unknown backend type: %s", config.Type)
	}
}

// Backend creation functions
// These functions create backend instances from configuration.
// They use build tags appropriately so backends compile conditionally.

func createPKCS8Backend(config BackendConfig) (types.Backend, error) {
	keyDir, ok := config.Config["key_dir"].(string)
	if !ok || keyDir == "" {
		keyDir = "/tmp/keystore/pkcs8"
	}

	keyStorage, err := createKeyStorage(keyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create key storage: %w", err)
	}

	pkcs8Config := &pkcs8.Config{
		KeyStorage: keyStorage,
	}

	return pkcs8.NewBackend(pkcs8Config)
}

func createSoftwareBackend(config BackendConfig) (types.Backend, error) {
	keyDir, ok := config.Config["key_dir"].(string)
	if !ok || keyDir == "" {
		keyDir = "/tmp/keystore/software"
	}

	keyStorage, err := createKeyStorage(keyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create key storage: %w", err)
	}

	softwareConfig := &software.Config{
		KeyStorage: keyStorage,
		Tracker:    nil, // Use default memory tracker
	}

	return software.NewBackend(softwareConfig)
}

func createAESBackend(config BackendConfig) (types.Backend, error) {
	keyDir, ok := config.Config["key_dir"].(string)
	if !ok || keyDir == "" {
		keyDir = "/tmp/keystore/aes"
	}

	keyStorage, err := createKeyStorage(keyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create key storage: %w", err)
	}

	aesConfig := &aes.Config{
		KeyStorage: keyStorage,
		Tracker:    nil, // Use default memory tracker
		RNGConfig:  nil, // Use default auto-detection
	}

	return aes.NewBackend(aesConfig)
}

// Helper function to create key storage
func createKeyStorage(keyDir string) (storage.Backend, error) {
	if keyDir == "" || keyDir == "memory" {
		return storage.New(), nil
	}
	return file.New(keyDir)
}

func createCertStorage(certDir string) (storage.Backend, error) {
	if certDir == "" || certDir == "memory" {
		return storage.New(), nil
	}
	return file.New(certDir)
}
