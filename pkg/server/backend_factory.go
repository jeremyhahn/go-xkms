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

package server

import (
	"fmt"
	"path/filepath"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/pkcs8"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/symmetric"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
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

// Initialize creates backends from configuration and initializes the xkms.
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
		return &ErrStorageCreate{Resource: "certificate storage", Err: err}
	}

	backends := make(map[string]xkms.Backend)
	keyProviders := make(map[string]xkms.Backend)

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
		ks, err := xkms.New(&xkms.BackendConfig{
			Backend:     backend,
			CertStorage: certStorage,
		})
		if err != nil {
			fmt.Printf("Warning: Failed to create keystore for backend '%s': %v\n", bc.Name, err)
			continue
		}

		// Separate full-service backends from partial key providers
		switch bc.Type {
		case "pkcs8", "symmetric", "quantum", "frost", "threshold":
			keyProviders[bc.Name] = ks
		default:
			backends[bc.Name] = ks
		}
	}

	// Ensure at least one backend is available
	if len(backends) == 0 {
		return ErrNoBackendsAvailable
	}

	// Determine default backend
	defaultBackend := config.DefaultBackend
	if _, ok := backends[defaultBackend]; !ok {
		// Fall back to first available backend
		for name := range backends {
			defaultBackend = name
			break
		}
	}

	// Initialize the service
	serviceConfig := &xkms.ServiceConfig{
		Backends:       backends,
		KeyProviders:   keyProviders,
		DefaultBackend: defaultBackend,
	}

	return xkms.Initialize(serviceConfig)
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
			Name:    "symmetric",
			Type:    "symmetric",
			Enabled: true,
			Config: map[string]interface{}{
				"key_dir": "/tmp/keystore/symmetric",
			},
		},
		// Hardware backends (may not be available in all environments)
		{
			Name:    "pkcs11",
			Type:    "pkcs11",
			Enabled: true,
			Config: map[string]interface{}{
				"library_path": "/usr/lib/softhsm/libsofthsm2.so",
				"token_label":  "xkms",
				"pin":          "1234",
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
				"key_ring_id": "xkms",
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
		// Threshold signature backends (optional, requires build tags)
		{
			Name:    "frost",
			Type:    "frost",
			Enabled: true,
			Config: map[string]interface{}{
				"public_dir":            "/tmp/keystore/frost/public",
				"secret_dir":            "/tmp/keystore/frost/secrets",
				"secret_backend":        "pkcs8",
				"algorithm":             "FROST-Ed25519-SHA512",
				"threshold":             2,
				"total":                 3,
				"participant_id":        1,
				"enable_nonce_tracking": true,
			},
		},
	}
}

// createBackend creates a backend instance from configuration.
// Returns error if backend type is not compiled in or configuration is invalid.
func createBackend(config BackendConfig) (types.KeyProvider, error) {
	switch config.Type {
	case "pkcs8":
		return createPKCS8Backend(config)
	case "software":
		return createSoftwareBackend(config)
	case "symmetric":
		return createSymmetricBackend(config)
	case "pkcs11":
		return createPKCS11Backend(config)
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
	case "frost":
		return createFrostBackend(config)
	default:
		return nil, &ErrUnknownBackendType{Type: config.Type}
	}
}

// Backend creation functions
// These functions create backend instances from configuration.
// They use build tags appropriately so backends compile conditionally.

func createPKCS8Backend(config BackendConfig) (types.KeyProvider, error) {
	keyDir, ok := config.Config["key_dir"].(string)
	if !ok || keyDir == "" {
		keyDir = "/tmp/keystore/pkcs8"
	}

	keyStorage, err := createKeyStorage(keyDir)
	if err != nil {
		return nil, &ErrStorageCreate{Resource: "key storage", Err: err}
	}

	pkcs8Config := &pkcs8.Config{
		KeyStorage: keyStorage,
	}

	return pkcs8.NewBackend(pkcs8Config)
}

func createSoftwareBackend(config BackendConfig) (types.KeyProvider, error) {
	keyDir, ok := config.Config["key_dir"].(string)
	if !ok || keyDir == "" {
		keyDir = "/tmp/keystore/software"
	}

	keyStorage, err := createKeyStorage(keyDir)
	if err != nil {
		return nil, &ErrStorageCreate{Resource: "key storage", Err: err}
	}

	softwareConfig := &software.Config{
		KeyStorage: keyStorage,
		Tracker:    nil, // Use default memory tracker
	}

	return software.NewBackend(softwareConfig)
}

func createSymmetricBackend(config BackendConfig) (types.KeyProvider, error) {
	keyDir, ok := config.Config["key_dir"].(string)
	if !ok || keyDir == "" {
		keyDir = "/tmp/keystore/symmetric"
	}

	keyStorage, err := createKeyStorage(keyDir)
	if err != nil {
		return nil, &ErrStorageCreate{Resource: "key storage", Err: err}
	}

	symmetricConfig := &symmetric.Config{
		KeyStorage: keyStorage,
		Tracker:    nil, // Use default memory tracker
		RNGConfig:  nil, // Use default auto-detection
	}

	return symmetric.NewBackend(symmetricConfig)
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

// createStorage creates a storage backend based on the server's StorageConfig.
// The subdir is appended to the storage path for persistent engines.
func (s *Server) createStorage(subdir string) (storage.Backend, error) {
	cfg := s.config.Storage
	switch cfg.Backend {
	case "memory":
		return storage.NewMemoryBackend()
	case "pebble":
		path := filepath.Join(cfg.Path, subdir)
		return storage.NewPebble(path)
	case "file", "":
		path := filepath.Join(cfg.Path, subdir)
		return file.New(path)
	default:
		return nil, &ErrUnsupportedStorageBackend{Backend: cfg.Backend}
	}
}

// createStorageAt creates a storage backend using the server's configured
// storage engine but at the given absolute path. This is used for backend
// key storage paths that are configured independently of the metadata
// storage root (e.g., Backends.Software.Path, Backends.PKCS8.Path).
func (s *Server) createStorageAt(path string) (storage.Backend, error) {
	cfg := s.config.Storage
	switch cfg.Backend {
	case "memory":
		return storage.NewMemoryBackend()
	case "pebble":
		return storage.NewPebble(path)
	case "file", "":
		return file.New(path)
	default:
		return nil, &ErrUnsupportedStorageBackend{Backend: cfg.Backend}
	}
}
