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

package xkms

import (
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
)

// AutoConfig configures automatic backend initialization.
type AutoConfig struct {
	// DataDir is the base directory for key and certificate storage.
	// When empty, in-memory storage is used for all backends.
	DataDir string

	// DefaultBackend overrides the default backend selection.
	// When empty, defaults to "software". If the specified backend
	// is not available, the first successfully initialized backend is used.
	DefaultBackend string

	// BackendConfigs provides per-backend configuration overrides.
	// Only backends returned by SupportedBackends() with registered
	// factories will be initialized. Keys are BackendType constants.
	//
	// Common configuration keys supported by most backends:
	//   - "key_dir" (string): Directory for key storage
	//
	// Backend-specific keys are documented on each registration file's
	// factory function.
	BackendConfigs map[BackendType]map[string]interface{}
}

// AutoInitialize discovers compiled-in backends via the registry and
// initializes the XKMSService using registered factory functions.
//
// If config is nil, sensible defaults are used: in-memory storage for all
// backends with "software" as the default backend.
//
// Backends that fail to initialize (e.g., no TPM hardware available) are
// skipped with a warning log. Only backends with both a registered type
// AND a registered factory function are attempted.
//
// Returns ErrNoBackendsAvailable if no backends could be initialized.
// Returns an error from Initialize if the service is already initialized.
func AutoInitialize(config *AutoConfig) error {
	if config == nil {
		config = &AutoConfig{}
	}

	supported := SupportedBackends()
	if len(supported) == 0 {
		return ErrNoBackendsAvailable
	}

	// Create shared certificate storage
	certStorage, err := createCertStorage(config.DataDir)
	if err != nil {
		return err
	}

	// Iterate supported backends, create KeyProviders via factories.
	// Full-service backends go into backends map; partial key providers
	// go into keyProviders map.
	backends := make(map[string]Backend, len(supported))
	keyProviders := make(map[string]Backend)
	for _, bt := range supported {
		factory, ok := GetBackendFactory(bt)
		if !ok {
			slog.Warn("no factory registered for backend, skipping",
				"backend", string(bt))
			continue
		}

		backendConfig := resolveBackendConfig(config, bt)

		kp, factoryErr := factory(backendConfig)
		if factoryErr != nil {
			slog.Warn("failed to initialize backend, skipping",
				"backend", string(bt),
				"error", factoryErr)
			continue
		}

		ks, newErr := New(&BackendConfig{
			Backend:     kp,
			CertStorage: certStorage,
		})
		if newErr != nil {
			slog.Warn("failed to create keystore for backend, skipping",
				"backend", string(bt),
				"error", newErr)
			continue
		}

		if IsKeyProviderType(bt) {
			keyProviders[string(bt)] = ks
		} else {
			backends[string(bt)] = ks
		}
	}

	if len(backends) == 0 {
		return ErrNoBackendsAvailable
	}

	// Resolve default backend name
	defaultBackend := resolveDefaultBackend(config.DefaultBackend, backends)

	return Initialize(&ServiceConfig{
		Backends:       backends,
		KeyProviders:   keyProviders,
		DefaultBackend: defaultBackend,
	})
}

// createCertStorage creates the certificate storage backend.
// Uses file-based storage when dataDir is non-empty, otherwise in-memory.
func createCertStorage(dataDir string) (storage.Backend, error) {
	if dataDir == "" {
		return storage.New(), nil
	}
	certDir := dataDir + "/certs"
	return file.New(certDir)
}

// resolveBackendConfig returns the configuration map for a given backend type.
// It merges the data directory default with any user-provided overrides.
func resolveBackendConfig(config *AutoConfig, bt BackendType) map[string]interface{} {
	backendConfig := make(map[string]interface{})

	// Apply user overrides if provided
	if config.BackendConfigs != nil {
		if bc, ok := config.BackendConfigs[bt]; ok {
			for k, v := range bc {
				backendConfig[k] = v
			}
		}
	}

	// Set key_dir default from DataDir if not already specified.
	// Each full-service backend gets its own subdirectory (e.g., "software/",
	// "tpm2/"). Key providers (pkcs8, symmetric) share the software directory.
	// Note: storage.KeyPath() adds a "keys/" prefix internally, so key_dir
	// should NOT include a trailing "/keys" to avoid double nesting.
	if config.DataDir != "" {
		if _, ok := backendConfig["key_dir"]; !ok {
			dir := string(bt)
			if IsKeyProviderType(bt) {
				dir = "software"
			}
			backendConfig["key_dir"] = config.DataDir + "/" + dir
		}
	}

	return backendConfig
}

// resolveDefaultBackend determines which backend should be the default.
// If the requested default is available, it is used. Otherwise, the first
// available backend is selected deterministically by iterating sorted keys.
func resolveDefaultBackend(requested string, backends map[string]Backend) string {
	if requested == "" {
		requested = string(BackendSoftware)
	}

	if _, ok := backends[requested]; ok {
		return requested
	}

	// Fall back to the first available backend (sorted for determinism)
	names := make([]BackendType, 0, len(backends))
	for name := range backends {
		names = append(names, BackendType(name))
	}
	sortBackends(names)

	return string(names[0])
}
