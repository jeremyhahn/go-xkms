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

//go:build pkcs11

package cmd

import (
	"log/slog"
	"strings"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// pivPINSecret seals s into a *secure.Secret for PIVPKCS11StorageConfig's
// PIN/SOPIN fields. An empty s returns nil: no PIN was configured.
//
// createPKCS11PIVStorage has no error return to propagate a sealing
// failure through, so a failure is logged and treated as "no PIN
// configured" rather than propagated, mirroring xkey's fido2PINSecret. In
// practice this path is unreachable: the underlying memguard allocator
// panics the whole process on allocation failure before NewSecret could
// return an error here.
func pivPINSecret(s string) *secure.Secret {
	if s == "" {
		return nil
	}
	secret, err := secure.NewSecret([]byte(s))
	if err != nil {
		slog.Default().Error("piv: failed to seal PKCS#11 PIN into protected memory", "error", err)
		return nil
	}
	return secret
}

// createPKCS11PIVStorage creates a PKCS#11-backed PIV certificate storage.
// It opens a new PKCS#11 session using the library path, token label, and PIN
// from the PIV configuration.
func createPKCS11PIVStorage(cfg *PIVConfig, logger *slog.Logger) (xkms.PIVCertificateStorage, error) {
	logger.Info("initializing PKCS#11 PIV certificate storage",
		slog.String("library", cfg.PKCS11Library),
		slog.String("token", cfg.PKCS11Token),
	)

	isYubiKey := strings.Contains(strings.ToLower(cfg.PKCS11Library), "ykcs11")
	return xkms.NewPIVPKCS11Backend(&xkms.PIVPKCS11StorageConfig{
		LibraryPath: cfg.PKCS11Library,
		TokenLabel:  cfg.PKCS11Token,
		SlotID:      -1, // Use TokenLabel for resolution
		PIN:         pivPINSecret(cfg.PKCS11PIN),
		SOPIN:       pivPINSecret(cfg.PKCS11SOPIN),
		RequireSO:   isYubiKey,
	})
}

// ensurePKCS11Backend initializes the xkms PKCS#11 backend and sets up the
// PIV backend resolver so that GeneratePIVKey can delegate to the hardware
// token for key generation.
func ensurePKCS11Backend(cfg *PIVConfig, logger *slog.Logger) error {
	// Skip if xkms is already initialized (e.g., second call in same process).
	if xkms.IsInitialized() {
		return ensurePKCS11BackendResolver(logger)
	}

	logger.Info("initializing xkms PKCS#11 backend",
		slog.String("library", cfg.PKCS11Library),
		slog.String("token", cfg.PKCS11Token),
	)

	backendConfig := map[string]interface{}{
		"library": cfg.PKCS11Library,
		"label":   cfg.PKCS11Token,
		"pin":     cfg.PKCS11PIN,
	}
	if cfg.PKCS11SOPIN != "" {
		backendConfig["so_pin"] = cfg.PKCS11SOPIN
	}

	if err := xkms.AutoInitialize(&xkms.AutoConfig{
		DefaultBackend: string(xkms.BackendPKCS11),
		BackendConfigs: map[xkms.ServiceBackendType]map[string]interface{}{
			xkms.BackendPKCS11: backendConfig,
		},
	}); err != nil {
		return err
	}

	// AutoInitialize creates the backend but does not authenticate.
	// Login establishes the PKCS#11 session pool required for all operations.
	backend, err := xkms.GetBackend("pkcs11")
	if err != nil {
		return err
	}
	type loginer interface{ Login() error }
	if l, ok := backend.KeyProvider().(loginer); ok {
		if loginErr := l.Login(); loginErr != nil {
			return loginErr
		}
		logger.Debug("PKCS#11 backend login successful")
	}

	return ensurePKCS11BackendResolver(logger)
}

// ensurePKCS11BackendResolver wires the PIV backend resolver to the initialized
// xkms service so PIV key generation uses the PKCS#11 hardware backend.
func ensurePKCS11BackendResolver(logger *slog.Logger) error {
	svc, err := xkms.Get()
	if err != nil {
		return err
	}
	logger.Debug("setting PIV backend resolver for PKCS#11")
	return svc.InitPIVBackendResolver()
}
