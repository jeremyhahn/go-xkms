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

package rand

import (
	"fmt"
	"os"
	"sync"
)

// autoResolver automatically selects the best available RNG source.
// Preference order: TPM2 > PKCS#11 > Software
type autoResolver struct {
	resolver Resolver
	fallback Resolver
	mu       sync.RWMutex
}

var _ Resolver = (*autoResolver)(nil)

func newAutoResolver(cfg *Config) (Resolver, error) {
	// Try to find the best available RNG source
	// Priority: PKCS#11 > TPM2 > Software
	var resolver Resolver
	var fallback Resolver

	// Try PKCS#11 first (highest priority)
	if pkcs11Available() {
		if pkcs11Resolver, pkcs11Err := newPKCS11Resolver(cfg.PKCS11Config); pkcs11Err == nil { //nolint:staticcheck // SA4023: build-tag conditional
			if pkcs11Resolver.Available() {
				resolver = pkcs11Resolver
			} else {
				if closeErr := pkcs11Resolver.Close(); closeErr != nil {
					fmt.Fprintf(os.Stderr, "failed to close unavailable PKCS#11 resolver: %v\n", closeErr)
				}
			}
		}
	}

	// Try TPM2 if PKCS#11 not available
	if resolver == nil && tpm2Available() {
		if tpm2Resolver, tpm2Err := newTPM2Resolver(cfg.TPM2Config); tpm2Err == nil { //nolint:staticcheck // SA4023: build-tag conditional
			if tpm2Resolver.Available() {
				resolver = tpm2Resolver
			} else {
				if closeErr := tpm2Resolver.Close(); closeErr != nil {
					fmt.Fprintf(os.Stderr, "failed to close unavailable TPM2 resolver: %v\n", closeErr)
				}
			}
		}
	}

	// Fall back to software if no hardware available
	if resolver == nil {
		var err error
		resolver, err = newSoftwareResolver()
		if err != nil {
			return nil, err
		}
	}

	// Set up fallback if configured (non-fatal if it fails)
	if cfg.FallbackMode != "" {
		var err error
		fallback, err = newResolver(&Config{Mode: cfg.FallbackMode})
		if err != nil {
			// Fallback initialization failed, but this is not fatal
			// The primary resolver is still available
			fmt.Fprintf(os.Stderr, "fallback resolver (%s) unavailable: %v\n", cfg.FallbackMode, err)
			fallback = nil
		}
	}

	return &autoResolver{
		resolver: resolver,
		fallback: fallback,
	}, nil
}

func (a *autoResolver) Rand(n int) ([]byte, error) {
	a.mu.RLock()
	resolver := a.resolver
	fallback := a.fallback
	a.mu.RUnlock()

	result, err := resolver.Rand(n)
	if err != nil && fallback != nil {
		result, err = fallback.Rand(n)
	}
	return result, err
}

// Read implements io.Reader for compatibility with crypto/rand.Reader.
// This allows the auto resolver to be used with standard library
// functions that expect an io.Reader for randomness, such as
// rsa.GenerateKey, ecdsa.GenerateKey, and x509.CreateCertificate.
func (a *autoResolver) Read(p []byte) (n int, err error) {
	data, err := a.Rand(len(p))
	if err != nil {
		return 0, err
	}
	copy(p, data)
	return len(data), nil
}

func (a *autoResolver) Source() Source {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.resolver.Source()
}

func (a *autoResolver) Available() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.resolver.Available() || (a.fallback != nil && a.fallback.Available())
}

func (a *autoResolver) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	var primaryErr, fallbackErr error

	if a.resolver != nil {
		primaryErr = a.resolver.Close()
		if primaryErr != nil {
			fmt.Fprintf(os.Stderr, "failed to close primary resolver: %v\n", primaryErr)
		}
	}

	if a.fallback != nil {
		fallbackErr = a.fallback.Close()
		if fallbackErr != nil {
			fmt.Fprintf(os.Stderr, "failed to close fallback resolver: %v\n", fallbackErr)
		}
	}

	// Return the first error encountered, if any
	if primaryErr != nil {
		return fmt.Errorf("primary resolver close failed: %w", primaryErr)
	}
	if fallbackErr != nil {
		return fmt.Errorf("fallback resolver close failed: %w", fallbackErr)
	}

	return nil
}
