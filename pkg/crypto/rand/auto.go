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
		if pkcs11Resolver, pkcs11Err := newPKCS11Resolver(cfg.PKCS11Config); pkcs11Err == nil {
			if pkcs11Resolver.Available() {
				resolver = pkcs11Resolver
			} else {
				_ = pkcs11Resolver.Close()
			}
		}
	}

	// Try TPM2 if PKCS#11 not available
	if resolver == nil && tpm2Available() {
		if tpm2Resolver, tpm2Err := newTPM2Resolver(cfg.TPM2Config); tpm2Err == nil {
			if tpm2Resolver.Available() {
				resolver = tpm2Resolver
			} else {
				_ = tpm2Resolver.Close()
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

	// Set up fallback if configured
	if cfg.FallbackMode != "" {
		fallback, _ = newResolver(&Config{Mode: cfg.FallbackMode})
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

	if a.resolver != nil {
		_ = a.resolver.Close()
	}
	if a.fallback != nil {
		_ = a.fallback.Close()
	}
	return nil
}
