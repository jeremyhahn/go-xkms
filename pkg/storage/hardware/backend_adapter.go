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

package hardware

import (
	"crypto/x509"
	"fmt"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

// HardwareBackendAdapter wraps a HardwareCertStorage to implement storage.Backend.
// This allows hardware certificate storage to be used wherever storage.Backend is expected,
// by converting between byte-based storage operations and certificate-specific operations.
//
// Key Mapping:
//   - "certs/{id}.pem" -> SaveCert/GetCert
//   - "certs/{id}-chain.pem" -> SaveCertChain/GetCertChain
//
// This adapter allows HardwareCertStorage implementations (PKCS#11, TPM2) to be used
// as generic storage backends while maintaining certificate-specific semantics.
type HardwareBackendAdapter struct {
	hardware HardwareCertStorage
	mu       sync.RWMutex
}

// NewHardwareBackendAdapter creates a new adapter that wraps a HardwareCertStorage
// to implement the storage.Backend interface.
func NewHardwareBackendAdapter(hardware HardwareCertStorage) storage.Backend {
	return &HardwareBackendAdapter{
		hardware: hardware,
	}
}

// Get retrieves certificate data by key.
// Supports keys: "certs/{id}.pem" and "certs/{id}-chain.pem"
func (a *HardwareBackendAdapter) Get(key string) ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Parse key to determine operation
	if !strings.HasPrefix(key, "certs/") {
		return nil, fmt.Errorf("hardware storage only supports certificate keys (certs/*): got %s", key)
	}

	// Check if it's a chain request
	if strings.HasSuffix(key, "-chain.pem") {
		id := strings.TrimPrefix(key, "certs/")
		id = strings.TrimSuffix(id, "-chain.pem")

		chain, err := a.hardware.GetCertChain(id)
		if err != nil {
			return nil, err
		}

		// Concatenate DER-encoded certificates
		var data []byte
		for _, cert := range chain {
			data = append(data, cert.Raw...)
		}
		return data, nil
	}

	// Single certificate request
	if strings.HasSuffix(key, ".pem") {
		id := strings.TrimPrefix(key, "certs/")
		id = strings.TrimSuffix(id, ".pem")

		cert, err := a.hardware.GetCert(id)
		if err != nil {
			return nil, err
		}
		return cert.Raw, nil
	}

	return nil, fmt.Errorf("unsupported key format: %s", key)
}

// Put stores certificate data by key.
// Supports keys: "certs/{id}.pem" and "certs/{id}-chain.pem"
func (a *HardwareBackendAdapter) Put(key string, value []byte, opts *storage.Options) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !strings.HasPrefix(key, "certs/") {
		return fmt.Errorf("hardware storage only supports certificate keys (certs/*): got %s", key)
	}

	// Check if it's a chain
	if strings.HasSuffix(key, "-chain.pem") {
		id := strings.TrimPrefix(key, "certs/")
		id = strings.TrimSuffix(id, "-chain.pem")

		// Parse DER data as certificate chain
		chain, err := parseDERChain(value)
		if err != nil {
			return fmt.Errorf("failed to parse certificate chain: %w", err)
		}

		return a.hardware.SaveCertChain(id, chain)
	}

	// Single certificate
	if strings.HasSuffix(key, ".pem") {
		id := strings.TrimPrefix(key, "certs/")
		id = strings.TrimSuffix(id, ".pem")

		// Parse DER data as single certificate
		cert, err := x509.ParseCertificate(value)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}

		return a.hardware.SaveCert(id, cert)
	}

	return fmt.Errorf("unsupported key format: %s", key)
}

// Delete removes a certificate by key.
func (a *HardwareBackendAdapter) Delete(key string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !strings.HasPrefix(key, "certs/") {
		return fmt.Errorf("hardware storage only supports certificate keys (certs/*): got %s", key)
	}

	// Extract ID from key
	id := strings.TrimPrefix(key, "certs/")
	id = strings.TrimSuffix(id, ".pem")
	id = strings.TrimSuffix(id, "-chain.pem")

	return a.hardware.DeleteCert(id)
}

// List returns all certificate keys with the given prefix.
func (a *HardwareBackendAdapter) List(prefix string) ([]string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Get all certificate IDs
	ids, err := a.hardware.ListCerts()
	if err != nil {
		return nil, err
	}

	// Convert IDs to keys
	keys := make([]string, 0, len(ids))
	for _, id := range ids {
		key := "certs/" + id + ".pem"
		if prefix == "" || strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// Exists checks if a certificate exists by key.
func (a *HardwareBackendAdapter) Exists(key string) (bool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if !strings.HasPrefix(key, "certs/") {
		return false, nil
	}

	// Extract ID from key
	id := strings.TrimPrefix(key, "certs/")
	id = strings.TrimSuffix(id, ".pem")
	id = strings.TrimSuffix(id, "-chain.pem")

	return a.hardware.CertExists(id)
}

// Close closes the underlying hardware storage.
func (a *HardwareBackendAdapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.hardware.Close()
}

// GetHardwareStorage returns the underlying HardwareCertStorage.
// This allows callers to access hardware-specific methods if needed.
func (a *HardwareBackendAdapter) GetHardwareStorage() HardwareCertStorage {
	return a.hardware
}

// parseDERChain parses concatenated DER-encoded certificates.
func parseDERChain(data []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	remaining := data

	for len(remaining) > 0 {
		cert, err := x509.ParseCertificate(remaining)
		if err != nil {
			// Try parsing what we have so far
			if len(chain) > 0 {
				return chain, nil
			}
			return nil, err
		}

		chain = append(chain, cert)

		// Move past this certificate
		if len(remaining) <= len(cert.Raw) {
			break
		}
		remaining = remaining[len(cert.Raw):]
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificates found in data")
	}

	return chain, nil
}

// Ensure HardwareBackendAdapter implements storage.Backend
var _ storage.Backend = (*HardwareBackendAdapter)(nil)
