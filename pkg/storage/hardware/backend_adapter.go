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

package hardware

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
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
func (a *HardwareBackendAdapter) Get(_ context.Context, key string) ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Parse key to determine operation
	if !strings.HasPrefix(key, "certs/") {
		return nil, &errs.Message{Msg: fmt.Sprintf("hardware storage only supports certificate keys (certs/*): got %s", key)}
	}

	return a.readRecord(key)
}

// readRecord returns the DER bytes of the one record key names; the caller
// holds a.mu.
func (a *HardwareBackendAdapter) readRecord(key string) ([]byte, error) {
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

	return nil, &errs.Message{Msg: fmt.Sprintf("unsupported key format: %s", key)}
}

// Put stores certificate data by key.
// Supports keys: "certs/{id}.pem" and "certs/{id}-chain.pem"
func (a *HardwareBackendAdapter) Put(_ context.Context, key string, value []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !strings.HasPrefix(key, "certs/") {
		return &errs.Message{Msg: fmt.Sprintf("hardware storage only supports certificate keys (certs/*): got %s", key)}
	}

	// Check if it's a chain
	if strings.HasSuffix(key, "-chain.pem") {
		id := strings.TrimPrefix(key, "certs/")
		id = strings.TrimSuffix(id, "-chain.pem")

		// Parse DER data as certificate chain
		chain, err := parseDERChain(value)
		if err != nil {
			return &errs.Wrapped{Msg: "failed to parse certificate chain", Err: err}
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
			return &errs.Wrapped{Msg: "failed to parse certificate", Err: err}
		}

		return a.hardware.SaveCert(id, cert)
	}

	return &errs.Message{Msg: fmt.Sprintf("unsupported key format: %s", key)}
}

// Delete removes a certificate by key.
func (a *HardwareBackendAdapter) Delete(_ context.Context, key string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !strings.HasPrefix(key, "certs/") {
		return &errs.Message{Msg: fmt.Sprintf("hardware storage only supports certificate keys (certs/*): got %s", key)}
	}

	return a.deleteRecord(key)
}

// deleteRecord releases the one record the key names: certs/{id}-chain.pem is
// the chain, certs/{id}.pem the certificate. The two used to collapse onto
// DeleteCert, which on PKCS#11 destroyed both records of the pair, so a
// release of either key took the other with it. The caller holds a.mu.
func (a *HardwareBackendAdapter) deleteRecord(key string) error {
	id := strings.TrimPrefix(key, "certs/")
	if strings.HasSuffix(id, "-chain.pem") {
		return a.hardware.DeleteCertChain(strings.TrimSuffix(id, "-chain.pem"))
	}
	if strings.HasSuffix(id, ".pem") {
		return a.hardware.DeleteCert(strings.TrimSuffix(id, ".pem"))
	}
	// The same two shapes Get and Put accept, and nothing else: a key that
	// names no record must not fall through to the certificate whose key
	// it resembles.
	return &errs.Message{Msg: fmt.Sprintf("unsupported key format: %s", key)}
}

// List returns all certificate keys with the given prefix.
func (a *HardwareBackendAdapter) List(_ context.Context, prefix string) ([]string, error) {
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

// Scan iterates over all certificate key-value pairs matching the given prefix.
// It lists all certificates, then retrieves each one and calls fn.
func (a *HardwareBackendAdapter) Scan(_ context.Context, prefix string, fn func(key string, value []byte) error) error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ids, err := a.hardware.ListCerts()
	if err != nil {
		return err
	}

	for _, id := range ids {
		key := "certs/" + id + ".pem"
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			continue
		}

		cert, err := a.hardware.GetCert(id)
		if err != nil {
			return &errs.Wrapped{Msg: fmt.Sprintf("failed to get certificate %q", id), Err: err}
		}

		if err := fn(key, cert.Raw); err != nil {
			return err
		}
	}

	return nil
}

// Exists checks if a certificate exists by key.
func (a *HardwareBackendAdapter) Exists(_ context.Context, key string) (bool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if !strings.HasPrefix(key, "certs/") {
		return false, nil
	}

	// The chain record is probed as a chain, the way Get, Put and Delete
	// read the key; stripping ".pem" first resolved certs/{id}-chain.pem to
	// the certificate of "{id}-chain", a different record.
	id := strings.TrimPrefix(key, "certs/")
	if strings.HasSuffix(id, "-chain.pem") {
		_, err := a.hardware.GetCertChain(strings.TrimSuffix(id, "-chain.pem"))
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}

	return a.hardware.CertExists(strings.TrimSuffix(id, ".pem"))
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
	if len(data) == 0 {
		return nil, &errs.Message{Msg: "no certificates found in data"}
	}
	// The chain key's value is the concatenation of the members' DER, which
	// is exactly what Get emits for it; ParseCertificates walks that
	// sequence and rejects trailing bytes that are not a certificate.
	chain, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, &errs.Message{Msg: "no certificates found in data"}
	}
	return chain, nil
}

// Ensure HardwareBackendAdapter implements storage.Backend
var _ storage.Backend = (*HardwareBackendAdapter)(nil)
