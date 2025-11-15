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

package storage

import (
	"crypto/x509"
	"encoding/asn1"
)

// This file provides adapter functions to wrap Backend operations with KeyStorage-like interfaces.
// These are temporary migration helpers to ease the transition from legacy KeyStorage interfaces
// to the unified Backend interface.

// SaveKey stores key data for the given ID using the backend.
// It automatically constructs the storage path using KeyPath(id).
// Returns ErrInvalidID if the ID is empty.
// Returns any error from the backend Put operation.
func SaveKey(backend Backend, id string, keyData []byte) error {
	if id == "" {
		return ErrInvalidID
	}
	key := KeyPath(id)
	return backend.Put(key, keyData, nil)
}

// GetKey retrieves key data for the given ID using the backend.
// It automatically constructs the storage path using KeyPath(id).
// Returns ErrInvalidID if the ID is empty.
// Returns ErrNotFound if the key does not exist.
// Returns any error from the backend Get operation.
func GetKey(backend Backend, id string) ([]byte, error) {
	if id == "" {
		return nil, ErrInvalidID
	}
	key := KeyPath(id)
	return backend.Get(key)
}

// DeleteKey removes key data for the given ID using the backend.
// It automatically constructs the storage path using KeyPath(id).
// Returns ErrInvalidID if the ID is empty.
// Returns ErrNotFound if the key does not exist.
// Returns any error from the backend Delete operation.
func DeleteKey(backend Backend, id string) error {
	if id == "" {
		return ErrInvalidID
	}
	key := KeyPath(id)
	return backend.Delete(key)
}

// KeyExists checks if a key exists for the given ID using the backend.
// It automatically constructs the storage path using KeyPath(id).
// Returns ErrInvalidID if the ID is empty.
// Returns any error from the backend Exists operation.
func KeyExists(backend Backend, id string) (bool, error) {
	if id == "" {
		return false, ErrInvalidID
	}
	key := KeyPath(id)
	return backend.Exists(key)
}

// SaveCert stores certificate data for the given ID using the backend.
// It automatically constructs the storage path using CertPath(id).
// Returns ErrInvalidID if the ID is empty.
// Returns any error from the backend Put operation.
func SaveCert(backend Backend, id string, certData []byte) error {
	if id == "" {
		return ErrInvalidID
	}
	cert := CertPath(id)
	return backend.Put(cert, certData, nil)
}

// GetCert retrieves certificate data for the given ID using the backend.
// It automatically constructs the storage path using CertPath(id).
// Returns ErrInvalidID if the ID is empty.
// Returns ErrNotFound if the certificate does not exist.
// Returns any error from the backend Get operation.
func GetCert(backend Backend, id string) ([]byte, error) {
	if id == "" {
		return nil, ErrInvalidID
	}
	cert := CertPath(id)
	return backend.Get(cert)
}

// DeleteCert removes certificate data for the given ID using the backend.
// It automatically constructs the storage path using CertPath(id).
// Returns ErrInvalidID if the ID is empty.
// Returns ErrNotFound if the certificate does not exist.
// Returns any error from the backend Delete operation.
func DeleteCert(backend Backend, id string) error {
	if id == "" {
		return ErrInvalidID
	}
	cert := CertPath(id)
	return backend.Delete(cert)
}

// CertExists checks if a certificate exists for the given ID using the backend.
// It automatically constructs the storage path using CertPath(id).
// Returns ErrInvalidID if the ID is empty.
// Returns any error from the backend Exists operation.
func CertExists(backend Backend, id string) (bool, error) {
	if id == "" {
		return false, ErrInvalidID
	}
	cert := CertPath(id)
	return backend.Exists(cert)
}

// SaveCertChain stores certificate chain data for the given ID using the backend.
// It automatically constructs the storage path using CertChainPath(id).
// Returns ErrInvalidID if the ID is empty.
// Returns any error from the backend Put operation.
func SaveCertChain(backend Backend, id string, chainData []byte) error {
	if id == "" {
		return ErrInvalidID
	}
	chain := CertChainPath(id)
	return backend.Put(chain, chainData, nil)
}

// GetCertChain retrieves certificate chain data for the given ID using the backend.
// It automatically constructs the storage path using CertChainPath(id).
// Returns ErrInvalidID if the ID is empty.
// Returns ErrNotFound if the certificate chain does not exist.
// Returns any error from the backend Get operation.
func GetCertChain(backend Backend, id string) ([]byte, error) {
	if id == "" {
		return nil, ErrInvalidID
	}
	chain := CertChainPath(id)
	return backend.Get(chain)
}

// DeleteCertChain removes certificate chain data for the given ID using the backend.
// It automatically constructs the storage path using CertChainPath(id).
// Returns ErrInvalidID if the ID is empty.
// Returns ErrNotFound if the certificate chain does not exist.
// Returns any error from the backend Delete operation.
func DeleteCertChain(backend Backend, id string) error {
	if id == "" {
		return ErrInvalidID
	}
	chain := CertChainPath(id)
	return backend.Delete(chain)
}

// CertChainExists checks if a certificate chain exists for the given ID using the backend.
// It automatically constructs the storage path using CertChainPath(id).
// Returns ErrInvalidID if the ID is empty.
// Returns any error from the backend Exists operation.
func CertChainExists(backend Backend, id string) (bool, error) {
	if id == "" {
		return false, ErrInvalidID
	}
	chain := CertChainPath(id)
	return backend.Exists(chain)
}

// SaveCertParsed stores a parsed x509 certificate
func SaveCertParsed(backend Backend, id string, cert *x509.Certificate) error {
	if cert == nil {
		return ErrInvalidData
	}
	return SaveCert(backend, id, cert.Raw)
}

// GetCertParsed retrieves and parses an x509 certificate
func GetCertParsed(backend Backend, id string) (*x509.Certificate, error) {
	certData, err := GetCert(backend, id)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certData)
}

// SaveCertChainParsed stores a parsed certificate chain
func SaveCertChainParsed(backend Backend, id string, chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return ErrInvalidData
	}
	// Concatenate DER-encoded certificates
	var chainData []byte
	for _, cert := range chain {
		chainData = append(chainData, cert.Raw...)
	}
	return SaveCertChain(backend, id, chainData)
}

// GetCertChainParsed retrieves and parses a certificate chain
func GetCertChainParsed(backend Backend, id string) ([]*x509.Certificate, error) {
	chainData, err := GetCertChain(backend, id)
	if err != nil {
		return nil, err
	}

	// Parse concatenated DER certificates
	var chain []*x509.Certificate
	remaining := chainData

	for len(remaining) > 0 {
		// Use asn1.Unmarshal to extract the exact DER bytes for this certificate
		// This allows us to handle concatenated certificates properly
		var rawCert asn1.RawValue
		rest, err := asn1.Unmarshal(remaining, &rawCert)
		if err != nil {
			// If we have at least one cert, return what we have
			if len(chain) > 0 {
				return chain, nil
			}
			return nil, err
		}

		// Parse this certificate from its exact DER bytes
		certDER := remaining[:len(remaining)-len(rest)]
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			// If we have at least one cert, return what we have
			if len(chain) > 0 {
				return chain, nil
			}
			return nil, err
		}
		chain = append(chain, cert)

		// Move to the next certificate
		remaining = rest
	}

	if len(chain) == 0 {
		return nil, ErrNotFound
	}

	return chain, nil
}
