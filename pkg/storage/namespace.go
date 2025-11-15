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
	"strings"
)

// KeyPath returns the storage path for a key with the given ID.
// The path follows the convention: keys/{id}.key
func KeyPath(id string) string {
	return "keys/" + id + ".key"
}

// CertPath returns the storage path for a certificate with the given ID.
// The path follows the convention: certs/{id}.pem
func CertPath(id string) string {
	return "certs/" + id + ".pem"
}

// CertChainPath returns the storage path for a certificate chain with the given ID.
// The path follows the convention: certs/{id}-chain.pem
func CertChainPath(id string) string {
	return "certs/" + id + "-chain.pem"
}

// ListKeys retrieves all key IDs from the backend by listing all keys with the "keys/" prefix.
// It automatically strips the prefix and suffix to return just the IDs.
// Returns an empty slice if no keys exist.
// Returns an error if the backend operation fails.
func ListKeys(backend Backend) ([]string, error) {
	keys, err := backend.List("keys/")
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		// Strip "keys/" prefix and ".key" suffix
		id := strings.TrimPrefix(k, "keys/")
		id = strings.TrimSuffix(id, ".key")
		if id != "" {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// ListCerts retrieves all certificate IDs from the backend by listing all certs with the "certs/" prefix.
// It automatically strips the prefix and suffix to return just the IDs, excluding certificate chains.
// Returns an empty slice if no certificates exist.
// Returns an error if the backend operation fails.
func ListCerts(backend Backend) ([]string, error) {
	certs, err := backend.List("certs/")
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(certs))
	for _, c := range certs {
		// Strip "certs/" prefix and ".pem" suffix
		id := strings.TrimPrefix(c, "certs/")
		id = strings.TrimSuffix(id, ".pem")
		// Skip certificate chains (they have -chain suffix before .pem)
		if !strings.HasSuffix(id, "-chain") && id != "" {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// ListCertChains retrieves all certificate chain IDs from the backend by listing all certs with the "certs/" prefix.
// It automatically strips the prefix and suffix to return just the IDs, only including certificate chains.
// Returns an empty slice if no certificate chains exist.
// Returns an error if the backend operation fails.
func ListCertChains(backend Backend) ([]string, error) {
	certs, err := backend.List("certs/")
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(certs))
	for _, c := range certs {
		// Strip "certs/" prefix and "-chain.pem" suffix
		if strings.HasSuffix(c, "-chain.pem") {
			id := strings.TrimPrefix(c, "certs/")
			id = strings.TrimSuffix(id, "-chain.pem")
			if id != "" {
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}
