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

package storage

import (
	"context"
	"fmt"
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

// TenantKeyPath returns a tenant-namespaced key path.
// When tenantID is empty, returns the standard KeyPath (backward compatible).
func TenantKeyPath(tenantID, id string) string {
	if tenantID == "" {
		return KeyPath(id)
	}
	return tenantID + "/keys/" + id + ".key"
}

// TenantCertPath returns a tenant-namespaced certificate path.
// When tenantID is empty, returns the standard CertPath (backward compatible).
func TenantCertPath(tenantID, id string) string {
	if tenantID == "" {
		return CertPath(id)
	}
	return tenantID + "/certs/" + id + ".pem"
}

// TenantCertChainPath returns a tenant-namespaced certificate chain path.
// When tenantID is empty, returns the standard CertChainPath (backward compatible).
func TenantCertChainPath(tenantID, id string) string {
	if tenantID == "" {
		return CertChainPath(id)
	}
	return tenantID + "/certs/" + id + "-chain.pem"
}

// TenantKeyPrefix returns the key listing prefix for a tenant.
// When tenantID is empty, returns "keys/" (backward compatible).
func TenantKeyPrefix(tenantID string) string {
	if tenantID == "" {
		return "keys/"
	}
	return tenantID + "/keys/"
}

// TenantCertPrefix returns the cert listing prefix for a tenant.
// When tenantID is empty, returns "certs/" (backward compatible).
func TenantCertPrefix(tenantID string) string {
	if tenantID == "" {
		return "certs/"
	}
	return tenantID + "/certs/"
}

// ErrInvalidTenantID is returned when a tenant ID contains invalid characters.
type ErrInvalidTenantID struct {
	TenantID string
}

// Error returns the error message for an invalid tenant ID.
func (e *ErrInvalidTenantID) Error() string {
	return fmt.Sprintf("invalid tenant ID: %q (must not contain path separators or '..')", e.TenantID)
}

// ValidateTenantID validates a tenant identifier.
// Returns error if the tenant ID contains path traversal characters.
func ValidateTenantID(tenantID string) error {
	if tenantID == "" {
		return nil // empty = single-tenant, always valid
	}
	if strings.Contains(tenantID, "..") || strings.Contains(tenantID, "/") || strings.Contains(tenantID, "\\") {
		return &ErrInvalidTenantID{TenantID: tenantID}
	}
	return nil
}

// ListKeys retrieves all key IDs from the backend by listing all keys with the "keys/" prefix.
// It automatically strips the prefix and suffix to return just the IDs.
// Returns an empty slice if no keys exist.
// Returns an error if the backend operation fails.
func ListKeys(ctx context.Context, backend Backend) ([]string, error) {
	keys, err := backend.List(ctx, "keys/")
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
func ListCerts(ctx context.Context, backend Backend) ([]string, error) {
	certs, err := backend.List(ctx, "certs/")
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
func ListCertChains(ctx context.Context, backend Backend) ([]string, error) {
	certs, err := backend.List(ctx, "certs/")
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
