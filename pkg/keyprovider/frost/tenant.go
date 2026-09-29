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

//go:build frost

package frost

import (
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/validation"
)

// tenantSeparator joins a tenant ID to a key's common name in a storage key
// ID. storage.ValidateTenantID refuses it in a tenant ID and
// validation.ValidateKeyID refuses it in a common name, so a tenant's key can
// never share a storage key ID with another tenant's key or with a platform
// key. It is the same separator types.KeyAttributes.ID uses for its tenant
// prefix.
const tenantSeparator = ":"

// StorageKeyID returns the identifier a FROST key is stored under: the common
// name alone for a platform (untenanted) key, and "{tenantID}:{cn}" for a
// tenant's key. A key's common name is therefore unique only within its
// tenant, exactly as it is for every other key provider.
//
// The storage key ID is also what the round API -- GenerateNonces, SignRound,
// Aggregate and Verify -- addresses a key by. Every attribute-addressed method
// (GenerateKey, GetKey, DeleteKey, Signer, RotateKey, ImportKeyPackage)
// derives it from types.KeyAttributes.TenantID and CN.
//
// Both halves are validated, so neither can carry a path separator, a
// traversal sequence or the tenant separator into the storage path.
func StorageKeyID(tenantID, cn string) (string, error) {
	if cn == "" {
		return "", &ConfigError{Field: "CN", Message: "key ID (CN) is required"}
	}
	if err := validation.ValidateKeyID(cn); err != nil {
		return "", &KeyIDError{KeyID: cn, Err: err}
	}
	if tenantID == "" {
		return cn, nil
	}
	if err := storage.ValidateTenantID(tenantID); err != nil {
		return "", &KeyIDError{KeyID: cn, Err: err}
	}
	return tenantID + tenantSeparator + cn, nil
}

// storageKeyIDOf returns the storage key ID of the key attrs names.
func storageKeyIDOf(attrs *types.KeyAttributes) (string, error) {
	if attrs == nil {
		return "", ErrInvalidAttributes
	}
	return StorageKeyID(attrs.TenantID, attrs.CN)
}

// validateStorageKeyID checks a storage key ID handed to the round API: a
// bare common name, or a tenant ID and common name joined by
// tenantSeparator, each of which must be valid on its own.
func validateStorageKeyID(keyID string) error {
	tenantID, cn, scoped := strings.Cut(keyID, tenantSeparator)
	if !scoped {
		tenantID, cn = "", keyID
	} else if tenantID == "" {
		return &KeyIDError{KeyID: keyID, Err: ErrInvalidAttributes}
	}
	_, err := StorageKeyID(tenantID, cn)
	return err
}
