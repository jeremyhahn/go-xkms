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

package kms

import (
	"context"
	"crypto"
)

// KeyPurpose identifies the purpose of a cryptographic key.
type KeyPurpose string

const (
	// KeyPurposeTenantRootCA is for tenant root CA signing keys.
	KeyPurposeTenantRootCA KeyPurpose = "tenant-root-ca"

	// KeyPurposeTenantIntermediateCA is for tenant intermediate CA signing keys.
	KeyPurposeTenantIntermediateCA KeyPurpose = "tenant-intermediate-ca"

	// KeyPurposeOCSP is for OCSP response signing.
	KeyPurposeOCSP KeyPurpose = "ocsp"

	// KeyPurposeCRL is for CRL signing.
	KeyPurposeCRL KeyPurpose = "crl"
)

// KeyMetadata describes a managed key.
type KeyMetadata struct {
	// KeyID is the unique identifier for the key.
	KeyID string `json:"key_id"`

	// TenantID is the tenant that owns this key.
	TenantID string `json:"tenant_id"`

	// Purpose describes what this key is used for.
	Purpose KeyPurpose `json:"purpose"`

	// Algorithm is the key algorithm (e.g., "RSA-2048", "ECDSA-P256").
	Algorithm string `json:"algorithm"`

	// Enabled indicates whether the key is active.
	Enabled bool `json:"enabled"`

	// CreatedAt is when the key was created (Unix timestamp).
	CreatedAt int64 `json:"created_at"`
}

// KMSService provides key management operations for tenant CA signing.
// It abstracts the underlying KMS/go-xkms integration.
type KMSService interface {
	// CreateSigningKey creates a new signing key for the specified tenant.
	// The key is stored securely in the underlying KMS backend.
	CreateSigningKey(ctx context.Context, tenantID string, purpose KeyPurpose, algorithm string) (*KeyMetadata, error)

	// GetSigningKey retrieves a signing key for the specified tenant and purpose.
	// Returns a crypto.Signer interface for signing operations.
	GetSigningKey(ctx context.Context, tenantID string, purpose KeyPurpose) (crypto.Signer, error)

	// ListSigningKeys lists all signing keys for a tenant.
	ListSigningKeys(ctx context.Context, tenantID string) ([]*KeyMetadata, error)

	// DeleteSigningKey deletes a signing key.
	// This is a destructive operation - use with caution.
	DeleteSigningKey(ctx context.Context, tenantID string, keyID string) error

	// EnableSigningKey enables a previously disabled key.
	EnableSigningKey(ctx context.Context, tenantID string, keyID string) error

	// DisableSigningKey disables a key without deleting it.
	DisableSigningKey(ctx context.Context, tenantID string, keyID string) error

	// StoreCertificate stores a certificate for a tenant's CA.
	// This is typically called after generating/signing a tenant CA certificate.
	StoreCertificate(ctx context.Context, tenantID string, purpose KeyPurpose, certDER []byte) error

	// GetCertificate retrieves a certificate for a tenant's CA.
	// Returns the DER-encoded certificate.
	GetCertificate(ctx context.Context, tenantID string, purpose KeyPurpose) ([]byte, error)

	// DeleteCertificate deletes a tenant's CA certificate.
	DeleteCertificate(ctx context.Context, tenantID string, purpose KeyPurpose) error
}

// TenantCAFactory creates CA instances for tenants using KMS-managed keys.
type TenantCAFactory interface {
	// CreateTenantCA creates a new CA for a tenant using a KMS-managed signing key.
	// If the key doesn't exist, it will be created with the specified algorithm.
	CreateTenantCA(ctx context.Context, tenantID string, purpose KeyPurpose, algorithm string) (interface{}, error)

	// GetTenantCA retrieves an existing tenant CA.
	// Returns nil if the tenant doesn't have a CA configured.
	GetTenantCA(ctx context.Context, tenantID string, purpose KeyPurpose) (interface{}, error)
}
