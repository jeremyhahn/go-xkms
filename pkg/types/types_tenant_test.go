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

package types

import (
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKeyAttributes_TenantID_FieldExists verifies the TenantID field can be set and read.
func TestKeyAttributes_TenantID_FieldExists(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
	}{
		{
			name:     "empty tenant ID",
			tenantID: "",
		},
		{
			name:     "simple tenant ID",
			tenantID: "tenant-abc",
		},
		{
			name:     "UUID tenant ID",
			tenantID: "550e8400-e29b-41d4-a716-446655440000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := KeyAttributes{
				CN:       "test-key",
				TenantID: tt.tenantID,
			}
			assert.Equal(t, tt.tenantID, attrs.TenantID)
		})
	}
}

// TestKeyAttributes_ID_WithTenantID verifies that ID() prefixes with TenantID when set.
func TestKeyAttributes_ID_WithTenantID(t *testing.T) {
	tests := []struct {
		name   string
		attrs  KeyAttributes
		expect string
	}{
		{
			name: "tenant ID with ECDSA key",
			attrs: KeyAttributes{
				CN:           "my-key",
				TenantID:     "tenant-abc",
				StoreType:    StoreSoftware,
				KeyType:      KeyTypeSigning,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &ECCAttributes{
					Curve: elliptic.P256(),
				},
			},
			expect: "tenant-abc:software:signing:my-key:ecdsa",
		},
		{
			name: "tenant ID with partition and ECDSA key",
			attrs: KeyAttributes{
				CN:           "my-key",
				TenantID:     "org-42",
				Partition:    "part1",
				StoreType:    StorePKCS11,
				KeyType:      KeyTypeCA,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &ECCAttributes{
					Curve: elliptic.P256(),
				},
			},
			expect: "org-42:part1:pkcs11:ca:my-key:ecdsa",
		},
		{
			name: "tenant ID with RSA key",
			attrs: KeyAttributes{
				CN:           "rsa-key",
				TenantID:     "team-x",
				StoreType:    StoreSoftware,
				KeyType:      KeyTypeEncryption,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &RSAAttributes{
					KeySize: 4096,
				},
			},
			expect: "team-x:software:encryption:rsa-key:rsa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.attrs.ID()
			assert.Equal(t, tt.expect, result)
		})
	}
}

// TestKeyAttributes_ID_WithoutTenantID verifies ID() is unchanged when TenantID is empty.
func TestKeyAttributes_ID_WithoutTenantID(t *testing.T) {
	tests := []struct {
		name   string
		attrs  KeyAttributes
		expect string
	}{
		{
			name: "empty tenant ID preserves original format",
			attrs: KeyAttributes{
				CN:           "my-key",
				StoreType:    StoreSoftware,
				KeyType:      KeyTypeSigning,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &ECCAttributes{
					Curve: elliptic.P256(),
				},
			},
			expect: "software:signing:my-key:ecdsa",
		},
		{
			name: "empty tenant ID with partition preserves original format",
			attrs: KeyAttributes{
				CN:           "my-key",
				Partition:    "part1",
				StoreType:    StorePKCS11,
				KeyType:      KeyTypeCA,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &ECCAttributes{
					Curve: elliptic.P256(),
				},
			},
			expect: "part1:pkcs11:ca:my-key:ecdsa",
		},
		{
			name: "zero-value TenantID has no effect",
			attrs: KeyAttributes{
				CN:           "ed-key",
				TenantID:     "",
				StoreType:    StoreSoftware,
				KeyType:      KeyTypeSigning,
				KeyAlgorithm: x509.Ed25519,
			},
			expect: "software:signing:ed-key:ed25519",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.attrs.ID()
			assert.Equal(t, tt.expect, result)
		})
	}
}

// TestKeyAttributes_KeyID_NotAffectedByTenantID verifies that KeyID() ignores TenantID.
func TestKeyAttributes_KeyID_NotAffectedByTenantID(t *testing.T) {
	tests := []struct {
		name   string
		attrs  KeyAttributes
		expect string
	}{
		{
			name: "KeyID unchanged with tenant set",
			attrs: KeyAttributes{
				CN:           "my-key",
				TenantID:     "tenant-abc",
				StoreType:    StoreSoftware,
				KeyType:      KeyTypeSigning,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &ECCAttributes{
					Curve: elliptic.P256(),
				},
			},
			expect: "software:signing:ecdsa:my-key",
		},
		{
			name: "KeyID unchanged with empty tenant",
			attrs: KeyAttributes{
				CN:           "my-key",
				TenantID:     "",
				StoreType:    StoreSoftware,
				KeyType:      KeyTypeSigning,
				KeyAlgorithm: x509.ECDSA,
				ECCAttributes: &ECCAttributes{
					Curve: elliptic.P256(),
				},
			},
			expect: "software:signing:ecdsa:my-key",
		},
		{
			name: "KeyID shorthand unchanged with tenant set",
			attrs: KeyAttributes{
				CN:       "just-a-name",
				TenantID: "org-99",
			},
			expect: "just-a-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.attrs.KeyID()
			assert.Equal(t, tt.expect, result)
		})
	}
}

// TestKeyAttributes_TenantID_SameKeyIDDifferentID verifies that two keys with the
// same attributes but different TenantIDs produce different ID() results but
// identical KeyID() results.
func TestKeyAttributes_TenantID_SameKeyIDDifferentID(t *testing.T) {
	base := KeyAttributes{
		CN:           "shared-key",
		StoreType:    StoreSoftware,
		KeyType:      KeyTypeSigning,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &ECCAttributes{
			Curve: elliptic.P256(),
		},
	}

	tenantA := base
	tenantA.TenantID = "tenant-a"

	tenantB := base
	tenantB.TenantID = "tenant-b"

	noTenant := base

	// ID() should differ
	require.NotEqual(t, tenantA.ID(), tenantB.ID())
	require.NotEqual(t, tenantA.ID(), noTenant.ID())
	require.NotEqual(t, tenantB.ID(), noTenant.ID())

	// KeyID() should be identical
	assert.Equal(t, tenantA.KeyID(), tenantB.KeyID())
	assert.Equal(t, tenantA.KeyID(), noTenant.KeyID())
}
