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

package entities

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenant_IsActive(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected bool
	}{
		{"active tenant", TenantStatusActive, true},
		{"suspended tenant", TenantStatusSuspended, false},
		{"deleted tenant", TenantStatusDeleted, false},
		{"unknown status", "unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant := &Tenant{Status: tt.status}
			assert.Equal(t, tt.expected, tenant.IsActive())
		})
	}
}

func TestTenant_HasRootCA(t *testing.T) {
	t.Run("no root CA", func(t *testing.T) {
		tenant := &Tenant{}
		assert.False(t, tenant.HasRootCA())
	})

	t.Run("root CA not active", func(t *testing.T) {
		tenant := &Tenant{
			RootCA: &TenantRootCA{
				Status: CAStatusRevoked,
			},
		}
		assert.False(t, tenant.HasRootCA())
	})

	t.Run("active root CA", func(t *testing.T) {
		tenant := &Tenant{
			RootCA: &TenantRootCA{
				Status: CAStatusActive,
			},
		}
		assert.True(t, tenant.HasRootCA())
	})
}

func TestTenant_GetDefaultIntermediateCA(t *testing.T) {
	t.Run("no intermediate CAs", func(t *testing.T) {
		tenant := &Tenant{}
		assert.Nil(t, tenant.GetDefaultIntermediateCA())
	})

	t.Run("returns specified default", func(t *testing.T) {
		tenant := &Tenant{
			DefaultIntermediateCAID: "ca-2",
			IntermediateCAs: []*TenantIntermediateCA{
				{ID: "ca-1", Status: CAStatusActive},
				{ID: "ca-2", Status: CAStatusActive},
				{ID: "ca-3", Status: CAStatusActive},
			},
		}
		ca := tenant.GetDefaultIntermediateCA()
		require.NotNil(t, ca)
		assert.Equal(t, "ca-2", ca.ID)
	})

	t.Run("returns first active when default not set", func(t *testing.T) {
		tenant := &Tenant{
			IntermediateCAs: []*TenantIntermediateCA{
				{ID: "ca-1", Status: CAStatusRevoked},
				{ID: "ca-2", Status: CAStatusActive},
				{ID: "ca-3", Status: CAStatusActive},
			},
		}
		ca := tenant.GetDefaultIntermediateCA()
		require.NotNil(t, ca)
		assert.Equal(t, "ca-2", ca.ID)
	})

	t.Run("returns nil when default is not active", func(t *testing.T) {
		tenant := &Tenant{
			DefaultIntermediateCAID: "ca-revoked",
			IntermediateCAs: []*TenantIntermediateCA{
				{ID: "ca-revoked", Status: CAStatusRevoked},
			},
		}
		// Should fall back to first active (none available)
		ca := tenant.GetDefaultIntermediateCA()
		assert.Nil(t, ca)
	})
}

func TestTenant_GetIntermediateCAsByPurpose(t *testing.T) {
	tenant := &Tenant{
		IntermediateCAs: []*TenantIntermediateCA{
			{ID: "ca-general", Purpose: CAPurposeGeneral, Status: CAStatusActive},
			{ID: "ca-tpm-1", Purpose: CAPurposeTPMEndorsement, Status: CAStatusActive},
			{ID: "ca-tpm-2", Purpose: CAPurposeTPMEndorsement, Status: CAStatusRevoked},
			{ID: "ca-server", Purpose: CAPurposeServerAuth, Status: CAStatusActive},
		},
	}

	t.Run("finds TPM endorsement CAs", func(t *testing.T) {
		cas := tenant.GetIntermediateCAsByPurpose(CAPurposeTPMEndorsement)
		assert.Len(t, cas, 1) // Only active ones
		assert.Equal(t, "ca-tpm-1", cas[0].ID)
	})

	t.Run("finds server auth CAs", func(t *testing.T) {
		cas := tenant.GetIntermediateCAsByPurpose(CAPurposeServerAuth)
		assert.Len(t, cas, 1)
		assert.Equal(t, "ca-server", cas[0].ID)
	})

	t.Run("returns empty for non-existent purpose", func(t *testing.T) {
		cas := tenant.GetIntermediateCAsByPurpose(CAPurposeCodeSigning)
		assert.Empty(t, cas)
	})
}

// TestGetSigningCA_Hierarchy tests the CA fallback hierarchy implementation
func TestGetSigningCA_Hierarchy(t *testing.T) {
	t.Run("priority 1: purpose-specific intermediate CA", func(t *testing.T) {
		tenant := &Tenant{
			ID:     "tenant-1",
			Status: TenantStatusActive,
			RootCA: &TenantRootCA{Status: CAStatusActive},
			IntermediateCAs: []*TenantIntermediateCA{
				{ID: "ca-general", Purpose: CAPurposeGeneral, Status: CAStatusActive},
				{ID: "ca-tpm", Purpose: CAPurposeTPMEndorsement, Status: CAStatusActive},
			},
			DefaultIntermediateCAID: "ca-general",
		}

		info := tenant.GetSigningCA(CAPurposeTPMEndorsement)
		require.NotNil(t, info)
		assert.Equal(t, SigningCATypeIntermediate, info.Type)
		assert.Equal(t, "ca-tpm", info.IntermediateCA.ID)
		assert.Equal(t, "tenant-1", info.TenantID)
		assert.False(t, info.UseGlobalDefault)
	})

	t.Run("priority 2: default intermediate CA when no purpose match", func(t *testing.T) {
		tenant := &Tenant{
			ID:     "tenant-2",
			Status: TenantStatusActive,
			RootCA: &TenantRootCA{Status: CAStatusActive},
			IntermediateCAs: []*TenantIntermediateCA{
				{ID: "ca-general", Purpose: CAPurposeGeneral, Status: CAStatusActive},
			},
			DefaultIntermediateCAID: "ca-general",
		}

		// Request TPM purpose but only general is available
		info := tenant.GetSigningCA(CAPurposeTPMEndorsement)
		require.NotNil(t, info)
		assert.Equal(t, SigningCATypeIntermediate, info.Type)
		assert.Equal(t, "ca-general", info.IntermediateCA.ID)
	})

	t.Run("priority 3: root CA when no intermediate available", func(t *testing.T) {
		tenant := &Tenant{
			ID:     "tenant-3",
			Status: TenantStatusActive,
			RootCA: &TenantRootCA{
				CommonName: "Tenant 3 Root CA",
				Status:     CAStatusActive,
			},
			IntermediateCAs: nil, // No intermediate CAs
		}

		info := tenant.GetSigningCA("")
		require.NotNil(t, info)
		assert.Equal(t, SigningCATypeRoot, info.Type)
		assert.NotNil(t, info.RootCA)
		assert.Equal(t, "Tenant 3 Root CA", info.RootCA.CommonName)
		assert.Nil(t, info.IntermediateCA)
	})

	t.Run("priority 4: global default when no tenant CA", func(t *testing.T) {
		tenant := &Tenant{
			ID:              "tenant-4",
			Status:          TenantStatusActive,
			RootCA:          nil, // No root CA
			IntermediateCAs: nil, // No intermediate CAs
		}

		info := tenant.GetSigningCA("")
		require.NotNil(t, info)
		assert.Equal(t, SigningCATypeGlobal, info.Type)
		assert.True(t, info.UseGlobalDefault)
		assert.Nil(t, info.IntermediateCA)
		assert.Nil(t, info.RootCA)
		assert.Equal(t, "tenant-4", info.TenantID)
	})

	t.Run("fallback when root CA is revoked", func(t *testing.T) {
		tenant := &Tenant{
			ID:     "tenant-5",
			Status: TenantStatusActive,
			RootCA: &TenantRootCA{
				Status: CAStatusRevoked, // Root is revoked
			},
			IntermediateCAs: nil,
		}

		info := tenant.GetSigningCA("")
		require.NotNil(t, info)
		assert.Equal(t, SigningCATypeGlobal, info.Type)
		assert.True(t, info.UseGlobalDefault)
	})

	t.Run("empty purpose uses default intermediate", func(t *testing.T) {
		tenant := &Tenant{
			ID:     "tenant-6",
			Status: TenantStatusActive,
			IntermediateCAs: []*TenantIntermediateCA{
				{ID: "ca-default", Purpose: CAPurposeGeneral, Status: CAStatusActive},
			},
			DefaultIntermediateCAID: "ca-default",
		}

		info := tenant.GetSigningCA("")
		require.NotNil(t, info)
		assert.Equal(t, SigningCATypeIntermediate, info.Type)
		assert.Equal(t, "ca-default", info.IntermediateCA.ID)
	})
}

func TestGetSigningCAForEndorsement(t *testing.T) {
	t.Run("uses TPM endorsement purpose", func(t *testing.T) {
		tenant := &Tenant{
			ID:     "tenant-tpm",
			Status: TenantStatusActive,
			IntermediateCAs: []*TenantIntermediateCA{
				{ID: "ca-general", Purpose: CAPurposeGeneral, Status: CAStatusActive},
				{ID: "ca-tpm", Purpose: CAPurposeTPMEndorsement, Status: CAStatusActive},
			},
		}

		info := tenant.GetSigningCAForEndorsement()
		require.NotNil(t, info)
		assert.Equal(t, "ca-tpm", info.IntermediateCA.ID)
	})

	t.Run("falls back when no TPM CA", func(t *testing.T) {
		tenant := &Tenant{
			ID:     "tenant-no-tpm",
			Status: TenantStatusActive,
			IntermediateCAs: []*TenantIntermediateCA{
				{ID: "ca-general", Purpose: CAPurposeGeneral, Status: CAStatusActive},
			},
		}

		info := tenant.GetSigningCAForEndorsement()
		require.NotNil(t, info)
		assert.Equal(t, "ca-general", info.IntermediateCA.ID)
	})
}

func TestSigningCAInfo_Fields(t *testing.T) {
	info := &SigningCAInfo{
		Type: SigningCATypeIntermediate,
		IntermediateCA: &TenantIntermediateCA{
			ID:         "test-ca",
			CommonName: "Test CA",
		},
		TenantID:         "test-tenant",
		UseGlobalDefault: false,
	}

	assert.Equal(t, SigningCATypeIntermediate, info.Type)
	assert.Equal(t, "test-ca", info.IntermediateCA.ID)
	assert.Equal(t, "test-tenant", info.TenantID)
	assert.False(t, info.UseGlobalDefault)
}

func TestTenant_CanIssueCertificates(t *testing.T) {
	t.Run("active tenant with intermediate CA", func(t *testing.T) {
		tenant := &Tenant{
			Status: TenantStatusActive,
			IntermediateCAs: []*TenantIntermediateCA{
				{ID: "ca-1", Status: CAStatusActive},
			},
		}
		assert.True(t, tenant.CanIssueCertificates())
	})

	t.Run("suspended tenant cannot issue", func(t *testing.T) {
		tenant := &Tenant{
			Status: TenantStatusSuspended,
			IntermediateCAs: []*TenantIntermediateCA{
				{ID: "ca-1", Status: CAStatusActive},
			},
		}
		assert.False(t, tenant.CanIssueCertificates())
	})

	t.Run("active tenant without intermediate CA cannot issue", func(t *testing.T) {
		tenant := &Tenant{
			Status:          TenantStatusActive,
			IntermediateCAs: nil,
		}
		assert.False(t, tenant.CanIssueCertificates())
	})
}

func TestTenantIntermediateCA_IsActive(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected bool
	}{
		{"active CA", CAStatusActive, true},
		{"pending rotation", CAStatusPendingRotation, false},
		{"revoked CA", CAStatusRevoked, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := &TenantIntermediateCA{Status: tt.status}
			assert.Equal(t, tt.expected, ca.IsActive())
		})
	}
}

func TestTenant_GetIntermediateCA(t *testing.T) {
	tenant := &Tenant{
		IntermediateCAs: []*TenantIntermediateCA{
			{ID: "ca-1", CommonName: "CA 1"},
			{ID: "ca-2", CommonName: "CA 2"},
		},
	}

	t.Run("finds existing CA", func(t *testing.T) {
		ca := tenant.GetIntermediateCA("ca-1")
		require.NotNil(t, ca)
		assert.Equal(t, "CA 1", ca.CommonName)
	})

	t.Run("returns nil for non-existent CA", func(t *testing.T) {
		ca := tenant.GetIntermediateCA("ca-999")
		assert.Nil(t, ca)
	})
}

func TestTenant_GetActiveIntermediateCAs(t *testing.T) {
	tenant := &Tenant{
		IntermediateCAs: []*TenantIntermediateCA{
			{ID: "ca-1", Status: CAStatusActive},
			{ID: "ca-2", Status: CAStatusRevoked},
			{ID: "ca-3", Status: CAStatusActive},
			{ID: "ca-4", Status: CAStatusPendingRotation},
		},
	}

	active := tenant.GetActiveIntermediateCAs()
	assert.Len(t, active, 2)
	assert.Equal(t, "ca-1", active[0].ID)
	assert.Equal(t, "ca-3", active[1].ID)
}

func TestSigningCATypeConstants(t *testing.T) {
	assert.Equal(t, "intermediate", SigningCATypeIntermediate)
	assert.Equal(t, "root", SigningCATypeRoot)
	assert.Equal(t, "global", SigningCATypeGlobal)
}

func TestTenantStatusConstants(t *testing.T) {
	assert.Equal(t, "active", TenantStatusActive)
	assert.Equal(t, "suspended", TenantStatusSuspended)
	assert.Equal(t, "deleted", TenantStatusDeleted)
}

func TestCAStatusConstants(t *testing.T) {
	assert.Equal(t, "active", CAStatusActive)
	assert.Equal(t, "pending-rotation", CAStatusPendingRotation)
	assert.Equal(t, "revoked", CAStatusRevoked)
}

func TestCAParentTypeConstants(t *testing.T) {
	assert.Equal(t, "global", CAParentTypeGlobal)
	assert.Equal(t, "tenant", CAParentTypeTenant)
}

func TestCAPurposeConstants(t *testing.T) {
	assert.Equal(t, "general", CAPurposeGeneral)
	assert.Equal(t, "server-auth", CAPurposeServerAuth)
	assert.Equal(t, "client-auth", CAPurposeClientAuth)
	assert.Equal(t, "code-signing", CAPurposeCodeSigning)
	assert.Equal(t, "tpm-endorsement", CAPurposeTPMEndorsement)
}

func TestTenant_Fields(t *testing.T) {
	now := time.Now()
	tenant := &Tenant{
		ID:                      "test-id",
		Name:                    "Test Tenant",
		Status:                  TenantStatusActive,
		DEKKeyID:                "dek-123",
		DefaultIntermediateCAID: "ca-default",
		CreatedAt:               now,
		UpdatedAt:               now,
		CreatedBy:               "admin-user",
	}

	assert.Equal(t, "test-id", tenant.ID)
	assert.Equal(t, "Test Tenant", tenant.Name)
	assert.Equal(t, TenantStatusActive, tenant.Status)
	assert.Equal(t, "dek-123", tenant.DEKKeyID)
	assert.Equal(t, "ca-default", tenant.DefaultIntermediateCAID)
	assert.Equal(t, now, tenant.CreatedAt)
	assert.Equal(t, now, tenant.UpdatedAt)
	assert.Equal(t, "admin-user", tenant.CreatedBy)
}

func TestTenantSettings_Fields(t *testing.T) {
	settings := &TenantSettings{
		MaxCertificates:         1000,
		MaxAccounts:             100,
		AllowedKeyAlgorithms:    []string{"EC-P256", "EC-P384"},
		AllowedChallengeTypes:   []string{"http-01", "dns-01", "endorse-01"},
		CertificateValidityDays: 365,
		RequireEAB:              true,
		AllowEndorse01:          true,
		AllowEnroll01:           true,
		CustomMetadata: map[string]string{
			"department": "engineering",
		},
	}

	assert.Equal(t, 1000, settings.MaxCertificates)
	assert.Equal(t, 100, settings.MaxAccounts)
	assert.Contains(t, settings.AllowedKeyAlgorithms, "EC-P384")
	assert.Contains(t, settings.AllowedChallengeTypes, "endorse-01")
	assert.Equal(t, 365, settings.CertificateValidityDays)
	assert.True(t, settings.RequireEAB)
	assert.True(t, settings.AllowEndorse01)
	assert.True(t, settings.AllowEnroll01)
	assert.Equal(t, "engineering", settings.CustomMetadata["department"])
}

func TestTenantRootCA_Fields(t *testing.T) {
	now := time.Now()
	rootCA := &TenantRootCA{
		CommonName:     "Test Root CA",
		SerialNumber:   "12345",
		KeyID:          "key-123",
		KeyAlgorithm:   "EC-P384",
		NotBefore:      now,
		NotAfter:       now.Add(10 * 365 * 24 * time.Hour),
		Status:         CAStatusActive,
		CertificatePEM: "-----BEGIN CERTIFICATE-----",
		CreatedAt:      now,
	}

	assert.Equal(t, "Test Root CA", rootCA.CommonName)
	assert.Equal(t, "12345", rootCA.SerialNumber)
	assert.Equal(t, "key-123", rootCA.KeyID)
	assert.Equal(t, "EC-P384", rootCA.KeyAlgorithm)
	assert.Equal(t, CAStatusActive, rootCA.Status)
}

func TestTenantIntermediateCA_Fields(t *testing.T) {
	now := time.Now()
	intCA := &TenantIntermediateCA{
		ID:             "int-ca-1",
		CommonName:     "Test Intermediate CA",
		SerialNumber:   "67890",
		ParentType:     CAParentTypeTenant,
		Purpose:        CAPurposeTPMEndorsement,
		KeyID:          "int-key-123",
		KeyAlgorithm:   "EC-P256",
		NotBefore:      now,
		NotAfter:       now.Add(5 * 365 * 24 * time.Hour),
		Status:         CAStatusActive,
		CertificatePEM: "-----BEGIN CERTIFICATE-----",
		ChainPEM:       "-----BEGIN CERTIFICATE-----\n...",
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	assert.Equal(t, "int-ca-1", intCA.ID)
	assert.Equal(t, "Test Intermediate CA", intCA.CommonName)
	assert.Equal(t, CAParentTypeTenant, intCA.ParentType)
	assert.Equal(t, CAPurposeTPMEndorsement, intCA.Purpose)
	assert.Equal(t, "int-key-123", intCA.KeyID)
	assert.True(t, intCA.IsActive())
}

func TestResolveComplianceConfig(t *testing.T) {
	t.Run("nil global config returns nil", func(t *testing.T) {
		tenant := &TenantSettings{
			ComplianceConfig: &ComplianceConfig{
				Enabled: true,
			},
		}
		result := ResolveComplianceConfig(nil, tenant)
		assert.Nil(t, result)
	})

	t.Run("nil tenant settings with global config returns global", func(t *testing.T) {
		global := &GlobalComplianceConfig{
			ComplianceConfig: ComplianceConfig{
				Enabled:             true,
				RequireSignedReport: true,
			},
			Enforce: false,
		}
		result := ResolveComplianceConfig(global, nil)
		require.NotNil(t, result)
		assert.True(t, result.Enabled)
		assert.True(t, result.RequireSignedReport)
	})

	t.Run("global enforce true returns global config ignoring tenant", func(t *testing.T) {
		global := &GlobalComplianceConfig{
			ComplianceConfig: ComplianceConfig{
				Enabled:             true,
				RequireSignedReport: true,
				FailOpen:            false,
			},
			Enforce: true,
		}
		tenant := &TenantSettings{
			ComplianceConfig: &ComplianceConfig{
				Enabled:             false,
				RequireSignedReport: false,
				FailOpen:            true,
			},
		}
		result := ResolveComplianceConfig(global, tenant)
		require.NotNil(t, result)
		assert.True(t, result.Enabled)
		assert.True(t, result.RequireSignedReport)
		assert.False(t, result.FailOpen)
	})

	t.Run("global enforce false with tenant config returns tenant config", func(t *testing.T) {
		global := &GlobalComplianceConfig{
			ComplianceConfig: ComplianceConfig{
				Enabled:             true,
				RequireSignedReport: true,
				FailOpen:            false,
			},
			Enforce: false,
		}
		tenant := &TenantSettings{
			ComplianceConfig: &ComplianceConfig{
				Enabled:             false,
				RequireSignedReport: false,
				FailOpen:            true,
			},
		}
		result := ResolveComplianceConfig(global, tenant)
		require.NotNil(t, result)
		assert.False(t, result.Enabled)
		assert.False(t, result.RequireSignedReport)
		assert.True(t, result.FailOpen)
	})

	t.Run("global enforce false without tenant config returns global as fallback", func(t *testing.T) {
		global := &GlobalComplianceConfig{
			ComplianceConfig: ComplianceConfig{
				Enabled:             true,
				RequireSignedReport: true,
				FailOpen:            false,
			},
			Enforce: false,
		}
		tenant := &TenantSettings{
			ComplianceConfig: nil, // No tenant-specific config
		}
		result := ResolveComplianceConfig(global, tenant)
		require.NotNil(t, result)
		assert.True(t, result.Enabled)
		assert.True(t, result.RequireSignedReport)
		assert.False(t, result.FailOpen)
	})

	t.Run("global enforce false with nil tenant returns global as fallback", func(t *testing.T) {
		global := &GlobalComplianceConfig{
			ComplianceConfig: ComplianceConfig{
				Enabled:  true,
				FailOpen: true,
			},
			Enforce: false,
		}
		result := ResolveComplianceConfig(global, nil)
		require.NotNil(t, result)
		assert.True(t, result.Enabled)
		assert.True(t, result.FailOpen)
	})

	t.Run("returns global config when enforced", func(t *testing.T) {
		global := &GlobalComplianceConfig{
			ComplianceConfig: ComplianceConfig{
				Enabled:          true,
				CustomPolicyPath: "/etc/policy/global.rego",
			},
			Enforce: true,
		}
		tenant := &TenantSettings{
			ComplianceConfig: &ComplianceConfig{
				Enabled: false, // Tenant tries to disable
			},
		}
		result := ResolveComplianceConfig(global, tenant)
		require.NotNil(t, result)
		assert.True(t, result.Enabled)
		assert.Equal(t, "/etc/policy/global.rego", result.CustomPolicyPath)
	})

	t.Run("returns tenant config when not enforced", func(t *testing.T) {
		global := &GlobalComplianceConfig{
			ComplianceConfig: ComplianceConfig{
				Enabled:          true,
				CustomPolicyPath: "/etc/policy/global.rego",
			},
			Enforce: false,
		}
		tenant := &TenantSettings{
			ComplianceConfig: &ComplianceConfig{
				Enabled:          true,
				CustomPolicyPath: "/etc/policy/tenant.rego",
			},
		}
		result := ResolveComplianceConfig(global, tenant)
		require.NotNil(t, result)
		assert.Equal(t, "/etc/policy/tenant.rego", result.CustomPolicyPath)
	})
}

func TestComplianceConfig_Fields(t *testing.T) {
	config := &ComplianceConfig{
		Enabled:             true,
		RequireSignedReport: true,
		CustomPolicyPath:    "/path/to/policy.rego",
		FailOpen:            false,
	}

	assert.True(t, config.Enabled)
	assert.True(t, config.RequireSignedReport)
	assert.Equal(t, "/path/to/policy.rego", config.CustomPolicyPath)
	assert.False(t, config.FailOpen)
}

func TestGlobalComplianceConfig_Fields(t *testing.T) {
	global := &GlobalComplianceConfig{
		ComplianceConfig: ComplianceConfig{
			Enabled:             true,
			RequireSignedReport: true,
		},
		Enforce: true,
	}

	assert.True(t, global.Enabled)
	assert.True(t, global.RequireSignedReport)
	assert.True(t, global.Enforce)
}

func TestTenant_EntityID(t *testing.T) {
	tenant := &Tenant{
		ID: "tenant-xyz-123",
	}

	id := tenant.EntityID()

	// Must match FNV-1a hash of the ID string
	expected := StringToEntityID("tenant-xyz-123")
	assert.Equal(t, expected, id)
	assert.NotZero(t, id)
}

func TestTenant_EntityID_CachedNumericID(t *testing.T) {
	cachedID := uint64(77777)
	tenant := &Tenant{
		NumericID: cachedID,
		ID:        "tenant-xyz-123",
	}

	id := tenant.EntityID()

	// Must return the cached NumericID without recomputing
	assert.Equal(t, cachedID, id)
}

func TestTenant_SetEntityID(t *testing.T) {
	tenant := &Tenant{
		ID: "tenant-xyz-123",
	}

	newID := uint64(88888)
	tenant.SetEntityID(newID)

	assert.Equal(t, newID, tenant.NumericID)
	// Subsequent EntityID() calls must return the set value
	assert.Equal(t, newID, tenant.EntityID())
}

func TestTenant_EntityID_EmptyID(t *testing.T) {
	tenant := &Tenant{}

	id := tenant.EntityID()

	// Both NumericID and ID are zero/empty, so EntityID returns 0
	assert.Zero(t, id)
}
