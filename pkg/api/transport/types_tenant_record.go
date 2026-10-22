// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package transport

import "time"

// Tenant record lifecycle states, as a TenantRecord reports them.
const (
	TenantStatusActive    = "active"
	TenantStatusSuspended = "suspended"
	TenantStatusDeleted   = "deleted"
)

// TenantRecord is the certificate-authority record a tenant carries beside
// its go-qrdb identity: lifecycle status, CA hierarchy and issuance
// settings. The hosted ACME CA keeps it; the tenant lifecycle routes return
// it with the tenant.
type TenantRecord struct {
	Status                  string              `json:"status"`
	RootCA                  *TenantRootCAInfo   `json:"root_ca,omitempty"`
	IntermediateCAs         []*TenantIntCAInfo  `json:"intermediate_cas,omitempty"`
	DefaultIntermediateCAID string              `json:"default_intermediate_ca_id,omitempty"`
	Settings                *TenantSettingsInfo `json:"settings,omitempty"`
	CreatedBy               string              `json:"created_by,omitempty"`
}

// TenantDetail is a tenant together with the CA record kept beside it.
// Record is nil when no record is kept for the tenant.
type TenantDetail struct {
	Tenant TenantInfo
	Record *TenantRecord
}

// Status returns the tenant's lifecycle status: its record's, or active for
// a tenant without one.
func (d *TenantDetail) Status() string {
	if d.Record == nil {
		return TenantStatusActive
	}
	return d.Record.Status
}

// TenantRootCAInfo describes a tenant's root CA.
type TenantRootCAInfo struct {
	CommonName   string    `json:"common_name"`
	SerialNumber string    `json:"serial_number,omitempty"`
	KeyAlgorithm string    `json:"key_algorithm"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}

// TenantIntCAInfo describes one of a tenant's intermediate CAs.
type TenantIntCAInfo struct {
	ID           string    `json:"id"`
	CommonName   string    `json:"common_name"`
	SerialNumber string    `json:"serial_number,omitempty"`
	ParentType   string    `json:"parent_type"`       // "global" or "tenant"
	Purpose      string    `json:"purpose,omitempty"` // "general", "server-auth", "client-auth", etc.
	KeyAlgorithm string    `json:"key_algorithm"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

// TenantSettingsInfo holds a tenant's certificate issuance settings.
type TenantSettingsInfo struct {
	MaxCertificates         int                   `json:"max_certificates,omitempty"`
	MaxAccounts             int                   `json:"max_accounts,omitempty"`
	AllowedKeyAlgorithms    []string              `json:"allowed_key_algorithms,omitempty"`
	AllowedChallengeTypes   []string              `json:"allowed_challenge_types,omitempty"`
	CertificateValidityDays int                   `json:"certificate_validity_days,omitempty"`
	RequireEAB              bool                  `json:"require_eab,omitempty"`
	AllowEndorse01          bool                  `json:"allow_endorse_01,omitempty"`
	AllowEnroll01           bool                  `json:"allow_enroll_01,omitempty"`
	ComplianceConfig        *ComplianceConfigInfo `json:"compliance_config,omitempty"`
}

// ComplianceConfigInfo is the compliance configuration for certificate
// issuance.
type ComplianceConfigInfo struct {
	// Enabled indicates whether compliance validation is active
	Enabled bool `json:"enabled"`

	// RequireSignedReport indicates whether the compliance report must be signed
	RequireSignedReport bool `json:"require_signed_report"`

	// CustomPolicyPath is the path to a custom Rego policy file
	CustomPolicyPath string `json:"custom_policy_path,omitempty"`

	// FailOpen determines behavior when compliance data is missing
	// If true, missing report = pass (fail-open)
	// If false, missing report = fail (fail-closed)
	FailOpen bool `json:"fail_open"`
}
