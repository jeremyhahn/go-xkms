// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"crypto/x509/pkix"
	"errors"
)

// ErrOwnerOUMissing indicates a tenant certificate whose subject does not
// name its tenant as the first organizational unit (ruling 1073 (a)).
var ErrOwnerOUMissing = errors.New("ca: certificate subject does not carry the tenant OU")

// OwnerOUKind names what a certificate subject is for, which decides whether
// the subject must carry the tenant as OU[0]. The exemptions follow the
// profile or template kind, never a match on the subject's text.
type OwnerOUKind int

const (
	// OwnerOUKindTenantLeaf is a tenant end-entity certificate: OU[0] must
	// be the tenant.
	OwnerOUKindTenantLeaf OwnerOUKind = iota
	// OwnerOUKindTenantCA is a CA certificate issued for a tenant: OU[0]
	// must be the tenant.
	OwnerOUKindTenantCA
	// OwnerOUKindSystemCA is the system root or an intermediate: exempt.
	OwnerOUKindSystemCA
	// OwnerOUKindFIDO2Attestation is a FIDO2 attestation certificate, whose
	// OU WebAuthn fixes to FIDO2AttestationCertificateOU: exempt.
	OwnerOUKindFIDO2Attestation
	// OwnerOUKindTCGLAK is a TCG local attestation key certificate, whose
	// subject the TCG profile requires empty: exempt.
	OwnerOUKindTCGLAK
)

// OwnerOUKindFor returns the owner-OU kind of a certificate issued under the
// named profile (empty when none). A CA template with no tenant belongs to
// the system hierarchy.
func OwnerOUKindFor(profileName string, isCA bool, tenantID string) OwnerOUKind {
	switch {
	case profileName == ProfileNameFIDO2Attestation:
		return OwnerOUKindFIDO2Attestation
	case profileName == ProfileNameTCGLocalAK:
		return OwnerOUKindTCGLAK
	case isCA && tenantID == "":
		return OwnerOUKindSystemCA
	case isCA:
		return OwnerOUKindTenantCA
	default:
		return OwnerOUKindTenantLeaf
	}
}

// Exempt reports whether subjects of this kind need not carry the tenant OU.
func (k OwnerOUKind) Exempt() bool {
	switch k {
	case OwnerOUKindSystemCA, OwnerOUKindFIDO2Attestation, OwnerOUKindTCGLAK:
		return true
	default:
		return false
	}
}

// CheckOwnerOU refuses, with ErrOwnerOUMissing, a subject of a non-exempt
// kind whose first organizational unit is not tenantID. An empty tenantID on
// a non-exempt kind is refused with ErrTenantRequired.
func CheckOwnerOU(kind OwnerOUKind, tenantID string, subject pkix.Name) error {
	if kind.Exempt() {
		return nil
	}
	if tenantID == "" {
		return ErrTenantRequired
	}
	if firstOrEmpty(subject.OrganizationalUnit) != tenantID {
		return ErrOwnerOUMissing
	}
	return nil
}
