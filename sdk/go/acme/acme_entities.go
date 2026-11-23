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

package trustedca

// This file re-exports ACME entity types from pkg/acme/entities for SDK
// consumers that implement ACME storage backends (e.g., go-trusted-platform).

import (
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// =============================================================================
// ACME Entity Types
// =============================================================================

// ACMEAccountEntity represents an ACME account with contact info and keys.
type ACMEAccountEntity = entities.ACMEAccount

// ACMEOrderEntity represents an ACME order for certificate issuance.
type ACMEOrderEntity = entities.ACMEOrder

// ACMEAuthorizationEntity represents an ACME authorization proving domain control.
type ACMEAuthorizationEntity = entities.ACMEAuthorization

// ACMEChallengeEntity represents an ACME challenge used to validate authorization.
type ACMEChallengeEntity = entities.ACMEChallenge

// ACMEDeviceAttestationEntity is the verified device-attest-01 evidence
// persisted on a validated challenge so order finalization can bind the
// certificate request's key to it.
type ACMEDeviceAttestationEntity = entities.DeviceAttestation

// ACMECertificateEntity represents an issued ACME certificate.
type ACMECertificateEntity = entities.ACMECertificate

// ACMENonceEntity represents an ACME replay-prevention nonce.
type ACMENonceEntity = entities.ACMENonce

// ACMEExternalAccountBinding represents an ACME external account binding.
type ACMEExternalAccountBinding = entities.ExternalAccountBinding

// ACMETenant represents a tenant in a multi-tenant ACME deployment.
type ACMETenant = entities.Tenant

// TenantSettings is the per-tenant ACME policy of an ACMETenant.
type TenantSettings = entities.TenantSettings

// TenantRootCA is a tenant's root CA record.
type TenantRootCA = entities.TenantRootCA

// TenantIntermediateCA is a tenant's intermediate CA record.
type TenantIntermediateCA = entities.TenantIntermediateCA

// SigningCAInfo describes the CA that signs a tenant's certificates.
type SigningCAInfo = entities.SigningCAInfo

// EABDeviceInfo is the device binding of an external account binding.
type EABDeviceInfo = entities.EABDeviceInfo

// ExternalAccountBindingJWS is the flattened JWS of an externalAccountBinding.
type ExternalAccountBindingJWS = entities.ExternalAccountBindingJWS

// ExternalAccountBindingProtectedHeader is the protected header of an
// ExternalAccountBindingJWS.
type ExternalAccountBindingProtectedHeader = entities.ExternalAccountBindingProtectedHeader

// SubProblem is an RFC 8555 §6.7.1 subproblem of an ACME problem document.
type SubProblem = entities.SubProblem

// InvalidSerialError reports a certificate serial that does not parse.
type InvalidSerialError = entities.InvalidSerialError

// NormalizeSerial returns the canonical form of a certificate serial.
var NormalizeSerial = entities.NormalizeSerial

// StringToEntityID hashes a string key to an entity ID.
var StringToEntityID = entities.StringToEntityID

// AUTHORIZATION_INDEX_URL is the index key for authorization URL lookups.
const AUTHORIZATION_INDEX_URL = entities.AUTHORIZATION_INDEX_URL

// Tenant statuses.
const (
	TenantStatusActive    = entities.TenantStatusActive
	TenantStatusSuspended = entities.TenantStatusSuspended
	TenantStatusDeleted   = entities.TenantStatusDeleted
)

// CA statuses, parent types and purposes.
const (
	CAStatusActive          = entities.CAStatusActive
	CAStatusPendingRotation = entities.CAStatusPendingRotation
	CAStatusRevoked         = entities.CAStatusRevoked
	CAParentTypeGlobal      = entities.CAParentTypeGlobal
	CAParentTypeTenant      = entities.CAParentTypeTenant
	CAPurposeGeneral        = entities.CAPurposeGeneral
	CAPurposeServerAuth     = entities.CAPurposeServerAuth
	CAPurposeClientAuth     = entities.CAPurposeClientAuth
	CAPurposeCodeSigning    = entities.CAPurposeCodeSigning
	CAPurposeTPMEndorsement = entities.CAPurposeTPMEndorsement
)

// Signing CA types (SigningCAInfo.Type).
const (
	SigningCATypeIntermediate = entities.SigningCATypeIntermediate
	SigningCATypeRoot         = entities.SigningCATypeRoot
	SigningCATypeGlobal       = entities.SigningCATypeGlobal
)

// External account binding purposes and statuses.
const (
	EABPurposeAccountBinding = entities.EABPurposeAccountBinding
	EABPurposeEndorse01      = entities.EABPurposeEndorse01
	EABPurposeEnroll01       = entities.EABPurposeEnroll01
	EABStatusActive          = entities.EABStatusActive
	EABStatusUsed            = entities.EABStatusUsed
	EABStatusRevoked         = entities.EABStatusRevoked
	EABStatusExpired         = entities.EABStatusExpired
)
