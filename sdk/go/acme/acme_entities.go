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
