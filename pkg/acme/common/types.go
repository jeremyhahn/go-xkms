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

package common

import (
	"errors"
	"net"
)

// ACME status values for Account, Order, Authorization and Challenge objects.
// See https://tools.ietf.org/html/rfc8555#section-7.1.6 for details.
const (
	StatusValid       = "valid"       // Entity is valid (account, order, authorization, certificate)
	StatusPending     = "pending"     // Entity is pending (order, authorization, challenge)
	StatusProcessing  = "processing"  // Entity is processing (order, challenge)
	StatusInvalid     = "invalid"     // Entity is invalid (order, authorization, challenge)
	StatusDeactivated = "deactivated" // Entity is deactivated (account, authorization)
	StatusExpired     = "expired"     // Entity is expired (authorization, certificate)
	StatusRevoked     = "revoked"     // Entity is revoked (account, certificate)
	StatusReady       = "ready"       // Entity is ready (order)
)

// Authorization type constants.
const (
	AuthzTypeDNS                 = "dns"
	AuthzTypeIP                  = "ip"
	AuthzTypePermanentIdentifier = "permanent-identifier"
)

// Challenge type constants.
const (
	ChallengeTypeEnroll01       = "enroll-01"
	ChallengeTypeDNS01          = "dns-01"
	ChallengeTypeHTTP01         = "http-01"
	ChallengeTypeEndorse01      = "endorse-01"
	ChallengeTypeDeviceAttest01 = "device-attest-01"
)

var (
	// ErrInvalidChallengeType is returned when an invalid challenge type is provided.
	ErrInvalidChallengeType = errors.New("acme: invalid challenge type")

	// ErrAccountAlreadyExists is returned when attempting to create a duplicate account.
	ErrAccountAlreadyExists = errors.New("acme: account already exists")
)

// Directory provides the ACME server's directory endpoints as per RFC 8555 Section 7.1.1.
// It serves as the discovery mechanism for ACME clients to find the server's resources.
//
// RFC 8555 Section 7.1.1: "If the ACME server does not implement pre-authorization
// (Section 7.4.1), it MUST omit the 'newAuthz' field of the directory."
type Directory struct {
	NewNonce   string `json:"newNonce"`           // URL for obtaining a fresh nonce
	NewAccount string `json:"newAccount"`         // URL for creating a new account
	NewOrder   string `json:"newOrder"`           // URL for creating a new order
	NewAuthz   string `json:"newAuthz,omitempty"` // URL for pre-authorization (optional, only if supported)
	RevokeCert string `json:"revokeCert"`         // URL for revoking a certificate
	KeyChange  string `json:"keyChange"`          // URL for changing account key
	Meta       Meta   `json:"meta"`               // Server metadata
}

// Meta provides additional information about the ACME server.
type Meta struct {
	TermsOfService     string   `json:"termsOfService,omitempty"`          // URL of terms of service
	Website            string   `json:"website,omitempty"`                 // Server website URL
	CAAIdentities      []string `json:"caaIdentities,omitempty"`           // CAA identities for this server
	ExternalAccountReq bool     `json:"externalAccountRequired,omitempty"` // Whether external account binding is required
}

// CertificateAuthority is the opaque CA handle threaded through
// ChallengeVerifierFunc. It is deliberately method-free: the challenge types
// need mutually disjoint CA capabilities (enroll-01 needs TCG-CSR-IDEVID
// verification, endorse-01 needs CSR creation, http-01/dns-01 need nothing at
// all), so a verifier that requires a capability asserts this value to the
// narrow interface it needs and fails closed when the assertion does not hold.
// See ACMEAttestationVerifiers in sdk/go/acme for the canonical example.
//
// It is NOT a placeholder. Widening it to a concrete method set would force
// every CA implementation to satisfy the union of all challenge requirements.
type CertificateAuthority interface{}

// ChallengeVerifierFunc defines the function signature for challenge verification functions.
// Each challenge type (http-01, dns-01, etc.) implements this interface to verify
// that a client has control over the requested identifier.
//
// Parameters:
//   - resolver: DNS resolver to use for lookups
//   - ca: opaque CA handle; verifiers needing CA behavior assert it to a
//     narrow capability interface (see CertificateAuthority)
//   - authzValue: The identifier value being authorized (domain name, IP, etc.)
//   - challengePort: The port to use for verification
//   - challengeToken: The challenge token provided by the server
//   - expectedKeyAuth: The expected key authorization value
//
// Returns:
//   - nil if verification succeeds
//   - error describing the failure reason if verification fails
type ChallengeVerifierFunc func(
	resolver *net.Resolver,
	ca CertificateAuthority,
	authzValue, challengePort, challengeToken, expectedKeyAuth string) error
