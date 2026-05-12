// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package common

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Status Constants Tests
// =============================================================================

func TestStatusConstants(t *testing.T) {
	assert.Equal(t, "valid", StatusValid)
	assert.Equal(t, "pending", StatusPending)
	assert.Equal(t, "processing", StatusProcessing)
	assert.Equal(t, "invalid", StatusInvalid)
	assert.Equal(t, "deactivated", StatusDeactivated)
	assert.Equal(t, "expired", StatusExpired)
	assert.Equal(t, "revoked", StatusRevoked)
	assert.Equal(t, "ready", StatusReady)
}

// =============================================================================
// Authorization Type Constants Tests
// =============================================================================

func TestAuthorizationTypeConstants(t *testing.T) {
	assert.Equal(t, "dns", AuthzTypeDNS)
	assert.Equal(t, "ip", AuthzTypeIP)
	assert.Equal(t, "permanent-identifier", AuthzTypePermanentIdentifier)
}

// =============================================================================
// Challenge Type Constants Tests
// =============================================================================

func TestChallengeTypeConstants(t *testing.T) {
	assert.Equal(t, "enroll-01", ChallengeTypeEnroll01)
	assert.Equal(t, "dns-01", ChallengeTypeDNS01)
	assert.Equal(t, "http-01", ChallengeTypeHTTP01)
	assert.Equal(t, "endorse-01", ChallengeTypeEndorse01)
	assert.Equal(t, "device-attest-01", ChallengeTypeDeviceAttest01)
}

// =============================================================================
// Error Constants Tests
// =============================================================================

func TestErrorConstants(t *testing.T) {
	assert.NotNil(t, ErrInvalidChallengeType)
	assert.NotNil(t, ErrAccountAlreadyExists)

	assert.Equal(t, "acme: invalid challenge type", ErrInvalidChallengeType.Error())
	assert.Equal(t, "acme: account already exists", ErrAccountAlreadyExists.Error())
}

// =============================================================================
// Directory Type Tests
// =============================================================================

func TestDirectory(t *testing.T) {
	dir := Directory{
		NewNonce:   "https://example.com/nonce",
		NewAccount: "https://example.com/account",
		NewOrder:   "https://example.com/order",
		NewAuthz:   "https://example.com/authz",
		RevokeCert: "https://example.com/revoke",
		KeyChange:  "https://example.com/keychange",
		Meta: Meta{
			TermsOfService:     "https://example.com/tos",
			Website:            "https://example.com",
			CAAIdentities:      []string{"example.com"},
			ExternalAccountReq: true,
		},
	}

	assert.Equal(t, "https://example.com/nonce", dir.NewNonce)
	assert.Equal(t, "https://example.com/account", dir.NewAccount)
	assert.Equal(t, "https://example.com/order", dir.NewOrder)
	assert.Equal(t, "https://example.com/authz", dir.NewAuthz)
	assert.Equal(t, "https://example.com/revoke", dir.RevokeCert)
	assert.Equal(t, "https://example.com/keychange", dir.KeyChange)
	assert.Equal(t, "https://example.com/tos", dir.Meta.TermsOfService)
	assert.Equal(t, "https://example.com", dir.Meta.Website)
	assert.Equal(t, []string{"example.com"}, dir.Meta.CAAIdentities)
	assert.True(t, dir.Meta.ExternalAccountReq)
}

func TestDirectory_EmptyOptionalFields(t *testing.T) {
	dir := Directory{
		NewNonce:   "https://example.com/nonce",
		NewAccount: "https://example.com/account",
		NewOrder:   "https://example.com/order",
		RevokeCert: "https://example.com/revoke",
		KeyChange:  "https://example.com/keychange",
		// NewAuthz is optional
		Meta: Meta{
			// All meta fields are optional
		},
	}

	assert.Equal(t, "", dir.NewAuthz)
	assert.Equal(t, "", dir.Meta.TermsOfService)
	assert.Equal(t, "", dir.Meta.Website)
	assert.Nil(t, dir.Meta.CAAIdentities)
	assert.False(t, dir.Meta.ExternalAccountReq)
}

// =============================================================================
// Meta Type Tests
// =============================================================================

func TestMeta(t *testing.T) {
	meta := Meta{
		TermsOfService:     "https://example.com/tos",
		Website:            "https://example.com",
		CAAIdentities:      []string{"example.com", "example.org"},
		ExternalAccountReq: true,
	}

	assert.Equal(t, "https://example.com/tos", meta.TermsOfService)
	assert.Equal(t, "https://example.com", meta.Website)
	assert.Len(t, meta.CAAIdentities, 2)
	assert.Contains(t, meta.CAAIdentities, "example.com")
	assert.Contains(t, meta.CAAIdentities, "example.org")
	assert.True(t, meta.ExternalAccountReq)
}

func TestMeta_Empty(t *testing.T) {
	meta := Meta{}

	assert.Equal(t, "", meta.TermsOfService)
	assert.Equal(t, "", meta.Website)
	assert.Nil(t, meta.CAAIdentities)
	assert.False(t, meta.ExternalAccountReq)
}

// =============================================================================
// ChallengeVerifierFunc Type Tests
// =============================================================================

func TestChallengeVerifierFunc_TypeDefinition(t *testing.T) {
	// Verify the function type can be instantiated
	var verifier ChallengeVerifierFunc = func(
		resolver *net.Resolver,
		ca CertificateAuthority,
		authzValue, challengePort, challengeToken, expectedKeyAuth string,
	) error {
		return nil
	}

	// The function should be callable (compile-time check)
	err := verifier(nil, nil, "value", "port", "token", "keyAuth")
	assert.NoError(t, err)
}

func TestChallengeVerifierFunc_ReturnsError(t *testing.T) {
	expectedErr := ErrInvalidChallengeType

	var verifier ChallengeVerifierFunc = func(
		resolver *net.Resolver,
		ca CertificateAuthority,
		authzValue, challengePort, challengeToken, expectedKeyAuth string,
	) error {
		return expectedErr
	}

	err := verifier(nil, nil, "value", "port", "token", "keyAuth")
	assert.Equal(t, expectedErr, err)
}
