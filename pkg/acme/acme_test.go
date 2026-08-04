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

package acme

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestTypeExports verifies that type aliases are properly exported
func TestTypeExports(t *testing.T) {
	// Verify Config type alias works
	var _ Config
	var _ ClientParams
	var _ RenewalConfig
	var _ EnrollmentConfig
	var _ CrossSignConfig

	// Verify Directory type alias
	var _ Directory
	var _ Meta

	// Verify Entity type aliases
	var _ ACMEAccount
	var _ ACMEOrder
	var _ ACMEAuthorization
	var _ ACMEChallenge
	var _ ACMECertificate
	var _ ACMENonce
	var _ ACMEIdentifier
	var _ ExternalAccountBinding
	var _ Error
	var _ SubProblem

	// Verify Storage type aliases
	var _ Factory

	// Verify typed constants
	var _ AuthorizationType
	var _ ChallengeType
	var _ AccountStatus
	var _ OrderStatus
}

// TestAuthorizationTypeConstants verifies authorization type constants
func TestAuthorizationTypeConstants(t *testing.T) {
	assert.Equal(t, "dns", AuthzTypeDNS)
	assert.Equal(t, "ip", AuthzTypeIP)
	assert.Equal(t, "permanent-identifier", AuthzTypePermanentIdentifier)
}

// TestChallengeTypeConstants verifies challenge type constants
func TestChallengeTypeConstants(t *testing.T) {
	assert.Equal(t, "enroll-01", ChallengeTypeEnroll01)
	assert.Equal(t, "dns-01", ChallengeTypeDNS01)
	assert.Equal(t, "http-01", ChallengeTypeHTTP01)
	assert.Equal(t, "endorse-01", ChallengeTypeEndorse01)
	assert.Equal(t, "device-attest-01", ChallengeTypeDeviceAttest01)
}

// TestStatusConstants verifies status constants
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

// TestTypedConstants verifies typed constant values
func TestTypedConstants(t *testing.T) {
	// Authorization types
	assert.Equal(t, AuthorizationType("dns"), AuthzTypeDNSTyped)
	assert.Equal(t, AuthorizationType("ip"), AuthzTypeIPTyped)
	assert.Equal(t, AuthorizationType("permanent-identifier"), AuthzTypePermanentIdentifierTyped)

	// Challenge types
	assert.Equal(t, ChallengeType("http-01"), ChallengeTypeHTTP01Typed)
	assert.Equal(t, ChallengeType("dns-01"), ChallengeTypeDNS01Typed)
	assert.Equal(t, ChallengeType("tls-alpn-01"), ChallengeTypeTLSALPN01Typed)
	assert.Equal(t, ChallengeType("endorse-01"), ChallengeTypeEndorse01Typed)
	assert.Equal(t, ChallengeType("enroll-01"), ChallengeTypeEnroll01Typed)
	assert.Equal(t, ChallengeType("device-attest-01"), ChallengeTypeDeviceAttest01Type)

	// Account status
	assert.Equal(t, AccountStatus("valid"), AccountStatusValid)
	assert.Equal(t, AccountStatus("deactivated"), AccountStatusDeactivated)
	assert.Equal(t, AccountStatus("revoked"), AccountStatusRevoked)

	// Order status
	assert.Equal(t, OrderStatus("pending"), OrderStatusPending)
	assert.Equal(t, OrderStatus("ready"), OrderStatusReady)
	assert.Equal(t, OrderStatus("processing"), OrderStatusProcessing)
	assert.Equal(t, OrderStatus("valid"), OrderStatusValidOrder)
	assert.Equal(t, OrderStatus("invalid"), OrderStatusInvalid)
}

// TestClientErrors verifies client error variables are exported
func TestClientErrors(t *testing.T) {
	assert.NotNil(t, ErrAccountNotFound)
	assert.NotNil(t, ErrRegistrationFailed)
	assert.NotNil(t, ErrOrderCreationFailed)
	assert.NotNil(t, ErrChallengeResolution)
	assert.NotNil(t, ErrChallengeFinalization)
	assert.NotNil(t, ErrAuthorizationFailed)
	assert.NotNil(t, ErrCABundleDownloadFailed)
	assert.NotNil(t, ErrInvalidCACertificate)
	assert.NotNil(t, ErrInvalidCrossSignerAuthzID)
	assert.NotNil(t, ErrCertificateNotFound)
	assert.NotNil(t, ErrInvalidConfiguration)
	assert.NotNil(t, ErrNilSigner)
	assert.NotNil(t, ErrNilStorage)
	assert.NotNil(t, ErrInvalidRequest)
	assert.NotNil(t, ErrMissingAuthzType)
	assert.NotNil(t, ErrMissingAuthzValue)
	assert.NotNil(t, ErrMissingChallengeType)
	assert.NotNil(t, ErrMissingCSR)
	assert.NotNil(t, ErrInvalidChallengeSetup)
	assert.NotNil(t, ErrInvalidDirectoryURL)
	assert.NotNil(t, ErrInvalidTimeout)
	assert.NotNil(t, ErrInvalidRetryAttempts)
	assert.NotNil(t, ErrInvalidRenewalThreshold)
}

// TestCommonErrors verifies common error variables are exported
func TestCommonErrors(t *testing.T) {
	assert.NotNil(t, ErrInvalidChallengeType)
	assert.NotNil(t, ErrAccountAlreadyExists)
	assert.NotNil(t, ErrCrossSignerSameDirectoryURL)
}

// TestDefaultConfigFunctions verifies default config functions are exported
func TestDefaultConfigFunctions(t *testing.T) {
	assert.NotNil(t, DefaultConfig)
	assert.NotNil(t, DefaultRenewalConfig)

	// Test that functions return non-nil values
	config := DefaultConfig()
	assert.NotNil(t, config)

	renewalConfig := DefaultRenewalConfig()
	assert.NotNil(t, renewalConfig)
}
