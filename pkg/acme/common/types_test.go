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
	assert.Equal(t, "acme: invalid challenge type", ErrInvalidChallengeType.Error())
	assert.Equal(t, "acme: account already exists", ErrAccountAlreadyExists.Error())
}
