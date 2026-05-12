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

package rfc8555

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthorizationCreation tests ACME authorization object creation
func TestAuthorizationCreation(t *testing.T) {
	authz := &entities.ACMEAuthorization{
		ID: 11111,
		Identifier: entities.ACMEIdentifier{
			Type:  "dns",
			Value: "example.com",
		},
		Status:    common.StatusPending,
		Expires:   time.Now().Add(7 * 24 * time.Hour).Format(time.RFC3339),
		Wildcard:  false,
		AccountID: 12345,
		OrderID:   54321,
		URL:       "https://acme.example.com/acme/authz/11111",
		Challenges: []entities.ACMEChallenge{
			{
				Type:   common.ChallengeTypeHTTP01,
				Status: common.StatusPending,
				Token:  "test-token-12345",
				URL:    "https://acme.example.com/acme/challenge/1",
			},
		},
	}

	assert.Equal(t, uint64(11111), authz.ID)
	assert.Equal(t, "dns", authz.Identifier.Type)
	assert.Equal(t, "example.com", authz.Identifier.Value)
	assert.Equal(t, common.StatusPending, authz.Status)
	assert.False(t, authz.Wildcard)
	assert.Len(t, authz.Challenges, 1)
}

// TestAuthorizationStatus tests authorization status transitions
func TestAuthorizationStatus(t *testing.T) {
	validStatuses := []string{
		common.StatusPending,
		common.StatusValid,
		common.StatusInvalid,
		common.StatusDeactivated,
		common.StatusExpired,
	}

	for _, status := range validStatuses {
		t.Run(status, func(t *testing.T) {
			authz := &entities.ACMEAuthorization{
				ID:     11111,
				Status: status,
			}

			assert.Equal(t, status, authz.Status)
		})
	}
}

// TestAuthorizationExpiration tests authorization expiration handling
func TestAuthorizationExpiration(t *testing.T) {
	// Future expiration
	futureTime := time.Now().Add(7 * 24 * time.Hour)
	authz1 := &entities.ACMEAuthorization{
		ID:      11111,
		Status:  common.StatusPending,
		Expires: futureTime.Format(time.RFC3339),
	}

	expiresTime, err := time.Parse(time.RFC3339, authz1.Expires)
	require.NoError(t, err)
	assert.True(t, expiresTime.After(time.Now()))

	// Past expiration
	pastTime := time.Now().Add(-1 * time.Hour)
	authz2 := &entities.ACMEAuthorization{
		ID:      11112,
		Status:  common.StatusExpired,
		Expires: pastTime.Format(time.RFC3339),
	}

	expiresTime2, err := time.Parse(time.RFC3339, authz2.Expires)
	require.NoError(t, err)
	assert.True(t, expiresTime2.Before(time.Now()))
}

// TestAuthorizationWildcard tests wildcard authorization flag
func TestAuthorizationWildcard(t *testing.T) {
	// Regular domain
	authz1 := &entities.ACMEAuthorization{
		ID: 11111,
		Identifier: entities.ACMEIdentifier{
			Type:  "dns",
			Value: "example.com",
		},
		Wildcard: false,
	}
	assert.False(t, authz1.Wildcard)

	// Wildcard domain
	authz2 := &entities.ACMEAuthorization{
		ID: 11112,
		Identifier: entities.ACMEIdentifier{
			Type:  "dns",
			Value: "example.com", // Value is base domain, not *.example.com
		},
		Wildcard: true, // Flag indicates wildcard
	}
	assert.True(t, authz2.Wildcard)
}

// TestAuthorizationIdentifierTypes tests different identifier types
func TestAuthorizationIdentifierTypes(t *testing.T) {
	testCases := []struct {
		name           string
		identifierType string
		value          string
	}{
		{
			name:           "DNS identifier",
			identifierType: "dns",
			value:          "example.com",
		},
		{
			name:           "IP identifier",
			identifierType: "ip",
			value:          "192.0.2.1",
		},
		{
			name:           "Permanent identifier",
			identifierType: "permanent-identifier",
			value:          "serial-12345",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authz := &entities.ACMEAuthorization{
				ID: 11111,
				Identifier: entities.ACMEIdentifier{
					Type:  tc.identifierType,
					Value: tc.value,
				},
				Status: common.StatusPending,
			}

			assert.Equal(t, tc.identifierType, authz.Identifier.Type)
			assert.Equal(t, tc.value, authz.Identifier.Value)
		})
	}
}

// TestAuthorizationChallenges tests challenge association
func TestAuthorizationChallenges(t *testing.T) {
	challenges := []entities.ACMEChallenge{
		{
			ID:     1,
			Type:   common.ChallengeTypeHTTP01,
			Status: common.StatusPending,
			Token:  "http-token",
		},
		{
			ID:     2,
			Type:   common.ChallengeTypeDNS01,
			Status: common.StatusPending,
			Token:  "dns-token",
		},
	}

	authz := &entities.ACMEAuthorization{
		ID:         11111,
		Status:     common.StatusPending,
		Challenges: challenges,
	}

	assert.Len(t, authz.Challenges, 2)
	assert.Equal(t, common.ChallengeTypeHTTP01, authz.Challenges[0].Type)
	assert.Equal(t, common.ChallengeTypeDNS01, authz.Challenges[1].Type)
}

// TestAuthorizationDeactivation tests authorization deactivation
func TestAuthorizationDeactivation(t *testing.T) {
	authz := &entities.ACMEAuthorization{
		ID:     11111,
		Status: common.StatusValid,
	}

	// Deactivate
	authz.Status = common.StatusDeactivated

	assert.Equal(t, common.StatusDeactivated, authz.Status)
}

// TestAuthorizationJSON tests authorization JSON serialization
func TestAuthorizationJSON(t *testing.T) {
	authz := &entities.ACMEAuthorization{
		ID: 11111,
		Identifier: entities.ACMEIdentifier{
			Type:  "dns",
			Value: "example.com",
		},
		Status:    common.StatusPending,
		Expires:   time.Now().Add(7 * 24 * time.Hour).Format(time.RFC3339),
		Wildcard:  false,
		AccountID: 12345,
		URL:       "https://acme.example.com/acme/authz/11111",
		Challenges: []entities.ACMEChallenge{
			{
				Type:   common.ChallengeTypeHTTP01,
				Status: common.StatusPending,
				Token:  "test-token",
			},
		},
	}

	jsonData, err := json.Marshal(authz)
	require.NoError(t, err)

	var unmarshaled entities.ACMEAuthorization
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, authz.ID, unmarshaled.ID)
	assert.Equal(t, authz.Identifier.Type, unmarshaled.Identifier.Type)
	assert.Equal(t, authz.Identifier.Value, unmarshaled.Identifier.Value)
	assert.Equal(t, authz.Status, unmarshaled.Status)
	assert.Equal(t, authz.Wildcard, unmarshaled.Wildcard)
}

// TestAuthorizationEntityID tests entity ID methods
func TestAuthorizationEntityID(t *testing.T) {
	authz := &entities.ACMEAuthorization{}

	authz.SetEntityID(99999)
	assert.Equal(t, uint64(99999), authz.EntityID())
}

// TestAuthorizationAccountAssociation tests account association
func TestAuthorizationAccountAssociation(t *testing.T) {
	accountID := uint64(12345)
	authz := &entities.ACMEAuthorization{
		ID:        11111,
		AccountID: accountID,
	}

	assert.Equal(t, accountID, authz.AccountID)
}

// TestAuthorizationOrderAssociation tests order association
func TestAuthorizationOrderAssociation(t *testing.T) {
	orderID := uint64(54321)
	authz := &entities.ACMEAuthorization{
		ID:      11111,
		OrderID: orderID,
	}

	assert.Equal(t, orderID, authz.OrderID)
}

// TestAuthorizationValidation tests authorization validation completion
func TestAuthorizationValidation(t *testing.T) {
	// Initial state - pending
	authz := &entities.ACMEAuthorization{
		ID:     11111,
		Status: common.StatusPending,
		Challenges: []entities.ACMEChallenge{
			{
				ID:     1,
				Type:   common.ChallengeTypeHTTP01,
				Status: common.StatusPending,
			},
		},
	}

	assert.Equal(t, common.StatusPending, authz.Status)

	// After successful validation
	authz.Status = common.StatusValid
	authz.Challenges[0].Status = common.StatusValid
	authz.Challenges[0].Validated = time.Now().Format(time.RFC3339)

	assert.Equal(t, common.StatusValid, authz.Status)
	assert.Equal(t, common.StatusValid, authz.Challenges[0].Status)
	assert.NotEmpty(t, authz.Challenges[0].Validated)
}

// TestAuthorizationMultipleChallenges tests authorization with multiple challenge types
func TestAuthorizationMultipleChallenges(t *testing.T) {
	authz := &entities.ACMEAuthorization{
		ID:     11111,
		Status: common.StatusPending,
		Challenges: []entities.ACMEChallenge{
			{Type: common.ChallengeTypeHTTP01, Status: common.StatusPending},
			{Type: common.ChallengeTypeDNS01, Status: common.StatusPending},
			{Type: common.ChallengeTypeEnroll01, Status: common.StatusPending},
		},
	}

	// Client can choose any challenge type
	assert.Len(t, authz.Challenges, 3)

	// After completing one challenge, others become invalid
	authz.Challenges[0].Status = common.StatusValid
	authz.Status = common.StatusValid

	assert.Equal(t, common.StatusValid, authz.Status)
}
