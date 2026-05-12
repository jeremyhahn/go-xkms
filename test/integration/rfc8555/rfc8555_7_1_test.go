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

// TestDirectory_Structure tests ACME directory object structure
func TestDirectory_Structure(t *testing.T) {
	dir := common.Directory{
		NewNonce:   "https://acme.example.com/acme/new-nonce",
		NewAccount: "https://acme.example.com/acme/new-account",
		NewOrder:   "https://acme.example.com/acme/new-order",
		RevokeCert: "https://acme.example.com/acme/revoke-cert",
		KeyChange:  "https://acme.example.com/acme/key-change",
		Meta: common.Meta{
			TermsOfService: "https://acme.example.com/terms",
			Website:        "https://acme.example.com",
			CAAIdentities:  []string{"acme.example.com"},
		},
	}

	// Verify all required fields are present
	assert.NotEmpty(t, dir.NewNonce)
	assert.NotEmpty(t, dir.NewAccount)
	assert.NotEmpty(t, dir.NewOrder)
	assert.NotEmpty(t, dir.RevokeCert)
	assert.NotEmpty(t, dir.KeyChange)
}

// TestDirectory_JSONSerialization tests directory JSON marshaling
func TestDirectory_JSONSerialization(t *testing.T) {
	dir := common.Directory{
		NewNonce:   "https://acme.example.com/acme/new-nonce",
		NewAccount: "https://acme.example.com/acme/new-account",
		NewOrder:   "https://acme.example.com/acme/new-order",
		RevokeCert: "https://acme.example.com/acme/revoke-cert",
		KeyChange:  "https://acme.example.com/acme/key-change",
		Meta: common.Meta{
			TermsOfService:     "https://acme.example.com/terms",
			ExternalAccountReq: false,
		},
	}

	jsonData, err := json.Marshal(dir)
	require.NoError(t, err)

	var unmarshaled common.Directory
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, dir.NewNonce, unmarshaled.NewNonce)
	assert.Equal(t, dir.NewAccount, unmarshaled.NewAccount)
	assert.Equal(t, dir.NewOrder, unmarshaled.NewOrder)
	assert.Equal(t, dir.RevokeCert, unmarshaled.RevokeCert)
	assert.Equal(t, dir.KeyChange, unmarshaled.KeyChange)
}

// TestAccount_Creation tests ACME account object creation
func TestAccount_Creation(t *testing.T) {
	account := &entities.ACMEAccount{
		ID:                   12345,
		Status:               common.StatusValid,
		Contact:              []string{"mailto:admin@example.com"},
		TermsOfServiceAgreed: true,
		Orders:               "https://acme.example.com/acme/account/12345/orders",
		CreatedAt:            time.Now(),
	}

	assert.Equal(t, uint64(12345), account.ID)
	assert.Equal(t, common.StatusValid, account.Status)
	assert.Len(t, account.Contact, 1)
	assert.True(t, account.TermsOfServiceAgreed)
}

// TestAccount_EntityID tests account entity ID methods
func TestAccount_EntityID(t *testing.T) {
	account := &entities.ACMEAccount{}

	account.SetEntityID(99999)
	assert.Equal(t, uint64(99999), account.EntityID())
}

// TestOrder_Creation tests ACME order object creation
func TestOrder_Creation(t *testing.T) {
	order := &entities.ACMEOrder{
		ID:     54321,
		Status: common.StatusPending,
		Identifiers: []entities.ACMEIdentifier{
			{Type: "dns", Value: "example.com"},
			{Type: "dns", Value: "www.example.com"},
		},
		Authorizations: []string{
			"https://acme.example.com/acme/authz/1",
			"https://acme.example.com/acme/authz/2",
		},
		Finalize:  "https://acme.example.com/acme/order/54321/finalize",
		AccountID: 12345,
	}

	assert.Equal(t, uint64(54321), order.ID)
	assert.Equal(t, common.StatusPending, order.Status)
	assert.Len(t, order.Identifiers, 2)
	assert.Len(t, order.Authorizations, 2)
}

// TestOrder_EntityID tests order entity ID methods
func TestOrder_EntityID(t *testing.T) {
	order := &entities.ACMEOrder{}

	order.SetEntityID(88888)
	assert.Equal(t, uint64(88888), order.EntityID())
}

// TestAuthorization_Creation tests ACME authorization object creation
func TestAuthorization_Creation(t *testing.T) {
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
		Challenges: []entities.ACMEChallenge{
			{
				Type:   common.ChallengeTypeHTTP01,
				Status: common.StatusPending,
				Token:  "test-token-12345",
			},
		},
	}

	assert.Equal(t, uint64(11111), authz.ID)
	assert.Equal(t, "dns", authz.Identifier.Type)
	assert.Equal(t, "example.com", authz.Identifier.Value)
	assert.Equal(t, common.StatusPending, authz.Status)
	assert.Len(t, authz.Challenges, 1)
}

// TestAuthorization_EntityID tests authorization entity ID methods
func TestAuthorization_EntityID(t *testing.T) {
	authz := &entities.ACMEAuthorization{}

	authz.SetEntityID(77777)
	assert.Equal(t, uint64(77777), authz.EntityID())
}

// TestChallenge_Creation tests ACME challenge object creation
func TestChallenge_Creation(t *testing.T) {
	challenge := &entities.ACMEChallenge{
		ID:              22222,
		Type:            common.ChallengeTypeHTTP01,
		URL:             "https://acme.example.com/acme/challenge/22222",
		Status:          common.StatusPending,
		Token:           "test-token-abc123",
		AccountID:       12345,
		AuthorizationID: 11111,
	}

	assert.Equal(t, uint64(22222), challenge.ID)
	assert.Equal(t, common.ChallengeTypeHTTP01, challenge.Type)
	assert.Equal(t, common.StatusPending, challenge.Status)
	assert.NotEmpty(t, challenge.Token)
}

// TestChallenge_EntityID tests challenge entity ID methods
func TestChallenge_EntityID(t *testing.T) {
	challenge := &entities.ACMEChallenge{}

	challenge.SetEntityID(66666)
	assert.Equal(t, uint64(66666), challenge.EntityID())
}

// TestChallenge_Types tests all supported challenge types
func TestChallenge_Types(t *testing.T) {
	challengeTypes := []string{
		common.ChallengeTypeHTTP01,
		common.ChallengeTypeDNS01,
		common.ChallengeTypeEnroll01,
		common.ChallengeTypeEndorse01,
		common.ChallengeTypeDeviceAttest01,
	}

	for _, challengeType := range challengeTypes {
		t.Run(challengeType, func(t *testing.T) {
			challenge := &entities.ACMEChallenge{
				Type:   challengeType,
				Status: common.StatusPending,
			}

			assert.Equal(t, challengeType, challenge.Type)
		})
	}
}

// TestIdentifier_Types tests identifier types
func TestIdentifier_Types(t *testing.T) {
	testCases := []struct {
		name   string
		idType string
		value  string
	}{
		{
			name:   "DNS identifier",
			idType: "dns",
			value:  "example.com",
		},
		{
			name:   "IP identifier",
			idType: "ip",
			value:  "192.0.2.1",
		},
		{
			name:   "Permanent identifier",
			idType: "permanent-identifier",
			value:  "12345",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			identifier := entities.ACMEIdentifier{
				Type:  tc.idType,
				Value: tc.value,
			}

			assert.Equal(t, tc.idType, identifier.Type)
			assert.Equal(t, tc.value, identifier.Value)
		})
	}
}

// TestStatus_Values tests all valid status values
func TestStatus_Values(t *testing.T) {
	statusValues := []string{
		common.StatusValid,
		common.StatusPending,
		common.StatusProcessing,
		common.StatusInvalid,
		common.StatusDeactivated,
		common.StatusExpired,
		common.StatusRevoked,
		common.StatusReady,
	}

	for _, status := range statusValues {
		t.Run(status, func(t *testing.T) {
			// Each status should be a non-empty string
			assert.NotEmpty(t, status)

			// Verify it's one of the expected values
			validStatuses := map[string]bool{
				"valid":       true,
				"pending":     true,
				"processing":  true,
				"invalid":     true,
				"deactivated": true,
				"expired":     true,
				"revoked":     true,
				"ready":       true,
			}

			assert.True(t, validStatuses[status])
		})
	}
}

// TestOrder_JSONSerialization tests order JSON marshaling
func TestOrder_JSONSerialization(t *testing.T) {
	order := &entities.ACMEOrder{
		ID:     12345,
		Status: common.StatusReady,
		Identifiers: []entities.ACMEIdentifier{
			{Type: "dns", Value: "example.com"},
		},
		Authorizations: []string{"https://acme.example.com/authz/1"},
		Finalize:       "https://acme.example.com/order/12345/finalize",
	}

	jsonData, err := json.Marshal(order)
	require.NoError(t, err)

	var unmarshaled entities.ACMEOrder
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, order.ID, unmarshaled.ID)
	assert.Equal(t, order.Status, unmarshaled.Status)
	assert.Len(t, unmarshaled.Identifiers, 1)
}
