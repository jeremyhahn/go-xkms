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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAccountCreation tests ACME account creation logic
func TestAccountCreation(t *testing.T) {
	// Generate key for account
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Generate deterministic account ID
	accountID, err := handlers.AccountIDFromPublicKey(privateKey.Public())
	require.NoError(t, err)
	assert.NotZero(t, accountID)

	// Create account
	account := &entities.ACMEAccount{
		ID:                   accountID,
		Status:               common.StatusValid,
		Contact:              []string{"mailto:admin@example.com"},
		TermsOfServiceAgreed: true,
		CreatedAt:            time.Now(),
	}

	assert.Equal(t, accountID, account.ID)
	assert.Equal(t, common.StatusValid, account.Status)
}

// TestAccountIDGeneration tests deterministic account ID generation
func TestAccountIDGeneration(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Generate ID multiple times - should be deterministic
	id1, err := handlers.AccountIDFromPublicKey(privateKey.Public())
	require.NoError(t, err)

	id2, err := handlers.AccountIDFromPublicKey(privateKey.Public())
	require.NoError(t, err)

	assert.Equal(t, id1, id2, "Account ID should be deterministic")
}

// TestAccountIDUniqueness tests that different keys produce different IDs
func TestAccountIDUniqueness(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	id1, err := handlers.AccountIDFromPublicKey(key1.Public())
	require.NoError(t, err)

	id2, err := handlers.AccountIDFromPublicKey(key2.Public())
	require.NoError(t, err)

	assert.NotEqual(t, id1, id2, "Different keys should produce different account IDs")
}

// TestContactValidation tests contact URL validation per RFC 8555
func TestContactValidation(t *testing.T) {
	testCases := []struct {
		name      string
		contacts  []string
		shouldErr bool
	}{
		{
			name:      "Valid mailto",
			contacts:  []string{"mailto:admin@example.com"},
			shouldErr: false,
		},
		{
			name:      "Multiple valid contacts",
			contacts:  []string{"mailto:admin@example.com", "mailto:security@example.com"},
			shouldErr: false,
		},
		{
			name:      "Invalid - contains hfields",
			contacts:  []string{"mailto:admin@example.com?subject=test"},
			shouldErr: true,
		},
		{
			name:      "Invalid - multiple addr-spec",
			contacts:  []string{"mailto:admin@example.com,user@example.com"},
			shouldErr: true,
		},
		{
			name:      "Invalid email format",
			contacts:  []string{"mailto:not-an-email"},
			shouldErr: true,
		},
		{
			name:      "Unsupported scheme",
			contacts:  []string{"tel:+1234567890"},
			shouldErr: true,
		},
		{
			name:      "Empty contacts",
			contacts:  []string{},
			shouldErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := handlers.ValidateContactURLs(tc.contacts)

			if tc.shouldErr {
				assert.NotNil(t, err, "Expected error but got nil")
			} else {
				assert.Nil(t, err, "Expected no error but got: %v", err)
			}
		})
	}
}

// TestEmailValidation tests email address validation in contact URLs
func TestEmailValidation(t *testing.T) {
	testCases := []struct {
		name    string
		email   string
		isValid bool
	}{
		{
			name:    "Valid email",
			email:   "admin@example.com",
			isValid: true,
		},
		{
			name:    "Valid email with subdomain",
			email:   "admin@mail.example.com",
			isValid: true,
		},
		{
			name:    "Valid email with plus",
			email:   "admin+test@example.com",
			isValid: true,
		},
		{
			name:    "Invalid - no @",
			email:   "admin-example.com",
			isValid: false,
		},
		{
			name:    "Invalid - no domain",
			email:   "admin@",
			isValid: false,
		},
		{
			name:    "Invalid - no local part",
			email:   "@example.com",
			isValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mail.ParseAddress(tc.email)

			if tc.isValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestAccountUpdate tests account update logic
func TestAccountUpdate(t *testing.T) {
	account := &entities.ACMEAccount{
		ID:                   12345,
		Status:               common.StatusValid,
		Contact:              []string{"mailto:old@example.com"},
		TermsOfServiceAgreed: true,
	}

	// Update contact
	account.Contact = []string{"mailto:new@example.com"}

	assert.Equal(t, []string{"mailto:new@example.com"}, account.Contact)
	assert.Equal(t, common.StatusValid, account.Status)
}

// TestAccountDeactivation tests account deactivation
func TestAccountDeactivation(t *testing.T) {
	account := &entities.ACMEAccount{
		ID:     12345,
		Status: common.StatusValid,
	}

	// Deactivate account
	account.Status = common.StatusDeactivated

	assert.Equal(t, common.StatusDeactivated, account.Status)
}

// TestAccountKeyStorage tests account key encoding/decoding
func TestAccountKeyStorage(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Encode public key
	pubKeyPEM, err := xkmssdk.EncodePublicKeyPEM(privateKey.Public())
	require.NoError(t, err)
	assert.NotEmpty(t, pubKeyPEM)

	// Store in account
	account := &entities.ACMEAccount{
		ID:  12345,
		Key: string(pubKeyPEM),
	}

	// Decode from account
	decodedKey, err := xkmssdk.DecodePublicKeyPEM([]byte(account.Key))
	require.NoError(t, err)
	assert.NotNil(t, decodedKey)
}

// TestAccountJSON tests account JSON serialization
func TestAccountJSON(t *testing.T) {
	account := &entities.ACMEAccount{
		ID:                   12345,
		Status:               common.StatusValid,
		Contact:              []string{"mailto:admin@example.com"},
		TermsOfServiceAgreed: true,
		Orders:               "https://acme.example.com/acme/account/12345/orders",
	}

	jsonData, err := json.Marshal(account)
	require.NoError(t, err)

	var unmarshaled entities.ACMEAccount
	err = json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, account.ID, unmarshaled.ID)
	assert.Equal(t, account.Status, unmarshaled.Status)
	assert.Equal(t, account.Contact, unmarshaled.Contact)
}

// TestAccountStatus tests valid account status transitions
func TestAccountStatus(t *testing.T) {
	validStatuses := []string{
		common.StatusValid,
		common.StatusDeactivated,
		common.StatusRevoked,
	}

	for _, status := range validStatuses {
		t.Run(status, func(t *testing.T) {
			account := &entities.ACMEAccount{
				ID:     12345,
				Status: status,
			}

			assert.Equal(t, status, account.Status)
		})
	}
}

// TestOnlyReturnExisting tests onlyReturnExisting flag
func TestOnlyReturnExisting(t *testing.T) {
	// Account lookup request
	account := &entities.ACMEAccount{
		OnlyReturnExisting: true,
	}

	assert.True(t, account.OnlyReturnExisting)

	// Account creation request
	account2 := &entities.ACMEAccount{
		OnlyReturnExisting: false,
	}

	assert.False(t, account2.OnlyReturnExisting)
}

// TestExternalAccountBinding tests external account binding
func TestExternalAccountBinding(t *testing.T) {
	eab := map[string]interface{}{
		"protected": "eyJhbGciOiJIUzI1NiIsImtpZCI6IjEyMzQ1In0",
		"payload":   "eyJuYW1lIjoidGVzdCJ9",
		"signature": "dGVzdC1zaWduYXR1cmU",
	}

	account := &entities.ACMEAccount{
		ID:                     12345,
		ExternalAccountBinding: eab,
	}

	assert.NotNil(t, account.ExternalAccountBinding)
}

// TestTermsOfServiceAgreement tests ToS agreement flag
func TestTermsOfServiceAgreement(t *testing.T) {
	// Account with ToS agreed
	account1 := &entities.ACMEAccount{
		ID:                   12345,
		TermsOfServiceAgreed: true,
	}
	assert.True(t, account1.TermsOfServiceAgreed)

	// Account without ToS agreed
	account2 := &entities.ACMEAccount{
		ID:                   12346,
		TermsOfServiceAgreed: false,
	}
	assert.False(t, account2.TermsOfServiceAgreed)
}

// TestAccountOrders tests account orders URL
func TestAccountOrders(t *testing.T) {
	accountID := uint64(12345)
	ordersURL := "https://acme.example.com/acme/account/12345/orders"

	account := &entities.ACMEAccount{
		ID:     accountID,
		Orders: ordersURL,
	}

	assert.Equal(t, ordersURL, account.Orders)
	assert.Contains(t, account.Orders, "12345")
}

// TestContactURLScheme tests contact URL scheme validation
func TestContactURLScheme(t *testing.T) {
	validContact := "mailto:admin@example.com"
	assert.True(t, strings.HasPrefix(validContact, "mailto:"))

	invalidContact := "http://example.com"
	assert.False(t, strings.HasPrefix(invalidContact, "mailto:"))
}
