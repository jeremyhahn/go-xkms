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
	"net/http"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestErrorResponseFormat tests ACME error response structure per RFC 8555
func TestErrorResponseFormat(t *testing.T) {
	err := common.BadNonce("Invalid nonce provided")

	// Verify error structure
	assert.Equal(t, "urn:ietf:params:acme:error:badNonce", err.Type)
	assert.Equal(t, "Invalid nonce provided", err.Detail)
	assert.Equal(t, http.StatusBadRequest, err.Status)
}

// TestErrorResponseJSON tests error JSON serialization
func TestErrorResponseJSON(t *testing.T) {
	err := common.BadCSR("Invalid certificate signing request")

	jsonData, marshalErr := json.Marshal(err)
	require.NoError(t, marshalErr)

	var unmarshaled entities.Error
	unmarshalErr := json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, unmarshalErr)

	assert.Equal(t, err.Type, unmarshaled.Type)
	assert.Equal(t, err.Detail, unmarshaled.Detail)
	// Status is not serialized (json:"-")
}

// TestErrorTypes tests all standard ACME error types
func TestErrorTypes(t *testing.T) {
	testCases := []struct {
		name           string
		errorFunc      func(string) *entities.Error
		expectedType   string
		expectedStatus int
	}{
		{
			name:           "AccountDoesNotExist",
			errorFunc:      common.AccountDoesNotExist,
			expectedType:   "urn:ietf:params:acme:error:accountDoesNotExist",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "AlreadyRevoked",
			errorFunc:      common.AlreadyRevoked,
			expectedType:   "urn:ietf:params:acme:error:alreadyRevoked",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "BadCSR",
			errorFunc:      common.BadCSR,
			expectedType:   "urn:ietf:params:acme:error:badCSR",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "BadNonce",
			errorFunc:      common.BadNonce,
			expectedType:   "urn:ietf:params:acme:error:badNonce",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "BadPublicKey",
			errorFunc:      common.BadPublicKey,
			expectedType:   "urn:ietf:params:acme:error:badPublicKey",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "BadRevocationReason",
			errorFunc:      common.BadRevocationReason,
			expectedType:   "urn:ietf:params:acme:error:badRevocationReason",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "BadSignatureAlgorithm",
			errorFunc:      common.BadSignatureAlgorithm,
			expectedType:   "urn:ietf:params:acme:error:badSignatureAlgorithm",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "CAA",
			errorFunc:      common.CAAError,
			expectedType:   "urn:ietf:params:acme:error:caa",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Connection",
			errorFunc:      common.ConnectionError,
			expectedType:   "urn:ietf:params:acme:error:connection",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "DNS",
			errorFunc:      common.DNSError,
			expectedType:   "urn:ietf:params:acme:error:dns",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "ExternalAccountRequired",
			errorFunc:      common.ExternalAccountRequired,
			expectedType:   "urn:ietf:params:acme:error:externalAccountRequired",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "IncorrectResponse",
			errorFunc:      common.IncorrectResponse,
			expectedType:   "urn:ietf:params:acme:error:incorrectResponse",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "InvalidContact",
			errorFunc:      common.InvalidContact,
			expectedType:   "urn:ietf:params:acme:error:invalidContact",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "OrderNotReady",
			errorFunc:      common.OrderNotReady,
			expectedType:   "urn:ietf:params:acme:error:orderNotReady",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "RateLimited",
			errorFunc:      common.RateLimited,
			expectedType:   "urn:ietf:params:acme:error:rateLimited",
			expectedStatus: http.StatusTooManyRequests,
		},
		{
			name:           "RejectedIdentifier",
			errorFunc:      common.RejectedIdentifier,
			expectedType:   "urn:ietf:params:acme:error:rejectedIdentifier",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "ServerInternal",
			errorFunc:      common.ServerInternal,
			expectedType:   "urn:ietf:params:acme:error:serverInternal",
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "TLS",
			errorFunc:      common.TLSError,
			expectedType:   "urn:ietf:params:acme:error:tls",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Unauthorized",
			errorFunc:      common.Unauthorized,
			expectedType:   "urn:ietf:params:acme:error:unauthorized",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "UnsupportedContact",
			errorFunc:      common.UnsupportedContact,
			expectedType:   "urn:ietf:params:acme:error:unsupportedContact",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "UnsupportedIdentifier",
			errorFunc:      common.UnsupportedIdentifier,
			expectedType:   "urn:ietf:params:acme:error:unsupportedIdentifier",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.errorFunc("Test error detail")

			assert.Equal(t, tc.expectedType, err.Type)
			assert.Equal(t, "Test error detail", err.Detail)
			assert.Equal(t, tc.expectedStatus, err.Status)
		})
	}
}

// TestCompoundError tests compound error with subproblems
func TestCompoundError(t *testing.T) {
	subproblems := []entities.SubProblem{
		{
			Type:   "urn:ietf:params:acme:error:unauthorized",
			Detail: "CAA check failed for example.com",
			Identifier: &entities.ACMEIdentifier{
				Type:  "dns",
				Value: "example.com",
			},
		},
		{
			Type:   "urn:ietf:params:acme:error:dns",
			Detail: "DNS lookup failed for example.net",
			Identifier: &entities.ACMEIdentifier{
				Type:  "dns",
				Value: "example.net",
			},
		},
	}

	err := common.CompoundError("Multiple validation failures", subproblems)

	assert.Equal(t, "urn:ietf:params:acme:error:compound", err.Type)
	assert.Equal(t, "Multiple validation failures", err.Detail)
	assert.Equal(t, http.StatusBadRequest, err.Status)
	assert.Len(t, err.SubProblems, 2)

	// Verify subproblems
	assert.Equal(t, "urn:ietf:params:acme:error:unauthorized", err.SubProblems[0].Type)
	assert.Equal(t, "example.com", err.SubProblems[0].Identifier.Value)
}

// TestErrorWithIdentifier tests error with identifier field
func TestErrorWithIdentifier(t *testing.T) {
	err := common.RejectedIdentifier("Domain not allowed")
	err.Identifier = &entities.ACMEIdentifier{
		Type:  "dns",
		Value: "forbidden.example.com",
	}

	jsonData, marshalErr := json.Marshal(err)
	require.NoError(t, marshalErr)

	var unmarshaled entities.Error
	unmarshalErr := json.Unmarshal(jsonData, &unmarshaled)
	require.NoError(t, unmarshalErr)

	assert.NotNil(t, unmarshaled.Identifier)
	assert.Equal(t, "dns", unmarshaled.Identifier.Type)
	assert.Equal(t, "forbidden.example.com", unmarshaled.Identifier.Value)
}

// TestUserActionRequiredError tests error with instance field
func TestUserActionRequiredError(t *testing.T) {
	instanceURL := "https://example.com/terms-update"
	err := common.UserActionRequired("Terms of service have been updated", instanceURL)

	assert.Equal(t, "urn:ietf:params:acme:error:userActionRequired", err.Type)
	assert.Equal(t, "Terms of service have been updated", err.Detail)
	assert.Equal(t, http.StatusForbidden, err.Status)
	assert.Equal(t, instanceURL, err.Instance)
}

// TestMalformedError tests malformed error with subproblems
func TestMalformedError(t *testing.T) {
	subproblems := []entities.SubProblem{
		{
			Type:   "urn:ietf:params:acme:error:malformed",
			Detail: "Missing required field: contact",
		},
	}

	err := common.MalformedError("Request body is malformed", subproblems)

	assert.Equal(t, "urn:ietf:params:acme:error:malformed", err.Type)
	assert.Equal(t, http.StatusBadRequest, err.Status)
	assert.Len(t, err.SubProblems, 1)
}

// TestErrorImplementsErrorInterface tests that Error implements error interface
func TestErrorImplementsErrorInterface(t *testing.T) {
	err := common.ServerInternal("Internal server error")

	// Should implement error interface
	var _ error = err

	// Error() method should return detail
	assert.Equal(t, "Internal server error", err.Error())
}

// TestErrorJSONOmitsEmptyFields tests that empty fields are omitted in JSON
func TestErrorJSONOmitsEmptyFields(t *testing.T) {
	err := common.BadNonce("Invalid nonce")

	jsonData, marshalErr := json.Marshal(err)
	require.NoError(t, marshalErr)

	var raw map[string]interface{}
	unmarshalErr := json.Unmarshal(jsonData, &raw)
	require.NoError(t, unmarshalErr)

	// Should have type and detail
	assert.Contains(t, raw, "type")
	assert.Contains(t, raw, "detail")

	// Should not have subproblems, identifier, or instance when empty
	assert.NotContains(t, raw, "subproblems")
	assert.NotContains(t, raw, "identifier")
	assert.NotContains(t, raw, "instance")
}
