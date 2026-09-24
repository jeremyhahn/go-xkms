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
	"net/http"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
)

// TestAccountDoesNotExist tests AccountDoesNotExist error
func TestAccountDoesNotExist(t *testing.T) {
	err := AccountDoesNotExist("test detail")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeAccountDoesNotExist)
	assert.Equal(t, http.StatusNotFound, err.Status)
	assert.Contains(t, err.Detail, "test detail")
}

// TestAlreadyRevoked tests AlreadyRevoked error
func TestAlreadyRevoked(t *testing.T) {
	err := AlreadyRevoked("certificate already revoked")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeAlreadyRevoked)
	assert.Equal(t, http.StatusBadRequest, err.Status)
}

// TestBadAttestationStatement tests BadAttestationStatement error
func TestBadAttestationStatement(t *testing.T) {
	err := BadAttestationStatement("invalid attestation")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, "badAttestationStatement")
	assert.Equal(t, http.StatusBadRequest, err.Status)
}

// TestBadCSR tests BadCSR error
func TestBadCSR(t *testing.T) {
	err := BadCSR("malformed CSR")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeBadCSR)
	assert.Equal(t, http.StatusBadRequest, err.Status)
}

// TestBadNonce tests BadNonce error
func TestBadNonce(t *testing.T) {
	err := BadNonce("invalid nonce")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeBadNonce)
	assert.Equal(t, http.StatusBadRequest, err.Status)
}

// TestBadPublicKey tests BadPublicKey error
func TestBadPublicKey(t *testing.T) {
	err := BadPublicKey("invalid public key")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeBadPublicKey)
	assert.Equal(t, http.StatusBadRequest, err.Status)
}

// TestBadRevocationReason tests BadRevocationReason error
func TestBadRevocationReason(t *testing.T) {
	err := BadRevocationReason("invalid reason")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeBadRevocationReason)
	assert.Equal(t, http.StatusBadRequest, err.Status)
}

// TestBadSignatureAlgorithm tests BadSignatureAlgorithm error
func TestBadSignatureAlgorithm(t *testing.T) {
	err := BadSignatureAlgorithm("unsupported algorithm")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeBadSignatureAlgorithm)
	assert.Equal(t, http.StatusBadRequest, err.Status)
}

// TestCAAError tests CAAError error
func TestCAAError(t *testing.T) {
	err := CAAError("CAA check failed")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeCAAError)
	assert.Equal(t, http.StatusUnauthorized, err.Status)
}

// TestCompoundError tests CompoundError error
func TestCompoundError(t *testing.T) {
	subproblems := []entities.SubProblem{
		{Type: "test1", Detail: "detail1"},
		{Type: "test2", Detail: "detail2"},
	}
	err := CompoundError("multiple errors", subproblems)
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeCompoundError)
	assert.Equal(t, http.StatusBadRequest, err.Status)
	assert.Len(t, err.SubProblems, 2)
}

// TestConnectionError tests ConnectionError error
func TestConnectionError(t *testing.T) {
	err := ConnectionError("connection failed")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeConnectionError)
	assert.Equal(t, http.StatusBadRequest, err.Status)
}

// TestDNSError tests DNSError error
func TestDNSError(t *testing.T) {
	err := DNSError("DNS lookup failed")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeDNSError)
	assert.Equal(t, http.StatusBadRequest, err.Status)
}

// TestExternalAccountRequired tests ExternalAccountRequired error
func TestExternalAccountRequired(t *testing.T) {
	err := ExternalAccountRequired("EAB required")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeExternalAccountRequired)
	assert.Equal(t, http.StatusUnauthorized, err.Status)
}

// TestIncorrectResponse tests IncorrectResponse error
func TestIncorrectResponse(t *testing.T) {
	err := IncorrectResponse("challenge response incorrect")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeIncorrectResponse)
	assert.Equal(t, http.StatusUnauthorized, err.Status)
}

// TestInvalidContact tests InvalidContact error
func TestInvalidContact(t *testing.T) {
	err := InvalidContact("invalid email")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeInvalidContact)
	assert.Equal(t, http.StatusBadRequest, err.Status)
}

// TestMalformedError tests MalformedError error
func TestMalformedError(t *testing.T) {
	err := MalformedError("malformed request", nil)
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeMalformedError)
	assert.Equal(t, http.StatusBadRequest, err.Status)
}

// TestOrderNotReady tests OrderNotReady error
func TestOrderNotReady(t *testing.T) {
	err := OrderNotReady("order not ready")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeOrderNotReady)
	assert.Equal(t, http.StatusForbidden, err.Status)
}

// TestRateLimited tests RateLimited error
func TestRateLimited(t *testing.T) {
	err := RateLimited("too many requests")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeRateLimited)
	assert.Equal(t, http.StatusTooManyRequests, err.Status)
}

// TestRejectedIdentifier tests RejectedIdentifier error
func TestRejectedIdentifier(t *testing.T) {
	err := RejectedIdentifier("identifier rejected")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeRejectedIdentifier)
	assert.Equal(t, http.StatusForbidden, err.Status)
}

// TestServerInternal tests ServerInternal error
func TestServerInternal(t *testing.T) {
	err := ServerInternal("internal server error")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeServerInternal)
	assert.Equal(t, http.StatusInternalServerError, err.Status)
}

// TestTLSError tests TLSError error
func TestTLSError(t *testing.T) {
	err := TLSError("TLS handshake failed")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeTLSError)
	assert.Equal(t, http.StatusBadRequest, err.Status)
}

// TestUnauthorized tests Unauthorized error
func TestUnauthorized(t *testing.T) {
	err := Unauthorized("not authorized")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeUnauthorized)
	assert.Equal(t, http.StatusUnauthorized, err.Status)
}

// TestUnsupportedContact tests UnsupportedContact error
func TestUnsupportedContact(t *testing.T) {
	err := UnsupportedContact("contact method not supported")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeUnsupportedContact)
	assert.Equal(t, http.StatusBadRequest, err.Status)
}

// TestUnsupportedIdentifier tests UnsupportedIdentifier error
func TestUnsupportedIdentifier(t *testing.T) {
	err := UnsupportedIdentifier("identifier type not supported")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeUnsupportedIdentifier)
	assert.Equal(t, http.StatusBadRequest, err.Status)
}

// TestUserActionRequired tests UserActionRequired error
func TestUserActionRequired(t *testing.T) {
	err := UserActionRequired("user action required", "https://example.com/tos")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeUserActionRequired)
	assert.Equal(t, http.StatusForbidden, err.Status)
}

// TestAccountExistsError tests AccountExistsError error
func TestAccountExistsError(t *testing.T) {
	err := AccountExistsError("account already exists", "https://example.com/account/123")
	assert.NotNil(t, err)
	assert.Contains(t, err.Type, ErrTypeAccountExists)
	assert.Equal(t, http.StatusConflict, err.Status)
}
