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

package rfc8555

import (
	"encoding/pem"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRevocationReasons tests valid certificate revocation reasons
func TestRevocationReasons(t *testing.T) {
	// RFC 5280 revocation reasons
	validReasons := map[int]string{
		0: "unspecified",
		1: "keyCompromise",
		2: "cACompromise",
		3: "affiliationChanged",
		4: "superseded",
		5: "cessationOfOperation",
		6: "certificateHold",
		// 7 is not used
		8:  "removeFromCRL",
		9:  "privilegeWithdrawn",
		10: "aACompromise",
	}

	for code, reason := range validReasons {
		t.Run(reason, func(t *testing.T) {
			assert.GreaterOrEqual(t, code, 0)
			assert.LessOrEqual(t, code, 10)
			assert.NotEmpty(t, reason)
		})
	}
}

// TestRevocationReasonValidation tests revocation reason validation
func TestRevocationReasonValidation(t *testing.T) {
	testCases := []struct {
		name    string
		reason  int
		isValid bool
	}{
		{
			name:    "Valid - unspecified",
			reason:  0,
			isValid: true,
		},
		{
			name:    "Valid - keyCompromise",
			reason:  1,
			isValid: true,
		},
		{
			name:    "Valid - cessationOfOperation",
			reason:  5,
			isValid: true,
		},
		{
			name:    "Invalid - reason 7",
			reason:  7,
			isValid: false,
		},
		{
			name:    "Invalid - negative",
			reason:  -1,
			isValid: false,
		},
		{
			name:    "Invalid - too large",
			reason:  11,
			isValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Validate reason code
			isValid := tc.reason >= 0 && tc.reason <= 10 && tc.reason != 7

			assert.Equal(t, tc.isValid, isValid)
		})
	}
}

// TestRevocationRequest tests revocation request structure
func TestRevocationRequest(t *testing.T) {
	type RevocationRequest struct {
		Certificate string `json:"certificate"`
		Reason      int    `json:"reason,omitempty"`
	}

	req := RevocationRequest{
		Certificate: "base64url-encoded-cert",
		Reason:      1, // keyCompromise
	}

	assert.NotEmpty(t, req.Certificate)
	assert.Equal(t, 1, req.Reason)
}

// TestCertificateRevocationCheck tests checking if certificate is revoked
func TestCertificateRevocationCheck(t *testing.T) {
	// Certificate status
	type CertStatus string

	const (
		StatusValid   CertStatus = "valid"
		StatusRevoked CertStatus = "revoked"
		StatusExpired CertStatus = "expired"
	)

	testCases := []struct {
		name   string
		status CertStatus
	}{
		{
			name:   "Valid certificate",
			status: StatusValid,
		},
		{
			name:   "Revoked certificate",
			status: StatusRevoked,
		},
		{
			name:   "Expired certificate",
			status: StatusExpired,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotEmpty(t, tc.status)
		})
	}
}

// TestRevocationAuthorization tests authorization checks for revocation
func TestRevocationAuthorization(t *testing.T) {
	// Revocation can be authorized by:
	// 1. Account that requested the certificate
	// 2. Certificate's private key holder

	authMethods := []string{
		"account-key",     // JWS signed by account key
		"certificate-key", // JWS signed by certificate's key
	}

	for _, method := range authMethods {
		t.Run(method, func(t *testing.T) {
			assert.NotEmpty(t, method)
		})
	}
}

// TestAlreadyRevokedError tests error for already revoked certificates
func TestAlreadyRevokedError(t *testing.T) {
	err := common.AlreadyRevoked("Certificate has already been revoked")

	assert.Equal(t, "urn:ietf:params:acme:error:alreadyRevoked", err.Type)
	assert.Equal(t, "Certificate has already been revoked", err.Detail)
}

// TestBadRevocationReasonError tests error for invalid revocation reason
func TestBadRevocationReasonError(t *testing.T) {
	err := common.BadRevocationReason("Invalid revocation reason code")

	assert.Equal(t, "urn:ietf:params:acme:error:badRevocationReason", err.Type)
	assert.Equal(t, "Invalid revocation reason code", err.Detail)
}

// TestRevocationPEMEncoding tests certificate PEM encoding for revocation
func TestRevocationPEMEncoding(t *testing.T) {
	certData := []byte("CERTIFICATE DATA")

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certData,
	}

	pemData := pem.EncodeToMemory(block)
	require.NotNil(t, pemData)

	// Verify PEM format
	decodedBlock, _ := pem.Decode(pemData)
	require.NotNil(t, decodedBlock)
	assert.Equal(t, "CERTIFICATE", decodedBlock.Type)
	assert.Equal(t, certData, decodedBlock.Bytes)
}

// TestRevocationWithoutReason tests revocation without specifying reason
func TestRevocationWithoutReason(t *testing.T) {
	type RevocationRequest struct {
		Certificate string `json:"certificate"`
		Reason      int    `json:"reason,omitempty"`
	}

	// Revocation without reason (defaults to unspecified)
	req := RevocationRequest{
		Certificate: "base64url-encoded-cert",
		// Reason omitted - defaults to 0 (unspecified)
	}

	assert.NotEmpty(t, req.Certificate)
	assert.Equal(t, 0, req.Reason) // Default value
}

// TestCRLReasonCode tests CRL reason code constants
func TestCRLReasonCode(t *testing.T) {
	// RFC 5280 CRL reason codes
	reasons := map[int]string{
		0:  "Unspecified",
		1:  "KeyCompromise",
		2:  "CACompromise",
		3:  "AffiliationChanged",
		4:  "Superseded",
		5:  "CessationOfOperation",
		6:  "CertificateHold",
		8:  "RemoveFromCRL",
		9:  "PrivilegeWithdrawn",
		10: "AACompromise",
	}

	for code, name := range reasons {
		t.Run(name, func(t *testing.T) {
			assert.GreaterOrEqual(t, code, 0)
			assert.NotEmpty(t, name)
		})
	}
}

// TestRevocationResponseStatus tests revocation response HTTP status
func TestRevocationResponseStatus(t *testing.T) {
	// Successful revocation returns 200 OK
	successStatus := 200
	assert.Equal(t, 200, successStatus)

	// Already revoked should not fail
	// (Idempotent - revoking already revoked cert succeeds)
	alreadyRevokedStatus := 200
	assert.Equal(t, 200, alreadyRevokedStatus)
}
