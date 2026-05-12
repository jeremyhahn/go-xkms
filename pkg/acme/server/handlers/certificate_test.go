//go:build codec_json

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

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestCertificate creates and saves a test certificate
func createTestCertificate(t *testing.T, service *RestService, certID uint64) *entities.ACMECertificate {
	ctx := context.Background()

	// Get certificate DAO
	certificateDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	// Create a test PEM certificate (this is a minimal valid PEM structure for testing)
	pemCert := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU1yUMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBIxEDAOBgNVBAMM
B3Rlc3RjZXJ0MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANLJhPHhITqQbPklG3ib
SDB4bXRsQ+fATVnE7aX0z9qJNYcgHJ4pHSI1y7NKtCFmSSFl4A8fnGZ2aeT7ZZC8
pCMCAwEAATANBgkqhkiG9w0BAQsFAAOBgQCYJm7MvT1u7b0uWCdBGLq4TvPPEzGq
2Eg6DkF5pCnhCfN9wFYiPB7w6j0vWY1J3mJ9qVFPYKqN9s0bPFnVJH7KuU9QXZM4
LZaD+rZF8mGzb5bE5PZCwY2Yl7J5z2aT0qX1VZQ5PNW9fQ2L6qXJF6Pv8pL1cEJj
YzqF2K5QZ3N6Qw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBjDCB9gIJAKHHCgVZU1yVMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnJv
b3RjYTAeFw0yNDAxMDEwMDAwMDBaFw0yNjAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDSyYTx4SE6kGz5JRt4m0gw
eG10bEPnwE1ZxO2l9M/aiTWHIByeKR0iNcuzSrQhZkkhZeAPH5xmdmnk+2WQvKQj
AgMBAAEwDQYJKoZIhvcNAQELBQADQQCg7LfmFnO2q0pqV5VJX5YZH5T1sDQx3RP0
2gw1qXHfJ4VVYLj1qVR3bJ5KF6dU1YQ2aQ1Q8vK6F8t7L2Z1sX2j
-----END CERTIFICATE-----`

	// Create certificate
	certificate := &entities.ACMECertificate{
		ID:        certID,
		CertURL:   fmt.Sprintf("%s/acme/cert/%d", service.baseRESTURI, certID),
		PEM:       pemCert,
		IssuedAt:  time.Now(),
		Status:    common.StatusValid,
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}

	// Save certificate
	err = certificateDAO.Save(ctx, certificate)
	require.NoError(t, err)

	return certificate
}

func TestCertificateHandler_GetCertificate(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Create test certificate
	certID := uint64(12345)
	certificate := createTestCertificate(t, service, certID)

	// Create GET request (POST-as-GET is not required for certificate download per RFC 8555)
	url := fmt.Sprintf("%s/acme/cert/%d", service.baseRESTURI, certID)
	req := httptest.NewRequest(http.MethodGet, url, nil)

	// Add mux vars to simulate gorilla/mux routing
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", certID)})

	// Execute request
	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// Verify response
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/pem-certificate-chain", resp.Header().Get("Content-Type"))

	// Verify PEM content
	assert.Equal(t, certificate.PEM, resp.Body.String())
}

func TestCertificateHandler_CertificateNotFound(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Request non-existent certificate
	nonExistentID := uint64(99999)
	url := fmt.Sprintf("%s/acme/cert/%d", service.baseRESTURI, nonExistentID)
	req := httptest.NewRequest(http.MethodGet, url, nil)

	// Add mux vars to simulate gorilla/mux routing
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", nonExistentID)})

	// Execute request
	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// Should return malformed error (certificate not found)
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestCertificateHandler_InvalidCertificateID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Request with invalid certificate ID (not a number)
	url := fmt.Sprintf("%s/acme/cert/invalid-id", service.baseRESTURI)
	req := httptest.NewRequest(http.MethodGet, url, nil)

	// Add mux vars with invalid ID
	req = mux.SetURLVars(req, map[string]string{"id": "invalid-id"})

	// Execute request
	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// Should return malformed error (invalid certificate ID)
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestCertificateHandler_NegativeCertificateID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Request with negative certificate ID
	url := fmt.Sprintf("%s/acme/cert/-1", service.baseRESTURI)
	req := httptest.NewRequest(http.MethodGet, url, nil)

	// Add mux vars with negative ID
	req = mux.SetURLVars(req, map[string]string{"id": "-1"})

	// Execute request
	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// Should return malformed error (invalid certificate ID - strconv.ParseUint will fail on negative)
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestCertificateHandler_ZeroCertificateID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Request with zero certificate ID
	certID := uint64(0)
	url := fmt.Sprintf("%s/acme/cert/%d", service.baseRESTURI, certID)
	req := httptest.NewRequest(http.MethodGet, url, nil)

	// Add mux vars
	req = mux.SetURLVars(req, map[string]string{"id": "0"})

	// Execute request
	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// Should return malformed error (certificate not found)
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestCertificateHandler_LargeCertificateID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Request with very large certificate ID (still valid uint64)
	certID := uint64(18446744073709551615) // max uint64
	url := fmt.Sprintf("%s/acme/cert/%d", service.baseRESTURI, certID)
	req := httptest.NewRequest(http.MethodGet, url, nil)

	// Add mux vars
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", certID)})

	// Execute request
	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// Should return malformed error (certificate not found)
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestCertificateHandler_MultipleCertificates(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Create multiple certificates
	cert1ID := uint64(1001)
	cert2ID := uint64(1002)
	cert3ID := uint64(1003)

	cert1 := createTestCertificate(t, service, cert1ID)
	cert2 := createTestCertificate(t, service, cert2ID)
	cert3 := createTestCertificate(t, service, cert3ID)

	// Retrieve each certificate and verify correct one is returned
	testCases := []struct {
		name     string
		certID   uint64
		expected *entities.ACMECertificate
	}{
		{"First certificate", cert1ID, cert1},
		{"Second certificate", cert2ID, cert2},
		{"Third certificate", cert3ID, cert3},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := fmt.Sprintf("%s/acme/cert/%d", service.baseRESTURI, tc.certID)
			req := httptest.NewRequest(http.MethodGet, url, nil)
			req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", tc.certID)})

			resp := httptest.NewRecorder()
			service.CertificateHandler(resp, req)

			require.Equal(t, http.StatusOK, resp.Code)
			require.Equal(t, "application/pem-certificate-chain", resp.Header().Get("Content-Type"))
			assert.Equal(t, tc.expected.PEM, resp.Body.String())
		})
	}
}

func TestCertificateHandler_CertificateChain(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Create certificate with chain
	certID := uint64(5001)
	certificate := createTestCertificate(t, service, certID)

	// Request certificate
	url := fmt.Sprintf("%s/acme/cert/%d", service.baseRESTURI, certID)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", certID)})

	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// Verify response contains the full chain
	require.Equal(t, http.StatusOK, resp.Code)
	pemContent := resp.Body.String()

	// Verify the PEM contains multiple certificates (chain)
	assert.Contains(t, pemContent, "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, pemContent, "-----END CERTIFICATE-----")

	// Count certificate blocks (should be 2 in the test PEM)
	beginCount := 0
	endCount := 0
	for i := 0; i < len(pemContent); i++ {
		if i+len("-----BEGIN CERTIFICATE-----") <= len(pemContent) &&
			pemContent[i:i+len("-----BEGIN CERTIFICATE-----")] == "-----BEGIN CERTIFICATE-----" {
			beginCount++
		}
		if i+len("-----END CERTIFICATE-----") <= len(pemContent) &&
			pemContent[i:i+len("-----END CERTIFICATE-----")] == "-----END CERTIFICATE-----" {
			endCount++
		}
	}

	assert.Equal(t, 2, beginCount, "Should have 2 certificate BEGIN markers in chain")
	assert.Equal(t, 2, endCount, "Should have 2 certificate END markers in chain")
	assert.Equal(t, certificate.PEM, pemContent)
}

func TestCertificateHandler_EmptyPEM(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	ctx := context.Background()
	certID := uint64(6001)

	// Create certificate with empty PEM (edge case)
	certificateDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	certificate := &entities.ACMECertificate{
		ID:        certID,
		CertURL:   fmt.Sprintf("%s/acme/cert/%d", service.baseRESTURI, certID),
		PEM:       "", // Empty PEM
		IssuedAt:  time.Now(),
		Status:    common.StatusValid,
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}

	err = certificateDAO.Save(ctx, certificate)
	require.NoError(t, err)

	// Request certificate
	url := fmt.Sprintf("%s/acme/cert/%d", service.baseRESTURI, certID)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", certID)})

	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// Should still return 200 with empty body
	require.Equal(t, http.StatusOK, resp.Code)
	require.Equal(t, "application/pem-certificate-chain", resp.Header().Get("Content-Type"))
	assert.Equal(t, "", resp.Body.String())
}

func TestCertificateHandler_ContentTypeHeader(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Create test certificate
	certID := uint64(7001)
	createTestCertificate(t, service, certID)

	// Request certificate
	url := fmt.Sprintf("%s/acme/cert/%d", service.baseRESTURI, certID)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", certID)})

	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// Verify Content-Type is set correctly per RFC 8555 Section 7.4.2
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "application/pem-certificate-chain", resp.Header().Get("Content-Type"))
}

func TestCertificateHandler_OverflowCertificateID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Request with ID that would overflow uint64
	url := fmt.Sprintf("%s/acme/cert/18446744073709551616", service.baseRESTURI) // max uint64 + 1
	req := httptest.NewRequest(http.MethodGet, url, nil)

	// Add mux vars with overflow ID
	req = mux.SetURLVars(req, map[string]string{"id": "18446744073709551616"})

	// Execute request
	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// Should return malformed error (invalid certificate ID - strconv.ParseUint will fail)
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestCertificateHandler_AlphanumericCertificateID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Request with alphanumeric ID
	url := fmt.Sprintf("%s/acme/cert/abc123def", service.baseRESTURI)
	req := httptest.NewRequest(http.MethodGet, url, nil)

	// Add mux vars with alphanumeric ID
	req = mux.SetURLVars(req, map[string]string{"id": "abc123def"})

	// Execute request
	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// Should return malformed error (invalid certificate ID)
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestCertificateHandler_HexadecimalCertificateID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Request with hexadecimal ID (0x prefix)
	url := fmt.Sprintf("%s/acme/cert/0x1234", service.baseRESTURI)
	req := httptest.NewRequest(http.MethodGet, url, nil)

	// Add mux vars with hex ID
	req = mux.SetURLVars(req, map[string]string{"id": "0x1234"})

	// Execute request
	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// Should return malformed error (invalid certificate ID - ParseUint with base 10 will fail)
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}
