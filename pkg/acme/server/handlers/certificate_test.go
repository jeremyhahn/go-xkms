//go:build codec_json

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

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestCertificate creates and saves a test certificate under the
// given hex-encoded serial (see entities.ACMECertificate.Serial).
func createTestCertificate(t *testing.T, service *RestService, serial string) *entities.ACMECertificate {
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
		Serial:    serial,
		CertURL:   fmt.Sprintf("%s/acme/cert/%s", service.baseRESTURI, serial),
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
	serial := "3039" // hex encoding of decimal 12345
	certificate := createTestCertificate(t, service, serial)

	// Create GET request (POST-as-GET is not required for certificate download per RFC 8555)
	url := fmt.Sprintf("%s/acme/cert/%s", service.baseRESTURI, serial)
	req := httptest.NewRequest(http.MethodGet, url, nil)

	// Add mux vars to simulate gorilla/mux routing
	req = mux.SetURLVars(req, map[string]string{"id": serial})

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

	// Request a well-formed but never-saved serial
	nonExistentSerial := "1869f"
	url := fmt.Sprintf("%s/acme/cert/%s", service.baseRESTURI, nonExistentSerial)
	req := httptest.NewRequest(http.MethodGet, url, nil)

	// Add mux vars to simulate gorilla/mux routing
	req = mux.SetURLVars(req, map[string]string{"id": nonExistentSerial})

	// Execute request
	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// Should return malformed error (certificate not found)
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestCertificateHandler_InvalidCertificateID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Request with an ID that isn't valid hexadecimal at all
	url := fmt.Sprintf("%s/acme/cert/not-a-serial!", service.baseRESTURI)
	req := httptest.NewRequest(http.MethodGet, url, nil)

	// Add mux vars with invalid ID
	req = mux.SetURLVars(req, map[string]string{"id": "not-a-serial!"})

	// Execute request
	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// Should return malformed error (invalid certificate ID)
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestCertificateHandler_NegativeCertificateID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Request with a negative certificate ID: RFC 5280 serials must be
	// positive, so this must be rejected even though "-1" parses as a
	// syntactically valid signed hex integer.
	url := fmt.Sprintf("%s/acme/cert/-1", service.baseRESTURI)
	req := httptest.NewRequest(http.MethodGet, url, nil)

	// Add mux vars with negative ID
	req = mux.SetURLVars(req, map[string]string{"id": "-1"})

	// Execute request
	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// Should return malformed error (invalid certificate ID - must be positive)
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestCertificateHandler_ZeroCertificateID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Request with zero certificate ID: RFC 5280 serials must be positive,
	// so zero is rejected as malformed rather than looked up.
	url := fmt.Sprintf("%s/acme/cert/0", service.baseRESTURI)
	req := httptest.NewRequest(http.MethodGet, url, nil)

	// Add mux vars
	req = mux.SetURLVars(req, map[string]string{"id": "0"})

	// Execute request
	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// Should return malformed error (zero is not a valid serial)
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestCertificateHandler_LargeCertificateID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Request with a serial exceeding uint64's range (32 hex digits = 128
	// bits, matching pkg/ca's serial generator). This must be accepted as
	// well-formed and simply not found, never truncated or rejected for
	// being "too large".
	serial := "ffffffffffffffffffffffffffffffff"
	url := fmt.Sprintf("%s/acme/cert/%s", service.baseRESTURI, serial)
	req := httptest.NewRequest(http.MethodGet, url, nil)

	// Add mux vars
	req = mux.SetURLVars(req, map[string]string{"id": serial})

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
	serial1 := "3e9" // 1001
	serial2 := "3ea" // 1002
	serial3 := "3eb" // 1003

	cert1 := createTestCertificate(t, service, serial1)
	cert2 := createTestCertificate(t, service, serial2)
	cert3 := createTestCertificate(t, service, serial3)

	// Retrieve each certificate and verify correct one is returned
	testCases := []struct {
		name     string
		serial   string
		expected *entities.ACMECertificate
	}{
		{"First certificate", serial1, cert1},
		{"Second certificate", serial2, cert2},
		{"Third certificate", serial3, cert3},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := fmt.Sprintf("%s/acme/cert/%s", service.baseRESTURI, tc.serial)
			req := httptest.NewRequest(http.MethodGet, url, nil)
			req = mux.SetURLVars(req, map[string]string{"id": tc.serial})

			resp := httptest.NewRecorder()
			service.CertificateHandler(resp, req)

			require.Equal(t, http.StatusOK, resp.Code)
			require.Equal(t, "application/pem-certificate-chain", resp.Header().Get("Content-Type"))
			assert.Equal(t, tc.expected.PEM, resp.Body.String())
		})
	}
}

func TestCertificateHandler_CollidingLowBitsCertificates(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Two distinct serials that share the same low 64 bits (16 hex digits)
	// but differ in the high bits. Before go-xkms#744 these collided in
	// storage because the ID was truncated to the low 64 bits; both must
	// now be stored and retrievable independently.
	lowBits := "0000000000000001"
	serialA := "ffeeddccbbaa9988" + lowBits
	serialB := "1122334455667788" + lowBits
	require.NotEqual(t, serialA, serialB)

	certA := createTestCertificate(t, service, serialA)
	certA.PEM = certA.PEM + "\n" // Distinguish stored bodies for the assertion below.
	certificateDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)
	require.NoError(t, certificateDAO.Save(context.Background(), certA))

	certB := createTestCertificate(t, service, serialB)

	urlA := fmt.Sprintf("%s/acme/cert/%s", service.baseRESTURI, serialA)
	reqA := httptest.NewRequest(http.MethodGet, urlA, nil)
	reqA = mux.SetURLVars(reqA, map[string]string{"id": serialA})
	respA := httptest.NewRecorder()
	service.CertificateHandler(respA, reqA)
	require.Equal(t, http.StatusOK, respA.Code)
	assert.Equal(t, certA.PEM, respA.Body.String())

	urlB := fmt.Sprintf("%s/acme/cert/%s", service.baseRESTURI, serialB)
	reqB := httptest.NewRequest(http.MethodGet, urlB, nil)
	reqB = mux.SetURLVars(reqB, map[string]string{"id": serialB})
	respB := httptest.NewRecorder()
	service.CertificateHandler(respB, reqB)
	require.Equal(t, http.StatusOK, respB.Code)
	assert.Equal(t, certB.PEM, respB.Body.String())

	// The two records are genuinely distinct in storage, not the same row
	// overwritten twice.
	assert.NotEqual(t, respA.Body.String(), respB.Body.String())
}

func TestCertificateHandler_CertificateChain(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Create certificate with chain
	serial := "1389" // 5001
	certificate := createTestCertificate(t, service, serial)

	// Request certificate
	url := fmt.Sprintf("%s/acme/cert/%s", service.baseRESTURI, serial)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req = mux.SetURLVars(req, map[string]string{"id": serial})

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
	serial := "1771" // 6001

	// Create certificate with empty PEM (edge case)
	certificateDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)

	certificate := &entities.ACMECertificate{
		Serial:    serial,
		CertURL:   fmt.Sprintf("%s/acme/cert/%s", service.baseRESTURI, serial),
		PEM:       "", // Empty PEM
		IssuedAt:  time.Now(),
		Status:    common.StatusValid,
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}

	err = certificateDAO.Save(ctx, certificate)
	require.NoError(t, err)

	// Request certificate
	url := fmt.Sprintf("%s/acme/cert/%s", service.baseRESTURI, serial)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req = mux.SetURLVars(req, map[string]string{"id": serial})

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
	serial := "1b59" // 7001
	createTestCertificate(t, service, serial)

	// Request certificate
	url := fmt.Sprintf("%s/acme/cert/%s", service.baseRESTURI, serial)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req = mux.SetURLVars(req, map[string]string{"id": serial})

	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// Verify Content-Type is set correctly per RFC 8555 Section 7.4.2
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "application/pem-certificate-chain", resp.Header().Get("Content-Type"))
}

func TestCertificateHandler_NonHexCertificateID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// "abc123def" is composed entirely of valid hex digits (a-f, 0-9), so
	// it does NOT exercise the malformed path; use a value containing
	// digits outside the hex alphabet instead.
	url := fmt.Sprintf("%s/acme/cert/xyz999", service.baseRESTURI)
	req := httptest.NewRequest(http.MethodGet, url, nil)

	// Add mux vars with a non-hexadecimal ID
	req = mux.SetURLVars(req, map[string]string{"id": "xyz999"})

	// Execute request
	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// Should return malformed error (invalid certificate ID)
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
}

func TestCertificateHandler_HexPrefixNormalizes(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// A certificate stored under its canonical (unprefixed, lowercase) hex
	// serial must still be reachable through a URL that spells the same
	// value with an explicit "0x" prefix and/or different case: both must
	// normalize to the same DAO lookup key.
	serial := "1a2b3c"
	certificate := createTestCertificate(t, service, serial)

	url := fmt.Sprintf("%s/acme/cert/0X1A2B3C", service.baseRESTURI)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req = mux.SetURLVars(req, map[string]string{"id": "0X1A2B3C"})

	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, certificate.PEM, resp.Body.String())
}

// collidingCertificateDAO wraps a real CertificateDAO but makes Get always
// return otherCert, simulating a genuine 64-bit FNV-1a hash collision
// between two DIFFERENT Serial values that hash to the same DAO row
// (entities.StringToEntityID's hash space is only 64 bits, so a collision
// is possible in principle - astronomically unlikely, but this is exactly
// the class of bug go-xkms#744 exists to close, so it must be handled, not
// just assumed away). A real collision cannot be manufactured cheaply in a
// unit test, so the DAO response is substituted directly instead.
type collidingCertificateDAO struct {
	qrdbsdk.GenericDAO[*entities.ACMECertificate]
	otherCert *entities.ACMECertificate
}

func (d *collidingCertificateDAO) Get(_ context.Context, _ uint64) (*entities.ACMECertificate, error) {
	return d.otherCert, nil
}

// collidingCertificateFactory swaps CertificateDAO() for one wrapped by
// collidingCertificateDAO; every other DAO is untouched.
type collidingCertificateFactory struct {
	storage.Factory
	otherCert *entities.ACMECertificate
}

func (f *collidingCertificateFactory) CertificateDAO() (qrdbsdk.GenericDAO[*entities.ACMECertificate], error) {
	real, err := f.Factory.CertificateDAO()
	if err != nil {
		return nil, err
	}
	return &collidingCertificateDAO{GenericDAO: real, otherCert: f.otherCert}, nil
}

func TestCertificateHandler_HashCollisionReturnsNotFound(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	requestedSerial := "1a2b3c"
	otherCert := &entities.ACMECertificate{
		Serial: "deadbeef", // a different certificate than the one requested
		PEM:    "-----BEGIN CERTIFICATE-----\nOTHER CERTIFICATE\n-----END CERTIFICATE-----",
		Status: common.StatusValid,
	}
	service.storageFactory = &collidingCertificateFactory{
		Factory:   service.storageFactory,
		otherCert: otherCert,
	}

	url := fmt.Sprintf("%s/acme/cert/%s", service.baseRESTURI, requestedSerial)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req = mux.SetURLVars(req, map[string]string{"id": requestedSerial})

	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	// The row's occupant carries a different Serial than what was asked
	// for, so this must be reported as not-found - never as otherCert's PEM.
	assertErrorType(t, resp, common.ErrTypeMalformedError, http.StatusBadRequest)
	assert.NotContains(t, resp.Body.String(), "OTHER CERTIFICATE")
}

func TestCertificateHandler_NoCollisionServesRequestedCertificate(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	// Control case for TestCertificateHandler_HashCollisionReturnsNotFound:
	// when the DAO row actually holds the requested certificate (Serial
	// matches), the collision check must not falsely reject it.
	serial := "1a2b3c"
	certificate := createTestCertificate(t, service, serial)

	url := fmt.Sprintf("%s/acme/cert/%s", service.baseRESTURI, serial)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req = mux.SetURLVars(req, map[string]string{"id": serial})

	resp := httptest.NewRecorder()
	service.CertificateHandler(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, certificate.PEM, resp.Body.String())
}
