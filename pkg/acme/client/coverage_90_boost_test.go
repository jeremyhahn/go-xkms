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

package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/ocsp"
)

// =============================================================================
// CheckOCSP Tests - exercises all paths in CheckOCSP function
// =============================================================================

func TestCheckOCSP_Success(t *testing.T) {
	// Create issuer certificate and key
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	issuerCertDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	require.NoError(t, err)

	issuerCert, err := x509.ParseCertificate(issuerCertDER)
	require.NoError(t, err)

	// Create OCSP responder server
	ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Create a valid OCSP response
		response := ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: big.NewInt(12345),
			ThisUpdate:   time.Now().Add(-1 * time.Hour),
			NextUpdate:   time.Now().Add(1 * time.Hour),
		}

		ocspRespBytes, err := ocsp.CreateResponse(issuerCert, issuerCert, response, issuerKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ocspRespBytes)
	}))
	defer ocspServer.Close()

	// Create subject certificate with OCSP URL
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	subjectTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: "Test Subject"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		OCSPServer:   []string{ocspServer.URL},
	}

	subjectCertDER, err := x509.CreateCertificate(rand.Reader, subjectTemplate, issuerTemplate, &subjectKey.PublicKey, issuerKey)
	require.NoError(t, err)

	subjectCert, err := x509.ParseCertificate(subjectCertDER)
	require.NoError(t, err)

	// Test CheckOCSP - should succeed with Good status
	err = CheckOCSP(context.Background(), subjectCert, issuerCert)
	require.NoError(t, err)
}

func TestCheckOCSP_Revoked(t *testing.T) {
	// Create issuer certificate and key
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	issuerCertDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	require.NoError(t, err)

	issuerCert, err := x509.ParseCertificate(issuerCertDER)
	require.NoError(t, err)

	// Create OCSP responder server that returns revoked
	ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := ocsp.Response{
			Status:           ocsp.Revoked,
			SerialNumber:     big.NewInt(12345),
			ThisUpdate:       time.Now().Add(-1 * time.Hour),
			NextUpdate:       time.Now().Add(1 * time.Hour),
			RevokedAt:        time.Now().Add(-30 * time.Minute),
			RevocationReason: ocsp.KeyCompromise,
		}

		ocspRespBytes, err := ocsp.CreateResponse(issuerCert, issuerCert, response, issuerKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ocspRespBytes)
	}))
	defer ocspServer.Close()

	// Create subject certificate with OCSP URL
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	subjectTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: "Test Subject"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		OCSPServer:   []string{ocspServer.URL},
	}

	subjectCertDER, err := x509.CreateCertificate(rand.Reader, subjectTemplate, issuerTemplate, &subjectKey.PublicKey, issuerKey)
	require.NoError(t, err)

	subjectCert, err := x509.ParseCertificate(subjectCertDER)
	require.NoError(t, err)

	// Test CheckOCSP - should return revoked error
	err = CheckOCSP(context.Background(), subjectCert, issuerCert)
	require.Error(t, err)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.OCSPFailure, caErr.Type)
}

func TestCheckOCSP_Unknown(t *testing.T) {
	// Create issuer certificate and key
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	issuerCertDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	require.NoError(t, err)

	issuerCert, err := x509.ParseCertificate(issuerCertDER)
	require.NoError(t, err)

	// Create OCSP responder server that returns unknown
	ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := ocsp.Response{
			Status:       ocsp.Unknown,
			SerialNumber: big.NewInt(12345),
			ThisUpdate:   time.Now().Add(-1 * time.Hour),
			NextUpdate:   time.Now().Add(1 * time.Hour),
		}

		ocspRespBytes, err := ocsp.CreateResponse(issuerCert, issuerCert, response, issuerKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ocspRespBytes)
	}))
	defer ocspServer.Close()

	// Create subject certificate with OCSP URL
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	subjectTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: "Test Subject"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		OCSPServer:   []string{ocspServer.URL},
	}

	subjectCertDER, err := x509.CreateCertificate(rand.Reader, subjectTemplate, issuerTemplate, &subjectKey.PublicKey, issuerKey)
	require.NoError(t, err)

	subjectCert, err := x509.ParseCertificate(subjectCertDER)
	require.NoError(t, err)

	// Test CheckOCSP - should return unknown error
	err = CheckOCSP(context.Background(), subjectCert, issuerCert)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOCSPCertUnknown)
}

func TestCheckOCSP_NilCert(t *testing.T) {
	issuerCert := createTestCert(t)
	err := CheckOCSP(context.Background(), nil, issuerCert)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestCheckOCSP_NilIssuer(t *testing.T) {
	cert := createTestCert(t)
	err := CheckOCSP(context.Background(), cert, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOCSPNoIssuer)
}

func TestCheckOCSP_NoResponder(t *testing.T) {
	cert := createTestCert(t)
	issuer := createTestCert(t)
	err := CheckOCSP(context.Background(), cert, issuer)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOCSPNoResponder)
}

func TestCheckOCSP_ServerError(t *testing.T) {
	// Create issuer certificate
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	issuerCertDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	require.NoError(t, err)

	issuerCert, err := x509.ParseCertificate(issuerCertDER)
	require.NoError(t, err)

	// Create OCSP responder server that returns error
	ocspServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ocspServer.Close()

	// Create subject certificate with OCSP URL
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	subjectTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject:      pkix.Name{CommonName: "Test Subject"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		OCSPServer:   []string{ocspServer.URL},
	}

	subjectCertDER, err := x509.CreateCertificate(rand.Reader, subjectTemplate, issuerTemplate, &subjectKey.PublicKey, issuerKey)
	require.NoError(t, err)

	subjectCert, err := x509.ParseCertificate(subjectCertDER)
	require.NoError(t, err)

	// Test CheckOCSP - should return request failed error
	err = CheckOCSP(context.Background(), subjectCert, issuerCert)
	require.Error(t, err)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.ConnectionFailure, caErr.Type)
}

// =============================================================================
// DNS Solver CheckDNS Tests - exercises authoritative and public DNS checks
// =============================================================================

func TestCheckDNSFromAuthoritative_Success(t *testing.T) {
	// Use a real domain that has NS records
	checkFunc := CheckDNSFromAuthoritative()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Query for a domain that exists - we expect the authoritative lookup to succeed
	// but the value check to fail (since we're using a fake value)
	err := checkFunc(ctx, "_acme-challenge.google.com.", "fake-value-that-wont-exist")

	// We expect an error because the value won't match
	require.Error(t, err)
	// The function successfully got authoritative nameservers and tried to check
	assert.ErrorIs(t, err, ErrDNSRecordNotPresent)
}

func TestCheckDNSFromAuthoritative_InvalidDomain(t *testing.T) {
	checkFunc := CheckDNSFromAuthoritative()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use a domain that definitely won't have NS records
	err := checkFunc(ctx, "_acme-challenge.this-domain-definitely-does-not-exist-xyz-abc-123.", "test-value")

	// Should fail to get authoritative nameservers
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get authoritative nameservers")
}

func TestCheckDNSFromPublic_NotPresent(t *testing.T) {
	checkFunc := CheckDNSFromPublic()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Use a real domain with a value that won't exist
	err := checkFunc(ctx, "_acme-challenge.example.com.", "unique-test-value-xyz-12345")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDNSRecordNotPresent)
}

func TestCheckDNSFromNameservers_NotPresent(t *testing.T) {
	checkFunc := CheckDNSFromNameservers([]string{"8.8.8.8:53", "1.1.1.1:53"})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Use a real domain with a value that won't exist
	err := checkFunc(ctx, "_acme-challenge.example.com.", "unique-test-value-xyz-67890")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDNSRecordNotPresent)
}

func TestCheckDNSFromNameservers_EmptyList(t *testing.T) {
	checkFunc := CheckDNSFromNameservers([]string{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// With empty nameservers, the propagation check should fail
	err := checkFunc(ctx, "_acme-challenge.example.com.", "test-value")

	// Behavior depends on the providers.CheckDNSPropagation implementation
	// but it should either error or return not present
	require.Error(t, err)
}

func TestGetAuthoritativeNameservers_Success(t *testing.T) {
	// Test with a well-known domain
	servers, err := getAuthoritativeNameservers("_acme-challenge.google.com.")
	require.NoError(t, err)
	assert.NotEmpty(t, servers)

	// Verify servers have the port suffix
	for _, server := range servers {
		assert.Contains(t, server, ":53")
	}
}

func TestGetAuthoritativeNameservers_NonExistentDomain(t *testing.T) {
	_, err := getAuthoritativeNameservers("_acme-challenge.this-domain-definitely-does-not-exist-abc-123.")
	require.Error(t, err)
}

// =============================================================================
// ListOrders - Test fetchOrdersList directly (full ListOrders uses ACME retry logic)
// =============================================================================

func TestFetchOrdersList_ConnectionRefused(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		logger:     slog.Default(),
		httpClient: http.DefaultClient,
		config:     &Config{DirectoryURL: "http://localhost:65535"},
		client: &acme.Client{
			DirectoryURL: "http://localhost:65535",
			Key:          privateKey,
		},
	}

	// Try to fetch from a port that won't be listening
	_, err = client.fetchOrdersList(context.Background(), "http://localhost:65535/orders")
	require.Error(t, err)
	var caErr *caerrors.TrustedCAError
	require.ErrorAs(t, err, &caErr)
	assert.Equal(t, caerrors.ConnectionFailure, caErr.Type)
}

func TestFetchOrdersList_ContextCancelled(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		logger:     slog.Default(),
		httpClient: http.DefaultClient,
		config:     &Config{DirectoryURL: "http://localhost"},
		client: &acme.Client{
			DirectoryURL: "http://localhost",
			Key:          privateKey,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = client.fetchOrdersList(ctx, "http://localhost/orders")
	require.Error(t, err)
}
