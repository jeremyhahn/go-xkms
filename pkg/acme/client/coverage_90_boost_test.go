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
	"errors"
	"log/slog"
	"math/big"
	"net"
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
	// The nameserver lookup succeeds and the value is not published, which is
	// what this test is about. Both are injected: resolving a real domain here
	// made the Unit Tests gate depend on the public internet (go-xkms#243).
	checkFunc := CheckDNSFromAuthoritative(
		WithNameserverLookup(staticNameservers("ns1.example-authoritative.test:53")),
		WithPropagationQuery(propagationResult(false)),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := checkFunc(ctx, "_acme-challenge.example.test.", "fake-value-that-wont-exist")

	// We expect an error because the value won't match
	require.Error(t, err)
	// The function successfully got authoritative nameservers and tried to check
	assert.ErrorIs(t, err, ErrDNSRecordNotPresent)
}

func TestCheckDNSFromAuthoritative_InvalidDomain(t *testing.T) {
	checkFunc := CheckDNSFromAuthoritative(WithNameserverLookup(failingNameservers()))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A domain with no authoritative nameservers.
	err := checkFunc(ctx, "_acme-challenge.this-domain-definitely-does-not-exist-xyz-abc-123.", "test-value")

	// Should fail to get authoritative nameservers
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get authoritative nameservers")
}

func TestCheckDNSFromPublic_NotPresent(t *testing.T) {
	checkFunc := CheckDNSFromPublic(WithPropagationQuery(propagationResult(false)))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := checkFunc(ctx, "_acme-challenge.example.test.", "unique-test-value-xyz-12345")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDNSRecordNotPresent)
}

func TestCheckDNSFromNameservers_NotPresent(t *testing.T) {
	checkFunc := CheckDNSFromNameservers(
		[]string{"8.8.8.8:53", "1.1.1.1:53"},
		WithPropagationQuery(propagationResult(false)),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := checkFunc(ctx, "_acme-challenge.example.test.", "unique-test-value-xyz-67890")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDNSRecordNotPresent)
}

func TestCheckDNSFromNameservers_EmptyList(t *testing.T) {
	// An empty nameserver list makes the real query fall back to the package
	// defaults, i.e. the public internet, so the query is supplied here. What
	// is under test is that the pre-check surfaces a failure either way.
	checkFunc := CheckDNSFromNameservers([]string{},
		WithPropagationQuery(propagationResult(false)))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := checkFunc(ctx, "_acme-challenge.example.test.", "test-value")

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDNSRecordNotPresent)
}

func TestGetAuthoritativeNameservers_Success(t *testing.T) {
	// Resolver supplied: this asserts the port suffix this function appends,
	// not that a third party's domain resolves from the runner (go-xkms#243).
	servers, err := authoritativeNameservers("_acme-challenge.example.test.",
		func(string) ([]*net.NS, error) {
			return []*net.NS{{Host: "ns1.example.test."}}, nil
		}, DefaultDNSPort)
	require.NoError(t, err)
	assert.Equal(t, []string{"ns1.example.test.:53"}, servers)
}

// TestGetAuthoritativeNameservers_UsesTheGivenPort proves the port is the
// caller's, not a literal: every nameserver host is joined with it (#140).
func TestGetAuthoritativeNameservers_UsesTheGivenPort(t *testing.T) {
	servers, err := authoritativeNameservers("_acme-challenge.example.test.",
		func(string) ([]*net.NS, error) {
			return []*net.NS{{Host: "ns1.example.test."}, {Host: "ns2.example.test."}}, nil
		}, "5353")
	require.NoError(t, err)
	assert.Equal(t, []string{"ns1.example.test.:5353", "ns2.example.test.:5353"}, servers)
}

// TestCheckDNSFromAuthoritative_NameserverPortReachesTheDefaultLookup proves
// WithNameserverPort threads through to the addresses the propagation query
// receives, with DefaultDNSPort when the option is absent or empty.
func TestCheckDNSFromAuthoritative_NameserverPortReachesTheDefaultLookup(t *testing.T) {
	resolver := func(string) ([]*net.NS, error) {
		return []*net.NS{{Host: "ns1.example.test."}}, nil
	}
	cases := []struct {
		name string
		opts []DNSCheckOption
		want []string
	}{
		{"configured port", []DNSCheckOption{WithNameserverPort("5353")}, []string{"ns1.example.test.:5353"}},
		{"default port", nil, []string{"ns1.example.test.:53"}},
		{"empty port keeps the default", []DNSCheckOption{WithNameserverPort("")}, []string{"ns1.example.test.:53"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var queried []string
			capture := func(_ context.Context, _, _ string, nameservers []string) (bool, error) {
				queried = nameservers
				return true, nil
			}
			opts := append([]DNSCheckOption{withNSResolver(resolver), WithPropagationQuery(capture)}, tc.opts...)
			checkFunc := CheckDNSFromAuthoritative(opts...)
			require.NoError(t, checkFunc(context.Background(), "_acme-challenge.example.test.", "value"))
			assert.Equal(t, tc.want, queried)
		})
	}
}

// TestCheckDNSFromAuthoritative_ExplicitLookupIgnoresThePort proves that a
// caller-supplied lookup returns complete addresses and is not re-ported.
func TestCheckDNSFromAuthoritative_ExplicitLookupIgnoresThePort(t *testing.T) {
	var queried []string
	capture := func(_ context.Context, _, _ string, nameservers []string) (bool, error) {
		queried = nameservers
		return true, nil
	}
	checkFunc := CheckDNSFromAuthoritative(
		WithNameserverPort("5353"),
		WithNameserverLookup(staticNameservers("ns1.example.test:8053")),
		WithPropagationQuery(capture),
	)
	require.NoError(t, checkFunc(context.Background(), "_acme-challenge.example.test.", "value"))
	assert.Equal(t, []string{"ns1.example.test:8053"}, queried)
}

func TestGetAuthoritativeNameservers_NonExistentDomain(t *testing.T) {
	_, err := authoritativeNameservers("_acme-challenge.this-domain-definitely-does-not-exist-abc-123.",
		func(string) ([]*net.NS, error) { return nil, errors.New("no such host") }, DefaultDNSPort)
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
