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

package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"log/slog"
	"math/big"
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestOCSPResponse_IsGood(t *testing.T) {
	tests := []struct {
		name     string
		response *OCSPResponse
		want     bool
	}{
		{
			name:     "nil response",
			response: nil,
			want:     false,
		},
		{
			name:     "nil inner response",
			response: &OCSPResponse{},
			want:     false,
		},
		{
			name: "good status",
			response: &OCSPResponse{
				Response: &ocsp.Response{Status: ocsp.Good},
			},
			want: true,
		},
		{
			name: "revoked status",
			response: &OCSPResponse{
				Response: &ocsp.Response{Status: ocsp.Revoked},
			},
			want: false,
		},
		{
			name: "unknown status",
			response: &OCSPResponse{
				Response: &ocsp.Response{Status: ocsp.Unknown},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.response.IsGood(); got != tt.want {
				t.Errorf("IsGood() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOCSPResponse_IsRevoked(t *testing.T) {
	tests := []struct {
		name     string
		response *OCSPResponse
		want     bool
	}{
		{
			name:     "nil response",
			response: nil,
			want:     false,
		},
		{
			name: "revoked status",
			response: &OCSPResponse{
				Response: &ocsp.Response{Status: ocsp.Revoked},
			},
			want: true,
		},
		{
			name: "good status",
			response: &OCSPResponse{
				Response: &ocsp.Response{Status: ocsp.Good},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.response.IsRevoked(); got != tt.want {
				t.Errorf("IsRevoked() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOCSPResponse_IsUnknown(t *testing.T) {
	tests := []struct {
		name     string
		response *OCSPResponse
		want     bool
	}{
		{
			name:     "nil response",
			response: nil,
			want:     false,
		},
		{
			name: "unknown status",
			response: &OCSPResponse{
				Response: &ocsp.Response{Status: ocsp.Unknown},
			},
			want: true,
		},
		{
			name: "good status",
			response: &OCSPResponse{
				Response: &ocsp.Response{Status: ocsp.Good},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.response.IsUnknown(); got != tt.want {
				t.Errorf("IsUnknown() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOCSPResponse_IsStale(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		response *OCSPResponse
		want     bool
	}{
		{
			name:     "nil response",
			response: nil,
			want:     true,
		},
		{
			name: "future next update",
			response: &OCSPResponse{
				Response:   &ocsp.Response{Status: ocsp.Good},
				NextUpdate: now.Add(1 * time.Hour),
			},
			want: false,
		},
		{
			name: "past next update",
			response: &OCSPResponse{
				Response:   &ocsp.Response{Status: ocsp.Good},
				NextUpdate: now.Add(-1 * time.Hour),
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.response.IsStale(); got != tt.want {
				t.Errorf("IsStale() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOCSPResponse_ShouldRefresh(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		response *OCSPResponse
		want     bool
	}{
		{
			name:     "nil response",
			response: nil,
			want:     true,
		},
		{
			name: "fresh - less than 50% validity",
			response: &OCSPResponse{
				Response:   &ocsp.Response{Status: ocsp.Good},
				ThisUpdate: now.Add(-1 * time.Hour),
				NextUpdate: now.Add(3 * time.Hour), // 25% elapsed
			},
			want: false,
		},
		{
			name: "should refresh - more than 50% validity",
			response: &OCSPResponse{
				Response:   &ocsp.Response{Status: ocsp.Good},
				ThisUpdate: now.Add(-3 * time.Hour),
				NextUpdate: now.Add(1 * time.Hour), // 75% elapsed
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.response.ShouldRefresh(); got != tt.want {
				t.Errorf("ShouldRefresh() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetOCSP_Errors(t *testing.T) {
	ctx := t.Context()

	t.Run("nil certificate", func(t *testing.T) {
		_, err := GetOCSP(ctx, nil, createTestCert(t), "", nil)
		if err != ErrInvalidCertificate {
			t.Errorf("expected ErrInvalidCertificate, got %v", err)
		}
	})

	t.Run("nil issuer", func(t *testing.T) {
		cert := createTestCert(t)
		_, err := GetOCSP(ctx, cert, nil, "", nil)
		if err != ErrOCSPNoIssuer {
			t.Errorf("expected ErrOCSPNoIssuer, got %v", err)
		}
	})

	t.Run("no OCSP responder URL", func(t *testing.T) {
		cert := createTestCert(t)
		issuer := createTestCert(t)
		_, err := GetOCSP(ctx, cert, issuer, "", nil)
		if err != ErrOCSPNoResponder {
			t.Errorf("expected ErrOCSPNoResponder, got %v", err)
		}
	})
}

func TestHasMustStaple(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
		want bool
	}{
		{
			name: "nil certificate",
			cert: nil,
			want: false,
		},
		{
			name: "no must-staple extension",
			cert: &x509.Certificate{},
			want: false,
		},
		{
			name: "has must-staple extension",
			cert: &x509.Certificate{
				Extensions: []pkix.Extension{
					{
						Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24},
						Critical: false,
						Value:    []byte{0x30, 0x03, 0x02, 0x01, 0x05},
					},
				},
			},
			want: true,
		},
		{
			name: "has other extension but not must-staple",
			cert: &x509.Certificate{
				Extensions: []pkix.Extension{
					{
						Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}, // AIA
						Critical: false,
						Value:    []byte{},
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasMustStaple(tt.cert); got != tt.want {
				t.Errorf("HasMustStaple() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMustStapleOID(t *testing.T) {
	// Verify the OID matches the expected value
	expected := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	if !MustStapleOID.Equal(expected) {
		t.Errorf("MustStapleOID = %v, want %v", MustStapleOID, expected)
	}
}

// createTestCert creates a basic test certificate for unit tests
func createTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// createTestCertWithOCSP creates a test certificate with an OCSP responder URL
func createTestCertWithOCSP(t *testing.T, ocspURL string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		OCSPServer:  []string{ocspURL},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert, key
}

// TestGetOCSPStandalone tests the standalone GetOCSP function
func TestGetOCSPStandalone(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		issuer := createTestCert(t)
		_, err := GetOCSP(context.Background(), nil, issuer, "http://ocsp.example.com", nil)
		if err != ErrInvalidCertificate {
			t.Errorf("expected ErrInvalidCertificate, got %v", err)
		}
	})

	t.Run("nil issuer", func(t *testing.T) {
		cert := createTestCert(t)
		_, err := GetOCSP(context.Background(), cert, nil, "http://ocsp.example.com", nil)
		if err != ErrOCSPNoIssuer {
			t.Errorf("expected ErrOCSPNoIssuer, got %v", err)
		}
	})

	t.Run("empty ocsp URL uses certificate URL", func(t *testing.T) {
		cert := createTestCert(t) // No OCSP URL
		issuer := createTestCert(t)
		_, err := GetOCSP(context.Background(), cert, issuer, "", nil)
		if err != ErrOCSPNoResponder {
			t.Errorf("expected ErrOCSPNoResponder, got %v", err)
		}
	})

	t.Run("empty ocsp URL with certificate having OCSP server", func(t *testing.T) {
		cert, _ := createTestCertWithOCSP(t, "http://invalid-ocsp.example.com")
		issuer := createTestCert(t)
		// This will fail because the OCSP server doesn't exist, but tests the path
		_, err := GetOCSP(context.Background(), cert, issuer, "", nil)
		if err == nil {
			t.Error("expected error for non-existent OCSP server")
		}
	})
}

// TestOCSPConstants tests the OCSP constants
func TestOCSPConstants(t *testing.T) {
	if OCSPContentType != "application/ocsp-request" {
		t.Errorf("unexpected OCSPContentType: %s", OCSPContentType)
	}
}

// TestOCSPErrors tests the OCSP error types
func TestOCSPErrors(t *testing.T) {
	errors := []error{
		ErrOCSPNoIssuer,
		ErrOCSPNoResponder,
		ErrOCSPRequestFailed,
		ErrOCSPResponseParseFailed,
		ErrOCSPResponseInvalid,
		ErrOCSPCertRevoked,
		ErrOCSPCertUnknown,
	}

	for _, err := range errors {
		if err == nil {
			t.Error("expected non-nil error")
		}
		if err.Error() == "" {
			t.Error("expected non-empty error message")
		}
	}
}

// TestOCSPResponseNilHandling tests nil handling in OCSPResponse methods
func TestOCSPResponseNilHandling(t *testing.T) {
	t.Run("nil OCSPResponse", func(t *testing.T) {
		var resp *OCSPResponse

		if resp.IsGood() {
			t.Error("nil response should not be good")
		}
		if resp.IsRevoked() {
			t.Error("nil response should not be revoked")
		}
		if resp.IsUnknown() {
			t.Error("nil response should not be unknown")
		}
		if !resp.IsStale() {
			t.Error("nil response should be stale")
		}
		if !resp.ShouldRefresh() {
			t.Error("nil response should need refresh")
		}
	})

	t.Run("OCSPResponse with nil inner response", func(t *testing.T) {
		resp := &OCSPResponse{}

		if resp.IsGood() {
			t.Error("response with nil inner should not be good")
		}
		if resp.IsRevoked() {
			t.Error("response with nil inner should not be revoked")
		}
		if resp.IsUnknown() {
			t.Error("response with nil inner should not be unknown")
		}
		if !resp.IsStale() {
			t.Error("response with nil inner should be stale")
		}
		if !resp.ShouldRefresh() {
			t.Error("response with nil inner should need refresh")
		}
	})
}

// TestMustStapleOIDValue tests the MustStaple OID value
func TestMustStapleOIDValue(t *testing.T) {
	expected := []int{1, 3, 6, 1, 5, 5, 7, 1, 24}
	if len(MustStapleOID) != len(expected) {
		t.Errorf("expected OID length %d, got %d", len(expected), len(MustStapleOID))
	}
	for i, v := range expected {
		if MustStapleOID[i] != v {
			t.Errorf("OID position %d: expected %d, got %d", i, v, MustStapleOID[i])
		}
	}
}

// TestClientGetOCSP_Coverage tests the Client.GetOCSP method
func TestClientGetOCSP_Coverage(t *testing.T) {
	t.Run("nil certificate returns error", func(t *testing.T) {
		client := &Client{
			httpClient: http.DefaultClient,
			logger:     slog.Default(),
		}

		_, err := client.GetOCSP(context.Background(), nil, createTestCert(t))
		if err != ErrInvalidCertificate {
			t.Errorf("expected ErrInvalidCertificate, got %v", err)
		}
	})

	t.Run("nil issuer returns error", func(t *testing.T) {
		client := &Client{
			httpClient: http.DefaultClient,
			logger:     slog.Default(),
		}

		cert := createTestCert(t)
		_, err := client.GetOCSP(context.Background(), cert, nil)
		if err != ErrOCSPNoIssuer {
			t.Errorf("expected ErrOCSPNoIssuer, got %v", err)
		}
	})

	t.Run("no OCSP responder URL returns error", func(t *testing.T) {
		client := &Client{
			httpClient: http.DefaultClient,
			logger:     slog.Default(),
		}

		cert := createTestCert(t)
		issuer := createTestCert(t)
		_, err := client.GetOCSP(context.Background(), cert, issuer)
		if err != ErrOCSPNoResponder {
			t.Errorf("expected ErrOCSPNoResponder, got %v", err)
		}
	})

	t.Run("certificate with OCSP URL attempts fetch", func(t *testing.T) {
		client := &Client{
			httpClient: &http.Client{Timeout: 100 * time.Millisecond},
			logger:     slog.Default(),
		}

		cert, _ := createTestCertWithOCSP(t, "http://invalid-ocsp.example.com")
		issuer := createTestCert(t)
		_, err := client.GetOCSP(context.Background(), cert, issuer)
		// We expect an error since the server doesn't exist
		if err == nil {
			t.Error("expected error for non-existent OCSP server")
		}
	})
}

// TestCheckOCSP_Coverage tests the CheckOCSP function
func TestCheckOCSP_Coverage(t *testing.T) {
	t.Run("nil certificate returns error", func(t *testing.T) {
		err := CheckOCSP(context.Background(), nil, createTestCert(t))
		if err != ErrInvalidCertificate {
			t.Errorf("expected ErrInvalidCertificate, got %v", err)
		}
	})

	t.Run("nil issuer returns error", func(t *testing.T) {
		cert := createTestCert(t)
		err := CheckOCSP(context.Background(), cert, nil)
		if err != ErrOCSPNoIssuer {
			t.Errorf("expected ErrOCSPNoIssuer, got %v", err)
		}
	})

	t.Run("no OCSP responder URL returns error", func(t *testing.T) {
		cert := createTestCert(t)
		issuer := createTestCert(t)
		err := CheckOCSP(context.Background(), cert, issuer)
		if err != ErrOCSPNoResponder {
			t.Errorf("expected ErrOCSPNoResponder, got %v", err)
		}
	})
}
