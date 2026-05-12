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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/ocsp"
)

// =============================================================================
// CertificateResource Tests (types.go)
// =============================================================================

func TestCertificateResource_GetCertificate(t *testing.T) {
	t.Run("empty certificate data", func(t *testing.T) {
		cr := &CertificateResource{}
		_, err := cr.GetCertificate()
		if !errors.Is(err, ErrNoCertificateData) {
			t.Errorf("expected ErrNoCertificateData, got %v", err)
		}
	})

	t.Run("invalid PEM data", func(t *testing.T) {
		cr := &CertificateResource{
			Certificate: []byte("not valid PEM"),
		}
		_, err := cr.GetCertificate()
		if !errors.Is(err, ErrInvalidCertificatePEM) {
			t.Errorf("expected ErrInvalidCertificatePEM, got %v", err)
		}
	})

	t.Run("invalid certificate in PEM", func(t *testing.T) {
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("invalid cert bytes"),
		})
		cr := &CertificateResource{
			Certificate: pemData,
		}
		_, err := cr.GetCertificate()
		if err == nil {
			t.Error("expected error for invalid certificate")
		}
	})

	t.Run("valid certificate", func(t *testing.T) {
		cert := createCov90TestCert(t, "Test Cert")
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		cr := &CertificateResource{
			Certificate: pemData,
		}
		parsed, err := cr.GetCertificate()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if parsed.Subject.CommonName != "Test Cert" {
			t.Errorf("expected CN 'Test Cert', got %q", parsed.Subject.CommonName)
		}
	})
}

func TestCertificateResource_GetPrivateKey(t *testing.T) {
	t.Run("empty private key data", func(t *testing.T) {
		cr := &CertificateResource{}
		_, err := cr.GetPrivateKey()
		if !errors.Is(err, ErrNoPrivateKeyData) {
			t.Errorf("expected ErrNoPrivateKeyData, got %v", err)
		}
	})

	t.Run("invalid PEM data", func(t *testing.T) {
		cr := &CertificateResource{
			PrivateKey: []byte("not valid PEM"),
		}
		_, err := cr.GetPrivateKey()
		if !errors.Is(err, ErrInvalidPrivateKeyPEM) {
			t.Errorf("expected ErrInvalidPrivateKeyPEM, got %v", err)
		}
	})

	t.Run("invalid key in PEM", func(t *testing.T) {
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: []byte("invalid key bytes"),
		})
		cr := &CertificateResource{
			PrivateKey: pemData,
		}
		_, err := cr.GetPrivateKey()
		if !errors.Is(err, ErrInvalidPrivateKeyPEM) {
			t.Errorf("expected ErrInvalidPrivateKeyPEM, got %v", err)
		}
	})

	t.Run("valid PKCS8 EC key", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pkcs8Bytes, _ := x509.MarshalPKCS8PrivateKey(key)
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8Bytes,
		})
		cr := &CertificateResource{
			PrivateKey: pemData,
		}
		parsed, err := cr.GetPrivateKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
			t.Errorf("expected *ecdsa.PrivateKey, got %T", parsed)
		}
	})

	t.Run("valid EC private key", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ecBytes, _ := x509.MarshalECPrivateKey(key)
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: ecBytes,
		})
		cr := &CertificateResource{
			PrivateKey: pemData,
		}
		parsed, err := cr.GetPrivateKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
			t.Errorf("expected *ecdsa.PrivateKey, got %T", parsed)
		}
	})

	t.Run("valid RSA PKCS1 key", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		rsaBytes := x509.MarshalPKCS1PrivateKey(key)
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: rsaBytes,
		})
		cr := &CertificateResource{
			PrivateKey: pemData,
		}
		parsed, err := cr.GetPrivateKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := parsed.(*rsa.PrivateKey); !ok {
			t.Errorf("expected *rsa.PrivateKey, got %T", parsed)
		}
	})
}

func TestCertificateResource_GetTLSCertificate(t *testing.T) {
	t.Run("empty certificate data", func(t *testing.T) {
		cr := &CertificateResource{
			PrivateKey: []byte("key"),
		}
		_, err := cr.GetTLSCertificate()
		if !errors.Is(err, ErrNoCertificateData) {
			t.Errorf("expected ErrNoCertificateData, got %v", err)
		}
	})

	t.Run("empty private key data", func(t *testing.T) {
		cr := &CertificateResource{
			Certificate: []byte("cert"),
		}
		_, err := cr.GetTLSCertificate()
		if !errors.Is(err, ErrNoPrivateKeyData) {
			t.Errorf("expected ErrNoPrivateKeyData, got %v", err)
		}
	})

	t.Run("valid certificate and key", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Test"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
			DNSNames:     []string{"test.example.com"},
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		keyBytes, _ := x509.MarshalECPrivateKey(key)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

		cr := &CertificateResource{
			Certificate: certPEM,
			PrivateKey:  keyPEM,
		}
		tlsCert, err := cr.GetTLSCertificate()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tlsCert.Certificate) == 0 {
			t.Error("expected non-empty certificate")
		}
	})
}

func TestCertificateResource_SaveToFiles(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("saves certificate", func(t *testing.T) {
		certPath := filepath.Join(tmpDir, "cert.pem")
		keyPath := filepath.Join(tmpDir, "key.pem")

		cr := &CertificateResource{
			Certificate: []byte("cert data"),
			PrivateKey:  []byte("key data"),
		}
		err := cr.SaveToFiles(certPath, keyPath, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify files exist
		if _, err := os.Stat(certPath); err != nil {
			t.Errorf("certificate file not created: %v", err)
		}
		if _, err := os.Stat(keyPath); err != nil {
			t.Errorf("key file not created: %v", err)
		}
	})

	t.Run("saves issuer certificate", func(t *testing.T) {
		certPath := filepath.Join(tmpDir, "cert2.pem")
		keyPath := filepath.Join(tmpDir, "key2.pem")
		issuerPath := filepath.Join(tmpDir, "issuer.pem")

		cr := &CertificateResource{
			Certificate:       []byte("cert data"),
			PrivateKey:        []byte("key data"),
			IssuerCertificate: []byte("issuer data"),
		}
		err := cr.SaveToFiles(certPath, keyPath, issuerPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if _, err := os.Stat(issuerPath); err != nil {
			t.Errorf("issuer file not created: %v", err)
		}
	})

	t.Run("write error - invalid path", func(t *testing.T) {
		cr := &CertificateResource{
			Certificate: []byte("cert data"),
		}
		err := cr.SaveToFiles("/nonexistent/dir/cert.pem", "/nonexistent/dir/key.pem", "")
		if !errors.Is(err, ErrWriteFile) {
			t.Errorf("expected ErrWriteFile, got %v", err)
		}
	})

	t.Run("write error - key path invalid", func(t *testing.T) {
		certPath := filepath.Join(tmpDir, "cert_key_err.pem")
		cr := &CertificateResource{
			Certificate: []byte("cert data"),
			PrivateKey:  []byte("key data"),
		}
		err := cr.SaveToFiles(certPath, "/nonexistent/dir/key.pem", "")
		if !errors.Is(err, ErrWriteFile) {
			t.Errorf("expected ErrWriteFile, got %v", err)
		}
	})

	t.Run("write error - issuer path invalid", func(t *testing.T) {
		certPath := filepath.Join(tmpDir, "cert_issuer_err.pem")
		keyPath := filepath.Join(tmpDir, "key_issuer_err.pem")
		cr := &CertificateResource{
			Certificate:       []byte("cert data"),
			PrivateKey:        []byte("key data"),
			IssuerCertificate: []byte("issuer data"),
		}
		err := cr.SaveToFiles(certPath, keyPath, "/nonexistent/dir/issuer.pem")
		if !errors.Is(err, ErrWriteFile) {
			t.Errorf("expected ErrWriteFile, got %v", err)
		}
	})
}

func TestEncodePrivateKeyPEM_Coverage90(t *testing.T) {
	t.Run("RSA key", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		pemBytes, err := encodePrivateKeyPEM(key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Contains(pemBytes, []byte("RSA PRIVATE KEY")) {
			t.Error("expected RSA PRIVATE KEY block")
		}
	})

	t.Run("ECDSA key", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pemBytes, err := encodePrivateKeyPEM(key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Contains(pemBytes, []byte("EC PRIVATE KEY")) {
			t.Error("expected EC PRIVATE KEY block")
		}
	})

	t.Run("Ed25519 key", func(t *testing.T) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		pemBytes, err := encodePrivateKeyPEM(key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Contains(pemBytes, []byte("PRIVATE KEY")) {
			t.Error("expected PRIVATE KEY block")
		}
	})

	t.Run("unsupported key type", func(t *testing.T) {
		_, err := encodePrivateKeyPEM("not a key")
		if !errors.Is(err, ErrUnsupportedKeyType) {
			t.Errorf("expected ErrUnsupportedKeyType, got %v", err)
		}
	})
}

// =============================================================================
// OCSP Tests (ocsp.go)
// =============================================================================

func TestOCSPResponse_Methods_Coverage90(t *testing.T) {
	t.Run("IsGood", func(t *testing.T) {
		resp := &OCSPResponse{
			Response: &ocsp.Response{Status: ocsp.Good},
		}
		if !resp.IsGood() {
			t.Error("expected IsGood to return true")
		}

		// Test nil cases
		if (&OCSPResponse{}).IsGood() {
			t.Error("expected IsGood to return false for nil response")
		}
		if (*OCSPResponse)(nil).IsGood() {
			t.Error("expected IsGood to return false for nil")
		}
	})

	t.Run("IsRevoked", func(t *testing.T) {
		resp := &OCSPResponse{
			Response: &ocsp.Response{Status: ocsp.Revoked},
		}
		if !resp.IsRevoked() {
			t.Error("expected IsRevoked to return true")
		}
	})

	t.Run("IsUnknown", func(t *testing.T) {
		resp := &OCSPResponse{
			Response: &ocsp.Response{Status: ocsp.Unknown},
		}
		if !resp.IsUnknown() {
			t.Error("expected IsUnknown to return true")
		}
	})

	t.Run("IsStale", func(t *testing.T) {
		// Stale response
		resp := &OCSPResponse{
			Response:   &ocsp.Response{},
			NextUpdate: time.Now().Add(-1 * time.Hour),
		}
		if !resp.IsStale() {
			t.Error("expected IsStale to return true for expired")
		}

		// Fresh response
		resp.NextUpdate = time.Now().Add(1 * time.Hour)
		if resp.IsStale() {
			t.Error("expected IsStale to return false for fresh")
		}

		// Nil cases
		if !(&OCSPResponse{}).IsStale() {
			t.Error("expected IsStale to return true for nil response")
		}
		if !(*OCSPResponse)(nil).IsStale() {
			t.Error("expected IsStale to return true for nil")
		}
	})

	t.Run("ShouldRefresh", func(t *testing.T) {
		now := time.Now()
		// Just created, shouldn't refresh
		resp := &OCSPResponse{
			Response:   &ocsp.Response{},
			ThisUpdate: now,
			NextUpdate: now.Add(1 * time.Hour),
		}
		if resp.ShouldRefresh() {
			t.Error("expected ShouldRefresh to return false for fresh")
		}

		// Past half-life, should refresh
		resp.ThisUpdate = now.Add(-2 * time.Hour)
		resp.NextUpdate = now.Add(-1 * time.Hour)
		if !resp.ShouldRefresh() {
			t.Error("expected ShouldRefresh to return true past half-life")
		}

		// Nil cases
		if !(&OCSPResponse{}).ShouldRefresh() {
			t.Error("expected ShouldRefresh to return true for nil response")
		}
	})
}

func TestHasMustStaple_Coverage90(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		if HasMustStaple(nil) {
			t.Error("expected false for nil certificate")
		}
	})

	t.Run("certificate without must-staple", func(t *testing.T) {
		cert := createCov90TestCert(t, "No Must-Staple")
		if HasMustStaple(cert) {
			t.Error("expected false for certificate without must-staple")
		}
	})

	t.Run("certificate with must-staple", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Must-Staple Cert"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
			ExtraExtensions: []pkix.Extension{
				{
					Id:       MustStapleOID,
					Critical: false,
					Value:    []byte{0x30, 0x03, 0x02, 0x01, 0x05}, // TLS feature extension: status_request
				},
			},
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(certDER)
		if !HasMustStaple(cert) {
			t.Error("expected true for certificate with must-staple")
		}
	})
}

func TestGetOCSPErrors_Coverage90(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		_, err := GetOCSP(context.Background(), nil, nil, "", nil)
		if !errors.Is(err, ErrInvalidCertificate) {
			t.Errorf("expected ErrInvalidCertificate, got %v", err)
		}
	})

	t.Run("nil issuer", func(t *testing.T) {
		cert := createCov90TestCert(t, "Test")
		_, err := GetOCSP(context.Background(), cert, nil, "", nil)
		if !errors.Is(err, ErrOCSPNoIssuer) {
			t.Errorf("expected ErrOCSPNoIssuer, got %v", err)
		}
	})

	t.Run("no OCSP responder", func(t *testing.T) {
		cert := createCov90TestCert(t, "Test")
		issuer := createCov90TestCert(t, "Issuer")
		_, err := GetOCSP(context.Background(), cert, issuer, "", nil)
		if !errors.Is(err, ErrOCSPNoResponder) {
			t.Errorf("expected ErrOCSPNoResponder, got %v", err)
		}
	})
}

func TestCheckOCSP_Client90(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		err := CheckOCSP(context.Background(), nil, nil)
		if !errors.Is(err, ErrInvalidCertificate) {
			t.Errorf("expected ErrInvalidCertificate, got %v", err)
		}
	})

	t.Run("nil issuer", func(t *testing.T) {
		cert := createCov90TestCert(t, "Test")
		err := CheckOCSP(context.Background(), cert, nil)
		if !errors.Is(err, ErrOCSPNoIssuer) {
			t.Errorf("expected ErrOCSPNoIssuer, got %v", err)
		}
	})
}

// =============================================================================
// ARI Tests (ari.go)
// =============================================================================

func TestRenewalInfo_ShouldRenewNow_Coverage90(t *testing.T) {
	t.Run("nil RenewalInfo", func(t *testing.T) {
		var ri *RenewalInfo
		if ri.ShouldRenewNow() {
			t.Error("expected false for nil RenewalInfo")
		}
	})

	t.Run("current time before window", func(t *testing.T) {
		ri := &RenewalInfo{}
		ri.SuggestedWindow.Start = time.Now().Add(1 * time.Hour)
		ri.SuggestedWindow.End = time.Now().Add(2 * time.Hour)
		if ri.ShouldRenewNow() {
			t.Error("expected false when before window")
		}
	})

	t.Run("current time in window", func(t *testing.T) {
		ri := &RenewalInfo{}
		ri.SuggestedWindow.Start = time.Now().Add(-1 * time.Hour)
		ri.SuggestedWindow.End = time.Now().Add(1 * time.Hour)
		if !ri.ShouldRenewNow() {
			t.Error("expected true when in window")
		}
	})
}

func TestRenewalInfo_ShouldRenewSoon_Coverage90(t *testing.T) {
	t.Run("nil RenewalInfo", func(t *testing.T) {
		var ri *RenewalInfo
		if ri.ShouldRenewSoon(1 * time.Hour) {
			t.Error("expected false for nil RenewalInfo")
		}
	})

	t.Run("within duration before window", func(t *testing.T) {
		ri := &RenewalInfo{}
		ri.SuggestedWindow.Start = time.Now().Add(30 * time.Minute)
		ri.SuggestedWindow.End = time.Now().Add(2 * time.Hour)
		if !ri.ShouldRenewSoon(1 * time.Hour) {
			t.Error("expected true when within duration before window")
		}
	})

	t.Run("outside duration before window", func(t *testing.T) {
		ri := &RenewalInfo{}
		ri.SuggestedWindow.Start = time.Now().Add(2 * time.Hour)
		ri.SuggestedWindow.End = time.Now().Add(3 * time.Hour)
		if ri.ShouldRenewSoon(1 * time.Hour) {
			t.Error("expected false when outside duration before window")
		}
	})
}

func TestRenewalInfo_RandomRenewalTime_Coverage90(t *testing.T) {
	t.Run("nil RenewalInfo", func(t *testing.T) {
		var ri *RenewalInfo
		renewAt := ri.RandomRenewalTime()
		if !renewAt.IsZero() {
			t.Error("expected zero time for nil RenewalInfo")
		}
	})

	t.Run("invalid window - end before start", func(t *testing.T) {
		ri := &RenewalInfo{}
		ri.SuggestedWindow.Start = time.Now().Add(2 * time.Hour)
		ri.SuggestedWindow.End = time.Now().Add(1 * time.Hour)
		renewAt := ri.RandomRenewalTime()
		if !renewAt.Equal(ri.SuggestedWindow.Start) {
			t.Error("expected start time for invalid window")
		}
	})

	t.Run("valid window", func(t *testing.T) {
		start := time.Now()
		end := start.Add(24 * time.Hour)
		ri := &RenewalInfo{}
		ri.SuggestedWindow.Start = start
		ri.SuggestedWindow.End = end

		renewAt := ri.RandomRenewalTime()
		if renewAt.Before(start) || renewAt.After(end) {
			t.Errorf("renewal time %v not within window [%v, %v]", renewAt, start, end)
		}
	})
}

func TestParseCertificateID_Coverage90(t *testing.T) {
	t.Run("empty ID", func(t *testing.T) {
		_, _, err := ParseCertificateID("")
		if !errors.Is(err, ErrInvalidCertificateID) {
			t.Errorf("expected ErrInvalidCertificateID, got %v", err)
		}
	})

	t.Run("invalid format - no dot", func(t *testing.T) {
		_, _, err := ParseCertificateID("nodothere")
		var caErr *caerrors.TrustedCAError
		if !errors.As(err, &caErr) || caErr.Type != caerrors.Malformed {
			t.Errorf("expected caerrors.Malformed, got %v", err)
		}
	})

	t.Run("invalid AKI encoding", func(t *testing.T) {
		_, _, err := ParseCertificateID("!!!invalid.Cg")
		var caErr *caerrors.TrustedCAError
		if !errors.As(err, &caErr) || caErr.Type != caerrors.Malformed {
			t.Errorf("expected caerrors.Malformed, got %v", err)
		}
	})

	t.Run("invalid serial encoding", func(t *testing.T) {
		_, _, err := ParseCertificateID("Cg.!!!invalid")
		var caErr *caerrors.TrustedCAError
		if !errors.As(err, &caErr) || caErr.Type != caerrors.Malformed {
			t.Errorf("expected caerrors.Malformed, got %v", err)
		}
	})

	t.Run("valid certificate ID", func(t *testing.T) {
		aki, serial, err := ParseCertificateID("AQIDBAUGBwg.MDk")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(aki) == 0 {
			t.Error("expected non-empty AKI")
		}
		if len(serial) == 0 {
			t.Error("expected non-empty serial")
		}
	})
}

func TestValidateCertificateID_Coverage90(t *testing.T) {
	t.Run("valid ID", func(t *testing.T) {
		err := ValidateCertificateID("AQIDBAUGBwg.MDk")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid ID", func(t *testing.T) {
		err := ValidateCertificateID("")
		if err == nil {
			t.Error("expected error for empty ID")
		}
	})
}

func TestBuildRenewalInfoURL_Coverage90(t *testing.T) {
	t.Run("empty base URL", func(t *testing.T) {
		_, err := BuildRenewalInfoURL("", "certID")
		if !errors.Is(err, ErrARINotSupported) {
			t.Errorf("expected ErrARINotSupported, got %v", err)
		}
	})

	t.Run("empty cert ID", func(t *testing.T) {
		_, err := BuildRenewalInfoURL("https://example.com/ari", "")
		if !errors.Is(err, ErrInvalidCertificateID) {
			t.Errorf("expected ErrInvalidCertificateID, got %v", err)
		}
	})

	t.Run("valid inputs", func(t *testing.T) {
		url, err := BuildRenewalInfoURL("https://example.com/ari/", "AQIDBAUGBwg.MDk")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "https://example.com/ari/AQIDBAUGBwg.MDk"
		if url != expected {
			t.Errorf("expected %q, got %q", expected, url)
		}
	})

	t.Run("invalid base URL", func(t *testing.T) {
		_, err := BuildRenewalInfoURL("://invalid", "certID")
		if err == nil {
			t.Error("expected error for invalid URL")
		}
	})
}

func TestComputeRenewalTime_Client90(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		result := ComputeRenewalTime(nil, 0.3)
		if !result.IsZero() {
			t.Error("expected zero time for nil certificate")
		}
	})

	t.Run("zero threshold defaults to 0.3", func(t *testing.T) {
		cert := createCov90TestCert(t, "Test")
		result := ComputeRenewalTime(cert, 0)
		if result.IsZero() {
			t.Error("expected non-zero time")
		}
	})

	t.Run("threshold >= 1 defaults to 0.3", func(t *testing.T) {
		cert := createCov90TestCert(t, "Test")
		result := ComputeRenewalTime(cert, 1.5)
		if result.IsZero() {
			t.Error("expected non-zero time")
		}
	})

	t.Run("valid threshold", func(t *testing.T) {
		cert := createCov90TestCert(t, "Test")
		result := ComputeRenewalTime(cert, 0.5)
		// The renewal time should be between NotBefore and NotAfter
		if result.Before(cert.NotBefore) || result.After(cert.NotAfter) {
			t.Error("renewal time should be within certificate validity")
		}
	})
}

func TestNeedsRenewal_Client90(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		if NeedsRenewal(nil, 0.3) {
			t.Error("expected false for nil certificate")
		}
	})

	t.Run("certificate not needing renewal", func(t *testing.T) {
		// Create a certificate valid for 1 year
		cert := createCov90TestCert(t, "Test")
		// With 0.3 threshold, should not need renewal yet
		if NeedsRenewal(cert, 0.3) {
			t.Error("expected false for fresh certificate")
		}
	})
}

func TestDaysUntilExpiry_Client90(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		if DaysUntilExpiry(nil) != 0 {
			t.Error("expected 0 for nil certificate")
		}
	})

	t.Run("valid certificate", func(t *testing.T) {
		cert := createCov90TestCert(t, "Test")
		days := DaysUntilExpiry(cert)
		// Certificate is valid for 365 days
		if days < 364 || days > 366 {
			t.Errorf("expected ~365 days, got %d", days)
		}
	})
}

// =============================================================================
// Chain Selection Helper Tests (chain.go)
// =============================================================================

func TestChainHelperFunctions_Coverage90(t *testing.T) {
	// Create test certificates
	leaf := createCov90TestCert(t, "Leaf")
	root := createCov90TestCert(t, "ISRG Root X1")
	chain := []*x509.Certificate{leaf, root}

	t.Run("chainToInfo with empty chain", func(t *testing.T) {
		info := chainToInfo(nil, "url")
		if info != nil {
			t.Error("expected nil for empty chain")
		}
	})

	t.Run("chainToInfo with valid chain", func(t *testing.T) {
		info := chainToInfo(chain, "https://example.com/cert")
		if info == nil {
			t.Fatal("expected non-nil info")
		}
		if info.ChainLength != 2 {
			t.Errorf("expected chain length 2, got %d", info.ChainLength)
		}
		if info.RootName != "ISRG Root X1" {
			t.Errorf("expected root name 'ISRG Root X1', got %q", info.RootName)
		}
	})

	t.Run("matchesPreferredChain empty chain", func(t *testing.T) {
		if matchesPreferredChain(nil, "test") {
			t.Error("expected false for empty chain")
		}
	})

	t.Run("matchesPreferredChain empty name", func(t *testing.T) {
		if matchesPreferredChain(chain, "") {
			t.Error("expected false for empty name")
		}
	})

	t.Run("matchesPreferredChain matching name", func(t *testing.T) {
		if !matchesPreferredChain(chain, "ISRG Root X1") {
			t.Error("expected true for matching root name")
		}
	})

	t.Run("matchesPreferredChain case insensitive", func(t *testing.T) {
		if !matchesPreferredChain(chain, "isrg root x1") {
			t.Error("expected true for case-insensitive match")
		}
	})

	t.Run("matchesPreferredChain no match", func(t *testing.T) {
		if matchesPreferredChain(chain, "Other Root") {
			t.Error("expected false for non-matching name")
		}
	})

	t.Run("parseLinkHeaders empty", func(t *testing.T) {
		result := parseLinkHeaders(nil)
		if len(result) != 0 {
			t.Error("expected empty result for nil headers")
		}
	})

	t.Run("parseLinkHeaders with alternate", func(t *testing.T) {
		headers := []string{
			`<https://example.com/alt1>; rel="alternate"`,
			`<https://example.com/alt2>; rel=alternate`,
		}
		result := parseLinkHeaders(headers)
		if len(result) != 2 {
			t.Errorf("expected 2 alternate URLs, got %d", len(result))
		}
	})

	t.Run("parseLinkHeaders without alternate", func(t *testing.T) {
		headers := []string{`<https://example.com/other>; rel="other"`}
		result := parseLinkHeaders(headers)
		if len(result) != 0 {
			t.Errorf("expected 0 alternate URLs, got %d", len(result))
		}
	})

	t.Run("parseLinkHeaders single part", func(t *testing.T) {
		headers := []string{`<https://example.com/norel>`}
		result := parseLinkHeaders(headers)
		if len(result) != 0 {
			t.Errorf("expected 0 alternate URLs, got %d", len(result))
		}
	})

	t.Run("parseCertificateChain valid PEM", func(t *testing.T) {
		pemData := cov90CertsToPEM(chain)
		certs, err := parseCertificateChain(pemData)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(certs) != 2 {
			t.Errorf("expected 2 certs, got %d", len(certs))
		}
	})

	t.Run("parseCertificateChain no certs", func(t *testing.T) {
		_, err := parseCertificateChain([]byte("not a cert"))
		if err == nil {
			t.Error("expected error for invalid data")
		}
	})

	t.Run("parseCertificateChain invalid cert in PEM", func(t *testing.T) {
		invalidPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("invalid"),
		})
		_, err := parseCertificateChain(invalidPEM)
		if err == nil {
			t.Error("expected error for invalid certificate in PEM")
		}
	})

	t.Run("SelectChainByRootName empty name", func(t *testing.T) {
		chains := []*ChainInfo{{RootName: "Test"}}
		result := SelectChainByRootName(chains, "")
		if result != nil {
			t.Error("expected nil for empty name")
		}
	})

	t.Run("SelectChainByRootName match", func(t *testing.T) {
		chains := []*ChainInfo{
			{RootName: "Root A"},
			{RootName: "Root B"},
		}
		result := SelectChainByRootName(chains, "Root B")
		if result == nil || result.RootName != "Root B" {
			t.Error("expected to find Root B")
		}
	})

	t.Run("SelectChainByRootName no match", func(t *testing.T) {
		chains := []*ChainInfo{
			{RootName: "Root A"},
			{RootName: "Root B"},
		}
		result := SelectChainByRootName(chains, "Root C")
		if result != nil {
			t.Error("expected nil for no match")
		}
	})

	t.Run("SelectShortestChain empty", func(t *testing.T) {
		result := SelectShortestChain(nil)
		if result != nil {
			t.Error("expected nil for empty chains")
		}
	})

	t.Run("SelectShortestChain selects shortest", func(t *testing.T) {
		chains := []*ChainInfo{
			{ChainLength: 3, RootName: "Long"},
			{ChainLength: 1, RootName: "Short"},
			{ChainLength: 2, RootName: "Medium"},
		}
		result := SelectShortestChain(chains)
		if result == nil || result.RootName != "Short" {
			t.Error("expected to find shortest chain")
		}
	})

	t.Run("SelectLongestChain empty", func(t *testing.T) {
		result := SelectLongestChain(nil)
		if result != nil {
			t.Error("expected nil for empty chains")
		}
	})

	t.Run("SelectLongestChain selects longest", func(t *testing.T) {
		chains := []*ChainInfo{
			{ChainLength: 1, RootName: "Short"},
			{ChainLength: 3, RootName: "Long"},
			{ChainLength: 2, RootName: "Medium"},
		}
		result := SelectLongestChain(chains)
		if result == nil || result.RootName != "Long" {
			t.Error("expected to find longest chain")
		}
	})

	t.Run("DefaultChainOption returns defaults", func(t *testing.T) {
		opt := DefaultChainOption()
		if opt == nil {
			t.Fatal("expected non-nil option")
		}
		if !opt.AllowFallback {
			t.Error("expected AllowFallback to be true")
		}
		if opt.PreferredChain != "" {
			t.Error("expected empty PreferredChain")
		}
	})
}

// =============================================================================
// DNS Solver Tests (dns_solver.go)
// =============================================================================

func TestComputeDNS01ChallengeValue_Coverage90(t *testing.T) {
	keyAuth := "token.thumbprint"
	result := ComputeDNS01ChallengeValue(keyAuth)
	if result == "" {
		t.Error("expected non-empty challenge value")
	}
	// Should be base64url encoded without padding
	if strings.Contains(result, "=") {
		t.Error("expected no padding in base64url encoding")
	}
}

func TestBuildACMEChallengeFQDN_Coverage90(t *testing.T) {
	tests := []struct {
		domain   string
		expected string
	}{
		{"example.com", "_acme-challenge.example.com."},
		{"example.com.", "_acme-challenge.example.com."},
		{"sub.example.com", "_acme-challenge.sub.example.com."},
	}

	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			result := buildACMEChallengeFQDN(tc.domain)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestBuildRecordKey_Coverage90(t *testing.T) {
	key := buildRecordKey("example.com", "token123")
	expected := "example.com:token123"
	if key != expected {
		t.Errorf("expected %q, got %q", expected, key)
	}
}

func TestPreCheckDNSSolverDelegation_Coverage90(t *testing.T) {
	solver := &DNSSolver{}
	wrapped := WrapPreCheck(solver, nil)

	t.Run("Type returns underlying type", func(t *testing.T) {
		if wrapped.Type() != ChallengeTypeDNS01.String() {
			t.Errorf("expected dns-01, got %s", wrapped.Type())
		}
	})

	t.Run("IsClosed returns underlying state", func(t *testing.T) {
		if wrapped.IsClosed() {
			t.Error("expected not closed")
		}
	})

	t.Run("ActiveRecordCount returns underlying count", func(t *testing.T) {
		if wrapped.ActiveRecordCount() != 0 {
			t.Error("expected 0 active records")
		}
	})

	t.Run("Close delegates to underlying solver", func(t *testing.T) {
		if err := wrapped.Close(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !wrapped.IsClosed() {
			t.Error("expected closed after Close()")
		}
	})
}

func TestCheckDNSFunctions_Coverage90(t *testing.T) {
	t.Run("CheckDNSFromAuthoritative returns function", func(t *testing.T) {
		fn := CheckDNSFromAuthoritative()
		if fn == nil {
			t.Error("expected non-nil function")
		}
	})

	t.Run("CheckDNSFromPublic returns function", func(t *testing.T) {
		fn := CheckDNSFromPublic()
		if fn == nil {
			t.Error("expected non-nil function")
		}
	})

	t.Run("CheckDNSFromNameservers returns function", func(t *testing.T) {
		fn := CheckDNSFromNameservers([]string{"8.8.8.8:53"})
		if fn == nil {
			t.Error("expected non-nil function")
		}
	})
}

func TestDefaultPreCheckOption_Client90(t *testing.T) {
	opt := DefaultPreCheckOption()
	if opt == nil {
		t.Fatal("expected non-nil option")
	}
	if opt.Timeout <= 0 {
		t.Error("expected positive timeout")
	}
	if opt.Interval <= 0 {
		t.Error("expected positive interval")
	}
	if opt.AllowFailure {
		t.Error("expected AllowFailure to be false")
	}
}

func TestWrapPreCheck_Client90(t *testing.T) {
	solver := &DNSSolver{}

	t.Run("with nil option uses defaults", func(t *testing.T) {
		wrapped := WrapPreCheck(solver, nil)
		if wrapped == nil {
			t.Fatal("expected non-nil wrapped solver")
		}
	})

	t.Run("with custom option", func(t *testing.T) {
		opt := &PreCheckOption{
			Timeout:  5 * time.Second,
			Interval: 1 * time.Second,
		}
		wrapped := WrapPreCheck(solver, opt)
		if wrapped == nil {
			t.Fatal("expected non-nil wrapped solver")
		}
	})

	t.Run("with zero timeout uses default", func(t *testing.T) {
		opt := &PreCheckOption{
			Timeout:  0,
			Interval: 1 * time.Second,
		}
		wrapped := WrapPreCheck(solver, opt)
		if wrapped == nil {
			t.Fatal("expected non-nil wrapped solver")
		}
	})

	t.Run("with zero interval uses default", func(t *testing.T) {
		opt := &PreCheckOption{
			Timeout:  5 * time.Second,
			Interval: 0,
		}
		wrapped := WrapPreCheck(solver, opt)
		if wrapped == nil {
			t.Fatal("expected non-nil wrapped solver")
		}
	})
}

// =============================================================================
// Resolver Tests (resolver.go)
// =============================================================================

func TestChallengeResolver_SetPreferencesWhenClosed_Coverage90(t *testing.T) {
	resolver := NewChallengeResolver()
	resolver.Close()

	// Should not panic or error, just do nothing
	resolver.SetPreferences("dns-01", "http-01")

	// Verify preferences weren't set
	prefs := resolver.GetPreferences()
	if len(prefs) != 0 {
		t.Error("expected empty preferences after setting when closed")
	}
}

func TestChallengeResolver_SolveWithCleanup_Coverage90(t *testing.T) {
	t.Run("returns error when solve fails", func(t *testing.T) {
		resolver := NewChallengeResolver()
		resolver.RegisterSolver(&cov90MockChallengeSolver{
			solveErr: errors.New("solve failed"),
		})

		authz := &acme.Authorization{
			Identifier: acme.AuthzID{Value: "example.com"},
			Challenges: []*acme.Challenge{
				{Type: "test-01", Status: "pending"},
			},
		}

		err := resolver.SolveWithCleanup(
			context.Background(),
			authz,
			"keyAuth",
			func(ctx context.Context, c *acme.Challenge) error { return nil },
		)
		if err == nil {
			t.Error("expected error when solve fails")
		}
	})
}

// =============================================================================
// ACMEError Tests (errors.go)
// =============================================================================

func TestACMEError_ShortType_Coverage90(t *testing.T) {
	err := &ACMEError{
		Type: ErrTypeBadNonce,
	}
	short := err.ShortType()
	if short != "badNonce" {
		t.Errorf("expected 'badNonce', got %q", short)
	}
}

func TestACMEError_Is_Coverage90(t *testing.T) {
	err1 := &ACMEError{Type: ErrTypeBadNonce}
	err2 := &ACMEError{Type: ErrTypeBadNonce}
	err3 := &ACMEError{Type: ErrTypeBadCSR}

	if !err1.Is(err2) {
		t.Error("expected Is to return true for same type")
	}
	if err1.Is(err3) {
		t.Error("expected Is to return false for different type")
	}
	if err1.Is(errors.New("other")) {
		t.Error("expected Is to return false for non-ACMEError")
	}
}

func TestACMEError_IsRetryable_Coverage90(t *testing.T) {
	retryableTypes := []string{
		ErrTypeBadNonce,
		ErrTypeConnection,
		ErrTypeDNS,
		ErrTypeServerInternal,
		ErrTypeRateLimited,
	}
	for _, errType := range retryableTypes {
		err := &ACMEError{Type: errType}
		if !err.IsRetryable() {
			t.Errorf("expected %s to be retryable", errType)
		}
	}

	nonRetryable := &ACMEError{Type: ErrTypeBadCSR}
	if nonRetryable.IsRetryable() {
		t.Error("expected BadCSR to not be retryable")
	}
}

// =============================================================================
// Type String Methods
// =============================================================================

func TestTypeStringMethods_Coverage90(t *testing.T) {
	t.Run("AuthorizationType.String", func(t *testing.T) {
		at := AuthzTypeDNS
		if at.String() != "dns" {
			t.Errorf("expected 'dns', got %q", at.String())
		}
	})

	t.Run("ChallengeType.String", func(t *testing.T) {
		ct := ChallengeTypeHTTP01
		if ct.String() != "http-01" {
			t.Errorf("expected 'http-01', got %q", ct.String())
		}
	})

	t.Run("AccountStatus.String", func(t *testing.T) {
		as := AccountStatusValid
		if as.String() != "valid" {
			t.Errorf("expected 'valid', got %q", as.String())
		}
	})

	t.Run("OrderStatus.String", func(t *testing.T) {
		os := OrderStatusPending
		if os.String() != "pending" {
			t.Errorf("expected 'pending', got %q", os.String())
		}
	})
}

// =============================================================================
// CertificateRequest Validation
// =============================================================================

func TestCertificateRequestValidate_Coverage90(t *testing.T) {
	t.Run("missing AuthzType", func(t *testing.T) {
		req := &CertificateRequest{
			AuthzValue:    "example.com",
			ChallengeType: "http-01",
			CSR:           []byte("csr"),
		}
		err := req.Validate()
		if !errors.Is(err, ErrMissingAuthzType) {
			t.Errorf("expected ErrMissingAuthzType, got %v", err)
		}
	})

	t.Run("missing AuthzValue", func(t *testing.T) {
		req := &CertificateRequest{
			AuthzType:     "dns",
			ChallengeType: "http-01",
			CSR:           []byte("csr"),
		}
		err := req.Validate()
		if !errors.Is(err, ErrMissingAuthzValue) {
			t.Errorf("expected ErrMissingAuthzValue, got %v", err)
		}
	})

	t.Run("missing ChallengeType", func(t *testing.T) {
		req := &CertificateRequest{
			AuthzType:  "dns",
			AuthzValue: "example.com",
			CSR:        []byte("csr"),
		}
		err := req.Validate()
		if !errors.Is(err, ErrMissingChallengeType) {
			t.Errorf("expected ErrMissingChallengeType, got %v", err)
		}
	})

	t.Run("missing CSR", func(t *testing.T) {
		req := &CertificateRequest{
			AuthzType:     "dns",
			AuthzValue:    "example.com",
			ChallengeType: "http-01",
		}
		err := req.Validate()
		if !errors.Is(err, ErrMissingCSR) {
			t.Errorf("expected ErrMissingCSR, got %v", err)
		}
	})

	t.Run("valid request", func(t *testing.T) {
		req := &CertificateRequest{
			AuthzType:     "dns",
			AuthzValue:    "example.com",
			ChallengeType: "http-01",
			CSR:           []byte("csr"),
		}
		err := req.Validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// =============================================================================
// Client Operations Tests (client.go) - ListOrders, GetOrder, etc.
// =============================================================================

func TestClient_ListOrders_Client90(t *testing.T) {
	// Create a mock server that simulates an ACME server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/orders" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ordersListResponse{
				Orders: []string{
					"https://example.com/order/1",
					"https://example.com/order/2",
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	t.Run("fetches orders from URL", func(t *testing.T) {
		// Test fetchOrdersList directly
		client := &Client{
			httpClient: server.Client(),
			logger:     slog.Default(),
		}

		orders, err := client.fetchOrdersList(context.Background(), server.URL+"/orders")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(orders) != 2 {
			t.Errorf("expected 2 orders, got %d", len(orders))
		}
	})
}

func TestClient_fetchOrdersList_Client90(t *testing.T) {
	t.Run("request creation error", func(t *testing.T) {
		client := &Client{
			httpClient: http.DefaultClient,
			logger:     slog.Default(),
		}

		// Use invalid URL to trigger request creation error
		_, err := client.fetchOrdersList(context.Background(), "://invalid-url")
		if err == nil {
			t.Error("expected error for invalid URL")
		}
	})

	t.Run("server error status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("server error"))
		}))
		defer server.Close()

		client := &Client{
			httpClient: server.Client(),
			logger:     slog.Default(),
		}

		_, err := client.fetchOrdersList(context.Background(), server.URL)
		if err == nil {
			t.Error("expected error for server error")
		}
		var caErr *caerrors.TrustedCAError
		if !errors.As(err, &caErr) || caErr.Type != caerrors.ConnectionFailure {
			t.Errorf("expected caerrors.ConnectionFailure, got %v", err)
		}
	})

	t.Run("invalid JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("not valid json"))
		}))
		defer server.Close()

		client := &Client{
			httpClient: server.Client(),
			logger:     slog.Default(),
		}

		_, err := client.fetchOrdersList(context.Background(), server.URL)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

func TestClient_GetOrder_Client90(t *testing.T) {
	t.Run("empty order URL", func(t *testing.T) {
		client := &Client{
			logger: slog.Default(),
		}
		_, err := client.GetOrder(context.Background(), "")
		if !errors.Is(err, ErrInvalidOrderURL) {
			t.Errorf("expected ErrInvalidOrderURL, got %v", err)
		}
	})
}

func TestClient_DeactivateAuthorization_Client90(t *testing.T) {
	t.Run("empty authorization URL", func(t *testing.T) {
		client := &Client{
			logger: slog.Default(),
		}
		err := client.DeactivateAuthorization(context.Background(), "")
		if !errors.Is(err, ErrInvalidAuthorizationURL) {
			t.Errorf("expected ErrInvalidAuthorizationURL, got %v", err)
		}
	})
}

func TestClient_GetAuthorization_Client90(t *testing.T) {
	t.Run("empty authorization URL", func(t *testing.T) {
		client := &Client{
			logger: slog.Default(),
		}
		_, err := client.GetAuthorization(context.Background(), "")
		if !errors.Is(err, ErrInvalidAuthorizationURL) {
			t.Errorf("expected ErrInvalidAuthorizationURL, got %v", err)
		}
	})
}

// =============================================================================
// Chain Fetch Tests (chain.go)
// =============================================================================

func TestClient_FetchChainFromURL_Client90(t *testing.T) {
	cert := createCov90TestCert(t, "Test")
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	t.Run("successful fetch", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/pem-certificate-chain")
			w.Write(pemData)
		}))
		defer server.Close()

		client := &Client{
			httpClient: server.Client(),
			logger:     slog.Default(),
		}

		chain, err := client.fetchChainFromURL(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(chain) != 1 {
			t.Errorf("expected 1 cert, got %d", len(chain))
		}
	})

	t.Run("server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		client := &Client{
			httpClient: server.Client(),
			logger:     slog.Default(),
		}

		_, err := client.fetchChainFromURL(context.Background(), server.URL)
		if err == nil {
			t.Error("expected error for server error")
		}
	})

	t.Run("invalid URL", func(t *testing.T) {
		client := &Client{
			httpClient: http.DefaultClient,
			logger:     slog.Default(),
		}

		_, err := client.fetchChainFromURL(context.Background(), "://invalid")
		if err == nil {
			t.Error("expected error for invalid URL")
		}
	})
}

func TestClient_FetchAlternateChains_Client90(t *testing.T) {
	cert := createCov90TestCert(t, "Alt Cert")
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	t.Run("no alternate chains", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No Link headers
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := &Client{
			httpClient: server.Client(),
			logger:     slog.Default(),
		}

		_, err := client.fetchAlternateChains(context.Background(), server.URL)
		if !errors.Is(err, ErrNoAlternateChains) {
			t.Errorf("expected ErrNoAlternateChains, got %v", err)
		}
	})

	t.Run("with alternate chains", func(t *testing.T) {
		altServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(pemData)
		}))
		defer altServer.Close()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Link", `<`+altServer.URL+`>; rel="alternate"`)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := &Client{
			httpClient: server.Client(),
			logger:     slog.Default(),
		}

		chains, err := client.fetchAlternateChains(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(chains) != 1 {
			t.Errorf("expected 1 chain, got %d", len(chains))
		}
	})

	t.Run("alternate chain fetch fails", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Link", `<http://invalid-url-that-doesnt-exist.local/cert>; rel="alternate"`)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := &Client{
			httpClient: &http.Client{Timeout: 100 * time.Millisecond},
			logger:     slog.Default(),
		}

		_, err := client.fetchAlternateChains(context.Background(), server.URL)
		if !errors.Is(err, ErrNoAlternateChains) {
			t.Errorf("expected ErrNoAlternateChains when all fetches fail, got %v", err)
		}
	})
}

// =============================================================================
// Rate Limiter Tests (rate_limiter.go)
// =============================================================================

func TestRateLimiter_Wait_Client90(t *testing.T) {
	t.Run("disabled limiter returns immediately", func(t *testing.T) {
		cfg := &RateLimiterConfig{Enabled: false}
		rl := NewRateLimiter(cfg)

		err := rl.Wait(context.Background())
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("closed limiter returns error", func(t *testing.T) {
		cfg := &RateLimiterConfig{
			Enabled:           true,
			RequestsPerSecond: 10,
			BurstSize:         10,
			MaxWaitTime:       time.Second,
		}
		rl := NewRateLimiter(cfg)
		rl.Close()

		err := rl.Wait(context.Background())
		if !errors.Is(err, ErrRateLimiterClosed) {
			t.Errorf("expected ErrRateLimiterClosed, got %v", err)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		cfg := &RateLimiterConfig{
			Enabled:           true,
			RequestsPerSecond: 1,
			BurstSize:         0,
			MaxWaitTime:       5 * time.Second,
		}
		rl := NewRateLimiter(cfg)

		// Drain all tokens first
		for rl.Allow() {
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := rl.Wait(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	})
}

func TestRateLimiter_Allow_Client90(t *testing.T) {
	t.Run("disabled limiter always allows", func(t *testing.T) {
		cfg := &RateLimiterConfig{Enabled: false}
		rl := NewRateLimiter(cfg)

		if !rl.Allow() {
			t.Error("expected Allow to return true when disabled")
		}
	})

	t.Run("closed limiter denies", func(t *testing.T) {
		cfg := &RateLimiterConfig{
			Enabled:           true,
			RequestsPerSecond: 10,
			BurstSize:         10,
		}
		rl := NewRateLimiter(cfg)
		rl.Close()

		if rl.Allow() {
			t.Error("expected Allow to return false when closed")
		}
	})

	t.Run("respects rate limit", func(t *testing.T) {
		cfg := &RateLimiterConfig{
			Enabled:           true,
			RequestsPerSecond: 1000,
			BurstSize:         2,
		}
		rl := NewRateLimiter(cfg)

		// Should allow first few requests
		allowed := 0
		for i := 0; i < 10; i++ {
			if rl.Allow() {
				allowed++
			}
		}
		// Should have allowed at least burst size
		if allowed < 2 {
			t.Errorf("expected at least 2 allowed, got %d", allowed)
		}
	})
}

func TestRateLimiter_SetRetryAfter_Client90(t *testing.T) {
	cfg := &RateLimiterConfig{
		Enabled:           true,
		RequestsPerSecond: 10,
		BurstSize:         10,
		MaxWaitTime:       time.Second,
	}
	rl := NewRateLimiter(cfg)

	// Set a retry-after time in the past
	rl.SetRetryAfterTime(time.Now().Add(-1 * time.Second))

	// Should still allow since retry-after is in the past
	if !rl.Allow() {
		t.Error("expected Allow to return true after retry-after expires")
	}
}

func TestRateLimiter_Close_Client90(t *testing.T) {
	cfg := &RateLimiterConfig{
		Enabled:           true,
		RequestsPerSecond: 10,
		BurstSize:         10,
	}
	rl := NewRateLimiter(cfg)

	// Close the rate limiter
	rl.Close()

	// Verify it's closed by checking that Allow returns false
	if rl.Allow() {
		t.Error("expected Allow to return false after Close")
	}

	// Verify Wait returns ErrRateLimiterClosed
	err := rl.Wait(context.Background())
	if err != ErrRateLimiterClosed {
		t.Errorf("expected ErrRateLimiterClosed, got %v", err)
	}
}

func TestNewRateLimiter_Client90(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		rl := NewRateLimiter(nil)
		if rl == nil {
			t.Fatal("expected non-nil rate limiter")
		}
	})

	t.Run("with config", func(t *testing.T) {
		cfg := &RateLimiterConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			BurstSize:         50,
			MaxWaitTime:       5 * time.Second,
		}
		rl := NewRateLimiter(cfg)
		if rl == nil {
			t.Fatal("expected non-nil rate limiter")
		}
	})
}

// =============================================================================
// GetOCSP with HTTP server mock (ocsp.go)
// =============================================================================

func TestGetOCSP_HTTPMock_Client90(t *testing.T) {
	// Create issuer key and cert
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Issuer"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	issuer, _ := x509.ParseCertificate(issuerDER)

	// Create server that returns bad status
	t.Run("server returns non-200 status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		// Create a certificate with OCSP URL
		certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		certTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "Test Cert"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
			OCSPServer:   []string{server.URL},
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, certTemplate, issuerTemplate, &certKey.PublicKey, issuerKey)
		cert, _ := x509.ParseCertificate(certDER)

		_, err := GetOCSP(context.Background(), cert, issuer, server.URL, server.Client())
		if err == nil {
			t.Error("expected error for server error")
		}
	})

	t.Run("invalid OCSP response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", OCSPContentType)
			w.Write([]byte("invalid ocsp response"))
		}))
		defer server.Close()

		certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		certTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(3),
			Subject:      pkix.Name{CommonName: "Test Cert"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
			OCSPServer:   []string{server.URL},
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, certTemplate, issuerTemplate, &certKey.PublicKey, issuerKey)
		cert, _ := x509.ParseCertificate(certDER)

		_, err := GetOCSP(context.Background(), cert, issuer, server.URL, server.Client())
		if err == nil {
			t.Error("expected error for invalid OCSP response")
		}
	})

	t.Run("request read error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Read but don't write anything - this will cause a read error
			io.ReadAll(r.Body)
			// Close connection abruptly by not writing response
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
			}
		}))
		defer server.Close()

		certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		certTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(4),
			Subject:      pkix.Name{CommonName: "Test Cert"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
			OCSPServer:   []string{server.URL},
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, certTemplate, issuerTemplate, &certKey.PublicKey, issuerKey)
		cert, _ := x509.ParseCertificate(certDER)

		_, err := GetOCSP(context.Background(), cert, issuer, server.URL, server.Client())
		if err == nil {
			t.Error("expected error for connection error")
		}
	})
}

// =============================================================================
// GetCertificateID and related functions (ari.go)
// =============================================================================

func TestGetCertificateID_Client90(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		id := GetCertificateID(nil)
		if id != "" {
			t.Error("expected empty string for nil certificate")
		}
	})

	t.Run("certificate without AKI", func(t *testing.T) {
		cert := createCov90TestCert(t, "Test")
		id := GetCertificateID(cert)
		// Self-signed cert may not have AKI
		if id != "" && !strings.Contains(id, ".") {
			t.Error("expected empty string or valid ID format")
		}
	})

	t.Run("certificate with AKI", func(t *testing.T) {
		// Create a CA-signed certificate with AKI
		caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		caTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Test CA"},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			SubjectKeyId:          []byte{1, 2, 3, 4, 5},
		}
		caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
		ca, _ := x509.ParseCertificate(caDER)

		certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		certTemplate := &x509.Certificate{
			SerialNumber:   big.NewInt(2),
			Subject:        pkix.Name{CommonName: "Test Cert"},
			NotBefore:      time.Now(),
			NotAfter:       time.Now().Add(24 * time.Hour),
			AuthorityKeyId: ca.SubjectKeyId,
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, certTemplate, ca, &certKey.PublicKey, caKey)
		cert, _ := x509.ParseCertificate(certDER)

		id := GetCertificateID(cert)
		if id == "" {
			t.Error("expected non-empty ID for certificate with AKI")
		}
		if !strings.Contains(id, ".") {
			t.Error("expected ID to contain dot separator")
		}
	})
}

func TestGetCertificateIDFromHash_Client90(t *testing.T) {
	t.Run("nil certificate", func(t *testing.T) {
		id := GetCertificateIDFromHash(nil)
		if id != "" {
			t.Error("expected empty string for nil certificate")
		}
	})

	t.Run("certificate with empty Raw", func(t *testing.T) {
		cert := &x509.Certificate{}
		id := GetCertificateIDFromHash(cert)
		if id != "" {
			t.Error("expected empty string for certificate with empty Raw")
		}
	})

	t.Run("valid certificate", func(t *testing.T) {
		cert := createCov90TestCert(t, "Test")
		id := GetCertificateIDFromHash(cert)
		if id == "" {
			t.Error("expected non-empty ID")
		}
		if len(id) > 32 {
			t.Error("expected ID to be truncated to 32 chars")
		}
	})
}

// =============================================================================
// Helper Functions
// =============================================================================

func createCov90TestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func cov90CertsToPEM(certs []*x509.Certificate) []byte {
	var pemData []byte
	for _, cert := range certs {
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}
	return pemData
}

// cov90MockStorage implements storage.AccountDAO for testing
type cov90MockStorage struct{}

func (m *cov90MockStorage) Save(_ context.Context, _ *entities.ACMEAccount) error {
	return nil
}

func (m *cov90MockStorage) Get(_ context.Context, _ uint64) (*entities.ACMEAccount, error) {
	return nil, nil
}

func (m *cov90MockStorage) Exists(_ context.Context, _ uint64) (bool, error) {
	return false, nil
}

func (m *cov90MockStorage) Delete(_ context.Context, _ uint64) error {
	return nil
}

func (m *cov90MockStorage) List(_ context.Context, _ string) ([]*entities.ACMEAccount, error) {
	return nil, nil
}

// cov90MockChallengeSolver for testing
type cov90MockChallengeSolver struct {
	solveErr   error
	cleanupErr error
}

func (m *cov90MockChallengeSolver) Type() string {
	return "test-01"
}

func (m *cov90MockChallengeSolver) Solve(ctx context.Context, domain string, challenge *acme.Challenge, keyAuth string) error {
	return m.solveErr
}

func (m *cov90MockChallengeSolver) Cleanup(ctx context.Context, domain string, challenge *acme.Challenge) error {
	return m.cleanupErr
}
