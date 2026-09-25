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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// failingCloseBody wraps a real response body so the underlying connection
// is still released, but Close always reports a synthetic error - the same
// shape a flaky peer or a half-closed TLS session produces in production.
type failingCloseBody struct {
	io.ReadCloser
}

func (b failingCloseBody) Close() error {
	_ = b.ReadCloser.Close()
	return errors.New("simulated close failure")
}

// failingCloseTransport decorates every response's body with
// failingCloseBody so response-body closes fail without touching what the
// server actually sends.
type failingCloseTransport struct {
	inner http.RoundTripper
}

func (t failingCloseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.inner.RoundTrip(req)
	if err != nil {
		return resp, err
	}
	resp.Body = failingCloseBody{ReadCloser: resp.Body}
	return resp, nil
}

// TestFetchChainFromURL_ClosingResponseBodyFails confirms that a resp.Body
// close failure is logged rather than propagated: fetchChainFromURL must
// still return the certificate chain the server sent, unchanged, exactly
// like it does when Close succeeds (go-xkms#866).
func TestFetchChainFromURL_ClosingResponseBodyFails(t *testing.T) {
	cert := createCov90TestCert(t, "close-logging")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(pemData)
	}))
	defer server.Close()

	var logBuf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(restore)

	httpClient := server.Client()
	httpClient.Transport = failingCloseTransport{inner: httpClient.Transport}

	client := &Client{
		httpClient: httpClient,
		logger:     slog.Default(),
	}

	chain, err := client.fetchChainFromURL(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(chain))
	}
	if chain[0].Subject.CommonName != "close-logging" {
		t.Errorf("unexpected certificate returned: %q", chain[0].Subject.CommonName)
	}

	if !bytes.Contains(logBuf.Bytes(), []byte("failed to close response body")) {
		t.Fatalf("expected the close failure to be logged, got: %q", logBuf.String())
	}
	if !bytes.Contains(logBuf.Bytes(), []byte("simulated close failure")) {
		t.Fatalf("expected the close error to be included in the log, got: %q", logBuf.String())
	}
}

// TestGetOCSP_ClosingResponseBodyFails is the same assertion for the
// standalone GetOCSP function, which has no *Client (and so no c.logger) to
// log through and falls back to the package-level slog logger.
func TestGetOCSP_ClosingResponseBodyFails(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate issuer key: %v", err)
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Issuer"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("failed to create issuer certificate: %v", err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("failed to parse issuer certificate: %v", err)
	}

	// The server does not need to return a well-formed OCSP response: any
	// non-200 status short-circuits GetOCSP before it parses the body, which
	// is enough to exercise the deferred close.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate cert key: %v", err)
	}
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		OCSPServer:   []string{server.URL},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, issuerTemplate, &certKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}

	var logBuf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(restore)

	httpClient := server.Client()
	httpClient.Transport = failingCloseTransport{inner: httpClient.Transport}

	_, err = GetOCSP(context.Background(), cert, issuer, server.URL, httpClient)
	if err == nil {
		t.Fatal("expected the HTTP 500 status to still surface as an error")
	}

	if !bytes.Contains(logBuf.Bytes(), []byte("ocsp: failed to close response body")) {
		t.Fatalf("expected the close failure to be logged, got: %q", logBuf.String())
	}
}
