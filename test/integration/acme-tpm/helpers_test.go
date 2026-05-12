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

//go:build integration && tpm2

package tpm_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/go-jose/go-jose/v4"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Common types

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type OrderRequest struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   string       `json:"notBefore,omitempty"`
	NotAfter    string       `json:"notAfter,omitempty"`
}

type OrderResponse struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
}

type AuthorizationResponse struct {
	Status     string      `json:"status"`
	Expires    string      `json:"expires,omitempty"`
	Identifier Identifier  `json:"identifier"`
	Challenges []Challenge `json:"challenges"`
}

type Challenge struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	URL    string `json:"url"`
	Token  string `json:"token"`
}

type AccountRequest struct {
	Contact              []string `json:"contact,omitempty"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	OnlyReturnExisting   bool     `json:"onlyReturnExisting,omitempty"`
}

// Helper functions

func getServerURL() string {
	url := os.Getenv("ACME_SERVER_URL")
	if url == "" {
		return "https://acme-server"
	}
	return url
}

func getTLSConfig() *tls.Config {
	caFile := os.Getenv("ACME_CA_CERT")
	if caFile != "" {
		caCert, err := os.ReadFile(caFile)
		if err == nil {
			certPool := x509.NewCertPool()
			certPool.AppendCertsFromPEM(caCert)
			return &tls.Config{
				RootCAs:    certPool,
				MinVersion: tls.VersionTLS13,
			}
		}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
}

func fetchNonce(client *http.Client, serverURL string) (string, error) {
	nonceURL := fmt.Sprintf("%s/acme/new-nonce", serverURL)
	req, err := http.NewRequest("HEAD", nonceURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", caerrors.MalformedError("no nonce in response")
	}

	return nonce, nil
}

func createJWS(payload interface{}, privateKey crypto.Signer, keyID, nonce, url string) (string, error) {
	var alg jose.SignatureAlgorithm

	switch privateKey.(type) {
	case *rsa.PrivateKey:
		alg = jose.RS256
	case *ecdsa.PrivateKey:
		alg = jose.ES256
	default:
		return "", caerrors.MalformedError("unsupported key type")
	}

	signerOpts := &jose.SignerOptions{
		NonceSource: staticNonceSource(nonce),
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	}

	if keyID == "" {
		signerOpts.EmbedJWK = true
	} else {
		signerOpts.ExtraHeaders["kid"] = keyID
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: privateKey}, signerOpts)
	if err != nil {
		return "", err
	}

	var payloadBytes []byte
	if payload != nil {
		payloadBytes, err = json.Marshal(payload)
		if err != nil {
			return "", err
		}
	} else {
		payloadBytes = []byte("")
	}

	jws, err := signer.Sign(payloadBytes)
	if err != nil {
		return "", err
	}

	return jws.FullSerialize(), nil
}

func sendJWSRequest(client *http.Client, url string, payload interface{}, privateKey crypto.Signer, keyID, nonce string) (*http.Response, error) {
	jws, err := createJWS(payload, privateKey, keyID, nonce, url)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBufferString(jws))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/jose+json")

	return client.Do(req)
}

func createAccount(client *http.Client, serverURL string, privateKey crypto.Signer, contacts []string) (string, error) {
	nonce, err := fetchNonce(client, serverURL)
	if err != nil {
		return "", err
	}

	accountReq := AccountRequest{
		Contact:              contacts,
		TermsOfServiceAgreed: true,
	}

	newAccountURL := fmt.Sprintf("%s/acme/new-account", serverURL)
	resp, err := sendJWSRequest(client, newAccountURL, accountReq, privateKey, "", nonce)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", caerrors.ConnectionFailureError("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	accountURL := resp.Header.Get("Location")
	if accountURL == "" {
		return "", caerrors.MalformedError("no Location header in response")
	}

	return accountURL, nil
}

type staticNonceSource string

func (s staticNonceSource) Nonce() (string, error) {
	return string(s), nil
}

// Mock implementations for TPM integration tests
// These are stub implementations that allow the test code to compile.
// The actual test that uses these is skipped because real implementations
// require a fully configured TPM mock environment.

// MockTPM is a stub implementation of the enroll01.TrustedPlatformModule interface
type MockTPM struct {
	t *testing.T
}

// NewMockTPM creates a new mock TPM for testing
func NewMockTPM(t *testing.T) *MockTPM {
	return &MockTPM{t: t}
}

// EKCertificate returns the TPM Endorsement Key certificate
func (m *MockTPM) EKCertificate() ([]byte, error) {
	return nil, nil
}

// IAKAttributes returns the attestation key attributes
func (m *MockTPM) IAKAttributes() (interface{}, error) {
	return nil, nil
}

// CreateIDevID creates an IDevID key and generates TCG-CSR-IDEVID
func (m *MockTPM) CreateIDevID(akAttrs interface{}, ekCert []byte, qualifyingData []byte) (interface{}, interface{}, error) {
	return nil, nil, nil
}

// ActivateCredential performs TPM2_ActivateCredential operation
func (m *MockTPM) ActivateCredential(credentialBlob, encryptedSecret []byte) ([]byte, error) {
	return nil, nil
}

// MockEnrollCA is a stub implementation of the enroll01.CertificateAuthority interface
type MockEnrollCA struct {
	t *testing.T
}

// NewMockEnrollCA creates a new mock CA for testing
func NewMockEnrollCA(t *testing.T) *MockEnrollCA {
	return &MockEnrollCA{t: t}
}

// VerifyTCG_CSR_IDevIDBytes verifies a TCG-CSR-IDEVID and returns credential components
func (m *MockEnrollCA) VerifyTCG_CSR_IDevIDBytes(packedCSR []byte, sigAlg interface{}) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}

// DefaultSignatureAlgorithm returns the CA's default signature algorithm
func (m *MockEnrollCA) DefaultSignatureAlgorithm() x509.SignatureAlgorithm {
	return x509.SHA256WithRSA
}

// =============================================================================
// Certificate Display Helpers
// =============================================================================

// LogCertificate logs a certificate's details to the test output using
// the xkmssdk.CertToString function which displays TCG and Trusted Platform OIDs.
func LogCertificate(t *testing.T, cert *x509.Certificate, title string) {
	t.Helper()
	if title != "" {
		t.Logf("\n%s", title)
	}
	t.Log(xkmssdk.CertToString(cert))
}

// LogCertificateChain logs all certificates in a chain using
// the xkmssdk.CertChainToString function.
func LogCertificateChain(t *testing.T, chain []*x509.Certificate, title string) {
	t.Helper()
	if title != "" {
		t.Logf("\n%s", title)
	}
	t.Log(xkmssdk.CertChainToString(chain))
}

// base64URLEncode encodes data using base64url encoding without padding
// as required by ACME protocol (RFC 8555)
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
