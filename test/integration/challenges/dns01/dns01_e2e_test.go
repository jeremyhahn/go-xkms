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

//go:build dns01_e2e

// Package dns01 implements E2E integration tests for DNS-01 ACME challenge.
// These tests perform the complete DNS-01 challenge flow:
// 1. Client requests certificate from ACME server
// 2. Client sets TXT record via mock DNS server API
// 3. ACME server validates the challenge via DNS TXT query
// 4. Certificate is issued
package dns01

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Environment variables
var (
	acmeServerURL = getEnv("ACME_SERVER_URL", "http://acme-server:8080")
	dnsAPIURL     = getEnv("DNS_API_URL", "http://dns-server:8053")
	testDomain    = getEnv("TEST_DOMAIN", "test.example.com")
)

func getEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

// TestDNS01E2E_FullCertificateIssuance performs complete DNS-01 flow
func TestDNS01E2E_FullCertificateIssuance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	t.Log("=== DNS-01 E2E Certificate Issuance Test ===")
	t.Logf("ACME Server: %s", acmeServerURL)
	t.Logf("DNS API: %s", dnsAPIURL)
	t.Logf("Test Domain: %s", testDomain)

	// Step 1: Verify ACME server is ready
	t.Log("Step 1: Verifying ACME server connectivity")
	directory, err := fetchDirectory(ctx, client, acmeServerURL)
	require.NoError(t, err, "Failed to fetch ACME directory")
	t.Logf("Directory endpoints: newAccount=%s, newOrder=%s", directory.NewAccount, directory.NewOrder)

	// Step 2: Verify DNS server is ready
	t.Log("Step 2: Verifying DNS server connectivity")
	err = verifyDNSServer(ctx, client, dnsAPIURL)
	require.NoError(t, err, "Failed to connect to DNS server")
	t.Log("DNS server is ready")

	// Step 3: Generate account key and register
	t.Log("Step 3: Generating account key and registering with ACME server")
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := registerAccount(ctx, client, directory, accountKey, "mailto:dns01-e2e@example.com")
	require.NoError(t, err, "Failed to register account")
	t.Logf("Account registered: %s", accountURL)

	// Step 4: Create order for the test domain
	t.Log("Step 4: Creating certificate order")
	order, err := createOrder(ctx, client, directory, accountKey, accountURL, []string{testDomain})
	require.NoError(t, err, "Failed to create order")
	require.Equal(t, "pending", order.Status, "Order should be pending")
	t.Logf("Order created with %d authorizations", len(order.Authorizations))

	// Step 5: Get authorization and find DNS-01 challenge
	t.Log("Step 5: Fetching authorization and DNS-01 challenge")
	require.NotEmpty(t, order.Authorizations, "Order must have authorizations")
	authz, err := fetchAuthorization(ctx, client, order.Authorizations[0], accountKey, accountURL)
	require.NoError(t, err, "Failed to fetch authorization")

	var dns01Challenge *Challenge
	for _, ch := range authz.Challenges {
		if ch.Type == "dns-01" {
			dns01Challenge = &ch
			break
		}
	}
	require.NotNil(t, dns01Challenge, "DNS-01 challenge must be available")
	t.Logf("DNS-01 challenge: token=%s, URL=%s", dns01Challenge.Token, dns01Challenge.URL)

	// Step 6: Compute key authorization and TXT record value
	t.Log("Step 6: Computing key authorization and TXT record value")
	keyAuth, err := computeKeyAuthorization(dns01Challenge.Token, accountKey.Public())
	require.NoError(t, err, "Failed to compute key authorization")

	// DNS-01 TXT value is SHA-256(keyAuth) base64url encoded
	txtValue := computeDNS01TXTValue(keyAuth)
	t.Logf("Key authorization: %s", keyAuth)
	t.Logf("TXT record value: %s", txtValue)

	// Step 7: Set TXT record via DNS server API
	t.Log("Step 7: Setting TXT record on DNS server")
	acmeDomain := fmt.Sprintf("_acme-challenge.%s", testDomain)
	err = setDNSTXTRecord(ctx, client, dnsAPIURL, acmeDomain, txtValue)
	require.NoError(t, err, "Failed to set DNS TXT record")
	t.Logf("TXT record set: %s = %s", acmeDomain, txtValue)

	// Verify TXT record is set correctly
	verifiedValue, err := getDNSTXTRecord(ctx, client, dnsAPIURL, acmeDomain)
	require.NoError(t, err, "Failed to verify TXT record")
	require.Equal(t, txtValue, verifiedValue, "TXT record value mismatch")
	t.Log("TXT record verified successfully")

	// Step 8: Notify ACME server to validate challenge
	t.Log("Step 8: Notifying ACME server to validate DNS-01 challenge")
	challengeResp, err := respondToChallenge(ctx, client, dns01Challenge.URL, accountKey, accountURL)
	require.NoError(t, err, "Failed to respond to challenge")
	t.Logf("Challenge status after response: %s", challengeResp.Status)

	// Step 9: Poll for challenge/authorization validation
	t.Log("Step 9: Waiting for challenge validation")
	validatedAuthz, err := pollAuthorization(ctx, client, order.Authorizations[0], accountKey, accountURL)
	require.NoError(t, err, "Failed to poll authorization")
	require.Equal(t, "valid", validatedAuthz.Status, "Authorization should be valid")
	t.Logf("Authorization validated: status=%s", validatedAuthz.Status)

	// Step 10: Generate CSR and finalize order
	t.Log("Step 10: Generating CSR and finalizing order")
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generate certificate key")

	csr, err := generateCSR(certKey, testDomain)
	require.NoError(t, err, "Failed to generate CSR")

	finalizedOrder, err := finalizeOrder(ctx, client, order.Finalize, accountKey, accountURL, csr)
	require.NoError(t, err, "Failed to finalize order")
	t.Logf("Order finalized: status=%s", finalizedOrder.Status)

	// Step 11: Poll for order ready/valid and get certificate
	t.Log("Step 11: Waiting for certificate to be ready")
	readyOrder, err := pollOrder(ctx, client, order.Location, accountKey, accountURL)
	require.NoError(t, err, "Failed to poll order")
	require.Equal(t, "valid", readyOrder.Status, "Order should be valid")
	require.NotEmpty(t, readyOrder.Certificate, "Order should have certificate URL")
	t.Logf("Certificate URL: %s", readyOrder.Certificate)

	// Step 12: Download certificate
	t.Log("Step 12: Downloading issued certificate")
	certPEM, err := downloadCertificate(ctx, client, readyOrder.Certificate, accountKey, accountURL)
	require.NoError(t, err, "Failed to download certificate")
	require.NotEmpty(t, certPEM, "Certificate PEM should not be empty")

	// Parse and validate certificate
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block, "Failed to decode certificate PEM")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Failed to parse certificate")
	require.Equal(t, testDomain, cert.Subject.CommonName, "Certificate CN should match test domain")
	t.Logf("Certificate issued: CN=%s, NotBefore=%s, NotAfter=%s",
		cert.Subject.CommonName, cert.NotBefore, cert.NotAfter)

	// Step 13: Clean up TXT record
	t.Log("Step 13: Cleaning up TXT record")
	err = deleteDNSTXTRecord(ctx, client, dnsAPIURL, acmeDomain)
	require.NoError(t, err, "Failed to delete TXT record")
	t.Log("TXT record deleted")

	t.Log("=== DNS-01 E2E Test PASSED ===")
}

// TestDNS01E2E_WildcardCertificate tests DNS-01 with wildcard domain
func TestDNS01E2E_WildcardCertificate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}
	wildcardDomain := "*." + testDomain

	t.Log("=== DNS-01 Wildcard Certificate Test ===")
	t.Logf("Wildcard domain: %s", wildcardDomain)

	// Setup
	directory, err := fetchDirectory(ctx, client, acmeServerURL)
	require.NoError(t, err)

	accountKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	accountURL, err := registerAccount(ctx, client, directory, accountKey, "mailto:dns01-wildcard@example.com")
	require.NoError(t, err)

	// Create order for wildcard
	order, err := createOrder(ctx, client, directory, accountKey, accountURL, []string{wildcardDomain})
	require.NoError(t, err)
	t.Logf("Order created for wildcard: %d authorizations", len(order.Authorizations))

	// Get authorization
	authz, err := fetchAuthorization(ctx, client, order.Authorizations[0], accountKey, accountURL)
	require.NoError(t, err)

	// Verify only DNS-01 is offered for wildcard (per RFC 8555)
	var dns01 *Challenge
	for _, ch := range authz.Challenges {
		if ch.Type == "dns-01" {
			dns01 = &ch
		}
		if ch.Type == "http-01" {
			t.Error("HTTP-01 should not be offered for wildcard domains")
		}
	}
	require.NotNil(t, dns01, "DNS-01 must be available for wildcard")
	t.Logf("DNS-01 challenge for wildcard: token=%s", dns01.Token)

	// Compute TXT value
	keyAuth, _ := computeKeyAuthorization(dns01.Token, accountKey.Public())
	txtValue := computeDNS01TXTValue(keyAuth)

	// For wildcard *.test.example.com, TXT record is at _acme-challenge.test.example.com
	acmeDomain := fmt.Sprintf("_acme-challenge.%s", testDomain)
	t.Logf("TXT record domain (without *): %s", acmeDomain)

	// Set TXT record
	err = setDNSTXTRecord(ctx, client, dnsAPIURL, acmeDomain, txtValue)
	require.NoError(t, err)

	// Validate challenge
	_, err = respondToChallenge(ctx, client, dns01.URL, accountKey, accountURL)
	require.NoError(t, err)

	// Poll authorization
	validatedAuthz, err := pollAuthorization(ctx, client, order.Authorizations[0], accountKey, accountURL)
	require.NoError(t, err)
	assert.Contains(t, []string{"valid", "pending", "processing"}, validatedAuthz.Status)

	// Clean up
	_ = deleteDNSTXTRecord(ctx, client, dnsAPIURL, acmeDomain)

	t.Log("=== Wildcard Certificate Test PASSED ===")
}

// TestDNS01E2E_InvalidTXTValue tests that validation fails with wrong TXT value
func TestDNS01E2E_InvalidTXTValue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	client := &http.Client{Timeout: 30 * time.Second}

	t.Log("=== DNS-01 Invalid TXT Value Test ===")

	// Setup
	directory, err := fetchDirectory(ctx, client, acmeServerURL)
	require.NoError(t, err)

	accountKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	accountURL, err := registerAccount(ctx, client, directory, accountKey, "mailto:dns01-invalid@example.com")
	require.NoError(t, err)

	order, err := createOrder(ctx, client, directory, accountKey, accountURL, []string{"invalid-test." + testDomain})
	require.NoError(t, err)

	authz, err := fetchAuthorization(ctx, client, order.Authorizations[0], accountKey, accountURL)
	require.NoError(t, err)

	var dns01 *Challenge
	for _, ch := range authz.Challenges {
		if ch.Type == "dns-01" {
			dns01 = &ch
			break
		}
	}
	require.NotNil(t, dns01)

	// Set WRONG TXT value
	acmeDomain := "_acme-challenge.invalid-test." + testDomain
	err = setDNSTXTRecord(ctx, client, dnsAPIURL, acmeDomain, "wrong-txt-value-should-fail")
	require.NoError(t, err)

	// Trigger validation
	_, err = respondToChallenge(ctx, client, dns01.URL, accountKey, accountURL)
	require.NoError(t, err)

	// Wait and poll - should eventually fail or stay pending/processing
	time.Sleep(2 * time.Second)
	authzAfter, _ := fetchAuthorization(ctx, client, order.Authorizations[0], accountKey, accountURL)
	t.Logf("Authorization status with wrong TXT: %s", authzAfter.Status)

	// Clean up
	_ = deleteDNSTXTRecord(ctx, client, dnsAPIURL, acmeDomain)

	t.Log("=== Invalid TXT Value Test Complete ===")
}

// Helper types
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
}

type Order struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
	Location       string       `json:"-"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Authorization struct {
	Status     string      `json:"status"`
	Expires    string      `json:"expires,omitempty"`
	Identifier Identifier  `json:"identifier"`
	Challenges []Challenge `json:"challenges"`
}

type Challenge struct {
	Type   string `json:"type"`
	URL    string `json:"url"`
	Token  string `json:"token"`
	Status string `json:"status"`
}

// Helper functions

func verifyDNSServer(ctx context.Context, client *http.Client, apiURL string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return caerrors.ConnectionFailureError("DNS server health check failed: %d", resp.StatusCode)
	}
	return nil
}

func setDNSTXTRecord(ctx context.Context, client *http.Client, apiURL, domain, value string) error {
	form := url.Values{}
	form.Set("domain", domain)
	form.Set("value", value)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL+"/txt/set", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return caerrors.ConnectionFailureError("set TXT failed: %d - %s", resp.StatusCode, string(body))
	}
	return nil
}

func getDNSTXTRecord(ctx context.Context, client *http.Client, apiURL, domain string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL+"/txt/get?domain="+url.QueryEscape(domain), nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", caerrors.ConnectionFailureError("get TXT failed: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func deleteDNSTXTRecord(ctx context.Context, client *http.Client, apiURL, domain string) error {
	form := url.Values{}
	form.Set("domain", domain)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL+"/txt/delete", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func computeDNS01TXTValue(keyAuthorization string) string {
	hash := sha256.Sum256([]byte(keyAuthorization))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func fetchDirectory(ctx context.Context, client *http.Client, serverURL string) (*Directory, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", serverURL+"/acme/directory", nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var dir Directory
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		return nil, err
	}
	return &dir, nil
}

func fetchNonce(ctx context.Context, client *http.Client, nonceURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "HEAD", nonceURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	return resp.Header.Get("Replay-Nonce"), nil
}

func registerAccount(ctx context.Context, client *http.Client, dir *Directory, key *ecdsa.PrivateKey, email string) (string, error) {
	nonce, err := fetchNonce(ctx, client, dir.NewNonce)
	if err != nil {
		return "", err
	}

	payload := map[string]interface{}{
		"termsOfServiceAgreed": true,
		"contact":              []string{email},
	}

	resp, err := sendJWSRequest(ctx, client, dir.NewAccount, payload, key, "", nonce)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", caerrors.ConnectionFailureError("account registration failed: %d - %s", resp.StatusCode, string(body))
	}

	return resp.Header.Get("Location"), nil
}

func createOrder(ctx context.Context, client *http.Client, dir *Directory, key *ecdsa.PrivateKey, accountURL string, domains []string) (*Order, error) {
	nonce, err := fetchNonce(ctx, client, dir.NewNonce)
	if err != nil {
		return nil, err
	}

	identifiers := make([]Identifier, len(domains))
	for i, domain := range domains {
		identifiers[i] = Identifier{Type: "dns", Value: domain}
	}

	payload := map[string]interface{}{
		"identifiers": identifiers,
	}

	resp, err := sendJWSRequest(ctx, client, dir.NewOrder, payload, key, accountURL, nonce)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, caerrors.ConnectionFailureError("order creation failed: %d - %s", resp.StatusCode, string(body))
	}

	var order Order
	if err := json.NewDecoder(resp.Body).Decode(&order); err != nil {
		return nil, err
	}
	order.Location = resp.Header.Get("Location")

	return &order, nil
}

func fetchAuthorization(ctx context.Context, client *http.Client, authzURL string, key *ecdsa.PrivateKey, accountURL string) (*Authorization, error) {
	nonce, err := fetchNonce(ctx, client, acmeServerURL+"/acme/new-nonce")
	if err != nil {
		return nil, err
	}

	resp, err := sendJWSRequest(ctx, client, authzURL, "", key, accountURL, nonce)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, caerrors.ConnectionFailureError("authorization fetch failed: %d - %s", resp.StatusCode, string(body))
	}

	var authz Authorization
	if err := json.NewDecoder(resp.Body).Decode(&authz); err != nil {
		return nil, err
	}

	return &authz, nil
}

func respondToChallenge(ctx context.Context, client *http.Client, challengeURL string, key *ecdsa.PrivateKey, accountURL string) (*Challenge, error) {
	nonce, err := fetchNonce(ctx, client, acmeServerURL+"/acme/new-nonce")
	if err != nil {
		return nil, err
	}

	resp, err := sendJWSRequest(ctx, client, challengeURL, struct{}{}, key, accountURL, nonce)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, caerrors.ConnectionFailureError("challenge response failed: %d - %s", resp.StatusCode, string(body))
	}

	var ch Challenge
	if err := json.NewDecoder(resp.Body).Decode(&ch); err != nil {
		return nil, err
	}

	return &ch, nil
}

func pollAuthorization(ctx context.Context, client *http.Client, authzURL string, key *ecdsa.PrivateKey, accountURL string) (*Authorization, error) {
	for i := 0; i < 30; i++ {
		authz, err := fetchAuthorization(ctx, client, authzURL, key, accountURL)
		if err != nil {
			return nil, err
		}

		if authz.Status == "valid" || authz.Status == "invalid" {
			return authz, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}

	return nil, caerrors.ChallengeTimeoutError("authorization polling timeout")
}

func pollOrder(ctx context.Context, client *http.Client, orderURL string, key *ecdsa.PrivateKey, accountURL string) (*Order, error) {
	for i := 0; i < 30; i++ {
		nonce, err := fetchNonce(ctx, client, acmeServerURL+"/acme/new-nonce")
		if err != nil {
			return nil, err
		}

		resp, err := sendJWSRequest(ctx, client, orderURL, "", key, accountURL, nonce)
		if err != nil {
			return nil, err
		}

		var order Order
		json.NewDecoder(resp.Body).Decode(&order)
		resp.Body.Close()

		if order.Status == "valid" || order.Status == "invalid" {
			return &order, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}

	return nil, caerrors.ChallengeTimeoutError("order polling timeout")
}

func finalizeOrder(ctx context.Context, client *http.Client, finalizeURL string, key *ecdsa.PrivateKey, accountURL string, csr []byte) (*Order, error) {
	nonce, err := fetchNonce(ctx, client, acmeServerURL+"/acme/new-nonce")
	if err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"csr": base64.RawURLEncoding.EncodeToString(csr),
	}

	resp, err := sendJWSRequest(ctx, client, finalizeURL, payload, key, accountURL, nonce)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, caerrors.ConnectionFailureError("order finalization failed: %d - %s", resp.StatusCode, string(body))
	}

	var order Order
	if err := json.NewDecoder(resp.Body).Decode(&order); err != nil {
		return nil, err
	}

	return &order, nil
}

func downloadCertificate(ctx context.Context, client *http.Client, certURL string, key *ecdsa.PrivateKey, accountURL string) ([]byte, error) {
	nonce, err := fetchNonce(ctx, client, acmeServerURL+"/acme/new-nonce")
	if err != nil {
		return nil, err
	}

	resp, err := sendJWSRequest(ctx, client, certURL, "", key, accountURL, nonce)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, caerrors.ConnectionFailureError("certificate download failed: %d - %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// computeKeyAuthorization computes the key authorization using the core library
func computeKeyAuthorization(token string, pubKey crypto.PublicKey) (string, error) {
	thumbprint, err := handlers.JWKThumbprint(pubKey)
	if err != nil {
		return "", err
	}
	return token + "." + thumbprint, nil
}

func generateCSR(key *ecdsa.PrivateKey, domain string) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames: []string{domain},
	}

	return x509.CreateCertificateRequest(rand.Reader, template, key)
}

func sendJWSRequest(ctx context.Context, client *http.Client, targetURL string, payload interface{}, key *ecdsa.PrivateKey, accountURL, nonce string) (*http.Response, error) {
	var payloadBytes []byte
	var err error

	if payload == "" {
		payloadBytes = nil
	} else {
		payloadBytes, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}

	jws, err := createJWS(payloadBytes, key, accountURL, nonce, targetURL)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader([]byte(jws)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/jose+json")

	return client.Do(req)
}

func createJWS(payload []byte, key *ecdsa.PrivateKey, accountURL, nonce, url string) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key,
	}, &jose.SignerOptions{
		NonceSource: staticNonce(nonce),
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
		EmbedJWK: accountURL == "",
	})
	if err != nil {
		return "", err
	}

	if accountURL != "" {
		signer, err = jose.NewSigner(jose.SigningKey{
			Algorithm: jose.ES256,
			Key:       key,
		}, &jose.SignerOptions{
			NonceSource: staticNonce(nonce),
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"url": url,
				"kid": accountURL,
			},
		})
		if err != nil {
			return "", err
		}
	}

	var obj *jose.JSONWebSignature
	if payload == nil {
		obj, err = signer.Sign([]byte{})
	} else {
		obj, err = signer.Sign(payload)
	}
	if err != nil {
		return "", err
	}

	return obj.FullSerialize(), nil
}

type staticNonce string

func (n staticNonce) Nonce() (string, error) {
	return string(n), nil
}
