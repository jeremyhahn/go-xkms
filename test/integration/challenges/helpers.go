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

//go:build integration

package challenges

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
)

// Challenge test helper functions for Docker integration tests
// These tests connect to an ACME server running in Docker

// Identifier represents an ACME identifier
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// OrderRequest represents an ACME order creation request
type OrderRequest struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   string       `json:"notBefore,omitempty"`
	NotAfter    string       `json:"notAfter,omitempty"`
}

// OrderResponse represents an ACME order response
type OrderResponse struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
}

// AuthorizationResponse represents an ACME authorization response
type AuthorizationResponse struct {
	Status     string     `json:"status"`
	Expires    string     `json:"expires,omitempty"`
	Identifier Identifier `json:"identifier"`
	Challenges []Info     `json:"challenges"`
}

// Info represents a single ACME challenge
type Info struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	URL    string `json:"url"`
	Token  string `json:"token"`
}

// AccountRequest represents an ACME account creation request
type AccountRequest struct {
	Contact              []string `json:"contact,omitempty"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	OnlyReturnExisting   bool     `json:"onlyReturnExisting,omitempty"`
}

// GetServerURL returns the ACME server URL from environment
func GetServerURL() string {
	url := os.Getenv("ACME_SERVER_URL")
	if url == "" {
		return "http://acme-server:8080"
	}
	return url
}

// GetTLSConfig returns TLS config for HTTPS connections.
// Uses ACME_CA_CERT environment variable for proper certificate verification.
func GetTLSConfig() *tls.Config {
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
	// For integration tests with self-signed certs, allow InsecureSkipVerify
	if os.Getenv("TRUSTED_CA_TLS_INSECURE") == "true" {
		return &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
}

// CreateHTTPClient creates an HTTP client for challenge tests
func CreateHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: GetTLSConfig(),
		},
	}
}

// FetchNonce fetches a new nonce from the ACME server
func FetchNonce(client *http.Client, serverURL string) (string, error) {
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

// staticNonceSource implements jose.NonceSource
type staticNonceSource string

func (s staticNonceSource) Nonce() (string, error) {
	return string(s), nil
}

// CreateJWS creates a JWS-signed request for the ACME server
func CreateJWS(payload interface{}, privateKey crypto.Signer, keyID, nonce, url string) (string, error) {
	var alg jose.SignatureAlgorithm

	switch privateKey.(type) {
	case *ecdsa.PrivateKey:
		alg = jose.ES256
	default:
		return "", caerrors.MalformedError("unsupported key type: %T", privateKey)
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

// SendJWSRequest sends a JWS-signed request to the ACME server
func SendJWSRequest(client *http.Client, url string, payload interface{}, privateKey crypto.Signer, keyID, nonce string) (*http.Response, error) {
	jws, err := CreateJWS(payload, privateKey, keyID, nonce, url)
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

// CreateAccount creates an ACME account on the server
func CreateAccount(client *http.Client, serverURL string, privateKey crypto.Signer, contacts []string) (string, error) {
	nonce, err := FetchNonce(client, serverURL)
	if err != nil {
		return "", err
	}

	accountReq := AccountRequest{
		Contact:              contacts,
		TermsOfServiceAgreed: true,
	}

	newAccountURL := fmt.Sprintf("%s/acme/new-account", serverURL)
	resp, err := SendJWSRequest(client, newAccountURL, accountReq, privateKey, "", nonce)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", caerrors.InternalServerError("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	accountURL := resp.Header.Get("Location")
	if accountURL == "" {
		return "", caerrors.MalformedError("no Location header in response (status: %d, body: %s)", resp.StatusCode, string(body))
	}

	return accountURL, nil
}

// CreateOrder creates an order on the ACME server
func CreateOrder(client *http.Client, serverURL string, privateKey crypto.Signer, accountURL string, identifiers []Identifier) (*OrderResponse, error) {
	nonce, err := FetchNonce(client, serverURL)
	if err != nil {
		return nil, err
	}

	orderReq := OrderRequest{
		Identifiers: identifiers,
	}

	newOrderURL := fmt.Sprintf("%s/acme/new-order", serverURL)
	resp, err := SendJWSRequest(client, newOrderURL, orderReq, privateKey, accountURL, nonce)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, caerrors.InternalServerError("unexpected status code %d: %s", resp.StatusCode, string(body))
	}

	var order OrderResponse
	if err := json.Unmarshal(body, &order); err != nil {
		return nil, err
	}

	return &order, nil
}

// FetchAuthorization fetches authorization details from the server
func FetchAuthorization(client *http.Client, authzURL string, privateKey crypto.Signer, accountURL, serverURL string) (*AuthorizationResponse, error) {
	nonce, err := FetchNonce(client, serverURL)
	if err != nil {
		return nil, err
	}

	resp, err := SendJWSRequest(client, authzURL, nil, privateKey, accountURL, nonce)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var authz AuthorizationResponse
	if err := json.Unmarshal(body, &authz); err != nil {
		return nil, err
	}

	return &authz, nil
}

// FindByType finds a specific challenge type in the authorization
func FindByType(authz *AuthorizationResponse, challengeType string) *Info {
	for i := range authz.Challenges {
		if authz.Challenges[i].Type == challengeType {
			return &authz.Challenges[i]
		}
	}
	return nil
}

// ComputeKeyAuthorization computes the key authorization for a challenge
// using the core library's JWKThumbprint implementation
func ComputeKeyAuthorization(token string, publicKey crypto.PublicKey) (string, error) {
	thumbprint, err := handlers.JWKThumbprint(publicKey)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", token, thumbprint), nil
}

// GenerateAccountKey generates a new ECDSA key for account
func GenerateAccountKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// InitiateVerification sends the challenge response to start verification
func InitiateVerification(client *http.Client, challengeURL string, privateKey crypto.Signer, accountURL, serverURL string) (*Info, error) {
	nonce, err := FetchNonce(client, serverURL)
	if err != nil {
		return nil, err
	}

	// Send empty object to initiate challenge
	resp, err := SendJWSRequest(client, challengeURL, struct{}{}, privateKey, accountURL, nonce)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var challenge Info
	if err := json.Unmarshal(body, &challenge); err != nil {
		return nil, err
	}

	return &challenge, nil
}

// PollStatus polls the challenge status until valid/invalid or timeout
func PollStatus(client *http.Client, challengeURL string, privateKey crypto.Signer, accountURL, serverURL string, timeout time.Duration) (string, error) {
	deadline := time.After(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			return "", caerrors.InternalServerError("timeout waiting for challenge status")
		case <-ticker.C:
			nonce, err := FetchNonce(client, serverURL)
			if err != nil {
				return "", err
			}

			resp, err := SendJWSRequest(client, challengeURL, nil, privateKey, accountURL, nonce)
			if err != nil {
				return "", err
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return "", err
			}

			var challenge Info
			if err := json.Unmarshal(body, &challenge); err != nil {
				return "", err
			}

			if challenge.Status == "valid" || challenge.Status == "invalid" {
				return challenge.Status, nil
			}
		}
	}
}
