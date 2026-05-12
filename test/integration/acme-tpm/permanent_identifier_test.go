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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPermanentIdentifier_AllTPMChallenges verifies that when a client requests
// an order with a permanent-identifier, the server correctly offers all three
// TPM-based challenges: enroll-01, endorse-01, and device-attest-01.
//
// This test validates RFC 8555 extension support for TPM device enrollment.
func TestPermanentIdentifier_AllTPMChallenges(t *testing.T) {
	serverURL := getServerURL()

	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: getTLSConfig(),
		},
	}

	// Create ACME account
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generate ECDSA key")

	accountURL, err := createAccount(client, serverURL, privateKey, []string{"mailto:tpm-test@example.com"})
	require.NoError(t, err, "Failed to create account")
	t.Logf("Account created: %s", accountURL)

	// Create order with permanent-identifier
	deviceIdentifier := "tpm-device-001.test.local"
	orderReq := OrderRequest{
		Identifiers: []Identifier{
			{Type: "permanent-identifier", Value: deviceIdentifier},
		},
	}

	nonce, err := fetchNonce(client, serverURL)
	require.NoError(t, err, "Failed to fetch nonce")

	newOrderURL := fmt.Sprintf("%s/acme/new-order", serverURL)
	resp, err := sendJWSRequest(client, newOrderURL, orderReq, privateKey, accountURL, nonce)
	require.NoError(t, err, "Failed to create order")

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err, "Failed to read response body")

	var order OrderResponse
	err = json.Unmarshal(body, &order)
	require.NoError(t, err, "Failed to parse order response")

	t.Logf("Order status: %s, authorizations: %d", order.Status, len(order.Authorizations))

	// Check if server supports permanent-identifier
	if len(order.Authorizations) == 0 {
		require.FailNow(t, "Server does not support permanent-identifier type - TPM challenges not configured")
	}

	assert.Equal(t, "pending", order.Status, "Order should be pending")
	require.NotEmpty(t, order.Authorizations, "Order should have authorizations")

	// Fetch authorization
	authzURL := order.Authorizations[0]
	nonce, err = fetchNonce(client, serverURL)
	require.NoError(t, err, "Failed to fetch nonce")

	resp, err = sendJWSRequest(client, authzURL, nil, privateKey, accountURL, nonce)
	require.NoError(t, err, "Failed to fetch authorization")

	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err, "Failed to read authorization response")

	var authz AuthorizationResponse
	err = json.Unmarshal(body, &authz)
	require.NoError(t, err, "Failed to parse authorization response")

	t.Logf("Authorization has %d challenges", len(authz.Challenges))

	// Map challenges by type for verification
	challengesByType := make(map[string]*Challenge)
	for i := range authz.Challenges {
		challengesByType[authz.Challenges[i].Type] = &authz.Challenges[i]
		t.Logf("  Challenge type: %s, status: %s", authz.Challenges[i].Type, authz.Challenges[i].Status)
	}

	// Verify all three TPM challenges are offered
	t.Run("enroll-01 challenge available", func(t *testing.T) {
		challenge, ok := challengesByType["enroll-01"]
		assert.True(t, ok, "enroll-01 challenge should be available for permanent-identifier")
		if ok {
			assert.Equal(t, "pending", challenge.Status, "enroll-01 challenge should be pending")
			assert.NotEmpty(t, challenge.URL, "enroll-01 challenge should have URL")
			assert.NotEmpty(t, challenge.Token, "enroll-01 challenge should have token")
			t.Logf("enroll-01 challenge URL: %s", challenge.URL)
		}
	})

	t.Run("endorse-01 challenge available", func(t *testing.T) {
		challenge, ok := challengesByType["endorse-01"]
		assert.True(t, ok, "endorse-01 challenge should be available for permanent-identifier")
		if ok {
			assert.Equal(t, "pending", challenge.Status, "endorse-01 challenge should be pending")
			assert.NotEmpty(t, challenge.URL, "endorse-01 challenge should have URL")
			assert.NotEmpty(t, challenge.Token, "endorse-01 challenge should have token")
			t.Logf("endorse-01 challenge URL: %s", challenge.URL)
		}
	})

	t.Run("device-attest-01 challenge available", func(t *testing.T) {
		challenge, ok := challengesByType["device-attest-01"]
		assert.True(t, ok, "device-attest-01 challenge should be available for permanent-identifier")
		if ok {
			assert.Equal(t, "pending", challenge.Status, "device-attest-01 challenge should be pending")
			assert.NotEmpty(t, challenge.URL, "device-attest-01 challenge should have URL")
			assert.NotEmpty(t, challenge.Token, "device-attest-01 challenge should have token")
			t.Logf("device-attest-01 challenge URL: %s", challenge.URL)
		}
	})

	// Verify DNS-01 and HTTP-01 are NOT offered for permanent-identifier
	t.Run("http-01 challenge not offered for permanent-identifier", func(t *testing.T) {
		_, ok := challengesByType["http-01"]
		assert.False(t, ok, "http-01 challenge should NOT be available for permanent-identifier")
	})

	t.Run("dns-01 challenge not offered for permanent-identifier", func(t *testing.T) {
		_, ok := challengesByType["dns-01"]
		assert.False(t, ok, "dns-01 challenge should NOT be available for permanent-identifier")
	})
}

// TestEnroll01_ChallengeValidation tests the enroll-01 challenge verification
// by initiating the challenge and verifying it transitions through proper states.
func TestEnroll01_ChallengeValidation(t *testing.T) {
	serverURL := getServerURL()

	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: getTLSConfig(),
		},
	}

	// Create account and order
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generate ECDSA key")

	accountURL, err := createAccount(client, serverURL, privateKey, []string{"mailto:enroll01-test@example.com"})
	require.NoError(t, err, "Failed to create account")

	deviceIdentifier := "enroll-device-001.test.local"
	orderReq := OrderRequest{
		Identifiers: []Identifier{
			{Type: "permanent-identifier", Value: deviceIdentifier},
		},
	}

	nonce, err := fetchNonce(client, serverURL)
	require.NoError(t, err, "Failed to fetch nonce")

	newOrderURL := fmt.Sprintf("%s/acme/new-order", serverURL)
	resp, err := sendJWSRequest(client, newOrderURL, orderReq, privateKey, accountURL, nonce)
	require.NoError(t, err, "Failed to create order")

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var order OrderResponse
	json.Unmarshal(body, &order)

	if len(order.Authorizations) == 0 {
		require.FailNow(t, "Server does not support permanent-identifier type")
	}

	// Fetch authorization and find enroll-01 challenge
	authzURL := order.Authorizations[0]
	nonce, _ = fetchNonce(client, serverURL)

	resp, _ = sendJWSRequest(client, authzURL, nil, privateKey, accountURL, nonce)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	var authz AuthorizationResponse
	json.Unmarshal(body, &authz)

	var enrollChallenge *Challenge
	for i := range authz.Challenges {
		if authz.Challenges[i].Type == "enroll-01" {
			enrollChallenge = &authz.Challenges[i]
			break
		}
	}

	require.NotNil(t, enrollChallenge, "enroll-01 challenge should be available")

	// Initiate challenge verification
	nonce, _ = fetchNonce(client, serverURL)
	resp, err = sendJWSRequest(client, enrollChallenge.URL, struct{}{}, privateKey, accountURL, nonce)
	require.NoError(t, err, "Failed to initiate challenge")

	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	var challengeResp Challenge
	json.Unmarshal(body, &challengeResp)

	// Since we have a mock verifier that always succeeds, challenge should be valid
	// or processing (depending on async behavior)
	t.Logf("Challenge status after initiation: %s", challengeResp.Status)
	assert.Contains(t, []string{"pending", "processing", "valid"}, challengeResp.Status,
		"Challenge should be in a valid state after initiation")
}

// TestEndorse01_ChallengeValidation tests the endorse-01 challenge verification.
func TestEndorse01_ChallengeValidation(t *testing.T) {
	serverURL := getServerURL()

	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: getTLSConfig(),
		},
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generate ECDSA key")

	accountURL, err := createAccount(client, serverURL, privateKey, []string{"mailto:endorse01-test@example.com"})
	require.NoError(t, err, "Failed to create account")

	orderReq := OrderRequest{
		Identifiers: []Identifier{
			{Type: "permanent-identifier", Value: "endorse-device-001.test.local"},
		},
	}

	nonce, _ := fetchNonce(client, serverURL)
	newOrderURL := fmt.Sprintf("%s/acme/new-order", serverURL)
	resp, _ := sendJWSRequest(client, newOrderURL, orderReq, privateKey, accountURL, nonce)

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var order OrderResponse
	json.Unmarshal(body, &order)

	if len(order.Authorizations) == 0 {
		require.FailNow(t, "Server does not support permanent-identifier type")
	}

	authzURL := order.Authorizations[0]
	nonce, _ = fetchNonce(client, serverURL)
	resp, _ = sendJWSRequest(client, authzURL, nil, privateKey, accountURL, nonce)

	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	var authz AuthorizationResponse
	json.Unmarshal(body, &authz)

	var endorseChallenge *Challenge
	for i := range authz.Challenges {
		if authz.Challenges[i].Type == "endorse-01" {
			endorseChallenge = &authz.Challenges[i]
			break
		}
	}

	require.NotNil(t, endorseChallenge, "endorse-01 challenge should be available")

	nonce, _ = fetchNonce(client, serverURL)
	resp, err = sendJWSRequest(client, endorseChallenge.URL, struct{}{}, privateKey, accountURL, nonce)
	require.NoError(t, err, "Failed to initiate endorse-01 challenge")

	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	var challengeResp Challenge
	json.Unmarshal(body, &challengeResp)

	t.Logf("endorse-01 challenge status after initiation: %s", challengeResp.Status)
	assert.Contains(t, []string{"pending", "processing", "valid"}, challengeResp.Status,
		"endorse-01 challenge should be in a valid state")
}

// TestDeviceAttest01_ChallengeValidation tests the device-attest-01 challenge verification.
func TestDeviceAttest01_ChallengeValidation(t *testing.T) {
	serverURL := getServerURL()

	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: getTLSConfig(),
		},
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generate ECDSA key")

	accountURL, err := createAccount(client, serverURL, privateKey, []string{"mailto:deviceattest01-test@example.com"})
	require.NoError(t, err, "Failed to create account")

	orderReq := OrderRequest{
		Identifiers: []Identifier{
			{Type: "permanent-identifier", Value: "attest-device-001.test.local"},
		},
	}

	nonce, _ := fetchNonce(client, serverURL)
	newOrderURL := fmt.Sprintf("%s/acme/new-order", serverURL)
	resp, _ := sendJWSRequest(client, newOrderURL, orderReq, privateKey, accountURL, nonce)

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var order OrderResponse
	json.Unmarshal(body, &order)

	if len(order.Authorizations) == 0 {
		require.FailNow(t, "Server does not support permanent-identifier type")
	}

	authzURL := order.Authorizations[0]
	nonce, _ = fetchNonce(client, serverURL)
	resp, _ = sendJWSRequest(client, authzURL, nil, privateKey, accountURL, nonce)

	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	var authz AuthorizationResponse
	json.Unmarshal(body, &authz)

	var attestChallenge *Challenge
	for i := range authz.Challenges {
		if authz.Challenges[i].Type == "device-attest-01" {
			attestChallenge = &authz.Challenges[i]
			break
		}
	}

	require.NotNil(t, attestChallenge, "device-attest-01 challenge should be available")

	nonce, _ = fetchNonce(client, serverURL)
	resp, err = sendJWSRequest(client, attestChallenge.URL, struct{}{}, privateKey, accountURL, nonce)
	require.NoError(t, err, "Failed to initiate device-attest-01 challenge")

	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	var challengeResp Challenge
	json.Unmarshal(body, &challengeResp)

	t.Logf("device-attest-01 challenge status after initiation: %s", challengeResp.Status)
	assert.Contains(t, []string{"pending", "processing", "valid"}, challengeResp.Status,
		"device-attest-01 challenge should be in a valid state")
}
