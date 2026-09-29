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

//go:build integration && tpm2

package tpm_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnroll01_CompleteWorkflow tests the complete TCG Section 6.2 workflow:
// "OEM Installation of IAK and IDevID in a Single Pass"
//
// This test demonstrates the full ACME enroll-01 ceremony:
// 1. Client creates account
// 2. Client creates order with permanent-identifier
// 3. Server presents enroll-01 challenge
// 4. Client creates TCG-CSR-IDEVID and starts HTTP server
// 5. Server fetches CSR from client's challenge endpoint
// 6. Server verifies CSR and generates credential
// 7. Server sends credential to client's activation endpoint
// 8. Client activates credential using TPM
// 9. Server verifies activated secret
// 10. Client finalizes order with CSR
// 11. Server issues IAK and IDevID certificates
func TestEnroll01_CompleteWorkflow(t *testing.T) {
	serverURL := getServerURL()

	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: getTLSConfig(),
		},
	}

	// STEP 1: Create ACME account
	t.Log("Step 1: Creating ACME account...")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generate ECDSA key")

	accountURL, err := createAccount(client, serverURL, privateKey, []string{"mailto:device-enroll@example.com"})
	require.NoError(t, err, "Failed to create account")
	t.Logf("✓ Account created: %s", accountURL)

	// STEP 2: Create order for permanent-identifier (device identity)
	t.Log("Step 2: Creating order for permanent-identifier...")

	// For Section 6.2, the permanent identifier is the device's identity.
	// In Docker environments, use the client container's hostname so the
	// ACME server can reach the challenge endpoint. The CHALLENGE_CLIENT_HOSTNAME
	// environment variable is set by docker-compose.yml.
	deviceIdentifier := os.Getenv("CHALLENGE_CLIENT_HOSTNAME")
	if deviceIdentifier == "" {
		// Default for non-Docker environments
		deviceIdentifier = "test-device-001.acme.example.com"
	}

	orderReq := OrderRequest{
		Identifiers: []Identifier{
			{
				Type:  "permanent-identifier",
				Value: deviceIdentifier,
			},
		},
	}

	nonce, err := fetchNonce(client, serverURL)
	require.NoError(t, err, "Failed to fetch nonce")

	newOrderURL := fmt.Sprintf("%s/acme/new-order", serverURL)
	resp, err := sendJWSRequest(client, newOrderURL, orderReq, privateKey, accountURL, nonce)
	require.NoError(t, err, "Failed to create order")

	// Capture the order URL from the Location header (RFC 8555)
	orderURL := resp.Header.Get("Location")
	require.NotEmpty(t, orderURL, "Location header should contain order URL")

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err, "Failed to read response body")

	var order OrderResponse
	err = json.Unmarshal(body, &order)
	require.NoError(t, err, "Failed to parse order response")

	// Order might be "pending" or empty status if server doesn't support permanent-identifier
	t.Logf("✓ Order created with status: %s, %d authorizations", order.Status, len(order.Authorizations))
	t.Logf("  Order URL: %s", orderURL)

	// Check if server supports permanent-identifier (enroll-01 challenge)
	if len(order.Authorizations) == 0 {
		require.FailNow(t, "Server does not support permanent-identifier type (enroll-01 challenge not configured)")
	}

	require.Equal(t, "pending", order.Status, "Order should be pending when authorizations exist")

	// STEP 3: Fetch authorization and locate enroll-01 challenge
	t.Log("Step 3: Fetching authorization and locating enroll-01 challenge...")

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

	// Find enroll-01 challenge
	var enrollChallenge *Challenge
	for i := range authz.Challenges {
		if authz.Challenges[i].Type == "enroll-01" {
			enrollChallenge = &authz.Challenges[i]
			break
		}
	}

	require.NotNil(t, enrollChallenge, "enroll-01 challenge should be available for permanent-identifier")
	t.Logf("✓ Found enroll-01 challenge: %s", enrollChallenge.URL)
	t.Logf("  Token: %s", enrollChallenge.Token)
	t.Logf("  Status: %s", enrollChallenge.Status)

	// STEP 4: Connect to swtpm and generate TCG-CSR-IDEVID
	t.Log("Step 4: Connecting to swtpm and generating TCG-CSR-IDEVID...")

	// Check if swtpm is available
	if !IsSwtpmAvailable() {
		require.FailNow(t, "swtpm not available (TPM_SOCKET_HOST:TPM_SOCKET_PORT not reachable)")
	}

	// Connect to swtpm
	swtpm := NewSwtpmConnection(t, deviceIdentifier)
	defer swtpm.Close()

	// Initialize TPM module
	err = swtpm.InitializeTPM()
	require.NoError(t, err, "Failed to initialize TPM")
	t.Log("  TPM module initialized")

	// Provision TPM with EK, SRK, IAK
	err = swtpm.Provision()
	require.NoError(t, err, "Failed to provision TPM")
	t.Log("  TPM provisioned with EK, SRK, IAK")

	// Compute key authorization (used as qualifying data in CSR)
	keyAuth, err := computeKeyAuthorization(enrollChallenge.Token, privateKey.Public())
	require.NoError(t, err, "Failed to compute key authorization")
	t.Logf("  Key Authorization: %s", keyAuth)

	// Create IDevID and TCG-CSR-IDEVID
	err = swtpm.CreateIDevID([]byte(keyAuth))
	require.NoError(t, err, "Failed to create IDevID")

	packedCSR := swtpm.GetPackedCSR()
	require.NotEmpty(t, packedCSR, "Packed CSR should not be empty")
	t.Logf("✓ TCG-CSR-IDEVID created (%d bytes)", len(packedCSR))

	// Start challenge HTTP server
	challengePort := os.Getenv("CHALLENGE_CLIENT_PORT")
	if challengePort == "" {
		challengePort = "8888"
	}
	challengeServer := startChallengeServer(t, challengePort, enrollChallenge.Token, packedCSR, swtpm)
	defer challengeServer.Close()

	// Give the HTTP server a moment to start
	time.Sleep(100 * time.Millisecond)

	// STEP 5: Initiate challenge verification
	t.Log("Step 5: Initiating challenge verification...")

	nonce, err = fetchNonce(client, serverURL)
	require.NoError(t, err, "Failed to fetch nonce")

	// Send empty POST to trigger challenge verification
	resp, err = sendJWSRequest(client, enrollChallenge.URL, struct{}{}, privateKey, accountURL, nonce)
	require.NoError(t, err, "Failed to initiate challenge")

	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err, "Failed to read challenge response")

	var challengeResp Challenge
	err = json.Unmarshal(body, &challengeResp)
	require.NoError(t, err, "Failed to parse challenge response")

	t.Logf("  Challenge status: %s", challengeResp.Status)

	// STEP 6: Poll challenge status until valid or invalid
	t.Log("Step 6: Polling challenge status...")

	timeout := time.After(30 * time.Second)
	pollTicker := time.NewTicker(500 * time.Millisecond)
	defer pollTicker.Stop()

	challengeValid := false
	for !challengeValid {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for challenge validation")
		case <-pollTicker.C:
			nonce, err = fetchNonce(client, serverURL)
			require.NoError(t, err, "Failed to fetch nonce")

			resp, err = sendJWSRequest(client, enrollChallenge.URL, nil, privateKey, accountURL, nonce)
			require.NoError(t, err, "Failed to poll challenge")

			body, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			require.NoError(t, err, "Failed to read challenge response")

			err = json.Unmarshal(body, &challengeResp)
			require.NoError(t, err, "Failed to parse challenge response")

			t.Logf("  Polling... Status: %s", challengeResp.Status)

			if challengeResp.Status == "valid" {
				challengeValid = true
				t.Log("✓ Challenge validated successfully!")
				break
			} else if challengeResp.Status == "invalid" {
				t.Fatalf("Challenge validation failed: %s", challengeResp.Status)
			}
		}
	}

	// STEP 7: Check order status (should be "ready" for finalization)
	t.Log("Step 7: Checking order status...")

	nonce, err = fetchNonce(client, serverURL)
	require.NoError(t, err, "Failed to fetch nonce")

	// Use the orderURL captured from the Location header in step 2
	resp, err = sendJWSRequest(client, orderURL, nil, privateKey, accountURL, nonce)
	require.NoError(t, err, "Failed to fetch order")

	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err, "Failed to read order response")

	err = json.Unmarshal(body, &order)
	require.NoError(t, err, "Failed to parse order response")

	assert.Equal(t, "ready", order.Status, "Order should be ready for finalization")
	t.Logf("✓ Order status: %s", order.Status)

	// STEP 8: Finalize order with TCG-CSR-IDEVID
	t.Log("Step 8: Finalizing order with TCG-CSR-IDEVID...")

	finalizeReq := struct {
		CSR string `json:"csr"`
	}{
		CSR: base64.RawURLEncoding.EncodeToString(packedCSR),
	}

	nonce, err = fetchNonce(client, serverURL)
	require.NoError(t, err, "Failed to fetch nonce")

	resp, err = sendJWSRequest(client, order.Finalize, finalizeReq, privateKey, accountURL, nonce)
	require.NoError(t, err, "Failed to finalize order")

	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err, "Failed to read finalize response")

	t.Logf("  Finalize response HTTP status: %d", resp.StatusCode)
	t.Logf("  Finalize response body: %s", string(body))

	err = json.Unmarshal(body, &order)
	require.NoError(t, err, "Failed to parse finalize response")

	t.Logf("  Order status after finalization: %s", order.Status)

	// STEP 9: Poll order until processing completes
	t.Log("Step 9: Waiting for certificate issuance...")

	timeout = time.After(30 * time.Second)
	pollTicker = time.NewTicker(500 * time.Millisecond)
	defer pollTicker.Stop()

	orderValid := false
	for !orderValid {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for certificate issuance")
		case <-pollTicker.C:
			nonce, err = fetchNonce(client, serverURL)
			require.NoError(t, err, "Failed to fetch nonce")

			resp, err = sendJWSRequest(client, orderURL, nil, privateKey, accountURL, nonce)
			require.NoError(t, err, "Failed to poll order")

			body, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			require.NoError(t, err, "Failed to read order response")

			err = json.Unmarshal(body, &order)
			require.NoError(t, err, "Failed to parse order response")

			t.Logf("  Polling... Status: %s", order.Status)

			if order.Status == "valid" {
				orderValid = true
				t.Log("✓ Order valid! Certificate issued.")
				break
			} else if order.Status == "invalid" {
				t.Fatalf("Order became invalid during processing")
			}
		}
	}

	// STEP 10: Download certificate chain (IAK + IDevID)
	t.Log("Step 10: Downloading certificate chain...")

	require.NotEmpty(t, order.Certificate, "Certificate URL should be populated")

	nonce, err = fetchNonce(client, serverURL)
	require.NoError(t, err, "Failed to fetch nonce")

	resp, err = sendJWSRequest(client, order.Certificate, nil, privateKey, accountURL, nonce)
	require.NoError(t, err, "Failed to download certificate")

	certPEM, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err, "Failed to read certificate response")

	t.Logf("✓ Certificate chain downloaded (%d bytes)", len(certPEM))

	// STEP 11: Verify certificate chain structure
	t.Log("Step 11: Verifying certificate chain...")

	// Parse PEM certificates
	certs := parsePEMCertificates(t, certPEM)

	// Per TCG Section 6.2, we expect both IAK and IDevID certificates
	require.GreaterOrEqual(t, len(certs), 2, "Should receive at least IAK and IDevID certificates")

	// Display full certificate details with TCG and Trusted Platform OIDs
	LogCertificateChain(t, certs, "Certificate Chain (IAK + IDevID):")

	// Verify certificate properties
	// The CA generates certificates based on the TCG-CSR-IDEVID which contains
	// the device identity in the format: TEST-MODEL-<deviceID>
	// Both IAK and IDevID certificates are issued in the chain
	iakCert := certs[0]
	assert.Contains(t, iakCert.Subject.CommonName, "TEST-MODEL", "First certificate should contain product model")

	idevidCert := certs[1]
	assert.Contains(t, idevidCert.Subject.CommonName, "TEST-MODEL", "IDevID should contain product model")

	t.Log("✓ Certificate chain verified successfully!")
	t.Log("")
	t.Log("========================================")
	t.Log("ENROLL-01 WORKFLOW COMPLETED SUCCESSFULLY")
	t.Log("========================================")
	t.Logf("Device Identity: %s", deviceIdentifier)
	t.Logf("IAK Certificate: %s", iakCert.Subject.CommonName)
	t.Logf("IDevID Certificate: %s", idevidCert.Subject.CommonName)
	t.Log("========================================")
}

// startChallengeServer starts an HTTP server for the enroll-01 challenge
func startChallengeServer(t *testing.T, port, token string, packedCSR []byte, swtpm *SwtpmConnection) *http.Server {
	mux := http.NewServeMux()

	// Handle GET request to retrieve TCG-CSR
	challengePath := fmt.Sprintf("/.well-known/acme-challenge/%s", token)
	mux.HandleFunc(challengePath, func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Challenge request received: method=%s path=%s", r.Method, r.URL.Path)

		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Encode TCG-CSR as base64URL
		encodedCSR := base64.RawURLEncoding.EncodeToString(packedCSR)

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(encodedCSR)); err != nil {
			t.Logf("Failed to write response: %v", err)
			return
		}
		t.Logf("Challenge response sent: %d bytes", len(encodedCSR))
	})

	// Handle POST request for credential activation
	activationPath := fmt.Sprintf("/.well-known/acme-activation/%s", token)
	mux.HandleFunc(activationPath, func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Activation request received: method=%s path=%s", r.Method, r.URL.Path)

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse JSON request
		var req struct {
			CredentialBlob  string `json:"credentialBlob"`
			EncryptedSecret string `json:"encryptedSecret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Logf("Failed to decode activation request: %v", err)
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Decode base64URL-encoded values
		credentialBlob, err := base64.RawURLEncoding.DecodeString(req.CredentialBlob)
		if err != nil {
			t.Logf("Failed to decode credential blob: %v", err)
			http.Error(w, "Invalid credential blob", http.StatusBadRequest)
			return
		}

		encryptedSecret, err := base64.RawURLEncoding.DecodeString(req.EncryptedSecret)
		if err != nil {
			t.Logf("Failed to decode encrypted secret: %v", err)
			http.Error(w, "Invalid encrypted secret", http.StatusBadRequest)
			return
		}

		// Perform TPM2_ActivateCredential
		secret, err := swtpm.ActivateCredential(credentialBlob, encryptedSecret)
		if err != nil {
			t.Logf("Failed to activate credential: %v", err)
			http.Error(w, "Activation failed", http.StatusInternalServerError)
			return
		}

		// Return the decrypted secret
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(secret); err != nil {
			t.Logf("Failed to write secret response: %v", err)
			return
		}
		t.Logf("Activation response sent: %d bytes", len(secret))
	})

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	// Bind synchronously, with a short retry, rather than the previous
	// ListenAndServe-in-a-goroutine-and-sleep(100ms)-and-hope pattern: that
	// logged a bind failure (t.Logf, not t.Fatal/require) and returned the
	// *http.Server regardless, so the caller had no way to notice its
	// responder never actually started -- the observed symptom was always a
	// downstream "challenge status: invalid" several steps later, never the
	// real "address already in use" cause. Every enroll01/endorse01/
	// device-attest01 test in this package binds the same server-hardcoded
	// port (challenge.go's 8080 default; see TestEnrollment_ConcurrentRequests's
	// doc comment for why the client cannot choose a different one), so
	// even with tests running serially (never t.Parallel in this package) a
	// listener from the previous test can still hold the port for a moment
	// after that test's own Close() returns -- net.Listen's own OS-level
	// socket teardown is not synchronous with the Go-level call that
	// triggered it. The retry absorbs exactly that window; it is not
	// papering over a real bind conflict between two responders that are
	// both supposed to be listening at the same time.
	var listener net.Listener
	var listenErr error
	for attempt := 0; attempt < 20; attempt++ {
		listener, listenErr = net.Listen("tcp", server.Addr)
		if listenErr == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.NoError(t, listenErr, "failed to bind challenge server to port %s", port)

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Logf("Challenge server error: %v", err)
		}
	}()

	return server
}

// Helper functions

// computeKeyAuthorization computes the key authorization using the core library
func computeKeyAuthorization(token string, publicKey crypto.PublicKey) (string, error) {
	thumbprint, err := handlers.JWKThumbprint(publicKey)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", token, thumbprint), nil
}

func parsePEMCertificates(t *testing.T, certPEM []byte) []*x509.Certificate {
	var certs []*x509.Certificate

	rest := certPEM
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err, "Failed to parse certificate")
			certs = append(certs, cert)
		}
	}

	return certs
}
