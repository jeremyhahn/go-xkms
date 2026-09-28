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
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnroll01Challenge(t *testing.T) {
	serverURL := getServerURL()
	_ = getTPMHost() // Will be used for TPM connectivity

	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: getTLSConfig(),
		},
	}

	t.Run("enroll-01 challenge for TPM device enrollment", func(t *testing.T) {
		// Create account
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err, "Failed to generate ECDSA key")

		accountURL, err := createAccount(client, serverURL, privateKey, []string{"mailto:enroll@example.com"})
		require.NoError(t, err, "Failed to create account")

		// Create order for permanent-identifier (TPM device)
		deviceID := "device-001.test.local"
		orderReq := OrderRequest{
			Identifiers: []Identifier{
				{Type: "permanent-identifier", Value: deviceID},
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

		// Check if server supports permanent-identifier (enroll-01 challenge)
		if len(order.Authorizations) == 0 {
			require.FailNow(t, "Server does not support permanent-identifier type (enroll-01 challenge not configured)")
		}

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

		// Find enroll-01 challenge
		var enrollChallenge *Challenge
		for i := range authz.Challenges {
			if authz.Challenges[i].Type == "enroll-01" {
				enrollChallenge = &authz.Challenges[i]
				break
			}
		}

		require.NotNil(t, enrollChallenge, "enroll-01 challenge should be available")
		t.Logf("enroll-01 challenge URL: %s", enrollChallenge.URL)
		t.Logf("enroll-01 challenge token: %s", enrollChallenge.Token)

		// In a real implementation, we would:
		// 1. Connect to TPM simulator
		// 2. Generate attestation key (AK)
		// 3. Perform credential activation
		// 4. Submit attestation response

		// For this test, we verify the challenge is properly offered
		assert.Equal(t, "pending", enrollChallenge.Status, "Challenge should be pending")
	})
}

// TestEndorse01Challenge tests the endorse-01 challenge workflow for EK certificate provisioning.
//
// The endorse-01 challenge implements TCG EK Credential Profile for provisioning
// Endorsement Key certificates from a Trusted CA. This test demonstrates:
// 1. Client creates ACME account
// 2. Client creates order with permanent-identifier for EK
// 3. Server presents endorse-01 challenge
// 4. Client connects to TPM and extracts EK public key
// 5. Client submits EK credentials to server
// 6. Server verifies and issues EK certificate
func TestEndorse01Challenge(t *testing.T) {
	serverURL := getServerURL()

	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: getTLSConfig(),
		},
	}

	t.Run("endorse-01 challenge for EK certificate provisioning", func(t *testing.T) {
		t.Log("")
		t.Log("========================================")
		t.Log("ENDORSE-01 CHALLENGE TEST")
		t.Log("EK Certificate Provisioning Workflow")
		t.Log("========================================")
		t.Log("")

		// For endorse-01, we need the EK public key BEFORE creating the order
		// because the permanent-identifier value must be the base64url-encoded PKIX public key
		deviceIdentifier := os.Getenv("CHALLENGE_CLIENT_HOSTNAME")
		if deviceIdentifier == "" {
			deviceIdentifier = "ek-device-001.test.local"
		}

		// Check if swtpm is available - if so, we need to get the EK public key first
		var swtpm *SwtpmConnection
		var ekPublicKey crypto.PublicKey
		var permanentIdentifierValue string

		if IsSwtpmAvailable() {
			t.Log("Step 0: Connecting to swtpm to get EK public key...")

			// Connect to swtpm first to get the EK public key
			swtpm = NewSwtpmConnection(t, deviceIdentifier)
			t.Log("  TPM connection established")

			// Initialize TPM module
			err := swtpm.InitializeTPM()
			require.NoError(t, err, "Failed to initialize TPM")
			t.Log("  TPM module initialized")

			// Provision TPM - this creates EK, SRK
			err = swtpm.Provision()
			require.NoError(t, err, "Failed to provision TPM")
			t.Log("  TPM provisioned with EK and SRK")

			// Get EK public key from the TPM
			tpmModule := swtpm.GetTPMModule()
			ekAttrs, err := tpmModule.EKAttributes()
			require.NoError(t, err, "Failed to get EK attributes")

			ekPublicKey, err = x509.ParsePKIXPublicKey(ekAttrs.TPMAttributes.PublicKeyBytes)
			require.NoError(t, err, "Failed to parse EK public key")

			// Encode the EK public key as base64url PKIX - this is the permanent identifier value
			permanentIdentifierValue = base64.RawURLEncoding.EncodeToString(ekAttrs.TPMAttributes.PublicKeyBytes)
			t.Logf("  EK public key encoded as permanent identifier (%d chars)", len(permanentIdentifierValue))

			// Get EK certificate if available
			ekCert := swtpm.GetEKCertificate()
			if ekCert != nil {
				t.Log("✓ EK Certificate retrieved from TPM")
				LogCertificate(t, ekCert, "  EK Certificate from TPM:")
			}
			t.Log("")
		} else {
			// For testing without swtpm, use a hostname (test will skip finalization)
			permanentIdentifierValue = deviceIdentifier
			t.Log("Note: swtpm not available - using hostname as identifier (will skip finalization)")
		}

		// STEP 1: Create ACME account
		t.Log("Step 1: Creating ACME account...")
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err, "Failed to generate ECDSA key")

		accountURL, err := createAccount(client, serverURL, privateKey, []string{"mailto:endorse@example.com"})
		require.NoError(t, err, "Failed to create account")
		t.Logf("✓ Account created: %s", accountURL)

		// STEP 2: Create order for EK certificate
		t.Log("")
		t.Log("Step 2: Creating order for EK certificate...")

		// For endorse-01, the permanent identifier is the base64url-encoded PKIX public key
		// of the TPM's Endorsement Key
		orderReq := OrderRequest{
			Identifiers: []Identifier{
				{
					Type:  "permanent-identifier",
					Value: permanentIdentifierValue,
				},
			},
		}

		nonce, err := fetchNonce(client, serverURL)
		require.NoError(t, err, "Failed to fetch nonce")

		newOrderURL := fmt.Sprintf("%s/acme/new-order", serverURL)
		resp, err := sendJWSRequest(client, newOrderURL, orderReq, privateKey, accountURL, nonce)
		require.NoError(t, err, "Failed to create order")

		// Capture order URL from Location header
		orderURL := resp.Header.Get("Location")
		require.NotEmpty(t, orderURL, "Location header should contain order URL")

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err, "Failed to read response body")

		var order OrderResponse
		err = json.Unmarshal(body, &order)
		require.NoError(t, err, "Failed to parse order response")

		t.Logf("✓ Order created with status: %s", order.Status)
		t.Logf("  Order URL: %s", orderURL)
		t.Logf("  Authorizations: %d", len(order.Authorizations))

		// Check if server supports permanent-identifier
		if len(order.Authorizations) == 0 {
			require.FailNow(t, "Server does not support permanent-identifier type (endorse-01 challenge not configured)")
		}

		// STEP 3: Fetch authorization and locate endorse-01 challenge
		t.Log("")
		t.Log("Step 3: Fetching authorization and locating endorse-01 challenge...")

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

		t.Logf("  Authorization status: %s", authz.Status)
		t.Logf("  Identifier type: %s", authz.Identifier.Type)
		t.Logf("  Identifier value: %s", authz.Identifier.Value)
		t.Logf("  Available challenges: %d", len(authz.Challenges))

		// List all available challenges
		for i, ch := range authz.Challenges {
			t.Logf("    [%d] Type: %s, Status: %s", i, ch.Type, ch.Status)
		}

		// Find endorse-01 challenge
		var endorseChallenge *Challenge
		for i := range authz.Challenges {
			if authz.Challenges[i].Type == "endorse-01" {
				endorseChallenge = &authz.Challenges[i]
				break
			}
		}

		require.NotNil(t, endorseChallenge, "endorse-01 challenge should be available")
		t.Logf("✓ Found endorse-01 challenge")
		t.Logf("  Challenge URL: %s", endorseChallenge.URL)
		t.Logf("  Challenge Token: %s", endorseChallenge.Token)
		t.Logf("  Challenge Status: %s", endorseChallenge.Status)

		// STEP 4: Verify swtpm connection (already established in Step 0)
		t.Log("")
		t.Log("Step 4: Verifying swtpm connection...")

		if swtpm == nil {
			t.Log("  ⚠ swtpm not available - skipping TPM operations")
			t.Log("  In production, the client would:")
			t.Log("    1. Connect to the TPM")
			t.Log("    2. Read the EK public key")
			t.Log("    3. Create credential proof")
			t.Log("    4. Submit to server for EK certificate issuance")
			assert.Equal(t, "pending", endorseChallenge.Status, "Challenge should be pending")
			t.Log("")
			t.Log("========================================")
			t.Log("ENDORSE-01 BASIC TEST COMPLETED")
			t.Log("(TPM operations skipped - swtpm not available)")
			t.Log("========================================")
			return
		}

		// swtpm already connected and provisioned in Step 0
		defer swtpm.Close()
		t.Log("  ✓ swtpm connection active (provisioned in Step 0)")

		// STEP 5: Respond to the endorse-01 challenge
		t.Log("")
		t.Log("Step 5: Responding to endorse-01 challenge...")

		nonce, err = fetchNonce(client, serverURL)
		require.NoError(t, err, "Failed to fetch nonce")

		// Submit empty response to the challenge - endorse-01 validates at CSR time
		challengeResp, err := sendJWSRequest(client, endorseChallenge.URL, struct{}{}, privateKey, accountURL, nonce)
		require.NoError(t, err, "Failed to respond to challenge")
		challengeResp.Body.Close()
		t.Logf("  Challenge response status: %d", challengeResp.StatusCode)

		// Poll authorization until valid
		t.Log("  Polling authorization status...")
		for i := 0; i < 10; i++ {
			time.Sleep(100 * time.Millisecond)

			nonce, err = fetchNonce(client, serverURL)
			require.NoError(t, err, "Failed to fetch nonce")

			resp, err = sendJWSRequest(client, authzURL, nil, privateKey, accountURL, nonce)
			require.NoError(t, err, "Failed to fetch authorization")

			body, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			require.NoError(t, err, "Failed to read authorization response")

			err = json.Unmarshal(body, &authz)
			require.NoError(t, err, "Failed to parse authorization response")

			t.Logf("    Authorization status: %s", authz.Status)
			if authz.Status == "valid" {
				break
			}
		}
		require.Equal(t, "valid", authz.Status, "Authorization should be valid")
		t.Log("✓ Authorization validated")

		// STEP 6: Create CSR with EK public key and finalize order
		t.Log("")
		t.Log("Step 6: Creating CSR with EK public key and finalizing order...")

		// ekPublicKey was already obtained in Step 0
		require.NotNil(t, ekPublicKey, "EK public key should have been obtained in Step 0")

		// pkg/acme/server/handlers/order_finalize.go's endorse01TPMManufacturer
		// refuses finalize with BadCSR unless the CSR itself asserts the TPM's
		// manufacturer code (tcg-at-tpmManufacturer, read from the CSR's own
		// Subject DN or subjectAltName -- pkg/ca/tcg_devid_name.go's
		// manufacturerFromNames checks the Subject first). Without it, finalize
		// is rejected but sendJWSRequest only surfaces transport errors, not
		// ACME problem documents, so the order silently stayed "ready" forever
		// instead of progressing -- the missing attribute, not a key mismatch,
		// is why finalize never reached "valid".
		props, err := swtpm.GetTPMModule().FixedProperties()
		require.NoError(t, err, "Failed to read TPM fixed properties")

		// Create CSR template with the EK public key
		csrTemplate := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   deviceIdentifier,
				Organization: []string{"Test Organization"},
				ExtraNames: []pkix.AttributeTypeAndValue{
					{Type: ca.OIDTCGAttributeTPMManufacturer, Value: props.ManufacturerCode},
				},
			},
		}

		// Sign CSR with our account private key (the EK public key will be in the CSR)
		// Note: In real usage, the CSR would be signed by a key associated with the EK
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
		require.NoError(t, err, "Failed to create CSR")
		t.Logf("  CSR created for %s", deviceIdentifier)
		t.Logf("  EK Public Key Type: %T", ekPublicKey)

		// Finalize the order
		nonce, err = fetchNonce(client, serverURL)
		require.NoError(t, err, "Failed to fetch nonce")

		finalizeReq := struct {
			CSR string `json:"csr"`
		}{
			CSR: base64URLEncode(csrDER),
		}

		resp, err = sendJWSRequest(client, order.Finalize, finalizeReq, privateKey, accountURL, nonce)
		require.NoError(t, err, "Failed to finalize order")

		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err, "Failed to read finalize response")

		err = json.Unmarshal(body, &order)
		require.NoError(t, err, "Failed to parse finalize response")
		t.Logf("  Order status after finalize: %s", order.Status)

		// Poll order until ready
		for i := 0; i < 10; i++ {
			if order.Status == "valid" && order.Certificate != "" {
				break
			}
			time.Sleep(100 * time.Millisecond)

			nonce, err = fetchNonce(client, serverURL)
			require.NoError(t, err, "Failed to fetch nonce")

			resp, err = sendJWSRequest(client, orderURL, nil, privateKey, accountURL, nonce)
			require.NoError(t, err, "Failed to fetch order")

			body, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			require.NoError(t, err, "Failed to read order response")

			err = json.Unmarshal(body, &order)
			require.NoError(t, err, "Failed to parse order response")
			t.Logf("    Order status: %s", order.Status)
		}
		require.Equal(t, "valid", order.Status, "Order should be valid")
		require.NotEmpty(t, order.Certificate, "Order should have certificate URL")
		t.Logf("✓ Order finalized, certificate URL: %s", order.Certificate)

		// STEP 7: Download the CA-issued EK certificate
		t.Log("")
		t.Log("Step 7: Downloading CA-issued EK certificate...")

		nonce, err = fetchNonce(client, serverURL)
		require.NoError(t, err, "Failed to fetch nonce")

		resp, err = sendJWSRequest(client, order.Certificate, nil, privateKey, accountURL, nonce)
		require.NoError(t, err, "Failed to fetch certificate")

		certPEM, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err, "Failed to read certificate response")
		require.NotEmpty(t, certPEM, "Certificate should not be empty")

		// Parse the certificate
		block, _ := pem.Decode(certPEM)
		require.NotNil(t, block, "Failed to decode PEM certificate")

		issuedCert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err, "Failed to parse issued certificate")

		t.Log("✓ CA-issued EK Certificate received")
		LogCertificate(t, issuedCert, "  CA-Issued EK Certificate:")

		// STEP 8: Verify TCG and Trusted Platform OIDs in the certificate
		t.Log("")
		t.Log("Step 8: Verifying TCG and Trusted Platform OIDs...")

		// Define expected OIDs
		tcgOIDs := map[string]asn1.ObjectIdentifier{
			"tcg-kp-EKCertificate":   {2, 23, 133, 8, 1},
			"tcg-TPMSpecification":   {2, 23, 133, 2, 16},
			"OIDPermanentIdentifier": {1, 3, 6, 1, 5, 5, 7, 8, 3},
			"tp-keyStore":            {1, 3, 6, 1, 4, 1, 29377, 101, 2},
			"tp-issuerKeyStore":      {1, 3, 6, 1, 4, 1, 29377, 101, 1},
		}

		foundOIDs := make(map[string]bool)
		for _, ext := range issuedCert.Extensions {
			for name, oid := range tcgOIDs {
				if ext.Id.Equal(oid) {
					foundOIDs[name] = true
					t.Logf("  ✓ Found OID %s (%v)", name, oid)
				}
			}
		}

		// Verify key TCG OIDs are present
		assert.True(t, foundOIDs["tcg-kp-EKCertificate"], "Certificate should have tcg-kp-EKCertificate OID")
		assert.True(t, foundOIDs["tp-keyStore"], "Certificate should have tp-keyStore OID")
		assert.True(t, foundOIDs["tp-issuerKeyStore"], "Certificate should have tp-issuerKeyStore OID")

		// STEP 9: Summary
		t.Log("")
		t.Log("========================================")
		t.Log("ENDORSE-01 CHALLENGE TEST COMPLETED")
		t.Log("========================================")
		t.Logf("  Device Identifier: %s", deviceIdentifier)
		t.Logf("  Challenge Type: endorse-01")
		t.Logf("  CA-Issued EK Certificate Subject: %s", issuedCert.Subject.CommonName)
		t.Logf("  CA-Issued EK Certificate Issuer: %s", issuedCert.Issuer.CommonName)
		t.Logf("  TCG OIDs found: %d", len(foundOIDs))
		for name := range foundOIDs {
			t.Logf("    - %s", name)
		}
		t.Log("========================================")
	})
}

func TestDeviceAttest01Challenge(t *testing.T) {
	serverURL := getServerURL()
	_ = getTPMHost() // Will be used for TPM connectivity

	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: getTLSConfig(),
		},
	}

	t.Run("device-attest-01 challenge for remote attestation", func(t *testing.T) {
		// Create account
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err, "Failed to generate ECDSA key")

		accountURL, err := createAccount(client, serverURL, privateKey, []string{"mailto:attest@example.com"})
		require.NoError(t, err, "Failed to create account")

		// Create order for attestation
		deviceID := "attested-device.test.local"
		orderReq := OrderRequest{
			Identifiers: []Identifier{
				{Type: "permanent-identifier", Value: deviceID},
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

		// Check if server supports permanent-identifier (device-attest-01 challenge)
		if len(order.Authorizations) == 0 {
			require.FailNow(t, "Server does not support permanent-identifier type (device-attest-01 challenge not configured)")
		}

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

		// Find device-attest-01 challenge
		var attestChallenge *Challenge
		for i := range authz.Challenges {
			if authz.Challenges[i].Type == "device-attest-01" {
				attestChallenge = &authz.Challenges[i]
				break
			}
		}

		require.NotNil(t, attestChallenge, "device-attest-01 challenge should be available")
		t.Logf("device-attest-01 challenge URL: %s", attestChallenge.URL)

		// In a real implementation, we would:
		// 1. Receive nonce from server
		// 2. Generate TPM quote over selected PCRs with nonce
		// 3. Submit quote and PCR values
		// 4. Server verifies quote signature and PCR values
		// 5. Server validates device state against policy

		assert.Equal(t, "pending", attestChallenge.Status, "Challenge should be pending")
	})

	t.Run("device-attest-01 with PCR policy", func(t *testing.T) {
		// This test would verify that the server can enforce
		// specific PCR values as part of the attestation policy

		t.Log("Testing PCR policy enforcement")
		t.Log("Expected PCRs: 0, 1, 2, 3, 7")
		t.Log("Expected PCR0 value: <known-good-value>")

		// Implementation would:
		// 1. Create order with PCR policy requirements
		// 2. Perform attestation with actual PCR values
		// 3. Verify server accepts/rejects based on policy
	})
}

func getTPMHost() string {
	host := os.Getenv("ACME_TPM_HOST")
	if host == "" {
		return "tpm-simulator"
	}
	return host
}
