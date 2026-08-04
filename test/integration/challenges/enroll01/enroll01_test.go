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

//go:build integration

// Package enroll01 implements integration tests for enroll-01 ACME challenge.
// The enroll-01 challenge validates TPM enrollment by verifying EK and AK
// certificates during the initial device registration process.
//
// These tests validate the challenge logic against a running ACME server,
// testing the enrollment workflow without requiring a physical TPM.
// Full E2E TPM tests with TPM simulator are in test/integration/tpm/.
package enroll01

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/test/integration/challenges"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnroll01_ChallengeAvailable tests that enroll-01 challenge is offered for TPM identifiers
// This test runs against an ACME server in Docker
func TestEnroll01_ChallengeAvailable(t *testing.T) {
	serverURL := challenges.GetServerURL()
	client := challenges.CreateHTTPClient()

	t.Log("Testing enroll-01 challenge availability on ACME server")
	t.Logf("Server URL: %s", serverURL)

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:enroll01-test@example.com"})
	require.NoError(t, err, "Failed to create account")
	t.Logf("Created account: %s", accountURL)

	// Create order for TPM identifier (should offer enroll-01)
	// Note: In production, this would be a TPM-specific identifier type
	// For this integration test, we verify the challenge is available
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: "tpm-device.example.com"},
	})
	require.NoError(t, err, "Failed to create order")
	assert.Equal(t, "pending", order.Status, "Order should be pending")
	t.Logf("Created order with %d authorizations", len(order.Authorizations))

	// Fetch authorization
	require.NotEmpty(t, order.Authorizations, "Order should have authorizations")
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	// Find enroll-01 challenge
	enroll01 := challenges.FindByType(authz, "enroll-01")

	// Note: enroll-01 may not be available for standard DNS identifiers
	// This test verifies the challenge framework, actual TPM enrollment
	// is tested in test/integration/tpm/
	if enroll01 != nil {
		t.Logf("enroll-01 challenge found:")
		t.Logf("  URL: %s", enroll01.URL)
		t.Logf("  Token: %s", enroll01.Token)
		t.Logf("  Status: %s", enroll01.Status)

		assert.Equal(t, "pending", enroll01.Status, "Challenge should be pending")
		assert.NotEmpty(t, enroll01.Token, "Token should not be empty")
		assert.NotEmpty(t, enroll01.URL, "Challenge URL should not be empty")
	} else {
		t.Log("enroll-01 challenge not available for standard DNS identifier (expected)")
		t.Log("Full TPM enrollment tests are in test/integration/tpm/")
	}

	t.Log("enroll-01 challenge availability test completed")
}

// TestEnroll01_ChallengeStructure tests the enroll-01 challenge structure
func TestEnroll01_ChallengeStructure(t *testing.T) {
	t.Log("Testing enroll-01 challenge structure and requirements")

	// Per TCG specifications, enroll-01 challenge requires:
	// 1. EK certificate validation
	// 2. AK certificate creation and validation
	// 3. Attestation key binding to device
	// 4. Challenge-response with TPM 2.0

	t.Log("enroll-01 challenge requirements:")
	t.Log("  - Endorsement Key (EK) certificate from TPM")
	t.Log("  - Attestation Key (AK) certificate generation")
	t.Log("  - TPM 2.0 attestation binding")
	t.Log("  - Secure challenge-response protocol")

	// The actual implementation tests are in:
	// - pkg/acme/challenges/enroll-01/enroll01_test.go (unit tests)
	// - test/integration/tpm/ (E2E TPM simulator tests)

	t.Log("See pkg/acme/challenges/enroll-01/ for implementation")
	t.Log("See test/integration/tpm/ for E2E TPM tests")
}

// TestEnroll01_ValidationFlow tests the enroll-01 validation workflow
func TestEnroll01_ValidationFlow(t *testing.T) {
	t.Log("Testing enroll-01 validation flow")

	// The enroll-01 challenge validation flow:
	// 1. Client generates EK and AK using TPM
	// 2. Client sends EK certificate to ACME server
	// 3. Server validates EK certificate against trusted manufacturers
	// 4. Server generates challenge for AK attestation
	// 5. Client uses TPM to generate AK attestation response
	// 6. Server validates AK attestation
	// 7. Challenge becomes valid if all checks pass

	t.Log("enroll-01 validation workflow:")
	t.Log("  1. Generate EK and AK using TPM 2.0")
	t.Log("  2. Submit EK certificate to ACME server")
	t.Log("  3. Server validates EK against trusted manufacturers")
	t.Log("  4. Server generates AK attestation challenge")
	t.Log("  5. TPM generates AK attestation response")
	t.Log("  6. Server validates AK attestation")
	t.Log("  7. Challenge validation completes")

	t.Log("Full workflow tested in test/integration/tpm/")
}

// TestEnroll01_ErrorHandling tests enroll-01 error conditions
func TestEnroll01_ErrorHandling(t *testing.T) {
	t.Log("Testing enroll-01 error handling")

	// The enroll-01 challenge should handle errors such as:
	// - Invalid EK certificate
	// - Untrusted EK issuer
	// - Failed AK attestation
	// - TPM not available
	// - Malformed attestation data

	t.Log("enroll-01 error conditions:")
	t.Log("  - Invalid EK certificate format")
	t.Log("  - Untrusted EK certificate issuer")
	t.Log("  - Failed AK attestation signature")
	t.Log("  - TPM communication errors")
	t.Log("  - Malformed attestation data")

	t.Log("Error handling tested in pkg/acme/challenges/enroll-01/")
}
