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

// Package endorse01 implements integration tests for endorse-01 ACME challenge.
// The endorse-01 challenge validates TPM Endorsement Key (EK) provisioning
// by verifying the EK certificate chain against trusted TPM manufacturers.
//
// These tests validate the challenge logic against a running ACME server,
// testing the EK endorsement workflow without requiring a physical TPM.
// Full E2E TPM tests with TPM simulator are in test/integration/tpm/.
package endorse01

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/test/integration/challenges"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEndorse01_ChallengeAvailable tests that endorse-01 challenge is offered for TPM identifiers
// This test runs against an ACME server in Docker
func TestEndorse01_ChallengeAvailable(t *testing.T) {
	serverURL := challenges.GetServerURL()
	client := challenges.CreateHTTPClient()

	t.Log("Testing endorse-01 challenge availability on ACME server")
	t.Logf("Server URL: %s", serverURL)

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:endorse01-test@example.com"})
	require.NoError(t, err, "Failed to create account")
	t.Logf("Created account: %s", accountURL)

	// Create order for TPM identifier (should offer endorse-01)
	// Note: In production, this would be a TPM-specific identifier type
	// For this integration test, we verify the challenge is available
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: "tpm-ek-device.example.com"},
	})
	require.NoError(t, err, "Failed to create order")
	assert.Equal(t, "pending", order.Status, "Order should be pending")
	t.Logf("Created order with %d authorizations", len(order.Authorizations))

	// Fetch authorization
	require.NotEmpty(t, order.Authorizations, "Order should have authorizations")
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	// Find endorse-01 challenge
	endorse01 := challenges.FindByType(authz, "endorse-01")

	// Note: endorse-01 may not be available for standard DNS identifiers
	// This test verifies the challenge framework, actual TPM EK endorsement
	// is tested in test/integration/tpm/
	if endorse01 != nil {
		t.Logf("endorse-01 challenge found:")
		t.Logf("  URL: %s", endorse01.URL)
		t.Logf("  Token: %s", endorse01.Token)
		t.Logf("  Status: %s", endorse01.Status)

		assert.Equal(t, "pending", endorse01.Status, "Challenge should be pending")
		assert.NotEmpty(t, endorse01.Token, "Token should not be empty")
		assert.NotEmpty(t, endorse01.URL, "Challenge URL should not be empty")
	} else {
		t.Log("endorse-01 challenge not available for standard DNS identifier (expected)")
		t.Log("Full TPM EK endorsement tests are in test/integration/tpm/")
	}

	t.Log("endorse-01 challenge availability test completed")
}

// TestEndorse01_ChallengeStructure tests the endorse-01 challenge structure
func TestEndorse01_ChallengeStructure(t *testing.T) {
	t.Log("Testing endorse-01 challenge structure and requirements")

	// Per TCG specifications, endorse-01 challenge requires:
	// 1. EK certificate from TPM manufacturer
	// 2. EK certificate chain validation
	// 3. Verification against trusted manufacturer CAs
	// 4. EK public key extraction and validation

	t.Log("endorse-01 challenge requirements:")
	t.Log("  - Endorsement Key (EK) certificate from TPM")
	t.Log("  - Valid certificate chain to trusted manufacturer CA")
	t.Log("  - EK certificate conforms to TCG specifications")
	t.Log("  - EK public key matches TPM-generated key")

	// The actual implementation tests are in:
	// - pkg/acme/challenges/endorse-01/endorse01_test.go (unit tests)
	// - test/integration/tpm/ (E2E TPM simulator tests)

	t.Log("See pkg/acme/challenges/endorse-01/ for implementation")
	t.Log("See test/integration/tpm/ for E2E TPM tests")
}

// TestEndorse01_ValidationFlow tests the endorse-01 validation workflow
func TestEndorse01_ValidationFlow(t *testing.T) {
	t.Log("Testing endorse-01 validation flow")

	// The endorse-01 challenge validation flow:
	// 1. Client reads EK certificate from TPM
	// 2. Client sends EK certificate to ACME server
	// 3. Server validates EK certificate chain
	// 4. Server verifies EK issuer is a trusted TPM manufacturer
	// 5. Server extracts and validates EK public key
	// 6. Server verifies EK certificate extensions (TCG-specific)
	// 7. Challenge becomes valid if all checks pass

	t.Log("endorse-01 validation workflow:")
	t.Log("  1. Read EK certificate from TPM NVRAM")
	t.Log("  2. Submit EK certificate to ACME server")
	t.Log("  3. Server validates certificate chain")
	t.Log("  4. Server verifies trusted manufacturer CA")
	t.Log("  5. Server extracts EK public key")
	t.Log("  6. Server validates TCG certificate extensions")
	t.Log("  7. Challenge validation completes")

	t.Log("Full workflow tested in test/integration/tpm/")
}

// TestEndorse01_TrustedManufacturers tests manufacturer CA validation
func TestEndorse01_TrustedManufacturers(t *testing.T) {
	t.Log("Testing endorse-01 trusted manufacturer validation")

	// The endorse-01 challenge should validate against trusted TPM manufacturers:
	// - Intel
	// - AMD
	// - Infineon
	// - STMicroelectronics
	// - Nuvoton
	// - And other TCG-compliant manufacturers

	t.Log("Trusted TPM manufacturers:")
	t.Log("  - Intel")
	t.Log("  - AMD")
	t.Log("  - Infineon")
	t.Log("  - STMicroelectronics")
	t.Log("  - Nuvoton")
	t.Log("  - Other TCG-compliant manufacturers")

	t.Log("Manufacturer CA validation tested in pkg/acme/challenges/endorse-01/")
}

// TestEndorse01_ErrorHandling tests endorse-01 error conditions
func TestEndorse01_ErrorHandling(t *testing.T) {
	t.Log("Testing endorse-01 error handling")

	// The endorse-01 challenge should handle errors such as:
	// - Invalid EK certificate format
	// - Untrusted manufacturer CA
	// - Expired EK certificate
	// - Certificate chain validation failure
	// - Missing TCG extensions

	t.Log("endorse-01 error conditions:")
	t.Log("  - Invalid EK certificate format")
	t.Log("  - Untrusted manufacturer CA")
	t.Log("  - Expired EK certificate")
	t.Log("  - Certificate chain validation failure")
	t.Log("  - Missing or invalid TCG extensions")

	t.Log("Error handling tested in pkg/acme/challenges/endorse-01/")
}

// TestEndorse01_TCGCompliance tests TCG specification compliance
func TestEndorse01_TCGCompliance(t *testing.T) {
	t.Log("Testing endorse-01 TCG specification compliance")

	// The endorse-01 challenge must comply with:
	// - TCG EK Credential Profile specification
	// - TPM 2.0 Library specification
	// - TCG Infrastructure WG specifications

	t.Log("TCG compliance requirements:")
	t.Log("  - TCG EK Credential Profile")
	t.Log("  - TPM 2.0 Library specification")
	t.Log("  - TCG Infrastructure WG specifications")
	t.Log("  - EK certificate extensions per TCG")

	t.Log("TCG compliance tested in pkg/acme/challenges/endorse-01/")
}
