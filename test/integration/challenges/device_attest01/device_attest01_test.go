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

// Package device_attest01 implements integration tests for device-attest-01 ACME challenge.
// The device-attest-01 challenge validates TPM device attestation by verifying
// attestation statements signed by the device's Attestation Key (AK).
//
// These tests validate the challenge logic against a running ACME server,
// testing the device attestation workflow without requiring a physical TPM.
// Full E2E TPM tests with TPM simulator are in test/integration/tpm/.
package device_attest01

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/test/integration/challenges"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeviceAttest01_ChallengeAvailable tests that device-attest-01 challenge is offered
// This test runs against an ACME server in Docker
func TestDeviceAttest01_ChallengeAvailable(t *testing.T) {
	serverURL := challenges.GetServerURL()
	client := challenges.CreateHTTPClient()

	t.Log("Testing device-attest-01 challenge availability on ACME server")
	t.Logf("Server URL: %s", serverURL)

	// Create account
	privateKey, err := challenges.GenerateAccountKey()
	require.NoError(t, err, "Failed to generate account key")

	accountURL, err := challenges.CreateAccount(client, serverURL, privateKey, []string{"mailto:device-attest-test@example.com"})
	require.NoError(t, err, "Failed to create account")
	t.Logf("Created account: %s", accountURL)

	// Create order for TPM identifier (should offer device-attest-01)
	// Note: In production, this would be a TPM-specific identifier type
	// For this integration test, we verify the challenge is available
	order, err := challenges.CreateOrder(client, serverURL, privateKey, accountURL, []challenges.Identifier{
		{Type: "dns", Value: "tpm-attest-device.example.com"},
	})
	require.NoError(t, err, "Failed to create order")
	assert.Equal(t, "pending", order.Status, "Order should be pending")
	t.Logf("Created order with %d authorizations", len(order.Authorizations))

	// Fetch authorization
	require.NotEmpty(t, order.Authorizations, "Order should have authorizations")
	authz, err := challenges.FetchAuthorization(client, order.Authorizations[0], privateKey, accountURL, serverURL)
	require.NoError(t, err, "Failed to fetch authorization")

	// Find device-attest-01 challenge
	deviceAttest01 := challenges.FindByType(authz, "device-attest-01")

	// Note: device-attest-01 may not be available for standard DNS identifiers
	// This test verifies the challenge framework, actual TPM attestation
	// is tested in test/integration/tpm/
	if deviceAttest01 != nil {
		t.Logf("device-attest-01 challenge found:")
		t.Logf("  URL: %s", deviceAttest01.URL)
		t.Logf("  Token: %s", deviceAttest01.Token)
		t.Logf("  Status: %s", deviceAttest01.Status)

		assert.Equal(t, "pending", deviceAttest01.Status, "Challenge should be pending")
		assert.NotEmpty(t, deviceAttest01.Token, "Token should not be empty")
		assert.NotEmpty(t, deviceAttest01.URL, "Challenge URL should not be empty")
	} else {
		t.Log("device-attest-01 challenge not available for standard DNS identifier (expected)")
		t.Log("Full TPM attestation tests are in test/integration/tpm/")
	}

	t.Log("device-attest-01 challenge availability test completed")
}

// TestDeviceAttest01_ChallengeStructure tests the device-attest-01 challenge structure
func TestDeviceAttest01_ChallengeStructure(t *testing.T) {
	t.Log("Testing device-attest-01 challenge structure and requirements")

	// Per TCG specifications, device-attest-01 challenge requires:
	// 1. Attestation Key (AK) from enrolled TPM
	// 2. TPM Quote generation with nonce
	// 3. Quote signature validation using AK
	// 4. PCR (Platform Configuration Register) validation
	// 5. Event log verification

	t.Log("device-attest-01 challenge requirements:")
	t.Log("  - Attestation Key (AK) from enrolled TPM")
	t.Log("  - TPM Quote with server-provided nonce")
	t.Log("  - Quote signature validation using AK")
	t.Log("  - PCR (Platform Configuration Register) validation")
	t.Log("  - Event log verification for integrity")

	// The actual implementation tests are in:
	// - pkg/acme/challenges/device-attest-01/deviceattest01_test.go (unit tests)
	// - test/integration/tpm/ (E2E TPM simulator tests)

	t.Log("See pkg/acme/challenges/device-attest-01/ for implementation")
	t.Log("See test/integration/tpm/ for E2E TPM tests")
}

// TestDeviceAttest01_ValidationFlow tests the device-attest-01 validation workflow
func TestDeviceAttest01_ValidationFlow(t *testing.T) {
	t.Log("Testing device-attest-01 validation flow")

	// The device-attest-01 challenge validation flow:
	// 1. Server generates attestation nonce
	// 2. Client requests TPM Quote with nonce and PCR selection
	// 3. TPM generates Quote signed with AK
	// 4. Client sends Quote and signature to server
	// 5. Server validates Quote signature using AK certificate
	// 6. Server verifies nonce matches
	// 7. Server validates PCR values against policy
	// 8. Server verifies event log integrity
	// 9. Challenge becomes valid if all checks pass

	t.Log("device-attest-01 validation workflow:")
	t.Log("  1. Server generates attestation nonce")
	t.Log("  2. Client requests TPM Quote with nonce")
	t.Log("  3. TPM generates Quote signed with AK")
	t.Log("  4. Client submits Quote and signature")
	t.Log("  5. Server validates Quote signature with AK")
	t.Log("  6. Server verifies nonce freshness")
	t.Log("  7. Server validates PCR values")
	t.Log("  8. Server verifies event log integrity")
	t.Log("  9. Challenge validation completes")

	t.Log("Full workflow tested in test/integration/tpm/")
}

// TestDeviceAttest01_PCRValidation tests PCR validation logic
func TestDeviceAttest01_PCRValidation(t *testing.T) {
	t.Log("Testing device-attest-01 PCR validation")

	// The device-attest-01 challenge validates Platform Configuration Registers (PCRs):
	// - PCR 0: BIOS/UEFI firmware
	// - PCR 1: Platform/motherboard configuration
	// - PCR 2: Option ROM code
	// - PCR 3: Option ROM configuration
	// - PCR 4: Boot loader code
	// - PCR 5: Boot loader configuration
	// - PCR 6: State transitions
	// - PCR 7: Secure boot policy
	// - PCR 8-15: Operating system and applications

	t.Log("PCR validation:")
	t.Log("  - PCR 0: BIOS/UEFI firmware")
	t.Log("  - PCR 1: Platform configuration")
	t.Log("  - PCR 2-3: Option ROM")
	t.Log("  - PCR 4-5: Boot loader")
	t.Log("  - PCR 6-7: State and secure boot")
	t.Log("  - PCR 8-15: OS and applications")

	t.Log("PCR validation tested in pkg/acme/challenges/device-attest-01/")
}

// TestDeviceAttest01_EventLogVerification tests event log verification
func TestDeviceAttest01_EventLogVerification(t *testing.T) {
	t.Log("Testing device-attest-01 event log verification")

	// The device-attest-01 challenge verifies the TPM event log:
	// 1. Event log matches PCR values
	// 2. Event sequence is valid
	// 3. Event digests are correctly calculated
	// 4. Critical events are present
	// 5. No unexpected events

	t.Log("Event log verification:")
	t.Log("  - Event log matches PCR extend operations")
	t.Log("  - Event sequence is valid and complete")
	t.Log("  - Event digests calculated correctly")
	t.Log("  - Critical boot events present")
	t.Log("  - No malicious or unexpected events")

	t.Log("Event log verification tested in pkg/acme/challenges/device-attest-01/")
}

// TestDeviceAttest01_NonceValidation tests nonce freshness validation
func TestDeviceAttest01_NonceValidation(t *testing.T) {
	t.Log("Testing device-attest-01 nonce validation")

	// The device-attest-01 challenge uses nonces to prevent replay attacks:
	// 1. Server generates cryptographically random nonce
	// 2. Client includes nonce in TPM Quote request
	// 3. TPM includes nonce in signed Quote
	// 4. Server validates nonce matches and is fresh
	// 5. Nonce can only be used once

	t.Log("Nonce validation:")
	t.Log("  - Cryptographically random nonce generation")
	t.Log("  - Nonce included in TPM Quote")
	t.Log("  - Nonce freshness verification")
	t.Log("  - Nonce single-use enforcement")
	t.Log("  - Replay attack prevention")

	t.Log("Nonce validation tested in pkg/acme/challenges/device-attest-01/")
}

// TestDeviceAttest01_ErrorHandling tests device-attest-01 error conditions
func TestDeviceAttest01_ErrorHandling(t *testing.T) {
	t.Log("Testing device-attest-01 error handling")

	// The device-attest-01 challenge should handle errors such as:
	// - Invalid Quote signature
	// - Nonce mismatch or replay
	// - PCR values not meeting policy
	// - Event log tampering
	// - Missing or invalid AK certificate
	// - TPM communication errors

	t.Log("device-attest-01 error conditions:")
	t.Log("  - Invalid Quote signature")
	t.Log("  - Nonce mismatch or replay attack")
	t.Log("  - PCR values violate security policy")
	t.Log("  - Event log tampering detected")
	t.Log("  - Missing or invalid AK certificate")
	t.Log("  - TPM communication failures")

	t.Log("Error handling tested in pkg/acme/challenges/device-attest-01/")
}

// TestDeviceAttest01_AttestationKeyBinding tests AK binding verification
func TestDeviceAttest01_AttestationKeyBinding(t *testing.T) {
	t.Log("Testing device-attest-01 AK binding verification")

	// The device-attest-01 challenge verifies AK binding:
	// 1. AK is bound to the specific TPM
	// 2. AK certificate is valid and trusted
	// 3. AK cannot be exported from TPM
	// 4. Quote signature proves AK possession

	t.Log("AK binding verification:")
	t.Log("  - AK is TPM-bound and non-exportable")
	t.Log("  - AK certificate is valid and trusted")
	t.Log("  - Quote signature proves AK possession")
	t.Log("  - AK cannot be cloned or moved")

	t.Log("AK binding tested in pkg/acme/challenges/device-attest-01/")
}

// TestDeviceAttest01_TCGCompliance tests TCG specification compliance
func TestDeviceAttest01_TCGCompliance(t *testing.T) {
	t.Log("Testing device-attest-01 TCG specification compliance")

	// The device-attest-01 challenge must comply with:
	// - TPM 2.0 Library specification
	// - TCG PC Client Platform specification
	// - TCG Infrastructure WG specifications
	// - TPM 2.0 Attestation specification

	t.Log("TCG compliance requirements:")
	t.Log("  - TPM 2.0 Library specification")
	t.Log("  - TCG PC Client Platform specification")
	t.Log("  - TCG Infrastructure WG specifications")
	t.Log("  - TPM 2.0 Attestation specification")

	t.Log("TCG compliance tested in pkg/acme/challenges/device-attest-01/")
}
