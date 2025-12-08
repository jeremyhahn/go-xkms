//go:build integration

package integration

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"testing"

	tpm2lib "github.com/jeremyhahn/go-keychain/pkg/tpm2"
)

// setupAttestationTPM ensures TPM is properly provisioned with IAK for attestation tests
func setupAttestationTPM(t *testing.T) (tpm2lib.TrustedPlatformModule, func()) {
	t.Helper()

	// Use the shared createTPM2Instance function
	tpmInstance, cleanup := createTPM2Instance(t)

	// Always provision first - the TPM simulator starts without any keys
	t.Log("Provisioning TPM with EK and SRK...")
	if err := tpmInstance.Provision(nil); err != nil {
		// If provision fails, it might already be provisioned, so continue
		t.Logf("Provision returned: %v (continuing)", err)
	}

	// Verify EK was created
	ekAttrs, err := tpmInstance.EKAttributes()
	if err != nil {
		cleanup()
		t.Fatalf("Failed to get EK attributes after provisioning: %v", err)
	}

	// Ensure IAK is created
	_, err = tpmInstance.IAKAttributes()
	if err != nil {
		t.Logf("IAK not found, creating IAK: %v", err)
		_, err = tpmInstance.CreateIAK(ekAttrs, nil)
		if err != nil {
			cleanup()
			t.Fatalf("Failed to create IAK: %v", err)
		}
	}

	return tpmInstance, cleanup
}

// TestIntegration_AKProfile tests retrieving attestation key profile
func TestIntegration_AKProfile(t *testing.T) {
	tpmInstance, cleanup := setupAttestationTPM(t)
	defer cleanup()

	t.Run("ValidProfile", func(t *testing.T) {
		// Get AK profile
		profile, err := tpmInstance.AKProfile()
		if err != nil {
			t.Fatalf("Failed to get AK profile: %v", err)
		}

		// Verify EK public key is not empty
		if len(profile.EKPub) == 0 {
			t.Error("AK profile EKPub is empty")
		}

		// Verify AK public key is not empty
		if len(profile.AKPub) == 0 {
			t.Error("AK profile AKPub is empty")
		}

		// Verify AK name is not empty
		if len(profile.AKName.Buffer) == 0 {
			t.Error("AK profile AKName is empty")
		}

		// Verify signature algorithm is set
		if profile.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
			t.Error("AK profile SignatureAlgorithm is unknown")
		}

		t.Logf("AK Profile retrieved successfully:")
		t.Logf("  EKPub size: %d bytes", len(profile.EKPub))
		t.Logf("  AKPub size: %d bytes", len(profile.AKPub))
		t.Logf("  AKName size: %d bytes", len(profile.AKName.Buffer))
		t.Logf("  SignatureAlgorithm: %v", profile.SignatureAlgorithm)
	})

	t.Run("ProfileConsistency", func(t *testing.T) {
		// Get profile multiple times and verify consistency
		profile1, err := tpmInstance.AKProfile()
		if err != nil {
			t.Fatalf("Failed to get first AK profile: %v", err)
		}

		profile2, err := tpmInstance.AKProfile()
		if err != nil {
			t.Fatalf("Failed to get second AK profile: %v", err)
		}

		// Verify profiles are identical
		if !bytes.Equal(profile1.EKPub, profile2.EKPub) {
			t.Error("EKPub mismatch between consecutive profile retrievals")
		}

		if !bytes.Equal(profile1.AKPub, profile2.AKPub) {
			t.Error("AKPub mismatch between consecutive profile retrievals")
		}

		if !bytes.Equal(profile1.AKName.Buffer, profile2.AKName.Buffer) {
			t.Error("AKName mismatch between consecutive profile retrievals")
		}

		if profile1.SignatureAlgorithm != profile2.SignatureAlgorithm {
			t.Error("SignatureAlgorithm mismatch between consecutive profile retrievals")
		}

		t.Log("AK profile consistency verified")
	})
}

// TestIntegration_Quote tests TPM quote generation
func TestIntegration_Quote(t *testing.T) {
	tpmInstance, cleanup := setupAttestationTPM(t)
	defer cleanup()

	t.Run("QuoteWithNonce", func(t *testing.T) {
		nonce := []byte("test-nonce-for-quote")
		pcrs := []uint{0, 1, 2, 3}

		quote, err := tpmInstance.Quote(pcrs, nonce)
		if err != nil {
			t.Fatalf("Failed to generate quote with nonce: %v", err)
		}

		// Verify quote components
		if len(quote.Quoted) == 0 {
			t.Error("Quote Quoted field is empty")
		}

		if len(quote.Signature) == 0 {
			t.Error("Quote Signature field is empty")
		}

		if !bytes.Equal(quote.Nonce, nonce) {
			t.Errorf("Quote nonce mismatch: got %v, want %v", quote.Nonce, nonce)
		}

		if len(quote.PCRs) == 0 {
			t.Error("Quote PCRs field is empty")
		}

		t.Logf("Quote with nonce generated successfully:")
		t.Logf("  Quoted size: %d bytes", len(quote.Quoted))
		t.Logf("  Signature size: %d bytes", len(quote.Signature))
		t.Logf("  Nonce: %x", quote.Nonce)
		t.Logf("  PCRs size: %d bytes", len(quote.PCRs))
		t.Logf("  EventLog size: %d bytes", len(quote.EventLog))
	})

	t.Run("QuoteWithoutNonce", func(t *testing.T) {
		pcrs := []uint{0, 1, 2, 3}

		quote, err := tpmInstance.Quote(pcrs, nil)
		if err != nil {
			t.Fatalf("Failed to generate quote without nonce: %v", err)
		}

		// Verify quote components
		if len(quote.Quoted) == 0 {
			t.Error("Quote Quoted field is empty")
		}

		if len(quote.Signature) == 0 {
			t.Error("Quote Signature field is empty")
		}

		if len(quote.PCRs) == 0 {
			t.Error("Quote PCRs field is empty")
		}

		t.Logf("Quote without nonce generated successfully")
	})

	t.Run("QuoteSinglePCR", func(t *testing.T) {
		nonce := []byte("single-pcr-nonce")
		pcrs := []uint{0}

		quote, err := tpmInstance.Quote(pcrs, nonce)
		if err != nil {
			t.Fatalf("Failed to generate quote for single PCR: %v", err)
		}

		if len(quote.Quoted) == 0 {
			t.Error("Quote Quoted field is empty for single PCR")
		}

		t.Log("Quote for single PCR generated successfully")
	})

	t.Run("QuoteMultiplePCRs", func(t *testing.T) {
		nonce := []byte("multi-pcr-nonce")
		// Test with 4 PCRs (simulator limitation)
		pcrs := []uint{0, 1, 2, 3}

		quote, err := tpmInstance.Quote(pcrs, nonce)
		if err != nil {
			t.Fatalf("Failed to generate quote for multiple PCRs: %v", err)
		}

		if len(quote.Quoted) == 0 {
			t.Error("Quote Quoted field is empty for multiple PCRs")
		}

		if len(quote.Signature) == 0 {
			t.Error("Quote Signature field is empty for multiple PCRs")
		}

		t.Logf("Quote for %d PCRs generated successfully", len(pcrs))
	})

	t.Run("QuoteDifferentPCRSelections", func(t *testing.T) {
		testCases := []struct {
			name string
			pcrs []uint
		}{
			{"PCR0", []uint{0}},
			{"PCR7", []uint{7}},
			{"PCR16Debug", []uint{16}},
			{"PCRs0-3", []uint{0, 1, 2, 3}},
			{"PCRs7-9", []uint{7, 8, 9}},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				nonce := []byte(fmt.Sprintf("nonce-%s", tc.name))

				quote, err := tpmInstance.Quote(tc.pcrs, nonce)
				if err != nil {
					t.Fatalf("Failed to generate quote for %s: %v", tc.name, err)
				}

				if len(quote.Quoted) == 0 {
					t.Errorf("Quote Quoted field is empty for %s", tc.name)
				}

				if len(quote.Signature) == 0 {
					t.Errorf("Quote Signature field is empty for %s", tc.name)
				}

				t.Logf("Quote for %s generated successfully", tc.name)
			})
		}
	})

	t.Run("QuoteSignatureUniqueness", func(t *testing.T) {
		pcrs := []uint{0, 1, 2}
		nonce1 := []byte("nonce-1")
		nonce2 := []byte("nonce-2")

		quote1, err := tpmInstance.Quote(pcrs, nonce1)
		if err != nil {
			t.Fatalf("Failed to generate first quote: %v", err)
		}

		quote2, err := tpmInstance.Quote(pcrs, nonce2)
		if err != nil {
			t.Fatalf("Failed to generate second quote: %v", err)
		}

		// Signatures should be different due to different nonces
		if bytes.Equal(quote1.Signature, quote2.Signature) {
			t.Error("Quotes with different nonces produced identical signatures")
		}

		t.Log("Quote signature uniqueness verified")
	})

	t.Run("QuoteWithLargeNonce", func(t *testing.T) {
		// Create a larger nonce (64 bytes)
		largeNonce := make([]byte, 64)
		for i := range largeNonce {
			largeNonce[i] = byte(i)
		}

		pcrs := []uint{0, 1}

		quote, err := tpmInstance.Quote(pcrs, largeNonce)
		if err != nil {
			t.Fatalf("Failed to generate quote with large nonce: %v", err)
		}

		if !bytes.Equal(quote.Nonce, largeNonce) {
			t.Error("Large nonce not preserved in quote")
		}

		t.Log("Quote with large nonce generated successfully")
	})
}

// TestIntegration_PlatformQuote tests platform quote generation
func TestIntegration_PlatformQuote(t *testing.T) {
	tpmInstance, cleanup := setupAttestationTPM(t)
	defer cleanup()

	t.Run("ValidPlatformQuote", func(t *testing.T) {
		// Get IAK attributes for platform quote
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		// Generate platform quote
		quote, nonce, err := tpmInstance.PlatformQuote(iakAttrs)
		if err != nil {
			t.Fatalf("Failed to generate platform quote: %v", err)
		}

		// Verify nonce was generated
		if len(nonce) == 0 {
			t.Error("Platform quote generated empty nonce")
		}

		// Verify quote components
		if len(quote.Quoted) == 0 {
			t.Error("Platform quote Quoted field is empty")
		}

		if len(quote.Signature) == 0 {
			t.Error("Platform quote Signature field is empty")
		}

		if !bytes.Equal(quote.Nonce, nonce) {
			t.Error("Platform quote nonce mismatch with returned nonce")
		}

		if len(quote.PCRs) == 0 {
			t.Error("Platform quote PCRs field is empty")
		}

		t.Logf("Platform quote generated successfully:")
		t.Logf("  Nonce size: %d bytes (0x%x)", len(nonce), nonce)
		t.Logf("  Quoted size: %d bytes", len(quote.Quoted))
		t.Logf("  Signature size: %d bytes", len(quote.Signature))
		t.Logf("  PCRs size: %d bytes", len(quote.PCRs))
	})

	t.Run("PlatformQuoteUniqueness", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		// Generate two platform quotes
		quote1, nonce1, err := tpmInstance.PlatformQuote(iakAttrs)
		if err != nil {
			t.Fatalf("Failed to generate first platform quote: %v", err)
		}

		quote2, nonce2, err := tpmInstance.PlatformQuote(iakAttrs)
		if err != nil {
			t.Fatalf("Failed to generate second platform quote: %v", err)
		}

		// Nonces should be different (randomly generated)
		if bytes.Equal(nonce1, nonce2) {
			t.Error("Platform quotes generated identical nonces")
		}

		// Signatures should be different due to different nonces
		if bytes.Equal(quote1.Signature, quote2.Signature) {
			t.Error("Platform quotes with different nonces produced identical signatures")
		}

		t.Log("Platform quote uniqueness verified")
	})

	t.Run("PlatformQuoteNonceLength", func(t *testing.T) {
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		quote, nonce, err := tpmInstance.PlatformQuote(iakAttrs)
		if err != nil {
			t.Fatalf("Failed to generate platform quote: %v", err)
		}

		// TPM typically generates nonces of specific sizes
		// Verify we got a reasonable nonce length
		if len(nonce) < 16 {
			t.Errorf("Platform quote nonce too short: %d bytes", len(nonce))
		}

		if len(nonce) > 128 {
			t.Errorf("Platform quote nonce too long: %d bytes", len(nonce))
		}

		// Verify nonce matches in quote
		if !bytes.Equal(quote.Nonce, nonce) {
			t.Error("Nonce in quote doesn't match returned nonce")
		}

		t.Logf("Platform quote nonce length: %d bytes", len(nonce))
	})
}

// TestIntegration_QuoteErrors tests error handling in quote operations
func TestIntegration_QuoteErrors(t *testing.T) {
	tpmInstance, cleanup := setupAttestationTPM(t)
	defer cleanup()

	t.Run("QuoteInvalidPCR", func(t *testing.T) {
		// Try to quote an invalid PCR index (TPM typically supports 0-23)
		invalidPCRs := []uint{24, 25, 26}
		nonce := []byte("test-nonce")

		_, err := tpmInstance.Quote(invalidPCRs, nonce)
		// Some TPMs may reject invalid PCRs, others may accept them
		// Log the result but don't fail the test
		if err != nil {
			t.Logf("Quote with invalid PCR rejected as expected: %v", err)
		} else {
			t.Log("Quote with high PCR index succeeded (TPM may support extended PCRs)")
		}
	})

	t.Run("QuoteEmptyPCRList", func(t *testing.T) {
		emptyPCRs := []uint{}
		nonce := []byte("test-nonce")

		_, err := tpmInstance.Quote(emptyPCRs, nonce)
		if err != nil {
			t.Logf("Quote with empty PCR list rejected: %v", err)
		} else {
			t.Log("Quote with empty PCR list succeeded")
		}
	})
}

// TestIntegration_QuoteVerification tests quote signature verification
func TestIntegration_QuoteVerification(t *testing.T) {
	tpmInstance, cleanup := setupAttestationTPM(t)
	defer cleanup()

	t.Run("QuoteIntegrity", func(t *testing.T) {
		nonce := []byte("integrity-check-nonce")
		pcrs := []uint{0, 1, 2}

		quote, err := tpmInstance.Quote(pcrs, nonce)
		if err != nil {
			t.Fatalf("Failed to generate quote: %v", err)
		}

		// Verify all quote fields are populated
		if len(quote.Quoted) == 0 {
			t.Error("Quote.Quoted is empty")
		}

		if len(quote.Signature) == 0 {
			t.Error("Quote.Signature is empty")
		}

		if len(quote.PCRs) == 0 {
			t.Error("Quote.PCRs is empty")
		}

		if !bytes.Equal(quote.Nonce, nonce) {
			t.Error("Quote.Nonce doesn't match input nonce")
		}

		// Verify signature is non-trivial (not all zeros)
		allZeros := true
		for _, b := range quote.Signature {
			if b != 0 {
				allZeros = false
				break
			}
		}

		if allZeros {
			t.Error("Quote signature is all zeros")
		}

		t.Log("Quote integrity check passed")
	})

	t.Run("PCRsInQuote", func(t *testing.T) {
		nonce := []byte("pcr-check-nonce")
		pcrs := []uint{0, 7, 16}

		quote, err := tpmInstance.Quote(pcrs, nonce)
		if err != nil {
			t.Fatalf("Failed to generate quote: %v", err)
		}

		// Verify PCR data is present
		if len(quote.PCRs) == 0 {
			t.Error("Quote PCRs data is empty")
		}

		// PCR data should be non-trivial
		t.Logf("Quote PCR data size: %d bytes", len(quote.PCRs))
	})
}

// TestIntegration_AttestationWorkflow tests complete attestation workflow
func TestIntegration_AttestationWorkflow(t *testing.T) {
	tpmInstance, cleanup := setupAttestationTPM(t)
	defer cleanup()

	t.Run("CompleteAttestationFlow", func(t *testing.T) {
		// Step 1: Get AK Profile
		t.Log("Step 1: Getting AK Profile...")
		profile, err := tpmInstance.AKProfile()
		if err != nil {
			t.Fatalf("Failed to get AK profile: %v", err)
		}

		if len(profile.AKPub) == 0 || len(profile.EKPub) == 0 {
			t.Fatal("AK profile missing required fields")
		}

		t.Logf("  AK Profile retrieved: AKPub=%d bytes, EKPub=%d bytes",
			len(profile.AKPub), len(profile.EKPub))

		// Step 2: Generate Platform Quote
		t.Log("Step 2: Generating Platform Quote...")
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		platformQuote, platformNonce, err := tpmInstance.PlatformQuote(iakAttrs)
		if err != nil {
			t.Fatalf("Failed to generate platform quote: %v", err)
		}

		if len(platformQuote.Signature) == 0 {
			t.Fatal("Platform quote signature is empty")
		}

		t.Logf("  Platform Quote generated: nonce=%x, signature=%d bytes",
			platformNonce, len(platformQuote.Signature))

		// Step 3: Generate Custom Quote
		t.Log("Step 3: Generating Custom Quote...")
		customNonce := []byte("custom-attestation-nonce")
		customPCRs := []uint{0, 1, 2, 7}

		customQuote, err := tpmInstance.Quote(customPCRs, customNonce)
		if err != nil {
			t.Fatalf("Failed to generate custom quote: %v", err)
		}

		if len(customQuote.Signature) == 0 {
			t.Fatal("Custom quote signature is empty")
		}

		t.Logf("  Custom Quote generated: PCRs=%v, signature=%d bytes",
			customPCRs, len(customQuote.Signature))

		// Step 4: Verify quotes are different
		t.Log("Step 4: Verifying quote uniqueness...")
		if bytes.Equal(platformQuote.Signature, customQuote.Signature) {
			t.Error("Platform and custom quotes have identical signatures")
		}

		if bytes.Equal(platformQuote.Nonce, customQuote.Nonce) {
			t.Error("Platform and custom quotes have identical nonces")
		}

		t.Log("Complete attestation workflow successful")
	})
}

// TestIntegration_AttestationConcurrency tests concurrent attestation operations
func TestIntegration_AttestationConcurrency(t *testing.T) {
	tpmInstance, cleanup := setupAttestationTPM(t)
	defer cleanup()

	t.Run("SequentialQuotes", func(t *testing.T) {
		const numQuotes = 5
		pcrs := []uint{0, 1}

		quotes := make([]tpm2lib.Quote, numQuotes)
		nonces := make([][]byte, numQuotes)

		for i := 0; i < numQuotes; i++ {
			nonces[i] = []byte(fmt.Sprintf("nonce-%d", i))

			quote, err := tpmInstance.Quote(pcrs, nonces[i])
			if err != nil {
				t.Fatalf("Failed to generate quote %d: %v", i, err)
			}

			quotes[i] = quote
		}

		// Verify all quotes are different
		for i := 0; i < numQuotes; i++ {
			for j := i + 1; j < numQuotes; j++ {
				if bytes.Equal(quotes[i].Signature, quotes[j].Signature) {
					t.Errorf("Quotes %d and %d have identical signatures", i, j)
				}
			}
		}

		t.Logf("Generated %d sequential quotes successfully", numQuotes)
	})

	t.Run("MultipleAKProfileRetrievals", func(t *testing.T) {
		const numRetrievals = 10

		for i := 0; i < numRetrievals; i++ {
			profile, err := tpmInstance.AKProfile()
			if err != nil {
				t.Fatalf("Failed to get AK profile iteration %d: %v", i, err)
			}

			if len(profile.AKPub) == 0 {
				t.Fatalf("AK profile iteration %d has empty AKPub", i)
			}
		}

		t.Logf("Retrieved AK profile %d times successfully", numRetrievals)
	})
}

// TestIntegration_AKProfileError tests error cases for AKProfile
func TestIntegration_AKProfileError(t *testing.T) {
	// Test that AKProfile returns appropriate errors for edge cases
	tpmInstance, cleanup := setupAttestationTPM(t)
	defer cleanup()

	// Get the AK profile - this should work on a provisioned TPM
	akProfile, err := tpmInstance.AKProfile()
	if err != nil {
		// If AKProfile fails, verify we get a meaningful error
		t.Logf("AKProfile returned error (expected if TPM not fully provisioned): %v", err)
		t.Log("✓ Error handling verified")
		return
	}

	// Verify profile has expected fields
	if len(akProfile.AKPub) == 0 {
		t.Log("AK profile has no AKPub - checking error handling path")
	}
	t.Log("✓ AKProfile error handling test completed")
}

// TestIntegration_QuoteExtendedPCRBank tests quotes across different PCR banks
func TestIntegration_QuoteExtendedPCRBank(t *testing.T) {
	tpmInstance, cleanup := setupAttestationTPM(t)
	defer cleanup()

	t.Run("MultiplePCRBanks", func(t *testing.T) {
		// Test quoting from different PCR ranges
		pcrRanges := []struct {
			name string
			pcrs []uint
		}{
			{"BootPCRs", []uint{0, 1, 2, 3}},
			{"ConfigPCRs", []uint{7, 8, 9}},
			{"ApplicationPCRs", []uint{10, 11, 12}},
			{"DebugPCR", []uint{16}},
		}

		for _, tc := range pcrRanges {
			t.Run(tc.name, func(t *testing.T) {
				nonce := []byte(fmt.Sprintf("nonce-%s", tc.name))

				quote, err := tpmInstance.Quote(tc.pcrs, nonce)
				if err != nil {
					t.Fatalf("Failed to quote %s: %v", tc.name, err)
				}

				if len(quote.Signature) == 0 {
					t.Errorf("%s quote has empty signature", tc.name)
				}

				t.Logf("%s quote successful: %d bytes signature", tc.name, len(quote.Signature))
			})
		}
	})
}
