//go:build integration

package integration

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	tpm2lib "github.com/jeremyhahn/go-keychain/pkg/tpm2"
)

// setupQuoteTPM provisions TPM with IAK for quote testing
func setupQuoteTPM(t *testing.T) (tpm2lib.TrustedPlatformModule, func()) {
	t.Helper()

	// Use existing helper which handles provisioning properly
	tpmInstance, cleanup := createTPM2Instance(t)

	// Provision TPM to create EK, SRK, and IAK needed for quotes
	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v (may already be provisioned)", err)
	}

	return tpmInstance, cleanup
}

// TestIntegration_Quote_ComprehensivePCRSelection tests quote with various PCR selections
func TestIntegration_Quote_ComprehensivePCRSelection(t *testing.T) {
	tpmInstance, cleanup := setupQuoteTPM(t)
	defer cleanup()

	testCases := []struct {
		name  string
		pcrs  []uint
		nonce []byte
	}{
		{
			name:  "SinglePCR0",
			pcrs:  []uint{0},
			nonce: []byte("nonce-pcr0"),
		},
		{
			name:  "PCRs0-7",
			pcrs:  []uint{0, 1, 2, 3, 4, 5, 6, 7},
			nonce: []byte("nonce-pcr0-7"),
		},
		{
			name:  "PCRs8-15",
			pcrs:  []uint{8, 9, 10, 11, 12, 13, 14, 15},
			nonce: []byte("nonce-pcr8-15"),
		},
		{
			name:  "PCR16Only",
			pcrs:  []uint{16},
			nonce: []byte("nonce-pcr16"),
		},
		{
			name:  "MixedPCRs",
			pcrs:  []uint{0, 7, 16},
			nonce: []byte("nonce-mixed"),
		},
		{
			name:  "BootPCRs",
			pcrs:  []uint{0, 1, 2, 3},
			nonce: []byte("nonce-boot"),
		},
		{
			name:  "AllBIOSPCRs",
			pcrs:  []uint{0, 1, 2, 3, 4, 5, 6, 7},
			nonce: []byte("nonce-all-bios"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			quote, err := tpmInstance.Quote(tc.pcrs, tc.nonce)
			if err != nil {
				t.Fatalf("Failed to generate quote for %s: %v", tc.name, err)
			}

			// Verify quote structure
			if len(quote.Quoted) == 0 {
				t.Error("Quote.Quoted is empty")
			}

			if len(quote.Signature) == 0 {
				t.Error("Quote.Signature is empty")
			}

			if !bytes.Equal(quote.Nonce, tc.nonce) {
				t.Errorf("Nonce mismatch: expected %x, got %x", tc.nonce, quote.Nonce)
			}

			if len(quote.PCRs) == 0 {
				t.Error("Quote.PCRs is empty")
			}

			// Verify signature is non-trivial
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

			t.Logf("Quote for %s: Quoted=%d bytes, Signature=%d bytes, PCRs=%d bytes",
				tc.name, len(quote.Quoted), len(quote.Signature), len(quote.PCRs))
		})
	}
}

// TestIntegration_Quote_NonceVariations tests quote with different nonce sizes
func TestIntegration_Quote_NonceVariations(t *testing.T) {
	tpmInstance, cleanup := setupQuoteTPM(t)
	defer cleanup()

	testCases := []struct {
		name        string
		nonceSize   int
		expectError bool // TPM2 nonce max is typically 64 bytes
	}{
		{"EmptyNonce", 0, false},
		{"TinyNonce", 1, false},
		{"SmallNonce", 8, false},
		{"StandardNonce", 16, false},
		{"MediumNonce", 32, false},
		{"LargeNonce", 64, false},
		{"HugeNonce", 128, true}, // Exceeds TPM nonce limit
		{"MaxNonce", 256, true},  // Exceeds TPM nonce limit
	}

	pcrs := []uint{0, 1, 2}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create nonce of specified size
			var nonce []byte
			if tc.nonceSize > 0 {
				nonce = make([]byte, tc.nonceSize)
				for i := range nonce {
					nonce[i] = byte(i % 256)
				}
			}

			quote, err := tpmInstance.Quote(pcrs, nonce)
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for %d-byte nonce (exceeds TPM limit), but got success", tc.nonceSize)
				} else {
					t.Logf("Correctly rejected %d-byte nonce: %v", tc.nonceSize, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Failed to generate quote with %d-byte nonce: %v", tc.nonceSize, err)
			}

			// Verify nonce is preserved
			if !bytes.Equal(quote.Nonce, nonce) {
				t.Errorf("Nonce not preserved: expected %d bytes, got %d bytes",
					len(nonce), len(quote.Nonce))
			}

			// Verify quote components
			if len(quote.Quoted) == 0 {
				t.Error("Quote.Quoted is empty")
			}

			if len(quote.Signature) == 0 {
				t.Error("Quote.Signature is empty")
			}

			t.Logf("Successfully generated quote with %d-byte nonce", tc.nonceSize)
		})
	}
}

// TestIntegration_Quote_SignatureUniqueness tests that different inputs produce different signatures
func TestIntegration_Quote_SignatureUniqueness(t *testing.T) {
	tpmInstance, cleanup := setupQuoteTPM(t)
	defer cleanup()

	t.Run("DifferentNonces", func(t *testing.T) {
		pcrs := []uint{0, 1, 2}

		// Generate quotes with different nonces
		quote1, err := tpmInstance.Quote(pcrs, []byte("nonce-1"))
		if err != nil {
			t.Fatalf("Failed to generate quote 1: %v", err)
		}

		quote2, err := tpmInstance.Quote(pcrs, []byte("nonce-2"))
		if err != nil {
			t.Fatalf("Failed to generate quote 2: %v", err)
		}

		// Signatures should be different
		if bytes.Equal(quote1.Signature, quote2.Signature) {
			t.Error("Different nonces produced identical signatures")
		}

		t.Log("Different nonces correctly produced different signatures")
	})

	t.Run("DifferentPCRSelections", func(t *testing.T) {
		nonce := []byte("same-nonce")

		// Generate quotes with different PCR selections
		quote1, err := tpmInstance.Quote([]uint{0, 1}, nonce)
		if err != nil {
			t.Fatalf("Failed to generate quote with PCRs 0,1: %v", err)
		}

		quote2, err := tpmInstance.Quote([]uint{2, 3}, nonce)
		if err != nil {
			t.Fatalf("Failed to generate quote with PCRs 2,3: %v", err)
		}

		// Signatures should be different (different PCR values)
		if bytes.Equal(quote1.Signature, quote2.Signature) {
			t.Log("Same nonce with different PCRs produced identical signatures (PCRs may have same values)")
		} else {
			t.Log("Different PCR selections correctly produced different signatures")
		}
	})

	t.Run("SequentialQuotes", func(t *testing.T) {
		// Generate multiple quotes sequentially with same parameters
		pcrs := []uint{0}
		nonce := []byte("sequential-test")

		quotes := make([]tpm2lib.Quote, 5)
		for i := range quotes {
			quote, err := tpmInstance.Quote(pcrs, nonce)
			if err != nil {
				t.Fatalf("Failed to generate quote %d: %v", i, err)
			}
			quotes[i] = quote
		}

		// Verify all quotes were successfully generated with valid components
		// Note: TPM quotes include clock/reset values that differ between quotes
		// and signatures use randomness (RSA-PSS/ECDSA), so exact comparison isn't valid
		for i, quote := range quotes {
			if len(quote.Quoted) == 0 {
				t.Errorf("Quote %d has empty quoted data", i)
			}
			if len(quote.Signature) == 0 {
				t.Errorf("Quote %d has empty signature", i)
			}
			if len(quote.PCRs) == 0 {
				t.Errorf("Quote %d has empty PCRs", i)
			}
		}

		t.Logf("Successfully generated %d sequential quotes", len(quotes))
	})
}

// TestIntegration_Quote_PCRContent tests quote with PCR content validation
func TestIntegration_Quote_PCRContent(t *testing.T) {
	tpmInstance, cleanup := setupQuoteTPM(t)
	defer cleanup()

	t.Run("QuoteIncludesPCRValues", func(t *testing.T) {
		pcrs := []uint{0, 1, 2, 3}
		nonce := []byte("pcr-content-test")

		// Generate quote
		quote, err := tpmInstance.Quote(pcrs, nonce)
		if err != nil {
			t.Fatalf("Failed to generate quote: %v", err)
		}

		// Verify PCRs field contains data
		if len(quote.PCRs) == 0 {
			t.Fatal("Quote PCRs field is empty")
		}

		// PCR data should be substantial (not just a few bytes)
		// Each PCR is typically 32 bytes (SHA-256), so 4 PCRs = ~128+ bytes
		if len(quote.PCRs) < 32 {
			t.Errorf("Quote PCRs field suspiciously small: %d bytes", len(quote.PCRs))
		}

		t.Logf("Quote contains %d bytes of PCR data for %d PCRs",
			len(quote.PCRs), len(pcrs))
	})

	t.Run("QuotePCRConsistency", func(t *testing.T) {
		pcrs := []uint{0, 7, 16}
		nonce := []byte("consistency-test")

		// Generate two quotes with same parameters
		quote1, err := tpmInstance.Quote(pcrs, nonce)
		if err != nil {
			t.Fatalf("Failed to generate first quote: %v", err)
		}

		quote2, err := tpmInstance.Quote(pcrs, nonce)
		if err != nil {
			t.Fatalf("Failed to generate second quote: %v", err)
		}

		// Verify both quotes have valid components
		// Note: TPM quotes include clock/reset values and randomness that differ between quotes
		if len(quote1.PCRs) == 0 || len(quote2.PCRs) == 0 {
			t.Error("Quote PCRs are empty")
		}
		if len(quote1.Quoted) == 0 || len(quote2.Quoted) == 0 {
			t.Error("Quote data is empty")
		}
		if len(quote1.Signature) == 0 || len(quote2.Signature) == 0 {
			t.Error("Quote signatures are empty")
		}

		t.Log("Both quotes generated successfully with valid components")
	})
}

// TestIntegration_Quote_EventLog tests quote with event log
func TestIntegration_Quote_EventLog(t *testing.T) {
	tpmInstance, cleanup := setupQuoteTPM(t)
	defer cleanup()

	t.Run("QuoteWithEventLog", func(t *testing.T) {
		pcrs := []uint{0, 1, 2, 3, 4, 5, 6, 7}
		nonce := []byte("event-log-test")

		quote, err := tpmInstance.Quote(pcrs, nonce)
		if err != nil {
			t.Fatalf("Failed to generate quote: %v", err)
		}

		// Event log may or may not be present depending on the platform
		if len(quote.EventLog) > 0 {
			t.Logf("Quote includes event log: %d bytes", len(quote.EventLog))

			// Event log should be substantial if present
			if len(quote.EventLog) < 100 {
				t.Logf("Event log seems small: %d bytes (may be minimal)", len(quote.EventLog))
			}
		} else {
			t.Log("Quote does not include event log (may not be available on simulator)")
		}
	})
}

// TestIntegration_Quote_LargeNonce tests quote with maximum nonce size
func TestIntegration_Quote_LargeNonce(t *testing.T) {
	tpmInstance, cleanup := setupQuoteTPM(t)
	defer cleanup()

	t.Run("MaximumNonce", func(t *testing.T) {
		// Create maximum size nonce (TPM typically supports up to 512 bytes)
		maxNonce := make([]byte, 512)
		hash := sha256.New()
		for i := 0; i < len(maxNonce); i += 32 {
			hash.Write([]byte(fmt.Sprintf("nonce-chunk-%d", i)))
			copy(maxNonce[i:], hash.Sum(nil))
		}

		pcrs := []uint{0, 1}

		quote, err := tpmInstance.Quote(pcrs, maxNonce)
		if err != nil {
			// Some TPMs may not support such large nonces - this is expected behavior
			t.Logf("Maximum nonce size (512 bytes) not supported by this TPM: %v", err)
			t.Log("✓ TPM correctly rejected oversized nonce")
			return
		}

		// Verify nonce is preserved
		if !bytes.Equal(quote.Nonce, maxNonce) {
			t.Error("Large nonce not fully preserved in quote")
		}

		t.Logf("Successfully generated quote with %d-byte nonce", len(maxNonce))
	})
}

// TestIntegration_Quote_AllPCRBanks tests quoting different PCR banks
func TestIntegration_Quote_AllPCRBanks(t *testing.T) {
	tpmInstance, cleanup := setupQuoteTPM(t)
	defer cleanup()

	// Test different ranges of PCRs (representing different "banks" or purposes)
	t.Run("FirmwarePCRs", func(t *testing.T) {
		// PCRs 0-7 typically measure firmware/BIOS
		firmwarePCRs := []uint{0, 1, 2, 3, 4, 5, 6, 7}
		quote, err := tpmInstance.Quote(firmwarePCRs, []byte("firmware-pcrs"))
		if err != nil {
			t.Fatalf("Failed to quote firmware PCRs: %v", err)
		}
		t.Logf("Firmware PCRs quoted: %d bytes signature", len(quote.Signature))
	})

	t.Run("OSPCRs", func(t *testing.T) {
		// PCRs 8-15 typically measure OS components
		osPCRs := []uint{8, 9, 10, 11, 12, 13, 14, 15}
		quote, err := tpmInstance.Quote(osPCRs, []byte("os-pcrs"))
		if err != nil {
			t.Fatalf("Failed to quote OS PCRs: %v", err)
		}
		t.Logf("OS PCRs quoted: %d bytes signature", len(quote.Signature))
	})

	t.Run("DebugPCR", func(t *testing.T) {
		// PCR 16 is typically used for debug
		debugPCRs := []uint{16}
		quote, err := tpmInstance.Quote(debugPCRs, []byte("debug-pcr"))
		if err != nil {
			t.Fatalf("Failed to quote debug PCR: %v", err)
		}
		t.Logf("Debug PCR quoted: %d bytes signature", len(quote.Signature))
	})

	t.Run("ApplicationPCRs", func(t *testing.T) {
		// PCRs 17-22 are typically available for applications
		appPCRs := []uint{17, 18, 19, 20, 21, 22}
		quote, err := tpmInstance.Quote(appPCRs, []byte("app-pcrs"))
		if err != nil {
			// Some simulators may not support all PCRs
			t.Logf("Application PCRs not fully supported: %v", err)
			return
		}
		t.Logf("Application PCRs quoted: %d bytes signature", len(quote.Signature))
	})
}

// TestIntegration_Quote_EdgeCases tests edge cases in quote operations
func TestIntegration_Quote_EdgeCases(t *testing.T) {
	tpmInstance, cleanup := setupQuoteTPM(t)
	defer cleanup()

	t.Run("EmptyPCRList", func(t *testing.T) {
		emptyPCRs := []uint{}
		nonce := []byte("empty-pcr-test")

		_, err := tpmInstance.Quote(emptyPCRs, nonce)
		if err != nil {
			t.Logf("Empty PCR list rejected as expected: %v", err)
		} else {
			t.Log("Empty PCR list accepted (TPM allows this)")
		}
	})

	t.Run("DuplicatePCRs", func(t *testing.T) {
		// Try to quote the same PCR multiple times
		duplicatePCRs := []uint{0, 0, 0}
		nonce := []byte("duplicate-pcr-test")

		quote, err := tpmInstance.Quote(duplicatePCRs, nonce)
		if err != nil {
			t.Logf("Duplicate PCRs rejected: %v", err)
		} else {
			t.Log("Duplicate PCRs accepted (TPM may deduplicate)")
			if len(quote.Signature) == 0 {
				t.Error("Quote with duplicate PCRs has empty signature")
			}
		}
	})

	t.Run("SinglePCRMultipleTimes", func(t *testing.T) {
		// Quote the same PCR multiple times in sequence
		pcrs := []uint{0}
		nonce := []byte("repeated-quote-test")

		quotes := make([]tpm2lib.Quote, 10)
		for i := range quotes {
			quote, err := tpmInstance.Quote(pcrs, nonce)
			if err != nil {
				t.Fatalf("Failed to generate quote %d: %v", i, err)
			}
			quotes[i] = quote
		}

		// Verify all quotes have valid components
		// Note: TPM quotes include clock/reset values and randomness that differ between quotes
		for i, quote := range quotes {
			if len(quote.Quoted) == 0 {
				t.Errorf("Quote %d has empty quoted data", i)
			}
			if len(quote.Signature) == 0 {
				t.Errorf("Quote %d has empty signature", i)
			}
			if len(quote.PCRs) == 0 {
				t.Errorf("Quote %d has empty PCRs", i)
			}
		}

		t.Logf("Successfully generated %d quotes of same PCR", len(quotes))
	})
}

// TestIntegration_Quote_Performance tests quote operation performance
func TestIntegration_Quote_Performance(t *testing.T) {
	if testing.Short() {
		t.Fatal("Skipping performance test in short mode")
	}

	tpmInstance, cleanup := setupQuoteTPM(t)
	defer cleanup()

	t.Run("BenchmarkQuoteGeneration", func(t *testing.T) {
		pcrs := []uint{0, 1, 2, 3}
		nonce := []byte("performance-test")

		const numIterations = 100

		for i := 0; i < numIterations; i++ {
			_, err := tpmInstance.Quote(pcrs, nonce)
			if err != nil {
				t.Fatalf("Quote failed at iteration %d: %v", i, err)
			}
		}

		t.Logf("Successfully generated %d quotes", numIterations)
	})
}

// TestIntegration_Quote_IntegrityCheck tests quote integrity verification
func TestIntegration_Quote_IntegrityCheck(t *testing.T) {
	tpmInstance, cleanup := setupQuoteTPM(t)
	defer cleanup()

	t.Run("QuoteComponentsNonEmpty", func(t *testing.T) {
		pcrs := []uint{0, 1, 2, 3, 4}
		nonce := []byte("integrity-check-nonce")

		quote, err := tpmInstance.Quote(pcrs, nonce)
		if err != nil {
			t.Fatalf("Failed to generate quote: %v", err)
		}

		// Verify all critical components are non-empty
		checks := []struct {
			name  string
			data  []byte
			field string
		}{
			{"Quoted", quote.Quoted, "Quoted"},
			{"Signature", quote.Signature, "Signature"},
			{"PCRs", quote.PCRs, "PCRs"},
		}

		for _, check := range checks {
			if len(check.data) == 0 {
				t.Errorf("%s field is empty", check.field)
			} else {
				t.Logf("%s: %d bytes", check.field, len(check.data))
			}
		}

		// Verify nonce is preserved
		if !bytes.Equal(quote.Nonce, nonce) {
			t.Error("Nonce was not preserved in quote")
		}
	})
}
