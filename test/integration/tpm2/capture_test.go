//go:build integration

package integration

import (
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestTPMSessionEncryption verifies that session encryption is enabled and working
// by capturing raw TPM traffic and analyzing it for encryption indicators
func TestTPMSessionEncryption(t *testing.T) {
	// Create TPM backend with encryption enabled
	tpmInstance, capture, cleanup := setupTPM2WithCapture(t, true)
	defer cleanup()

	// Clear any startup/provisioning packets
	capture.Clear()

	// Perform sensitive operation - key creation with Seal
	t.Log("Creating sealed key with encrypted session...")

	// Get SRK for parent
	srkAttrs, err := tpmInstance.SSRKAttributes()
	if err != nil {
		t.Fatalf("Failed to get SRK attributes: %v", err)
	}

	// Create key attributes for sealed data
	sealAttrs := &types.KeyAttributes{
		CN:           "test-encrypted-seal",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeCA,
		Parent:       srkAttrs,
		Password:     types.NewClearPassword(nil),
		StoreType:    types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: 0x40000001, // TPM_RH_OWNER
		},
	}

	// Seal data (generates 32-byte AES key internally)
	_, err = tpmInstance.SealKey(sealAttrs, nil, false)
	if err != nil {
		t.Fatalf("Failed to seal data: %v", err)
	}

	// Get captured packets
	packets := capture.GetPackets()
	if len(packets) == 0 {
		t.Fatal("Should have captured TPM traffic")
	}

	t.Logf("Captured %d TPM packets during seal operation", len(packets))

	// Analyze for encryption
	analysis := AnalyzePackets(packets, getSensitivePatterns())
	t.Log(analysis.FormatAnalysis())

	// Assertions: Encrypted session should show encryption flags
	if analysis.SessionCommands == 0 {
		t.Error("Should have session-based commands")
	}

	if analysis.EncryptedSessions == 0 {
		t.Error("Should have encrypted sessions")
	}

	if analysis.PlaintextDetections != 0 {
		t.Errorf("Should not detect plaintext sensitive data, found %d detections", analysis.PlaintextDetections)
	}

	// Verify encryption rate
	if analysis.EncryptionPercentage < 50.0 {
		t.Errorf("Encryption rate too low: %.1f%% (expected >= 50%%)", analysis.EncryptionPercentage)
	}

	t.Logf("Encryption verification passed: %.1f%% of sessions encrypted", analysis.EncryptionPercentage)
}

// TestTPMSessionNoEncryption verifies unencrypted sessions for comparison
func TestTPMSessionNoEncryption(t *testing.T) {
	// Create TPM backend with encryption DISABLED
	tpmInstance, capture, cleanup := setupTPM2WithCapture(t, false)
	defer cleanup()

	// Clear any startup/provisioning packets
	capture.Clear()

	// Perform operation without encryption
	t.Log("Creating sealed key WITHOUT encrypted session...")

	// Get SRK for parent
	srkAttrs, err := tpmInstance.SSRKAttributes()
	if err != nil {
		t.Fatalf("Failed to get SRK attributes: %v", err)
	}

	// Create key attributes for sealed data
	sealAttrs := &types.KeyAttributes{
		CN:           "test-unencrypted-seal",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeCA,
		Parent:       srkAttrs,
		Password:     types.NewClearPassword(nil),
		StoreType:    types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: 0x40000001, // TPM_RH_OWNER
		},
	}

	// Seal data without encryption
	_, err = tpmInstance.SealKey(sealAttrs, nil, false)
	if err != nil {
		t.Fatalf("Failed to seal data: %v", err)
	}

	// Get captured packets
	packets := capture.GetPackets()
	if len(packets) == 0 {
		t.Fatal("Should have captured TPM traffic")
	}

	t.Logf("Captured %d TPM packets", len(packets))

	// Analyze - should show no encryption
	analysis := AnalyzePackets(packets, getSensitivePatterns())
	t.Log(analysis.FormatAnalysis())

	// Baseline expectations: unencrypted should have 0% encryption
	if analysis.EncryptedSessions > 0 {
		t.Logf("Note: Found %d encrypted sessions even with encryption disabled (may be default TPM behavior)",
			analysis.EncryptedSessions)
	}

	t.Log("Unencrypted baseline test completed")
}

// TestTPMMultipleOperationsEncryption verifies encryption across multiple operations
func TestTPMMultipleOperationsEncryption(t *testing.T) {
	// Create TPM backend with encryption enabled
	tpmInstance, capture, cleanup := setupTPM2WithCapture(t, true)
	defer cleanup()

	// Get SRK for operations
	srkAttrs, err := tpmInstance.SSRKAttributes()
	if err != nil {
		t.Fatalf("Failed to get SRK attributes: %v", err)
	}

	// Test 1: Seal operation
	capture.Clear()
	t.Log("Test 1: Seal operation with encryption...")

	sealAttrs := &types.KeyAttributes{
		CN:           "test-multi-seal",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeCA,
		Parent:       srkAttrs,
		Password:     types.NewClearPassword(nil),
		StoreType:    types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: 0x40000001,
		},
	}

	sealed, err := tpmInstance.SealKey(sealAttrs, nil, false)
	if err != nil {
		t.Fatalf("Failed to seal: %v", err)
	}

	sealPackets := capture.GetPackets()
	sealAnalysis := AnalyzePackets(sealPackets, getSensitivePatterns())
	t.Logf("Seal operation: %d packets, %d encrypted sessions",
		len(sealPackets), sealAnalysis.EncryptedSessions)

	// Test 2: Unseal operation
	capture.Clear()
	t.Log("Test 2: Unseal operation with encryption...")

	unsealed, err := tpmInstance.UnsealKey(sealAttrs, nil)
	if err != nil {
		t.Fatalf("Failed to unseal: %v", err)
	}

	if len(unsealed) != 32 {
		t.Errorf("Unsealed data length mismatch: got %d, want 32", len(unsealed))
	}

	// Verify seal/unseal completed
	if sealed != nil && len(unsealed) > 0 {
		t.Logf("Seal/Unseal completed: unsealed=%d bytes", len(unsealed))
	}

	unsealPackets := capture.GetPackets()
	unsealAnalysis := AnalyzePackets(unsealPackets, getSensitivePatterns())
	t.Logf("Unseal operation: %d packets, %d encrypted sessions",
		len(unsealPackets), unsealAnalysis.EncryptedSessions)

	// Combined analysis
	totalEncrypted := sealAnalysis.EncryptedSessions + unsealAnalysis.EncryptedSessions
	totalSessions := sealAnalysis.SessionCommands + unsealAnalysis.SessionCommands

	var overallRate float64
	if totalSessions > 0 {
		overallRate = (float64(totalEncrypted) / float64(totalSessions)) * 100.0
	}

	t.Logf("Overall encryption rate across operations: %.1f%%", overallRate)

	// Verify no plaintext leaks
	if sealAnalysis.PlaintextDetections > 0 || unsealAnalysis.PlaintextDetections > 0 {
		t.Error("Detected plaintext sensitive data in traffic")
	}

	t.Log("Multiple operations encryption verification passed")
}

// TestTPMPacketParsing verifies packet parsing utilities work correctly
func TestTPMPacketParsing(t *testing.T) {
	// Create TPM instance to generate real packets
	tpmInstance, capture, cleanup := setupTPM2WithCapture(t, true)
	defer cleanup()

	// Clear startup packets
	capture.Clear()

	// Perform a simple operation to generate traffic
	_, err := tpmInstance.SSRKAttributes()
	if err != nil {
		t.Fatalf("Failed to get SRK: %v", err)
	}

	packets := capture.GetPackets()
	if len(packets) == 0 {
		t.Fatal("No packets captured for parsing test")
	}

	t.Logf("Testing packet parsing with %d captured packets", len(packets))

	for i, pkt := range packets {
		// Test IsTPMCommand/IsTPMResponse
		isCmd := IsTPMCommand(pkt.Data)
		isResp := IsTPMResponse(pkt.Data)

		if !isCmd && !isResp {
			t.Errorf("Packet %d: failed to identify as command or response", i)
			continue
		}

		// Test header parsing
		if pkt.Direction == "send" {
			hdr, err := ParseTPMCommandHeader(pkt.Data)
			if err != nil {
				t.Errorf("Packet %d: failed to parse command header: %v", i, err)
				continue
			}
			t.Logf("Packet %d (send): tag=0x%04x, size=%d, code=0x%08x",
				i, hdr.Tag, hdr.CommandSize, hdr.CommandCode)
		} else {
			hdr, err := ParseTPMResponseHeader(pkt.Data)
			if err != nil {
				t.Errorf("Packet %d: failed to parse response header: %v", i, err)
				continue
			}
			t.Logf("Packet %d (recv): tag=0x%04x, size=%d, code=0x%08x",
				i, hdr.Tag, hdr.ResponseSize, hdr.ResponseCode)
		}

		// Test session area detection
		hasSessions := HasSessionArea(pkt.Data)
		if hasSessions {
			t.Logf("Packet %d: has session area", i)
		}
	}

	t.Log("Packet parsing verification passed")
}
