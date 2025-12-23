//go:build integration && frost

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package frost_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCLI_FrostCommand tests the frost command exists
func TestCLI_FrostCommand(t *testing.T) {
	output, err := runCLI("frost", "--help")
	require.NoError(t, err, "frost command should exist")
	assert.Contains(t, output, "FROST", "Should show FROST description")
	assert.Contains(t, output, "threshold signing", "Should explain threshold signing")
	assert.Contains(t, output, "keygen", "Should list keygen subcommand")
	assert.Contains(t, output, "list", "Should list list subcommand")
	assert.Contains(t, output, "round1", "Should list round1 subcommand")
	assert.Contains(t, output, "round2", "Should list round2 subcommand")
	assert.Contains(t, output, "aggregate", "Should list aggregate subcommand")
	assert.Contains(t, output, "verify", "Should list verify subcommand")
}

// TestCLI_FrostKeygen tests key generation
func TestCLI_FrostKeygen(t *testing.T) {
	tempDir := t.TempDir()

	output, err := runCLI(
		"--local",
		"--key-dir", tempDir,
		"frost", "keygen",
		"--algorithm", "FROST-Ed25519-SHA512",
		"--threshold", "2",
		"--total", "3",
		"--participants", "alice,bob,charlie",
		"--key-id", "test-cli-key",
		"--participant-id", "1",
	)
	require.NoError(t, err, "keygen should succeed: %s", output)

	// Parse JSON output
	var result map[string]interface{}
	err = json.Unmarshal([]byte(output), &result)
	if err != nil {
		// Text output
		assert.Contains(t, output, "test-cli-key", "Should contain key ID")
	} else {
		assert.Equal(t, "test-cli-key", result["key_id"])
		assert.Equal(t, "FROST-Ed25519-SHA512", result["algorithm"])
		assert.NotEmpty(t, result["group_public_key"])
	}
}

// TestCLI_FrostList tests listing keys
func TestCLI_FrostList(t *testing.T) {
	tempDir := t.TempDir()

	// First generate a key (participant mode stores key locally)
	_, err := runCLI(
		"--local",
		"--key-dir", tempDir,
		"frost", "keygen",
		"--key-id", "list-test-key",
		"--threshold", "2",
		"--total", "3",
		"--participants", "a,b,c",
		"--participant-id", "1",
	)
	require.NoError(t, err)

	// Then list
	output, err := runCLI(
		"--local",
		"--key-dir", tempDir,
		"frost", "list",
	)
	require.NoError(t, err, "list should succeed")
	assert.Contains(t, output, "list-test-key", "Should contain the generated key")
}

// TestCLI_FrostInfo tests showing key info
func TestCLI_FrostInfo(t *testing.T) {
	tempDir := t.TempDir()

	// Generate a key (participant mode stores key locally)
	_, err := runCLI(
		"--local",
		"--key-dir", tempDir,
		"frost", "keygen",
		"--key-id", "info-test-key",
		"--threshold", "2",
		"--total", "3",
		"--participants", "a,b,c",
		"--participant-id", "1",
	)
	require.NoError(t, err)

	// Get info
	output, err := runCLI(
		"--local",
		"--key-dir", tempDir,
		"frost", "info", "info-test-key",
		"--show-public-key",
	)
	require.NoError(t, err, "info should succeed")
	assert.Contains(t, output, "info-test-key", "Should contain key ID")
}

// TestCLI_FrostDelete tests deleting keys
func TestCLI_FrostDelete(t *testing.T) {
	tempDir := t.TempDir()

	// Generate a key (participant mode stores key locally)
	_, err := runCLI(
		"--local",
		"--key-dir", tempDir,
		"frost", "keygen",
		"--key-id", "delete-test-key",
		"--threshold", "2",
		"--total", "3",
		"--participants", "a,b,c",
		"--participant-id", "1",
	)
	require.NoError(t, err)

	// Delete with force
	output, err := runCLI(
		"--local",
		"--key-dir", tempDir,
		"frost", "delete", "delete-test-key",
		"--force",
	)
	require.NoError(t, err, "delete should succeed")
	assert.Contains(t, output, "delete-test-key", "Should confirm deletion")

	// Verify key is gone
	_, err = runCLI(
		"--local",
		"--key-dir", tempDir,
		"frost", "info", "delete-test-key",
	)
	assert.Error(t, err, "Key should not exist after deletion")
}

// TestCLI_FrostSigningWorkflow tests the complete signing workflow via CLI
// using real CLI commands for key generation, distribution, and signing
func TestCLI_FrostSigningWorkflow(t *testing.T) {
	// Create directories: one for the dealer, one for each participant
	dealerDir := t.TempDir()
	participant1Dir := t.TempDir()
	participant2Dir := t.TempDir()
	exportDir := filepath.Join(dealerDir, "packages")
	keyID := "cli-signing-key"
	message := "Hello, FROST CLI!"

	// Step 1: Dealer generates all key packages
	output, err := runCLI(
		"--local",
		"--key-dir", dealerDir,
		"frost", "keygen",
		"--key-id", keyID,
		"--threshold", "2",
		"--total", "2",
		"--participants", "alice,bob",
		"--export-dir", exportDir,
	)
	require.NoError(t, err, "keygen should succeed: %s", output)
	t.Log("Dealer generated and exported key packages")

	// Verify package files were created
	package1 := filepath.Join(exportDir, "alice_participant_1.json")
	package2 := filepath.Join(exportDir, "bob_participant_2.json")
	_, err = os.Stat(package1)
	require.NoError(t, err, "Package 1 should exist")
	_, err = os.Stat(package2)
	require.NoError(t, err, "Package 2 should exist")

	// Step 2: Each participant imports their package
	output, err = runCLI(
		"--local",
		"--key-dir", participant1Dir,
		"frost", "import",
		"--package", package1,
	)
	require.NoError(t, err, "import p1 should succeed: %s", output)
	t.Log("Participant 1 (alice) imported key package")

	output, err = runCLI(
		"--local",
		"--key-dir", participant2Dir,
		"frost", "import",
		"--package", package2,
	)
	require.NoError(t, err, "import p2 should succeed: %s", output)
	t.Log("Participant 2 (bob) imported key package")

	// Step 3: Round 1 - Each participant generates nonces/commitments
	commitment1File := filepath.Join(participant1Dir, "round1.json")
	output, err = runCLI(
		"--local",
		"--key-dir", participant1Dir,
		"frost", "round1",
		"--key-id", keyID,
		"--output", commitment1File,
	)
	require.NoError(t, err, "round1 p1 should succeed: %s", output)
	t.Log("Round 1 complete for participant 1")

	commitment2File := filepath.Join(participant2Dir, "round1.json")
	output, err = runCLI(
		"--local",
		"--key-dir", participant2Dir,
		"frost", "round1",
		"--key-id", keyID,
		"--output", commitment2File,
	)
	require.NoError(t, err, "round1 p2 should succeed: %s", output)
	t.Log("Round 1 complete for participant 2")

	// Step 4: Round 2 - Each participant generates their signature share
	share1File := filepath.Join(participant1Dir, "share.json")
	output, err = runCLI(
		"--local",
		"--key-dir", participant1Dir,
		"frost", "round2",
		"--key-id", keyID,
		"--message", message,
		"--nonces", commitment1File,
		"--commitments", commitment1File+","+commitment2File,
		"--output", share1File,
	)
	require.NoError(t, err, "round2 p1 should succeed: %s", output)
	t.Log("Round 2 complete for participant 1")

	share2File := filepath.Join(participant2Dir, "share.json")
	output, err = runCLI(
		"--local",
		"--key-dir", participant2Dir,
		"frost", "round2",
		"--key-id", keyID,
		"--message", message,
		"--nonces", commitment2File,
		"--commitments", commitment1File+","+commitment2File,
		"--output", share2File,
	)
	require.NoError(t, err, "round2 p2 should succeed: %s", output)
	t.Log("Round 2 complete for participant 2")

	// Step 5: Aggregate both shares (can be done by any participant)
	signatureFile := filepath.Join(participant1Dir, "signature.bin")
	output, err = runCLI(
		"--local",
		"--key-dir", participant1Dir,
		"frost", "aggregate",
		"--key-id", keyID,
		"--message", message,
		"--commitments", commitment1File+","+commitment2File,
		"--shares", share1File+","+share2File,
		"--output", signatureFile,
		"--format", "hex",
		"--verify",
	)
	require.NoError(t, err, "aggregate should succeed: %s", output)
	t.Log("Aggregation complete")

	// Read signature
	sigData, err := os.ReadFile(signatureFile)
	require.NoError(t, err)
	t.Logf("Signature (hex): %s", string(sigData))

	// Step 6: Verify (can be done by anyone with access to the group public key)
	output, err = runCLI(
		"--local",
		"--key-dir", participant1Dir,
		"frost", "verify",
		"--key-id", keyID,
		"--message", message,
		"--signature-hex", string(sigData),
	)
	require.NoError(t, err, "verify should succeed: %s", output)
	assert.Contains(t, output, "PASSED", "Verification should pass")

	t.Log("Complete CLI signing workflow successful!")
}

// TestCLI_FrostSigningWithFile tests signing file content
func TestCLI_FrostSigningWithFile(t *testing.T) {
	// Create directories for dealer and participants
	dealerDir := t.TempDir()
	participant1Dir := t.TempDir()
	participant2Dir := t.TempDir()
	exportDir := filepath.Join(dealerDir, "packages")
	keyID := "file-signing-key"

	// Create a test file to sign
	testFile := filepath.Join(participant1Dir, "document.txt")
	err := os.WriteFile(testFile, []byte("This is a test document for signing."), 0644)
	require.NoError(t, err)

	// Step 1: Dealer generates and exports all packages
	_, err = runCLI(
		"--local",
		"--key-dir", dealerDir,
		"frost", "keygen",
		"--key-id", keyID,
		"--threshold", "2",
		"--total", "2",
		"--participants", "signer1,signer2",
		"--export-dir", exportDir,
	)
	require.NoError(t, err)

	// Step 2: Participants import their packages
	_, err = runCLI(
		"--local",
		"--key-dir", participant1Dir,
		"frost", "import",
		"--package", filepath.Join(exportDir, "signer1_participant_1.json"),
	)
	require.NoError(t, err)

	_, err = runCLI(
		"--local",
		"--key-dir", participant2Dir,
		"frost", "import",
		"--package", filepath.Join(exportDir, "signer2_participant_2.json"),
	)
	require.NoError(t, err)

	// Round 1 for each participant
	commitment1File := filepath.Join(participant1Dir, "commit.json")
	_, err = runCLI(
		"--local",
		"--key-dir", participant1Dir,
		"frost", "round1",
		"--key-id", keyID,
		"--output", commitment1File,
	)
	require.NoError(t, err)

	commitment2File := filepath.Join(participant2Dir, "commit.json")
	_, err = runCLI(
		"--local",
		"--key-dir", participant2Dir,
		"frost", "round1",
		"--key-id", keyID,
		"--output", commitment2File,
	)
	require.NoError(t, err)

	// Round 2 with file for each participant
	share1File := filepath.Join(participant1Dir, "share.json")
	_, err = runCLI(
		"--local",
		"--key-dir", participant1Dir,
		"frost", "round2",
		"--key-id", keyID,
		"--message-file", testFile,
		"--nonces", commitment1File,
		"--commitments", commitment1File+","+commitment2File,
		"--output", share1File,
	)
	require.NoError(t, err)

	share2File := filepath.Join(participant2Dir, "share.json")
	_, err = runCLI(
		"--local",
		"--key-dir", participant2Dir,
		"frost", "round2",
		"--key-id", keyID,
		"--message-file", testFile,
		"--nonces", commitment2File,
		"--commitments", commitment1File+","+commitment2File,
		"--output", share2File,
	)
	require.NoError(t, err)

	// Aggregate both shares
	signatureFile := filepath.Join(participant1Dir, "doc.sig")
	_, err = runCLI(
		"--local",
		"--key-dir", participant1Dir,
		"frost", "aggregate",
		"--key-id", keyID,
		"--message-file", testFile,
		"--commitments", commitment1File+","+commitment2File,
		"--shares", share1File+","+share2File,
		"--output", signatureFile,
	)
	require.NoError(t, err)

	// Verify
	output, err := runCLI(
		"--local",
		"--key-dir", participant1Dir,
		"frost", "verify",
		"--key-id", keyID,
		"--message-file", testFile,
		"--signature", signatureFile,
	)
	require.NoError(t, err)
	assert.Contains(t, output, "PASSED")

	t.Log("File signing workflow successful!")
}

// TestCLI_FrostSigningWithHex tests signing with hex-encoded message
func TestCLI_FrostSigningWithHex(t *testing.T) {
	// Create directories for dealer and participants
	dealerDir := t.TempDir()
	participant1Dir := t.TempDir()
	participant2Dir := t.TempDir()
	exportDir := filepath.Join(dealerDir, "packages")
	keyID := "hex-signing-key"

	// Create hex message (simulating a transaction hash)
	messageBytes := []byte{0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90}
	messageHex := hex.EncodeToString(messageBytes)

	// Step 1: Dealer generates and exports all packages (secp256k1 for blockchain)
	_, err := runCLI(
		"--local",
		"--key-dir", dealerDir,
		"frost", "keygen",
		"--key-id", keyID,
		"--algorithm", "FROST-secp256k1-SHA256",
		"--threshold", "2",
		"--total", "2",
		"--participants", "wallet1,wallet2",
		"--export-dir", exportDir,
	)
	require.NoError(t, err)

	// Step 2: Participants import their packages
	_, err = runCLI(
		"--local",
		"--key-dir", participant1Dir,
		"frost", "import",
		"--package", filepath.Join(exportDir, "wallet1_participant_1.json"),
	)
	require.NoError(t, err)

	_, err = runCLI(
		"--local",
		"--key-dir", participant2Dir,
		"frost", "import",
		"--package", filepath.Join(exportDir, "wallet2_participant_2.json"),
	)
	require.NoError(t, err)

	// Round 1 for each participant
	commitment1File := filepath.Join(participant1Dir, "commit.json")
	_, err = runCLI(
		"--local",
		"--key-dir", participant1Dir,
		"frost", "round1",
		"--key-id", keyID,
		"--output", commitment1File,
	)
	require.NoError(t, err)

	commitment2File := filepath.Join(participant2Dir, "commit.json")
	_, err = runCLI(
		"--local",
		"--key-dir", participant2Dir,
		"frost", "round1",
		"--key-id", keyID,
		"--output", commitment2File,
	)
	require.NoError(t, err)

	// Round 2 with hex message for each participant
	share1File := filepath.Join(participant1Dir, "share.json")
	_, err = runCLI(
		"--local",
		"--key-dir", participant1Dir,
		"frost", "round2",
		"--key-id", keyID,
		"--message-hex", messageHex,
		"--nonces", commitment1File,
		"--commitments", commitment1File+","+commitment2File,
		"--output", share1File,
	)
	require.NoError(t, err)

	share2File := filepath.Join(participant2Dir, "share.json")
	_, err = runCLI(
		"--local",
		"--key-dir", participant2Dir,
		"frost", "round2",
		"--key-id", keyID,
		"--message-hex", messageHex,
		"--nonces", commitment2File,
		"--commitments", commitment1File+","+commitment2File,
		"--output", share2File,
	)
	require.NoError(t, err)

	// Aggregate both shares
	signatureFile := filepath.Join(participant1Dir, "tx.sig")
	_, err = runCLI(
		"--local",
		"--key-dir", participant1Dir,
		"frost", "aggregate",
		"--key-id", keyID,
		"--message-hex", messageHex,
		"--commitments", commitment1File+","+commitment2File,
		"--shares", share1File+","+share2File,
		"--output", signatureFile,
		"--format", "hex",
	)
	require.NoError(t, err)

	// Read and verify signature
	sigData, err := os.ReadFile(signatureFile)
	require.NoError(t, err)

	output, err := runCLI(
		"--local",
		"--key-dir", participant1Dir,
		"frost", "verify",
		"--key-id", keyID,
		"--message-hex", messageHex,
		"--signature-hex", string(sigData),
	)
	require.NoError(t, err)
	assert.Contains(t, output, "PASSED")

	t.Log("Hex signing workflow successful!")
}

// TestCLI_FrostAllAlgorithms tests keygen with all algorithms via CLI
func TestCLI_FrostAllAlgorithms(t *testing.T) {
	algorithms := []string{
		"FROST-Ed25519-SHA512",
		"FROST-ristretto255-SHA512",
		"FROST-P256-SHA256",
		"FROST-secp256k1-SHA256",
	}

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			tempDir := t.TempDir()
			keyID := "algo-test-" + strings.ReplaceAll(algo, "-", "_")

			// Use participant mode to store key locally
			output, err := runCLI(
				"--local",
				"--key-dir", tempDir,
				"frost", "keygen",
				"--algorithm", algo,
				"--key-id", keyID,
				"--threshold", "2",
				"--total", "3",
				"--participants", "a,b,c",
				"--participant-id", "1",
			)
			require.NoError(t, err, "%s keygen should succeed: %s", algo, output)

			// Verify key was created
			output, err = runCLI(
				"--local",
				"--key-dir", tempDir,
				"frost", "list",
			)
			require.NoError(t, err)
			assert.Contains(t, output, keyID)

			t.Logf("%s key generation via CLI successful", algo)
		})
	}
}

// runCLI executes the keychain CLI with given arguments
func runCLI(args ...string) (string, error) {
	// Try to find the CLI binary
	cliPath := findCLI()
	if cliPath == "" {
		// Fall back to go run
		allArgs := append([]string{"run", "-tags=frost", "./cmd/cli/main.go"}, args...)
		cmd := exec.Command("go", allArgs...)
		cmd.Dir = getProjectRoot()
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			return stderr.String() + stdout.String(), err
		}
		return stdout.String(), nil
	}

	cmd := exec.Command(cliPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stderr.String() + stdout.String(), err
	}
	return stdout.String(), nil
}

// findCLI looks for the keychain CLI binary
func findCLI() string {
	// Check if installed in PATH
	if path, err := exec.LookPath("keychain"); err == nil {
		return path
	}

	// Check common locations
	locations := []string{
		"/usr/local/bin/keychain",
		"./bin/keychain",
		"../../../bin/keychain",
	}

	for _, loc := range locations {
		if _, err := os.Stat(loc); err == nil {
			return loc
		}
	}

	return ""
}

// getProjectRoot returns the project root directory
func getProjectRoot() string {
	// Walk up from current directory to find go.mod
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "../../.."
}
