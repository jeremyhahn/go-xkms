// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build frost

package cli

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/backend/frost"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/storage/file"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/spf13/cobra"
)

func init() {
	// Add frost command to root
	rootCmd.AddCommand(frostCmd)

	// Add subcommands
	frostCmd.AddCommand(frostKeygenCmd)
	frostCmd.AddCommand(frostImportCmd)
	frostCmd.AddCommand(frostListCmd)
	frostCmd.AddCommand(frostInfoCmd)
	frostCmd.AddCommand(frostDeleteCmd)
	frostCmd.AddCommand(frostRound1Cmd)
	frostCmd.AddCommand(frostRound2Cmd)
	frostCmd.AddCommand(frostAggregateCmd)
	frostCmd.AddCommand(frostVerifyCmd)

	// keygen flags
	frostKeygenCmd.Flags().StringP("algorithm", "a", "FROST-Ed25519-SHA512", "FROST ciphersuite algorithm")
	frostKeygenCmd.Flags().IntP("threshold", "t", 2, "Minimum signers required (M)")
	frostKeygenCmd.Flags().IntP("total", "n", 3, "Total participants (N)")
	frostKeygenCmd.Flags().StringP("participants", "p", "", "Comma-separated participant names")
	frostKeygenCmd.Flags().String("key-id", "", "Custom key identifier (auto-generated if not set)")
	frostKeygenCmd.Flags().Uint32("participant-id", 0, "This participant's ID (1 to total); 0 = dealer mode")
	frostKeygenCmd.Flags().String("export-dir", "", "Export all packages to directory (dealer mode)")

	// import flags
	frostImportCmd.Flags().String("package", "", "Path to key package file (required)")
	_ = frostImportCmd.MarkFlagRequired("package")

	// list flags
	frostListCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")

	// info flags
	frostInfoCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")
	frostInfoCmd.Flags().Bool("show-public-key", false, "Display group public key")

	// delete flags
	frostDeleteCmd.Flags().BoolP("force", "f", false, "Skip confirmation prompt")

	// round1 flags
	frostRound1Cmd.Flags().StringP("key-id", "k", "", "Key identifier (required)")
	frostRound1Cmd.Flags().StringP("output", "o", "", "Output file for commitment (required)")
	_ = frostRound1Cmd.MarkFlagRequired("key-id")
	_ = frostRound1Cmd.MarkFlagRequired("output")

	// round2 flags
	frostRound2Cmd.Flags().StringP("key-id", "k", "", "Key identifier (required)")
	frostRound2Cmd.Flags().StringP("message", "m", "", "Message to sign")
	frostRound2Cmd.Flags().String("message-file", "", "File containing message")
	frostRound2Cmd.Flags().String("message-hex", "", "Message as hex string")
	frostRound2Cmd.Flags().String("nonces", "", "This participant's nonce package file (required)")
	frostRound2Cmd.Flags().StringP("commitments", "c", "", "Comma-separated commitment files (required)")
	frostRound2Cmd.Flags().StringP("output", "o", "", "Output file for signature share (required)")
	_ = frostRound2Cmd.MarkFlagRequired("key-id")
	_ = frostRound2Cmd.MarkFlagRequired("nonces")
	_ = frostRound2Cmd.MarkFlagRequired("commitments")
	_ = frostRound2Cmd.MarkFlagRequired("output")

	// aggregate flags
	frostAggregateCmd.Flags().StringP("key-id", "k", "", "Key identifier (required)")
	frostAggregateCmd.Flags().StringP("message", "m", "", "Message that was signed")
	frostAggregateCmd.Flags().String("message-file", "", "File containing message")
	frostAggregateCmd.Flags().String("message-hex", "", "Message as hex string")
	frostAggregateCmd.Flags().StringP("commitments", "c", "", "Comma-separated commitment files (required)")
	frostAggregateCmd.Flags().String("shares", "", "Comma-separated signature share files (required)")
	frostAggregateCmd.Flags().StringP("output", "o", "", "Output file for signature (required)")
	frostAggregateCmd.Flags().String("format", "raw", "Signature format (raw, hex, base64)")
	frostAggregateCmd.Flags().Bool("verify", true, "Verify signature after aggregation")
	_ = frostAggregateCmd.MarkFlagRequired("key-id")
	_ = frostAggregateCmd.MarkFlagRequired("commitments")
	_ = frostAggregateCmd.MarkFlagRequired("shares")
	_ = frostAggregateCmd.MarkFlagRequired("output")

	// verify flags
	frostVerifyCmd.Flags().StringP("key-id", "k", "", "Key identifier")
	frostVerifyCmd.Flags().StringP("message", "m", "", "Original message")
	frostVerifyCmd.Flags().String("message-file", "", "File containing message")
	frostVerifyCmd.Flags().String("message-hex", "", "Message as hex string")
	frostVerifyCmd.Flags().String("signature", "", "Signature file")
	frostVerifyCmd.Flags().String("signature-hex", "", "Signature as hex string")
}

// frostCmd represents the frost command
var frostCmd = &cobra.Command{
	Use:   "frost",
	Short: "FROST threshold signature operations",
	Long: `FROST (Flexible Round-Optimized Schnorr Threshold) signature operations.

FROST enables M-of-N threshold signing where any M participants can
collaboratively sign messages without ever reconstructing the private key.

Supported algorithms:
  - FROST-Ed25519-SHA512 (default, recommended)
  - FROST-ristretto255-SHA512
  - FROST-Ed448-SHAKE256
  - FROST-P256-SHA256 (FIPS compliant)
  - FROST-secp256k1-SHA256 (blockchain compatible)`,
}

// KeyPackageExport is the JSON format for exported key packages
type KeyPackageExport struct {
	KeyID              string            `json:"key_id"`
	Algorithm          string            `json:"algorithm"`
	Threshold          int               `json:"threshold"`
	Total              int               `json:"total"`
	ParticipantID      uint32            `json:"participant_id"`
	ParticipantName    string            `json:"participant_name,omitempty"`
	SecretShare        string            `json:"secret_share"`        // hex-encoded
	GroupPublicKey     string            `json:"group_public_key"`    // hex-encoded
	VerificationShares map[uint32]string `json:"verification_shares"` // hex-encoded
}

// frostKeygenCmd generates FROST keys
var frostKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate FROST key packages (trusted dealer)",
	Long: `Generate new FROST key packages using the trusted dealer model.

In dealer mode (--participant-id=0 or --export-dir specified), generates all
participant key packages and exports them to files for secure distribution.

In participant mode (--participant-id=N), generates and stores only this
participant's key package locally.

Examples:
  # Dealer mode: generate and export all packages
  keychain frost keygen --key-id mykey --threshold 2 --total 3 --export-dir ./packages

  # Participant mode: generate and store locally (participant 1)
  keychain frost keygen --key-id mykey --threshold 2 --total 3 --participant-id 1`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		algorithm, _ := cmd.Flags().GetString("algorithm")
		threshold, _ := cmd.Flags().GetInt("threshold")
		total, _ := cmd.Flags().GetInt("total")
		participantsStr, _ := cmd.Flags().GetString("participants")
		keyID, _ := cmd.Flags().GetString("key-id")
		participantID, _ := cmd.Flags().GetUint32("participant-id")
		exportDir, _ := cmd.Flags().GetString("export-dir")

		// Parse participant names
		var participants []string
		if participantsStr != "" {
			participants = strings.Split(participantsStr, ",")
			for i := range participants {
				participants[i] = strings.TrimSpace(participants[i])
			}
		}

		// Generate key ID if not provided
		if keyID == "" {
			keyID = fmt.Sprintf("frost-key-%d", time.Now().UnixNano())
		}

		// Validate
		if len(participants) > 0 && len(participants) != total {
			handleError(fmt.Errorf("number of participants (%d) must match total (%d)", len(participants), total))
			return
		}

		// Determine mode: dealer (export all) or participant (store one)
		isDealerMode := exportDir != "" || participantID == 0

		if isDealerMode && exportDir == "" {
			handleError(fmt.Errorf("dealer mode requires --export-dir to specify where to save packages"))
			return
		}

		printVerbose("Generating FROST key: %s (algorithm=%s, threshold=%d/%d, dealer=%v)",
			keyID, algorithm, threshold, total, isDealerMode)

		// Generate all packages using trusted dealer
		td := frost.NewTrustedDealer()
		frostConfig := frost.FrostConfig{
			Threshold:     threshold,
			Total:         total,
			Algorithm:     types.FrostAlgorithm(algorithm),
			ParticipantID: 1, // Not used for generation
		}

		packages, pubPkg, err := td.Generate(frostConfig)
		if err != nil {
			handleError(fmt.Errorf("failed to generate FROST packages: %w", err))
			return
		}

		if isDealerMode {
			// Dealer mode: export all packages to files
			if err := os.MkdirAll(exportDir, 0700); err != nil {
				handleError(fmt.Errorf("failed to create export directory: %w", err))
				return
			}

			var exportedFiles []string
			for i, pkg := range packages {
				// Build verification shares map
				vsMap := make(map[uint32]string)
				for id, vs := range pubPkg.VerificationShares {
					vsMap[id] = hex.EncodeToString(vs)
				}

				// Get participant name if available
				var participantName string
				if i < len(participants) {
					participantName = participants[i]
				}

				export := &KeyPackageExport{
					KeyID:              keyID,
					Algorithm:          algorithm,
					Threshold:          threshold,
					Total:              total,
					ParticipantID:      pkg.ParticipantID,
					ParticipantName:    participantName,
					SecretShare:        hex.EncodeToString(pkg.SecretShare.Value),
					GroupPublicKey:     hex.EncodeToString(pubPkg.GroupPublicKey),
					VerificationShares: vsMap,
				}

				// Write package file
				fileName := fmt.Sprintf("participant_%d.json", pkg.ParticipantID)
				if participantName != "" {
					fileName = fmt.Sprintf("%s_participant_%d.json", participantName, pkg.ParticipantID)
				}
				filePath := filepath.Join(exportDir, fileName)

				data, err := json.MarshalIndent(export, "", "  ")
				if err != nil {
					handleError(fmt.Errorf("failed to marshal package: %w", err))
					return
				}

				if err := os.WriteFile(filePath, data, 0600); err != nil {
					handleError(fmt.Errorf("failed to write package file: %w", err))
					return
				}

				exportedFiles = append(exportedFiles, filePath)
				printVerbose("Exported package for participant %d to %s", pkg.ParticipantID, filePath)
			}

			result := map[string]interface{}{
				"key_id":           keyID,
				"algorithm":        algorithm,
				"threshold":        threshold,
				"total":            total,
				"group_public_key": hex.EncodeToString(pubPkg.GroupPublicKey),
				"exported_files":   exportedFiles,
				"mode":             "dealer",
			}
			if len(participants) > 0 {
				result["participants"] = participants
			}

			if err := printer.PrintJSON(result); err != nil {
				handleError(err)
			}
		} else {
			// Participant mode: store this participant's package locally
			if participantID < 1 || int(participantID) > total {
				handleError(fmt.Errorf("participant-id must be between 1 and %d", total))
				return
			}

			// Find this participant's package
			var myPackage *frost.KeyPackage
			for _, pkg := range packages {
				if pkg.ParticipantID == participantID {
					myPackage = pkg
					break
				}
			}
			if myPackage == nil {
				handleError(fmt.Errorf("package for participant %d not found", participantID))
				return
			}

			// Create backend and store
			be, err := createFrostBackend(cfg, types.FrostAlgorithm(algorithm), participantID, threshold, total, participants)
			if err != nil {
				handleError(fmt.Errorf("failed to create FROST backend: %w", err))
				return
			}
			defer func() { _ = be.Close() }()

			// Generate key via backend (which handles storage)
			attrs := &types.KeyAttributes{
				CN:        keyID,
				KeyType:   types.KeyTypeSigning,
				StoreType: types.StoreFrost,
				FrostAttributes: &types.FrostAttributes{
					Algorithm:     types.FrostAlgorithm(algorithm),
					Threshold:     threshold,
					Total:         total,
					Participants:  participants,
					ParticipantID: participantID,
				},
			}

			key, err := be.GenerateKey(attrs)
			if err != nil {
				handleError(fmt.Errorf("failed to generate FROST key: %w", err))
				return
			}

			handle := key.(*frost.FrostKeyHandle)

			result := map[string]interface{}{
				"key_id":           keyID,
				"algorithm":        algorithm,
				"threshold":        threshold,
				"total":            total,
				"participant_id":   participantID,
				"group_public_key": hex.EncodeToString(handle.GroupPublicKey),
				"mode":             "participant",
			}
			if len(participants) > 0 {
				result["participants"] = participants
			}

			if err := printer.PrintJSON(result); err != nil {
				handleError(err)
			}
		}
	},
}

// frostImportCmd imports a FROST key package
var frostImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import a FROST key package",
	Long: `Import a FROST key package from a file.

Each participant imports their key package file (received from the trusted dealer)
to enable their participation in threshold signing.

Example:
  keychain frost import --package ./alice_participant_1.json`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		packagePath, _ := cmd.Flags().GetString("package")

		// Read package file
		data, err := os.ReadFile(packagePath)
		if err != nil {
			handleError(fmt.Errorf("failed to read package file: %w", err))
			return
		}

		var pkg KeyPackageExport
		if err := json.Unmarshal(data, &pkg); err != nil {
			handleError(fmt.Errorf("failed to parse package file: %w", err))
			return
		}

		printVerbose("Importing FROST package: key=%s, participant=%d, algorithm=%s",
			pkg.KeyID, pkg.ParticipantID, pkg.Algorithm)

		// Decode hex values
		secretShare, err := hex.DecodeString(pkg.SecretShare)
		if err != nil {
			handleError(fmt.Errorf("failed to decode secret share: %w", err))
			return
		}

		groupPublicKey, err := hex.DecodeString(pkg.GroupPublicKey)
		if err != nil {
			handleError(fmt.Errorf("failed to decode group public key: %w", err))
			return
		}

		verificationShares := make(map[uint32][]byte)
		for id, vsHex := range pkg.VerificationShares {
			vs, err := hex.DecodeString(vsHex)
			if err != nil {
				handleError(fmt.Errorf("failed to decode verification share %d: %w", id, err))
				return
			}
			verificationShares[id] = vs
		}

		// Create storage backends
		publicDir := filepath.Join(cfg.KeyDir, "frost", "public")
		if err := os.MkdirAll(publicDir, 0755); err != nil {
			handleError(fmt.Errorf("failed to create public directory: %w", err))
			return
		}

		secretDir := filepath.Join(cfg.KeyDir, "frost", "secrets")
		if err := os.MkdirAll(secretDir, 0700); err != nil {
			handleError(fmt.Errorf("failed to create secret directory: %w", err))
			return
		}

		publicStorage, err := file.New(publicDir)
		if err != nil {
			handleError(fmt.Errorf("failed to create public storage: %w", err))
			return
		}

		secretStorage, err := file.New(secretDir)
		if err != nil {
			handleError(fmt.Errorf("failed to create secret storage: %w", err))
			return
		}

		secretBackend := newFileSecretBackend(secretStorage)

		// Create KeyStore and store package
		ks := frost.NewKeyStore(publicStorage, secretBackend)

		keyPackage := &frost.KeyPackage{
			ParticipantID: pkg.ParticipantID,
			SecretShare: &frost.SecretKeyShare{
				Value: secretShare,
			},
			GroupPublicKey:     groupPublicKey,
			VerificationShares: verificationShares,
			MinSigners:         uint32(pkg.Threshold),
			MaxSigners:         uint32(pkg.Total),
			Algorithm:          types.FrostAlgorithm(pkg.Algorithm),
		}

		metadata := &frost.KeyMetadata{
			KeyID:             pkg.KeyID,
			Algorithm:         types.FrostAlgorithm(pkg.Algorithm),
			Threshold:         pkg.Threshold,
			Total:             pkg.Total,
			ParticipantID:     pkg.ParticipantID,
			CreatedAt:         time.Now().Unix(),
			SecretBackendType: types.BackendTypeSoftware,
		}

		if err := ks.StoreKeyPackage(pkg.KeyID, keyPackage, metadata); err != nil {
			handleError(fmt.Errorf("failed to store key package: %w", err))
			return
		}

		result := map[string]interface{}{
			"key_id":           pkg.KeyID,
			"algorithm":        pkg.Algorithm,
			"threshold":        pkg.Threshold,
			"total":            pkg.Total,
			"participant_id":   pkg.ParticipantID,
			"group_public_key": pkg.GroupPublicKey,
			"imported_from":    packagePath,
		}
		if pkg.ParticipantName != "" {
			result["participant_name"] = pkg.ParticipantName
		}

		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	},
}

// frostListCmd lists FROST keys
var frostListCmd = &cobra.Command{
	Use:   "list",
	Short: "List FROST keys",
	Long:  `List all FROST keys managed by this node.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)
		format, _ := cmd.Flags().GetString("format")

		be, err := createFrostBackend(cfg, types.FrostAlgorithmEd25519, 1, 2, 3, nil)
		if err != nil {
			handleError(fmt.Errorf("failed to create FROST backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		keys, err := be.ListKeys()
		if err != nil {
			handleError(fmt.Errorf("failed to list keys: %w", err))
			return
		}

		if len(keys) == 0 {
			if err := printer.PrintSuccess("No FROST keys found"); err != nil {
				handleError(err)
			}
			return
		}

		if format == "json" {
			if err := printer.PrintJSON(keys); err != nil {
				handleError(err)
			}
			return
		}

		// Table format
		fmt.Printf("%-30s %-25s %-12s\n", "KEY ID", "ALGORITHM", "THRESHOLD")
		fmt.Println(strings.Repeat("-", 70))
		for _, k := range keys {
			if k.FrostAttributes != nil {
				fmt.Printf("%-30s %-25s %d/%d\n",
					k.CN,
					k.FrostAttributes.Algorithm,
					k.FrostAttributes.Threshold,
					k.FrostAttributes.Total)
			}
		}
	},
}

// frostInfoCmd shows key details
var frostInfoCmd = &cobra.Command{
	Use:   "info <key-id>",
	Short: "Show FROST key details",
	Long:  `Display detailed information about a FROST key.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)
		showPubKey, _ := cmd.Flags().GetBool("show-public-key")

		be, err := createFrostBackend(cfg, types.FrostAlgorithmEd25519, 1, 2, 3, nil)
		if err != nil {
			handleError(fmt.Errorf("failed to create FROST backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		attrs := &types.KeyAttributes{
			CN:        keyID,
			KeyType:   types.KeyTypeSigning,
			StoreType: types.StoreFrost,
		}

		key, err := be.GetKey(attrs)
		if err != nil {
			handleError(fmt.Errorf("failed to get key: %w", err))
			return
		}

		handle := key.(*frost.FrostKeyHandle)

		result := map[string]interface{}{
			"key_id":         keyID,
			"algorithm":      string(handle.Algorithm),
			"participant_id": handle.ParticipantID,
		}

		if showPubKey {
			result["group_public_key"] = hex.EncodeToString(handle.GroupPublicKey)
		}

		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	},
}

// frostDeleteCmd deletes a FROST key
var frostDeleteCmd = &cobra.Command{
	Use:   "delete <key-id>",
	Short: "Delete a FROST key",
	Long:  `Delete a FROST key and all associated data.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)
		force, _ := cmd.Flags().GetBool("force")

		if !force {
			fmt.Printf("Are you sure you want to delete key '%s'? [y/N]: ", keyID)
			var response string
			_, _ = fmt.Scanln(&response)
			if strings.ToLower(response) != "y" {
				fmt.Println("Aborted")
				return
			}
		}

		be, err := createFrostBackend(cfg, types.FrostAlgorithmEd25519, 1, 2, 3, nil)
		if err != nil {
			handleError(fmt.Errorf("failed to create FROST backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		attrs := &types.KeyAttributes{
			CN:        keyID,
			KeyType:   types.KeyTypeSigning,
			StoreType: types.StoreFrost,
		}

		if err := be.DeleteKey(attrs); err != nil {
			handleError(fmt.Errorf("failed to delete key: %w", err))
			return
		}

		if err := printer.PrintSuccess(fmt.Sprintf("Successfully deleted key: %s", keyID)); err != nil {
			handleError(err)
		}
	},
}

// CommitmentFile represents the JSON structure for round1 output
type CommitmentFile struct {
	ParticipantID uint32                    `json:"participant_id"`
	SessionID     string                    `json:"session_id"`
	Commitments   *frost.SigningCommitments `json:"commitments"`
	// Nonces are stored separately and kept secret
	nonces *frost.SigningNonces
}

// NonceFile represents the internal nonce storage (kept secret)
type NonceFile struct {
	ParticipantID uint32               `json:"participant_id"`
	SessionID     string               `json:"session_id"`
	Nonces        *frost.SigningNonces `json:"nonces"`
}

// frostRound1Cmd generates nonces for round 1
var frostRound1Cmd = &cobra.Command{
	Use:   "round1",
	Short: "Generate nonces and commitments (Round 1)",
	Long:  `Generate nonces and commitments for the first round of FROST signing.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		keyID, _ := cmd.Flags().GetString("key-id")
		outputPath, _ := cmd.Flags().GetString("output")

		be, err := createFrostBackend(cfg, types.FrostAlgorithmEd25519, 1, 2, 3, nil)
		if err != nil {
			handleError(fmt.Errorf("failed to create FROST backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// Generate nonces
		noncePackage, err := be.GenerateNonces(keyID)
		if err != nil {
			handleError(fmt.Errorf("failed to generate nonces: %w", err))
			return
		}

		// Write commitment file (public)
		commitmentFile := &CommitmentFile{
			ParticipantID: noncePackage.ParticipantID,
			SessionID:     noncePackage.SessionID,
			Commitments:   noncePackage.Commitments,
		}

		commitmentData, err := json.MarshalIndent(commitmentFile, "", "  ")
		if err != nil {
			handleError(fmt.Errorf("failed to marshal commitment: %w", err))
			return
		}

		if err := os.WriteFile(outputPath, commitmentData, 0644); err != nil {
			handleError(fmt.Errorf("failed to write commitment file: %w", err))
			return
		}

		// Write nonce file (secret) - same name with .nonces extension
		nonceFile := &NonceFile{
			ParticipantID: noncePackage.ParticipantID,
			SessionID:     noncePackage.SessionID,
			Nonces:        noncePackage.Nonces,
		}

		noncePath := outputPath + ".nonces"
		nonceData, err := json.MarshalIndent(nonceFile, "", "  ")
		if err != nil {
			handleError(fmt.Errorf("failed to marshal nonces: %w", err))
			return
		}

		if err := os.WriteFile(noncePath, nonceData, 0600); err != nil {
			handleError(fmt.Errorf("failed to write nonce file: %w", err))
			return
		}

		result := map[string]interface{}{
			"participant_id":  noncePackage.ParticipantID,
			"session_id":      noncePackage.SessionID,
			"commitment_file": outputPath,
			"nonce_file":      noncePath,
		}

		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	},
}

// frostRound2Cmd generates signature share for round 2
var frostRound2Cmd = &cobra.Command{
	Use:   "round2",
	Short: "Generate signature share (Round 2)",
	Long:  `Generate a signature share using collected commitments.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		keyID, _ := cmd.Flags().GetString("key-id")
		noncesPath, _ := cmd.Flags().GetString("nonces")
		commitmentsStr, _ := cmd.Flags().GetString("commitments")
		outputPath, _ := cmd.Flags().GetString("output")

		// Get message
		message, err := getMessage(cmd)
		if err != nil {
			handleError(err)
			return
		}

		be, err := createFrostBackend(cfg, types.FrostAlgorithmEd25519, 1, 2, 3, nil)
		if err != nil {
			handleError(fmt.Errorf("failed to create FROST backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// Load nonces (from the .nonces file)
		noncePath := noncesPath
		if !strings.HasSuffix(noncePath, ".nonces") {
			noncePath = noncePath + ".nonces"
		}

		nonceData, err := os.ReadFile(noncePath)
		if err != nil {
			handleError(fmt.Errorf("failed to read nonce file: %w", err))
			return
		}

		var nonceFile NonceFile
		if err := json.Unmarshal(nonceData, &nonceFile); err != nil {
			handleError(fmt.Errorf("failed to parse nonce file: %w", err))
			return
		}

		// Load commitment file to get session info
		commitmentPath := strings.TrimSuffix(noncesPath, ".nonces")
		commitmentData, err := os.ReadFile(commitmentPath)
		if err != nil {
			handleError(fmt.Errorf("failed to read commitment file: %w", err))
			return
		}

		var myCommitment CommitmentFile
		if err := json.Unmarshal(commitmentData, &myCommitment); err != nil {
			handleError(fmt.Errorf("failed to parse commitment file: %w", err))
			return
		}

		// Build NoncePackage
		noncePackage := &frost.NoncePackage{
			ParticipantID: nonceFile.ParticipantID,
			SessionID:     nonceFile.SessionID,
			Nonces:        nonceFile.Nonces,
			Commitments:   myCommitment.Commitments,
		}

		// Load all commitments
		commitmentFiles := strings.Split(commitmentsStr, ",")
		var commitments []*frost.Commitment
		for _, cf := range commitmentFiles {
			cf = strings.TrimSpace(cf)
			data, err := os.ReadFile(cf)
			if err != nil {
				handleError(fmt.Errorf("failed to read commitment file %s: %w", cf, err))
				return
			}

			var c CommitmentFile
			if err := json.Unmarshal(data, &c); err != nil {
				handleError(fmt.Errorf("failed to parse commitment file %s: %w", cf, err))
				return
			}

			commitments = append(commitments, &frost.Commitment{
				ParticipantID: c.ParticipantID,
				Commitments:   c.Commitments,
			})
		}

		// Generate signature share
		share, err := be.SignRound(keyID, message, noncePackage, commitments)
		if err != nil {
			handleError(fmt.Errorf("failed to generate signature share: %w", err))
			return
		}

		// Write share file
		shareFile := map[string]interface{}{
			"participant_id":  share.ParticipantID,
			"session_id":      share.SessionID,
			"signature_share": hex.EncodeToString(share.Share),
		}

		shareData, err := json.MarshalIndent(shareFile, "", "  ")
		if err != nil {
			handleError(fmt.Errorf("failed to marshal share: %w", err))
			return
		}

		if err := os.WriteFile(outputPath, shareData, 0644); err != nil {
			handleError(fmt.Errorf("failed to write share file: %w", err))
			return
		}

		result := map[string]interface{}{
			"participant_id": share.ParticipantID,
			"session_id":     share.SessionID,
			"share_file":     outputPath,
		}

		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	},
}

// ShareFile represents the JSON structure for signature shares
type ShareFile struct {
	ParticipantID  uint32 `json:"participant_id"`
	SessionID      string `json:"session_id"`
	SignatureShare string `json:"signature_share"`
}

// frostAggregateCmd aggregates signature shares
var frostAggregateCmd = &cobra.Command{
	Use:   "aggregate",
	Short: "Aggregate signature shares",
	Long:  `Combine signature shares into a final FROST signature.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		keyID, _ := cmd.Flags().GetString("key-id")
		commitmentsStr, _ := cmd.Flags().GetString("commitments")
		sharesStr, _ := cmd.Flags().GetString("shares")
		outputPath, _ := cmd.Flags().GetString("output")
		format, _ := cmd.Flags().GetString("format")
		verify, _ := cmd.Flags().GetBool("verify")

		// Get message
		message, err := getMessage(cmd)
		if err != nil {
			handleError(err)
			return
		}

		be, err := createFrostBackend(cfg, types.FrostAlgorithmEd25519, 1, 2, 3, nil)
		if err != nil {
			handleError(fmt.Errorf("failed to create FROST backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// Load commitments
		commitmentFiles := strings.Split(commitmentsStr, ",")
		var commitments []*frost.Commitment
		for _, cf := range commitmentFiles {
			cf = strings.TrimSpace(cf)
			data, err := os.ReadFile(cf)
			if err != nil {
				handleError(fmt.Errorf("failed to read commitment file %s: %w", cf, err))
				return
			}

			var c CommitmentFile
			if err := json.Unmarshal(data, &c); err != nil {
				handleError(fmt.Errorf("failed to parse commitment file %s: %w", cf, err))
				return
			}

			commitments = append(commitments, &frost.Commitment{
				ParticipantID: c.ParticipantID,
				Commitments:   c.Commitments,
			})
		}

		// Load shares
		shareFiles := strings.Split(sharesStr, ",")
		var shares []*frost.SignatureShare
		for _, sf := range shareFiles {
			sf = strings.TrimSpace(sf)
			data, err := os.ReadFile(sf)
			if err != nil {
				handleError(fmt.Errorf("failed to read share file %s: %w", sf, err))
				return
			}

			var s ShareFile
			if err := json.Unmarshal(data, &s); err != nil {
				handleError(fmt.Errorf("failed to parse share file %s: %w", sf, err))
				return
			}

			shareBytes, err := hex.DecodeString(s.SignatureShare)
			if err != nil {
				handleError(fmt.Errorf("failed to decode share from %s: %w", sf, err))
				return
			}

			shares = append(shares, &frost.SignatureShare{
				ParticipantID: s.ParticipantID,
				SessionID:     s.SessionID,
				Share:         shareBytes,
			})
		}

		// Aggregate
		signature, err := be.Aggregate(keyID, message, commitments, shares)
		if err != nil {
			handleError(fmt.Errorf("failed to aggregate signatures: %w", err))
			return
		}

		// Verify if requested
		if verify {
			if err := be.Verify(keyID, message, signature); err != nil {
				handleError(fmt.Errorf("signature verification failed: %w", err))
				return
			}
			printVerbose("Signature verified successfully")
		}

		// Format output
		var outputData []byte
		switch format {
		case "hex":
			outputData = []byte(hex.EncodeToString(signature))
		case "base64":
			outputData = []byte(base64.StdEncoding.EncodeToString(signature))
		default: // raw
			outputData = signature
		}

		if err := os.WriteFile(outputPath, outputData, 0644); err != nil {
			handleError(fmt.Errorf("failed to write signature file: %w", err))
			return
		}

		result := map[string]interface{}{
			"signature_file": outputPath,
			"format":         format,
			"verified":       verify,
			"size_bytes":     len(signature),
		}

		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	},
}

// frostVerifyCmd verifies a FROST signature
var frostVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a FROST signature",
	Long:  `Verify a FROST signature against the group public key.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		keyID, _ := cmd.Flags().GetString("key-id")
		sigFile, _ := cmd.Flags().GetString("signature")
		sigHex, _ := cmd.Flags().GetString("signature-hex")

		// Get message
		message, err := getMessage(cmd)
		if err != nil {
			handleError(err)
			return
		}

		// Get signature
		var signature []byte
		if sigHex != "" {
			signature, err = hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
			if err != nil {
				handleError(fmt.Errorf("invalid signature hex: %w", err))
				return
			}
		} else if sigFile != "" {
			signature, err = os.ReadFile(sigFile)
			if err != nil {
				handleError(fmt.Errorf("failed to read signature file: %w", err))
				return
			}
			// Try to detect format
			if decoded, err := hex.DecodeString(string(signature)); err == nil {
				signature = decoded
			} else if decoded, err := base64.StdEncoding.DecodeString(string(signature)); err == nil {
				signature = decoded
			}
		} else {
			handleError(fmt.Errorf("either --signature or --signature-hex is required"))
			return
		}

		be, err := createFrostBackend(cfg, types.FrostAlgorithmEd25519, 1, 2, 3, nil)
		if err != nil {
			handleError(fmt.Errorf("failed to create FROST backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		if err := be.Verify(keyID, message, signature); err != nil {
			handleError(fmt.Errorf("signature verification FAILED: %w", err))
			return
		}

		result := map[string]interface{}{
			"status":  "PASSED",
			"key_id":  keyID,
			"message": truncateMessage(message, 64),
		}

		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	},
}

// getMessage extracts the message from command flags
func getMessage(cmd *cobra.Command) ([]byte, error) {
	msgStr, _ := cmd.Flags().GetString("message")
	msgFile, _ := cmd.Flags().GetString("message-file")
	msgHex, _ := cmd.Flags().GetString("message-hex")

	if msgStr != "" {
		return []byte(msgStr), nil
	}

	if msgFile != "" {
		data, err := os.ReadFile(msgFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read message file: %w", err)
		}
		// Hash file contents for signing
		hash := sha256.Sum256(data)
		return hash[:], nil
	}

	if msgHex != "" {
		data, err := hex.DecodeString(strings.TrimPrefix(msgHex, "0x"))
		if err != nil {
			return nil, fmt.Errorf("invalid message hex: %w", err)
		}
		return data, nil
	}

	return nil, fmt.Errorf("one of --message, --message-file, or --message-hex is required")
}

// truncateMessage truncates a message for display
func truncateMessage(msg []byte, maxLen int) string {
	if len(msg) <= maxLen {
		return string(msg)
	}
	return string(msg[:maxLen]) + "..."
}

// createFrostBackend creates a FROST backend with appropriate configuration
func createFrostBackend(cfg *Config, algorithm types.FrostAlgorithm, participantID uint32, threshold, total int, participants []string) (*frost.FrostBackend, error) {
	// Create public storage
	publicDir := filepath.Join(cfg.KeyDir, "frost", "public")
	if err := os.MkdirAll(publicDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create public directory: %w", err)
	}

	publicStorage, err := file.New(publicDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create public storage: %w", err)
	}

	// Create secret storage (using pkcs8 backend for secret shares)
	secretDir := filepath.Join(cfg.KeyDir, "frost", "secrets")
	if err := os.MkdirAll(secretDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create secret directory: %w", err)
	}

	secretStorage, err := file.New(secretDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret storage: %w", err)
	}

	// Create a simple file-based secret backend
	secretBackend := newFileSecretBackend(secretStorage)

	frostConfig := &frost.Config{
		PublicStorage:       publicStorage,
		SecretBackend:       secretBackend,
		Algorithm:           algorithm,
		ParticipantID:       participantID,
		DefaultThreshold:    threshold,
		DefaultTotal:        total,
		Participants:        participants,
		EnableNonceTracking: true,
	}

	return frost.NewBackend(frostConfig)
}

// fileSecretBackend is a simple file-based backend for storing FROST secrets
type fileSecretBackend struct {
	storage storage.Backend
}

func newFileSecretBackend(storage storage.Backend) *fileSecretBackend {
	return &fileSecretBackend{storage: storage}
}

func (b *fileSecretBackend) Type() types.BackendType {
	return types.BackendTypeSoftware
}

func (b *fileSecretBackend) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:           true,
		Signing:        false,
		Decryption:     false,
		KeyRotation:    true,
		Import:         true,
		Export:         true,
		HardwareBacked: false,
	}
}

func (b *fileSecretBackend) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// For FROST, we store the secret share data from SealData
	if attrs.SealData != nil {
		data := attrs.SealData.Bytes()
		if len(data) > 0 {
			path := "frost/secrets/" + attrs.CN + ".secret"
			if err := b.storage.Put(path, data, nil); err != nil {
				return nil, fmt.Errorf("failed to store secret: %w", err)
			}
		}
		return nil, nil
	}
	return nil, nil
}

func (b *fileSecretBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// For FROST, we retrieve the secret share data
	path := "frost/secrets/" + attrs.CN + ".secret"
	data, err := b.storage.Get(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	// Return the raw bytes as the "private key"
	// The FROST backend will interpret this as the secret share
	return data, nil
}

func (b *fileSecretBackend) DeleteKey(attrs *types.KeyAttributes) error {
	path := "frost/secrets/" + attrs.CN + ".secret"
	return b.storage.Delete(path)
}

func (b *fileSecretBackend) ListKeys() ([]*types.KeyAttributes, error) {
	return nil, nil
}

func (b *fileSecretBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	return nil, fmt.Errorf("not implemented for file secret backend")
}

func (b *fileSecretBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, fmt.Errorf("not implemented for file secret backend")
}

func (b *fileSecretBackend) RotateKey(attrs *types.KeyAttributes) error {
	return nil
}

func (b *fileSecretBackend) Close() error {
	return nil
}

// Storage returns the underlying storage backend
func (b *fileSecretBackend) Storage() storage.Backend {
	return b.storage
}
