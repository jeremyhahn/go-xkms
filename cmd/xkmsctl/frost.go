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

//go:build frost

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
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
	markFlagRequired(frostImportCmd, "package")

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
	markFlagRequired(frostRound1Cmd, "key-id")
	markFlagRequired(frostRound1Cmd, "output")

	// round2 flags
	frostRound2Cmd.Flags().StringP("key-id", "k", "", "Key identifier (required)")
	frostRound2Cmd.Flags().StringP("message", "m", "", "Message to sign")
	frostRound2Cmd.Flags().String("message-file", "", "File containing message")
	frostRound2Cmd.Flags().String("message-hex", "", "Message as hex string")
	frostRound2Cmd.Flags().String("nonces", "", "This participant's nonce package file (required)")
	frostRound2Cmd.Flags().StringP("commitments", "c", "", "Comma-separated commitment files (required)")
	frostRound2Cmd.Flags().StringP("output", "o", "", "Output file for signature share (required)")
	markFlagRequired(frostRound2Cmd, "key-id")
	markFlagRequired(frostRound2Cmd, "nonces")
	markFlagRequired(frostRound2Cmd, "commitments")
	markFlagRequired(frostRound2Cmd, "output")

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
	markFlagRequired(frostAggregateCmd, "key-id")
	markFlagRequired(frostAggregateCmd, "commitments")
	markFlagRequired(frostAggregateCmd, "shares")
	markFlagRequired(frostAggregateCmd, "output")

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
  xkmsctl frost keygen --key-id mykey --threshold 2 --total 3 --export-dir ./packages

  # Participant mode: generate and store locally (participant 1)
  xkmsctl frost keygen --key-id mykey --threshold 2 --total 3 --participant-id 1`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		algorithm := fr.String("algorithm")
		threshold := fr.Int("threshold")
		total := fr.Int("total")
		participantsStr := fr.String("participants")
		keyID := fr.String("key-id")
		participantID := fr.Uint32("participant-id")
		exportDir := fr.String("export-dir")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

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
			handleError(&ParticipantCountError{Count: len(participants), Total: total})
			return
		}

		// Determine mode: dealer (export all) or participant (store one)
		isDealerMode := exportDir != "" || participantID == 0

		if isDealerMode && exportDir == "" {
			handleError(ErrDealerModeExportDirRequired)
			return
		}

		printVerbose("Generating FROST key: %s (algorithm=%s, threshold=%d/%d, dealer=%v)",
			keyID, algorithm, threshold, total, isDealerMode)

		// Generate all packages using trusted dealer
		td := client.NewFrostTrustedDealer()
		frostConfig := client.FrostConfig{
			Threshold:     threshold,
			Total:         total,
			Algorithm:     client.FrostAlgorithm(algorithm),
			ParticipantID: 1, // Not used for generation
		}

		packages, pubPkg, err := td.Generate(frostConfig)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrGenerateFROSTPackagesFailed, Err: err})
			return
		}

		if isDealerMode {
			// Dealer mode: export all packages to files
			if err := os.MkdirAll(exportDir, 0700); err != nil {
				handleError(&WrappedError{Sentinel: ErrCreateExportDirectoryFailed, Err: err})
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
					handleError(&WrappedError{Sentinel: ErrMarshalPackageFailed, Err: err})
					return
				}

				if err := os.WriteFile(filePath, data, 0600); err != nil {
					handleError(&WrappedError{Sentinel: ErrWritePackageFileFailed, Err: err})
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
				handleError(&ParticipantIDRangeError{Total: total})
				return
			}

			// Find this participant's package
			var myPackage *client.FrostKeyPackage
			for _, pkg := range packages {
				if pkg.ParticipantID == participantID {
					myPackage = pkg
					break
				}
			}
			if myPackage == nil {
				handleError(&ParticipantPackageNotFoundError{ID: participantID})
				return
			}

			// Create backend and store
			be, err := createFrostBackend(cfg, client.FrostAlgorithm(algorithm), participantID, threshold, total, participants)
			if err != nil {
				handleError(&WrappedError{Sentinel: ErrCreateFROSTBackendFailed, Err: err})
				return
			}
			defer closeQuietly(be)

			// Generate key via backend (which handles storage)
			attrs := &client.KeyAttributes{
				CN:        keyID,
				KeyType:   client.KeyTypeSigning,
				StoreType: client.StoreFrost,
				FrostAttributes: &client.FrostAttributes{
					Algorithm:     client.FrostAlgorithm(algorithm),
					Threshold:     threshold,
					Total:         total,
					Participants:  participants,
					ParticipantID: participantID,
				},
			}

			key, err := be.GenerateKey(cmd.Context(), attrs)
			if err != nil {
				handleError(&WrappedError{Sentinel: ErrGenerateFROSTKeyFailed, Err: err})
				return
			}

			handle := key.(*client.FrostKeyHandle)

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
  xkmsctl frost import --package ./alice_participant_1.json`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		packagePath := fr.String("package")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		// Read package file
		data, err := os.ReadFile(packagePath)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrReadPackageFileFailed, Err: err})
			return
		}

		var pkg KeyPackageExport
		if err := json.Unmarshal(data, &pkg); err != nil {
			handleError(&WrappedError{Sentinel: ErrParsePackageFileFailed, Err: err})
			return
		}

		printVerbose("Importing FROST package: key=%s, participant=%d, algorithm=%s",
			pkg.KeyID, pkg.ParticipantID, pkg.Algorithm)

		// Decode hex values
		secretShare, err := hex.DecodeString(pkg.SecretShare)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrDecodeSecretShareFailed, Err: err})
			return
		}

		groupPublicKey, err := hex.DecodeString(pkg.GroupPublicKey)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrDecodeGroupPublicKeyFailed, Err: err})
			return
		}

		verificationShares := make(map[uint32][]byte)
		for id, vsHex := range pkg.VerificationShares {
			vs, err := hex.DecodeString(vsHex)
			if err != nil {
				handleError(&VerificationShareDecodeError{ID: id, Err: err})
				return
			}
			verificationShares[id] = vs
		}

		// Create storage backends
		publicDir := filepath.Join(cfg.KeyDir, "frost", "public")
		if err := os.MkdirAll(publicDir, 0755); err != nil {
			handleError(&WrappedError{Sentinel: ErrCreatePublicDirectoryFailed, Err: err})
			return
		}

		publicStorage, err := client.NewFileStorageBackend(publicDir)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrCreatePublicStorageFailed, Err: err})
			return
		}

		secretBackend, err := newFrostSecretBackend(cfg)
		if err != nil {
			handleError(err)
			return
		}

		// Create KeyStore and store package
		ks := client.NewFrostKeyStore(publicStorage, secretBackend.provider, secretBackend.sealKeyAttrs)

		keyPackage := &client.FrostKeyPackage{
			ParticipantID: pkg.ParticipantID,
			SecretShare: &client.FrostSecretKeyShare{
				Value: secretShare,
			},
			GroupPublicKey:     groupPublicKey,
			VerificationShares: verificationShares,
			MinSigners:         uint32(pkg.Threshold),
			MaxSigners:         uint32(pkg.Total),
			Algorithm:          client.FrostAlgorithm(pkg.Algorithm),
		}

		metadata := &client.FrostKeyMetadata{
			KeyID:             pkg.KeyID,
			Algorithm:         client.FrostAlgorithm(pkg.Algorithm),
			Threshold:         pkg.Threshold,
			Total:             pkg.Total,
			ParticipantID:     pkg.ParticipantID,
			CreatedAt:         time.Now().Unix(),
			SecretBackendType: client.BackendTypeSoftware,
		}

		if err := ks.StoreKeyPackage(cmd.Context(), pkg.KeyID, keyPackage, metadata); err != nil {
			handleError(&WrappedError{Sentinel: ErrStoreKeyPackageFailed, Err: err})
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
		fr := newFlagReader(cmd)
		format := fr.String("format")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		be, err := createFrostBackend(cfg, client.FrostAlgorithmEd25519, 1, 2, 3, nil)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrCreateFROSTBackendFailed, Err: err})
			return
		}
		defer closeQuietly(be)

		keys, err := be.ListKeys(cmd.Context())
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrListKeysFailed, Err: err})
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
		fr := newFlagReader(cmd)
		showPubKey := fr.Bool("show-public-key")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		be, err := createFrostBackend(cfg, client.FrostAlgorithmEd25519, 1, 2, 3, nil)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrCreateFROSTBackendFailed, Err: err})
			return
		}
		defer closeQuietly(be)

		attrs := &client.KeyAttributes{
			CN:        keyID,
			KeyType:   client.KeyTypeSigning,
			StoreType: client.StoreFrost,
		}

		key, err := be.GetKey(cmd.Context(), attrs)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrGetKeyFailed, Err: err})
			return
		}

		handle := key.(*client.FrostKeyHandle)

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
		fr := newFlagReader(cmd)
		force := fr.Bool("force")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		if !force {
			fmt.Printf("Are you sure you want to delete key '%s'? [y/N]: ", keyID)
			var response string
			// A read failure (including an empty line, which Scanln reports
			// as an error) is treated the same as any other non-"y" answer:
			// abort rather than delete.
			if _, err := fmt.Scanln(&response); err != nil || !strings.EqualFold(response, "y") {
				fmt.Println("Aborted")
				return
			}
		}

		be, err := createFrostBackend(cfg, client.FrostAlgorithmEd25519, 1, 2, 3, nil)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrCreateFROSTBackendFailed, Err: err})
			return
		}
		defer closeQuietly(be)

		attrs := &client.KeyAttributes{
			CN:        keyID,
			KeyType:   client.KeyTypeSigning,
			StoreType: client.StoreFrost,
		}

		if err := be.DeleteKey(cmd.Context(), attrs); err != nil {
			handleError(&WrappedError{Sentinel: ErrDeleteKeyFailed, Err: err})
			return
		}

		if err := printer.PrintSuccess(fmt.Sprintf("Successfully deleted key: %s", keyID)); err != nil {
			handleError(err)
		}
	},
}

// CommitmentFile represents the JSON structure for round1 output
type CommitmentFile struct {
	ParticipantID uint32                          `json:"participant_id"`
	SessionID     string                          `json:"session_id"`
	Commitments   *client.FrostSigningCommitments `json:"commitments"`
}

// NonceFile represents the internal nonce storage (kept secret)
type NonceFile struct {
	ParticipantID uint32                     `json:"participant_id"`
	SessionID     string                     `json:"session_id"`
	Nonces        *client.FrostSigningNonces `json:"nonces"`
}

// frostRound1Cmd generates nonces for round 1
var frostRound1Cmd = &cobra.Command{
	Use:   "round1",
	Short: "Generate nonces and commitments (Round 1)",
	Long:  `Generate nonces and commitments for the first round of FROST signing.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		keyID := fr.String("key-id")
		outputPath := fr.String("output")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		be, err := createFrostBackend(cfg, client.FrostAlgorithmEd25519, 1, 2, 3, nil)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrCreateFROSTBackendFailed, Err: err})
			return
		}
		defer closeQuietly(be)

		// Generate nonces
		noncePackage, err := be.GenerateNonces(keyID)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrGenerateNoncesFailed, Err: err})
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
			handleError(&WrappedError{Sentinel: ErrMarshalCommitmentFailed, Err: err})
			return
		}

		if err := os.WriteFile(outputPath, commitmentData, 0644); err != nil {
			handleError(&WrappedError{Sentinel: ErrWriteCommitmentFileFailed, Err: err})
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
			handleError(&WrappedError{Sentinel: ErrMarshalNoncesFailed, Err: err})
			return
		}

		if err := os.WriteFile(noncePath, nonceData, 0600); err != nil {
			handleError(&WrappedError{Sentinel: ErrWriteNonceFileFailed, Err: err})
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

		fr := newFlagReader(cmd)
		keyID := fr.String("key-id")
		noncesPath := fr.String("nonces")
		commitmentsStr := fr.String("commitments")
		outputPath := fr.String("output")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		// Get message
		message, err := getMessage(cmd)
		if err != nil {
			handleError(err)
			return
		}

		be, err := createFrostBackend(cfg, client.FrostAlgorithmEd25519, 1, 2, 3, nil)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrCreateFROSTBackendFailed, Err: err})
			return
		}
		defer closeQuietly(be)

		// Load nonces (from the .nonces file)
		noncePath := noncesPath
		if !strings.HasSuffix(noncePath, ".nonces") {
			noncePath += ".nonces"
		}

		nonceData, err := os.ReadFile(noncePath)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrReadNonceFileFailed, Err: err})
			return
		}

		var nonceFile NonceFile
		if err := json.Unmarshal(nonceData, &nonceFile); err != nil {
			handleError(&WrappedError{Sentinel: ErrParseNonceFileFailed, Err: err})
			return
		}

		// Load commitment file to get session info
		commitmentPath := strings.TrimSuffix(noncesPath, ".nonces")
		commitmentData, err := os.ReadFile(commitmentPath)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrReadCommitmentFileFailed, Err: err})
			return
		}

		var myCommitment CommitmentFile
		if err := json.Unmarshal(commitmentData, &myCommitment); err != nil {
			handleError(&WrappedError{Sentinel: ErrParseCommitmentFileFailed, Err: err})
			return
		}

		// Build NoncePackage
		noncePackage := &client.FrostNoncePackage{
			ParticipantID: nonceFile.ParticipantID,
			SessionID:     nonceFile.SessionID,
			Nonces:        nonceFile.Nonces,
			Commitments:   myCommitment.Commitments,
		}

		// Load all commitments
		commitmentFiles := strings.Split(commitmentsStr, ",")
		var commitments []*client.FrostCommitment
		for _, cf := range commitmentFiles {
			cf = strings.TrimSpace(cf)
			data, err := os.ReadFile(cf)
			if err != nil {
				handleError(&CommitmentFileReadError{Path: cf, Err: err})
				return
			}

			var c CommitmentFile
			if err := json.Unmarshal(data, &c); err != nil {
				handleError(&CommitmentFileParseError{Path: cf, Err: err})
				return
			}

			commitments = append(commitments, &client.FrostCommitment{
				ParticipantID: c.ParticipantID,
				Commitments:   c.Commitments,
			})
		}

		// Generate signature share
		share, err := be.SignRound(keyID, message, noncePackage, commitments)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrGenerateSignatureShareFailed, Err: err})
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
			handleError(&WrappedError{Sentinel: ErrMarshalShareFailed, Err: err})
			return
		}

		if err := os.WriteFile(outputPath, shareData, 0644); err != nil {
			handleError(&WrappedError{Sentinel: ErrShareFileWrite, Err: err})
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

		fr := newFlagReader(cmd)
		keyID := fr.String("key-id")
		commitmentsStr := fr.String("commitments")
		sharesStr := fr.String("shares")
		outputPath := fr.String("output")
		format := fr.String("format")
		verify := fr.Bool("verify")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		// Get message
		message, err := getMessage(cmd)
		if err != nil {
			handleError(err)
			return
		}

		be, err := createFrostBackend(cfg, client.FrostAlgorithmEd25519, 1, 2, 3, nil)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrCreateFROSTBackendFailed, Err: err})
			return
		}
		defer closeQuietly(be)

		// Load commitments
		commitmentFiles := strings.Split(commitmentsStr, ",")
		var commitments []*client.FrostCommitment
		for _, cf := range commitmentFiles {
			cf = strings.TrimSpace(cf)
			data, err := os.ReadFile(cf)
			if err != nil {
				handleError(&CommitmentFileReadError{Path: cf, Err: err})
				return
			}

			var c CommitmentFile
			if err := json.Unmarshal(data, &c); err != nil {
				handleError(&CommitmentFileParseError{Path: cf, Err: err})
				return
			}

			commitments = append(commitments, &client.FrostCommitment{
				ParticipantID: c.ParticipantID,
				Commitments:   c.Commitments,
			})
		}

		// Load shares
		shareFiles := strings.Split(sharesStr, ",")
		var shares []*client.FrostSignatureShare
		for _, sf := range shareFiles {
			sf = strings.TrimSpace(sf)
			data, err := os.ReadFile(sf)
			if err != nil {
				handleError(&ShareFileReadError{Path: sf, Err: err})
				return
			}

			var s ShareFile
			if err := json.Unmarshal(data, &s); err != nil {
				handleError(&ShareFileParseError{Path: sf, Err: err})
				return
			}

			shareBytes, err := hex.DecodeString(s.SignatureShare)
			if err != nil {
				handleError(&ShareDecodeError{Path: sf, Err: err})
				return
			}

			shares = append(shares, &client.FrostSignatureShare{
				ParticipantID: s.ParticipantID,
				SessionID:     s.SessionID,
				Share:         shareBytes,
			})
		}

		// Aggregate
		signature, err := be.Aggregate(keyID, message, commitments, shares)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrAggregateSignaturesFailed, Err: err})
			return
		}

		// Verify if requested
		if verify {
			if err := be.Verify(keyID, message, signature); err != nil {
				handleError(&WrappedError{Sentinel: ErrSignatureVerificationFailed, Err: err})
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
			handleError(&WrappedError{Sentinel: ErrWriteSignatureFileFailed, Err: err})
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

		fr := newFlagReader(cmd)
		keyID := fr.String("key-id")
		sigFile := fr.String("signature")
		sigHex := fr.String("signature-hex")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

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
				handleError(&WrappedError{Sentinel: ErrInvalidSignatureHex, Err: err})
				return
			}
		} else if sigFile != "" {
			signature, err = os.ReadFile(sigFile)
			if err != nil {
				handleError(&WrappedError{Sentinel: ErrReadSignatureFileFailed, Err: err})
				return
			}
			// Try to detect format
			if decoded, err := hex.DecodeString(string(signature)); err == nil {
				signature = decoded
			} else if decoded, err := base64.StdEncoding.DecodeString(string(signature)); err == nil {
				signature = decoded
			}
		} else {
			handleError(ErrSignatureInputRequired)
			return
		}

		be, err := createFrostBackend(cfg, client.FrostAlgorithmEd25519, 1, 2, 3, nil)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrCreateFROSTBackendFailed, Err: err})
			return
		}
		defer closeQuietly(be)

		if err := be.Verify(keyID, message, signature); err != nil {
			handleError(&WrappedError{Sentinel: ErrFROSTVerifyFailed, Err: err})
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
	fr := newFlagReader(cmd)
	msgStr := fr.String("message")
	msgFile := fr.String("message-file")
	msgHex := fr.String("message-hex")
	if err := fr.Err(); err != nil {
		return nil, err
	}

	if msgStr != "" {
		return []byte(msgStr), nil
	}

	if msgFile != "" {
		data, err := os.ReadFile(msgFile)
		if err != nil {
			return nil, &WrappedError{Sentinel: ErrReadMessageFileFailed, Err: err}
		}
		// Hash file contents for signing
		hash := sha256.Sum256(data)
		return hash[:], nil
	}

	if msgHex != "" {
		data, err := hex.DecodeString(strings.TrimPrefix(msgHex, "0x"))
		if err != nil {
			return nil, &WrappedError{Sentinel: ErrInvalidMessageHex, Err: err}
		}
		return data, nil
	}

	return nil, ErrMessageInputRequired
}

// truncateMessage truncates a message for display
func truncateMessage(msg []byte, maxLen int) string {
	if len(msg) <= maxLen {
		return string(msg)
	}
	return string(msg[:maxLen]) + "..."
}

// createFrostBackend creates a FROST backend with appropriate configuration
func createFrostBackend(cfg *Config, algorithm client.FrostAlgorithm, participantID uint32, threshold, total int, participants []string) (*client.FrostBackend, error) {
	// Create public storage
	publicDir := filepath.Join(cfg.KeyDir, "frost", "public")
	if err := os.MkdirAll(publicDir, 0755); err != nil {
		return nil, &WrappedError{Sentinel: ErrCreatePublicDirectoryFailed, Err: err}
	}

	publicStorage, err := client.NewFileStorageBackend(publicDir)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrCreatePublicStorageFailed, Err: err}
	}

	secretBackend, err := newFrostSecretBackend(cfg)
	if err != nil {
		return nil, err
	}

	frostConfig := &client.FrostBackendConfig{
		PublicStorage:           publicStorage,
		SecretBackend:           secretBackend.provider,
		SecretSealKeyAttributes: secretBackend.sealKeyAttrs,
		Algorithm:               algorithm,
		ParticipantID:           participantID,
		DefaultThreshold:        threshold,
		DefaultTotal:            total,
		Participants:            participants,
		EnableNonceTracking:     true,
	}

	return client.NewFrostBackend(frostConfig)
}

// frostSecretBackend bundles the SDK software backend that holds FROST
// secret shares with the KeyAttributes identifying the wrapping key its
// Sealer implementation seals/unseals them under.
type frostSecretBackend struct {
	provider     client.SealingKeyProvider
	sealKeyAttrs *client.KeyAttributes
}

// newFrostSecretBackend builds the local secret backend every xkmsctl FROST
// command uses to hold participant secret shares: a real, production
// client.SoftwareBackend (the same Sealer/KeyProvider xkmsd registers under
// backends.software) rooted at cfg.KeyDir/frost/secrets, with its dedicated
// Ed25519 wrapping key (client.FrostAsymmetricSecretSealKeyAttributes)
// provisioned idempotently via client.EnsurePrivateSealKey -- the same
// composition pkg/server's ensureFrostSecretSealKey uses for the "software"
// secret_backend, so a share sealed by xkmsctl and one sealed by xkmsd are
// interchangeable in format.
//
// This replaced a bespoke fileSecretBackend that wrote each secret share to
// disk verbatim, in the clear (go-xkms#841): the software backend's Sealer
// gives every share an opaque, backend-encrypted envelope instead, with no
// duplicated crypto to maintain here.
func newFrostSecretBackend(cfg *Config) (*frostSecretBackend, error) {
	secretDir := filepath.Join(cfg.KeyDir, "frost", "secrets")
	if err := os.MkdirAll(secretDir, 0700); err != nil {
		return nil, &WrappedError{Sentinel: ErrCreateSecretDirectoryFailed, Err: err}
	}

	secretStorage, err := client.NewFileStorageBackend(secretDir)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrCreateSecretStorageFailed, Err: err}
	}

	backend, err := client.NewSoftwareBackend(&client.SoftwareBackendConfig{KeyStorage: secretStorage})
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrCreateSecretStorageFailed, Err: err}
	}
	provider, ok := backend.(client.SealingKeyProvider)
	if !ok {
		return nil, &WrappedError{Sentinel: ErrCreateSecretStorageFailed, Err: ErrSoftwareBackendNotSealer}
	}

	sealKeyAttrs := client.FrostAsymmetricSecretSealKeyAttributes(client.StoreSoftware)
	if err := client.EnsurePrivateSealKey(context.Background(), provider, sealKeyAttrs); err != nil {
		return nil, &WrappedError{Sentinel: ErrProvisionFrostSealKeyFailed, Err: err}
	}

	return &frostSecretBackend{provider: provider, sealKeyAttrs: sealKeyAttrs}, nil
}
