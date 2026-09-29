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
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	frostCmd.AddCommand(frostRecipientCmd)
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
	frostKeygenCmd.Flags().StringSlice("recipient", nil, "Dealer mode: <participant-id>=<public-key-file> naming the recipient key each package is encrypted to; one per participant (repeatable)")
	addFrostPassphraseFlags(frostKeygenCmd)

	// recipient flags
	frostRecipientCmd.Flags().String("public-key-file", "", "Also write the recipient public key (PEM) to this file")
	addFrostPassphraseFlags(frostRecipientCmd)

	// import flags
	frostImportCmd.Flags().String("package", "", "Path to key package file (required)")
	markFlagRequired(frostImportCmd, "package")
	addFrostPassphraseFlags(frostImportCmd)

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
	addFrostPassphraseFlags(frostRound1Cmd)

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
	addFrostPassphraseFlags(frostRound2Cmd)

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
  - FROST-secp256k1-SHA256 (blockchain compatible)

Every subcommand runs locally against --key-dir. Public material (group
public key, verification shares, metadata) and each secret share, sealed
with AES-256-GCM, live in <key-dir>/frost/public. The key that seals the
shares lives in <key-dir>/frost/secrets as encrypted PKCS#8 under the FROST
passphrase, so keygen (participant mode), import, round1 and round2 require
it: --passphrase-stdin, --passphrase-file or XKMS_FROST_PASSPHRASE. The
passphrase is never accepted as a flag value. Both directories are created
owner-only (0700).`,
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
participant key packages and exports each one to a file encrypted to that
participant's recipient key. Each participant first runs 'xkmsctl frost
recipient' and sends the dealer the public key it prints; the dealer passes
one --recipient <participant-id>=<public-key-file> per participant. Only the
holder of the matching recipient key can import a package. Dealer mode needs
no passphrase.

In participant mode (--participant-id=N), generates and stores only this
participant's key package locally.

Examples:
  # Dealer mode: generate all packages, each encrypted to its participant
  xkmsctl frost keygen --key-id mykey --threshold 2 --total 3 --export-dir ./packages \
    --recipient 1=alice.pem --recipient 2=bob.pem --recipient 3=carol.pem

  # Participant mode: generate and store locally (participant 1)
  xkmsctl frost keygen --key-id mykey --threshold 2 --total 3 --participant-id 1 \
    --passphrase-file ./frost.passphrase

Participant mode seals the share locally. ` + frostPassphraseUsage,
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
		recipientSpecs := fr.StringSlice("recipient")
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
		if !isDealerMode && len(recipientSpecs) > 0 {
			handleError(ErrFrostRecipientParticipantMode)
			return
		}

		// Resolve every recipient key before generating anything, so a
		// missing or malformed one fails before a share exists.
		var recipients map[uint32]*ecdsa.PublicKey
		if isDealerMode {
			var err error
			recipients, err = parseFrostRecipients(recipientSpecs, total)
			if err != nil {
				handleError(err)
				return
			}
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

				recipient, ok := recipients[pkg.ParticipantID]
				if !ok {
					handleError(&FrostRecipientMissingError{ID: pkg.ParticipantID})
					return
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

				encrypted, err := encryptKeyPackageExport(export, recipient)
				if err != nil {
					handleError(err)
					return
				}
				data, err := json.MarshalIndent(encrypted, "", "  ")
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
			be, err := openFrostShareBackend(cmd, cfg, client.FrostAlgorithm(algorithm), participantID, threshold, total, participants)
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

The package is encrypted to this --key-dir's recipient key (see 'xkmsctl
frost recipient'), which is decrypted with the FROST passphrase. A package
encrypted to another participant's key is refused.

Example:
  xkmsctl frost import --package ./alice_participant_1.json --passphrase-stdin < frost.passphrase

` + frostPassphraseUsage,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		packagePath := fr.String("package")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		store, err := openFrostLocalStore(cmd, cfg)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrCreateFROSTBackendFailed, Err: err})
			return
		}

		pkg, err := readFrostPackage(cmd.Context(), store, packagePath)
		if err != nil {
			handleError(err)
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

		be, err := store.shareBackend(cmd.Context(), client.FrostAlgorithm(pkg.Algorithm), pkg.ParticipantID, pkg.Threshold, pkg.Total, nil)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrCreateFROSTBackendFailed, Err: err})
			return
		}
		defer closeQuietly(be)

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
		attrs := &client.KeyAttributes{
			CN:        pkg.KeyID,
			KeyType:   client.KeyTypeSigning,
			StoreType: client.StoreFrost,
		}

		if err := be.ImportKeyPackage(cmd.Context(), attrs, keyPackage); err != nil {
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

// readFrostPackage reads the dealer package file at path and decrypts it
// with the store's recipient key.
func readFrostPackage(ctx context.Context, store *frostLocalStore, path string) (*KeyPackageExport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrReadPackageFileFailed, Err: err}
	}
	var encrypted EncryptedKeyPackageExport
	if err := json.Unmarshal(data, &encrypted); err != nil {
		return nil, &WrappedError{Sentinel: ErrParsePackageFileFailed, Err: err}
	}
	recipientKey, err := loadFrostRecipientKey(ctx, store)
	if err != nil {
		return nil, err
	}
	return decryptKeyPackageExport(&encrypted, recipientKey)
}

// frostRecipientCmd creates and prints this participant's recipient key.
var frostRecipientCmd = &cobra.Command{
	Use:   "recipient",
	Short: "Create and print this participant's package recipient key",
	Long: `Create (on first use) and print the public half of the recipient key that
the trusted dealer encrypts this participant's key package to.

The private key stays in <key-dir>/frost/secrets, encrypted under the FROST
passphrase, and is used only by 'xkmsctl frost import'. Send the public key
to the dealer, who passes it to keygen as --recipient <participant-id>=<file>.
Confirm recipient_id with the dealer over a separate channel: a dealer given
a substituted public key would encrypt your share to someone else.

Running it again prints the same key.

Example:
  xkmsctl frost recipient --public-key-file alice.pem --passphrase-file ./frost.passphrase

` + frostPassphraseUsage,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		publicKeyFile := fr.String("public-key-file")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}

		result, err := runFrostRecipient(cmd, cfg, publicKeyFile)
		if err != nil {
			handleError(err)
			return
		}
		if err := printer.PrintJSON(result); err != nil {
			handleError(err)
		}
	},
}

// runFrostRecipient ensures the store's recipient key exists and returns
// its PEM public key and thumbprint, also writing the PEM to publicKeyFile
// when it is not empty.
func runFrostRecipient(cmd *cobra.Command, cfg *Config, publicKeyFile string) (map[string]interface{}, error) {
	store, err := openFrostLocalStore(cmd, cfg)
	if err != nil {
		return nil, err
	}
	publicKey, err := ensureFrostRecipientKey(cmd.Context(), store)
	if err != nil {
		return nil, err
	}
	publicKeyPEM, err := client.EncodePublicKeyPEM(publicKey)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrProvisionFrostRecipientKeyFailed, Err: err}
	}
	recipientID, err := frostRecipientID(publicKey)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrProvisionFrostRecipientKeyFailed, Err: err}
	}

	result := map[string]interface{}{
		"recipient_id": recipientID,
		"public_key":   string(publicKeyPEM),
	}
	if publicKeyFile != "" {
		// A public key: readable by whoever carries it to the dealer.
		if err := os.WriteFile(publicKeyFile, publicKeyPEM, 0o644); err != nil {
			return nil, &WrappedError{Sentinel: ErrWriteRecipientKeyFailed, Err: err}
		}
		result["public_key_file"] = publicKeyFile
	}
	return result, nil
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

		be, err := openFrostPublicBackend(cfg)
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

		be, err := openFrostPublicBackend(cfg)
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

		// Describing a key needs only its public half, so info never
		// unseals the secret share and needs no passphrase.
		pubPkg, metadata, err := be.PublicKeyPackage(cmd.Context(), attrs)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrGetKeyFailed, Err: err})
			return
		}

		result := map[string]interface{}{
			"key_id":         keyID,
			"algorithm":      string(metadata.Algorithm),
			"participant_id": metadata.ParticipantID,
		}

		if showPubKey {
			result["group_public_key"] = hex.EncodeToString(pubPkg.GroupPublicKey)
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

		be, err := openFrostPublicBackend(cfg)
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
	Long: `Generate nonces and commitments for the first round of FROST signing.

` + frostPassphraseUsage,
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

		be, err := openFrostShareBackend(cmd, cfg, client.FrostAlgorithmEd25519, 1, 2, 3, nil)
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
	Long: `Generate a signature share using collected commitments.

` + frostPassphraseUsage,
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

		be, err := openFrostShareBackend(cmd, cfg, client.FrostAlgorithmEd25519, 1, 2, 3, nil)
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

		be, err := openFrostPublicBackend(cfg)
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

		be, err := openFrostPublicBackend(cfg)
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

// frostDirMode is the mode of every directory the local FROST store
// creates: <key-dir> (when absent), <key-dir>/frost, and its public and
// secrets subdirectories. Owner-only, so neither the sealed shares nor the
// encrypted wrapping key are readable by other local users.
const frostDirMode os.FileMode = 0o700

// frostWrapBackend is the only --backend the local FROST store accepts: the
// passphrase-encrypted software (PKCS#8) wrapping key. xkmsctl builds no
// local TPM 2.0 or PKCS#11 key backend (--pkcs11-module configures mTLS
// client authentication only), so any other --backend is refused rather than
// silently ignored.
const frostWrapBackend = string(client.BackendTypeSoftware)

// frostStoreDirs creates the local FROST store's directories owner-only and
// returns the public and secrets directory paths. os.MkdirAll leaves an
// existing directory's mode untouched, so the FROST directories themselves
// are also tightened to frostDirMode in case an earlier build created them
// world-readable. <key-dir> is shared with other xkmsctl commands and is
// only created, never re-moded.
func frostStoreDirs(keyDir string) (publicDir, secretDir string, err error) {
	frostDir := filepath.Join(keyDir, "frost")
	publicDir = filepath.Join(frostDir, "public")
	secretDir = filepath.Join(frostDir, "secrets")

	if err := os.MkdirAll(publicDir, frostDirMode); err != nil {
		return "", "", &WrappedError{Sentinel: ErrCreatePublicDirectoryFailed, Err: err}
	}
	if err := os.MkdirAll(secretDir, frostDirMode); err != nil {
		return "", "", &WrappedError{Sentinel: ErrCreateSecretDirectoryFailed, Err: err}
	}
	for _, dir := range []string{frostDir, publicDir, secretDir} {
		if err := os.Chmod(dir, frostDirMode); err != nil {
			return "", "", &WrappedError{Sentinel: ErrRestrictFrostDirectoryFailed, Err: err}
		}
	}
	return publicDir, secretDir, nil
}

// openFrostPublicBackend opens the local FROST store for the verbs that
// touch only public material -- list, info, delete, aggregate, verify --
// and therefore need no passphrase.
//
// A client.FrostBackend always carries a secret backend, so this one gets
// the same fail-closed PKCS#8 backend the share verbs use but no passphrase
// and no wrapping-key provisioning: any attempt to seal or unseal a share
// through it fails to decrypt the wrapping key instead of creating or
// reading one.
func openFrostPublicBackend(cfg *Config) (*client.FrostBackend, error) {
	publicDir, secretDir, err := frostStoreDirs(cfg.KeyDir)
	if err != nil {
		return nil, err
	}
	provider, err := newFrostWrapKeyProvider(secretDir)
	if err != nil {
		return nil, err
	}
	sealKeyAttrs := client.FrostAsymmetricSecretSealKeyAttributes(client.StoreSoftware)
	return newFrostBackend(publicDir, provider, sealKeyAttrs, client.FrostAlgorithmEd25519, 1, 2, 3, nil)
}

// frostLocalStore is the local FROST store opened with the operator's
// passphrase: the public directory, and the PKCS#8 backend holding the keys
// that are encrypted under the passphrase -- the share wrapping key and the
// recipient key dealer packages are encrypted to.
type frostLocalStore struct {
	publicDir  string
	provider   client.SealingKeyProvider
	passphrase client.Password
}

// openFrostLocalStore opens the local FROST store for the verbs that use
// its passphrase-protected keys: keygen in participant mode, import,
// recipient, round1 and round2.
//
// It refuses with ErrFrostWrapBackendUnsupported when --backend names a
// backend the store cannot hold its keys in, and with
// ErrFrostPassphraseRequired when no passphrase was supplied.
func openFrostLocalStore(cmd *cobra.Command, cfg *Config) (*frostLocalStore, error) {
	if cfg.Backend != frostWrapBackend {
		return nil, &WrappedDetailError{Sentinel: ErrFrostWrapBackendUnsupported, Detail: cfg.Backend}
	}
	passphrase, err := resolveFrostPassphrase(cmd)
	if err != nil {
		return nil, err
	}

	publicDir, secretDir, err := frostStoreDirs(cfg.KeyDir)
	if err != nil {
		return nil, err
	}
	provider, err := newFrostWrapKeyProvider(secretDir)
	if err != nil {
		return nil, err
	}
	return &frostLocalStore{publicDir: publicDir, provider: provider, passphrase: passphrase}, nil
}

// shareBackend returns the FROST backend that seals and unseals this
// participant's secret share under the store's wrapping key, provisioning
// the key on first use. A wrapping key that does not decrypt under the
// passphrase is reported as ErrFrostPassphraseRejected.
func (s *frostLocalStore) shareBackend(ctx context.Context, algorithm client.FrostAlgorithm, participantID uint32, threshold, total int, participants []string) (*client.FrostBackend, error) {
	sealKeyAttrs, err := ensureFrostWrapKey(ctx, s.provider, s.passphrase)
	if err != nil {
		return nil, err
	}
	return newFrostBackend(s.publicDir, s.provider, sealKeyAttrs, algorithm, participantID, threshold, total, participants)
}

// openFrostShareBackend opens the local FROST store (openFrostLocalStore) and
// returns its share backend (frostLocalStore.shareBackend), for the verbs
// that seal or unseal this participant's secret share.
func openFrostShareBackend(cmd *cobra.Command, cfg *Config, algorithm client.FrostAlgorithm, participantID uint32, threshold, total int, participants []string) (*client.FrostBackend, error) {
	store, err := openFrostLocalStore(cmd, cfg)
	if err != nil {
		return nil, err
	}
	return store.shareBackend(cmd.Context(), algorithm, participantID, threshold, total, participants)
}

// newFrostWrapKeyProvider builds the backend that holds the local FROST
// store's wrapping key under secretDir: a PKCS#8 backend with
// AllowPlaintextKeys false, so it refuses to write the key unencrypted. Its
// Sealer derives an AES-256-GCM key from the wrapping key (HKDF) and seals
// each secret share with it -- the same Sealer the "software" and "pkcs8"
// FROST secret backends use in xkmsd, so the sealed-share format is shared.
func newFrostWrapKeyProvider(secretDir string) (client.SealingKeyProvider, error) {
	secretStorage, err := client.NewFileStorageBackend(secretDir)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrCreateSecretStorageFailed, Err: err}
	}
	backend, err := client.NewPKCS8Backend(&client.PKCS8BackendConfig{KeyStorage: secretStorage})
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrCreateSecretStorageFailed, Err: err}
	}
	provider, ok := backend.(client.SealingKeyProvider)
	if !ok {
		return nil, &WrappedError{Sentinel: ErrCreateSecretStorageFailed, Err: ErrSoftwareBackendNotSealer}
	}
	return provider, nil
}

// ensureFrostWrapKey returns the KeyAttributes of the Ed25519 wrapping key
// the share verbs seal and unseal under, carrying passphrase so the PKCS#8
// backend stores the key as encrypted PKCS#8 (PBES2) and decrypts it on
// every use. The key is generated on first use and reused thereafter; a
// stored key that does not decrypt under passphrase is reported as
// ErrFrostPassphraseRejected.
func ensureFrostWrapKey(ctx context.Context, provider client.SealingKeyProvider, passphrase client.Password) (*client.KeyAttributes, error) {
	sealKeyAttrs := client.FrostAsymmetricSecretSealKeyAttributes(client.StoreSoftware)
	sealKeyAttrs.Password = passphrase
	if err := client.EnsurePrivateSealKey(ctx, provider, sealKeyAttrs); err != nil {
		if errors.Is(err, client.ErrPKCS8KeyDecodingFailed) {
			return nil, &WrappedError{Sentinel: ErrFrostPassphraseRejected, Err: err}
		}
		return nil, &WrappedError{Sentinel: ErrProvisionFrostSealKeyFailed, Err: err}
	}
	return sealKeyAttrs, nil
}

// newFrostBackend assembles a client.FrostBackend over the public store in
// publicDir and the given secret backend and wrapping key.
//
// The secret shares are sealed, not stored in the clear (go-xkms#841), and
// the sealed envelopes live beside the public material in publicDir. What
// protects them is the wrapping key in <key-dir>/frost/secrets, which is
// encrypted PKCS#8 under the operator's FROST passphrase (go-xkms#1324):
// read access to the key directory alone yields neither the shares nor the
// key that seals them. Both directories are owner-only (frostDirMode).
func newFrostBackend(publicDir string, provider client.SealingKeyProvider, sealKeyAttrs *client.KeyAttributes, algorithm client.FrostAlgorithm, participantID uint32, threshold, total int, participants []string) (*client.FrostBackend, error) {
	publicStorage, err := client.NewFileStorageBackend(publicDir)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrCreatePublicStorageFailed, Err: err}
	}

	return client.NewFrostBackend(&client.FrostBackendConfig{
		PublicStorage:           publicStorage,
		SecretBackend:           provider,
		SecretSealKeyAttributes: sealKeyAttrs,
		Algorithm:               algorithm,
		ParticipantID:           participantID,
		DefaultThreshold:        threshold,
		DefaultTotal:            total,
		Participants:            participants,
		EnableNonceTracking:     true,
	})
}
