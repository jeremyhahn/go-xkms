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

package cli

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/spf13/cobra"
)

// keyCmd represents the key command
var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage cryptographic keys",
	Long:  `Generate, list, delete, and manage cryptographic keys`,
}

// keyGenerateCmd generates a new key
var keyGenerateCmd = &cobra.Command{
	Use:   "generate <key-id>",
	Short: "Generate a new cryptographic key",
	Long:  `Generate a new cryptographic key with specified algorithm and parameters`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		algorithm, _ := cmd.Flags().GetString("algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")

		printVerbose("Generating %s key with ID: %s", keyType, keyID)

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// Check if this is a symmetric key (AES)
		if keyType == "aes" || algorithm == "aes-128-gcm" || algorithm == "aes-192-gcm" || algorithm == "aes-256-gcm" {
			// Generate symmetric key
			attrs, err := buildSymmetricKeyAttributes(keyID, algorithm, keySize)
			if err != nil {
				handleError(fmt.Errorf("invalid symmetric key parameters: %w", err))
				return
			}

			printVerbose("Symmetric key attributes: %+v", attrs)

			// Generate the symmetric key
			_, err = be.GenerateKey(attrs)
			if err != nil {
				handleError(fmt.Errorf("failed to generate symmetric key: %w", err))
				return
			}

			if err := printer.PrintSuccess(fmt.Sprintf("Successfully generated AES-%d key: %s", keySize, keyID)); err != nil {
				handleError(err)
			}
			return
		}

		// Build asymmetric key attributes
		attrs, err := buildKeyAttributes(keyID, keyType, keySize, curve)
		if err != nil {
			handleError(fmt.Errorf("invalid key parameters: %w", err))
			return
		}

		printVerbose("Key attributes: %+v", attrs)

		// Generate the key
		_, err = be.GenerateKey(attrs)
		if err != nil {
			handleError(fmt.Errorf("failed to generate key: %w", err))
			return
		}

		if err := printer.PrintSuccess(fmt.Sprintf("Successfully generated %s key: %s", keyType, keyID)); err != nil {
			handleError(err)
		}
	},
}

// keyListCmd lists all keys
var keyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all keys",
	Long:  `List all cryptographic keys in the keystore`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Listing keys from backend: %s", cfg.Backend)

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// List keys
		keys, err := be.ListKeys()
		if err != nil {
			handleError(fmt.Errorf("failed to list keys: %w", err))
			return
		}

		printVerbose("Found %d keys", len(keys))

		if err := printer.PrintKeyList(keys); err != nil {
			handleError(err)
		}
	},
}

// keyGetCmd gets information about a specific key
var keyGetCmd = &cobra.Command{
	Use:   "get <key-id>",
	Short: "Get information about a key",
	Long:  `Display detailed information about a specific key`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")

		printVerbose("Getting key info for: %s", keyID)

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// Build key attributes with algorithm-specific params
		attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve)
		if err != nil {
			handleError(fmt.Errorf("invalid key parameters: %w", err))
			return
		}

		// Try to get the key to verify it exists
		_, err = be.GetKey(attrs)
		if err != nil {
			handleError(fmt.Errorf("failed to get key: %w", err))
			return
		}

		if err := printer.PrintKeyInfo(attrs); err != nil {
			handleError(err)
		}
	},
}

// keyDeleteCmd deletes a key
var keyDeleteCmd = &cobra.Command{
	Use:   "delete <key-id>",
	Short: "Delete a key",
	Long:  `Delete a cryptographic key from the keystore`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")

		printVerbose("Deleting key: %s", keyID)

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// Build key attributes with algorithm-specific params
		attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve)
		if err != nil {
			handleError(fmt.Errorf("invalid key parameters: %w", err))
			return
		}

		// Delete the key
		if err := be.DeleteKey(attrs); err != nil {
			handleError(fmt.Errorf("failed to delete key: %w", err))
			return
		}

		if err := printer.PrintSuccess(fmt.Sprintf("Successfully deleted key: %s", keyID)); err != nil {
			handleError(err)
		}
	},
}

// keySignCmd signs data with a key
var keySignCmd = &cobra.Command{
	Use:   "sign <key-id> <data>",
	Short: "Sign data with a key",
	Long:  `Sign data using a cryptographic key`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		data := args[1]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")
		hashAlg, _ := cmd.Flags().GetString("hash")

		printVerbose("Signing data with key: %s", keyID)

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// Build key attributes with algorithm-specific params
		attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve)
		if err != nil {
			handleError(fmt.Errorf("invalid key parameters: %w", err))
			return
		}
		// Parse hash algorithm from string
		if hashAlgParsed, ok := types.AvailableHashes()[hashAlg]; ok {
			attrs.Hash = hashAlgParsed
		} else {
			handleError(fmt.Errorf("invalid hash algorithm: %s", hashAlg))
			return
		}

		// Get signer
		signer, err := be.Signer(attrs)
		if err != nil {
			handleError(fmt.Errorf("failed to get signer: %w", err))
			return
		}

		// Hash the data
		hash := attrs.Hash
		hasher := hash.New()
		hasher.Write([]byte(data))
		digest := hasher.Sum(nil)

		printVerbose("Data digest (hex): %x", digest)

		// Sign the digest
		signature, err := signer.Sign(nil, digest, hash)
		if err != nil {
			handleError(fmt.Errorf("failed to sign data: %w", err))
			return
		}

		// Encode signature as base64
		sigBase64 := base64.StdEncoding.EncodeToString(signature)

		if err := printer.PrintSignature(sigBase64); err != nil {
			handleError(err)
		}
	},
}

// keyRotateCmd rotates a key
var keyRotateCmd = &cobra.Command{
	Use:   "rotate <key-id>",
	Short: "Rotate a key",
	Long:  `Rotate a key by generating a new version and invalidating the old one`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")

		printVerbose("Rotating key: %s", keyID)

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// Build key attributes with algorithm-specific params
		attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve)
		if err != nil {
			handleError(fmt.Errorf("invalid key parameters: %w", err))
			return
		}

		// Rotate the key
		if err := be.RotateKey(attrs); err != nil {
			handleError(fmt.Errorf("failed to rotate key: %w", err))
			return
		}

		if err := printer.PrintSuccess(fmt.Sprintf("Successfully rotated key: %s", keyID)); err != nil {
			handleError(err)
		}
	},
}

// keyEncryptCmd encrypts data with a symmetric key
var keyEncryptCmd = &cobra.Command{
	Use:   "encrypt <key-id> <plaintext>",
	Short: "Encrypt data with a symmetric key",
	Long:  `Encrypt data using a symmetric (AES) key`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		plaintext := args[1]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		aad, _ := cmd.Flags().GetString("aad")

		printVerbose("Encrypting data with key: %s", keyID)

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// Build key attributes
		attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, "")
		if err != nil {
			handleError(fmt.Errorf("invalid key parameters: %w", err))
			return
		}

		// Get symmetric encrypter (requires SymmetricBackend)
		symBackend, ok := be.(types.SymmetricBackend)
		if !ok {
			handleError(fmt.Errorf("backend does not support symmetric encryption"))
			return
		}

		encrypter, err := symBackend.SymmetricEncrypter(attrs)
		if err != nil {
			handleError(fmt.Errorf("failed to get symmetric encrypter: %w", err))
			return
		}

		// Prepare encryption options
		opts := &types.EncryptOptions{}
		if aad != "" {
			opts.AdditionalData = []byte(aad)
		}

		// Encrypt the data
		encrypted, err := encrypter.Encrypt([]byte(plaintext), opts)
		if err != nil {
			handleError(fmt.Errorf("failed to encrypt data: %w", err))
			return
		}

		printVerbose("Encrypted data: ciphertext=%d bytes, nonce=%d bytes, tag=%d bytes",
			len(encrypted.Ciphertext), len(encrypted.Nonce), len(encrypted.Tag))

		if err := printer.PrintEncryptedData(encrypted); err != nil {
			handleError(err)
		}
	},
}

// keyDecryptCmd decrypts data with a key
var keyDecryptCmd = &cobra.Command{
	Use:   "decrypt <key-id> <ciphertext>",
	Short: "Decrypt data with a key",
	Long:  `Decrypt data using a cryptographic key (asymmetric or symmetric)`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		ciphertext := args[1]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")
		aad, _ := cmd.Flags().GetString("aad")
		nonce, _ := cmd.Flags().GetString("nonce")
		tag, _ := cmd.Flags().GetString("tag")

		printVerbose("Decrypting data with key: %s", keyID)

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// Build key attributes with algorithm-specific params
		attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve)
		if err != nil {
			handleError(fmt.Errorf("invalid key parameters: %w", err))
			return
		}

		// Check if this is symmetric decryption (nonce and tag present)
		if nonce != "" && tag != "" {
			// Symmetric decryption (requires SymmetricBackend)
			symBackend, ok := be.(types.SymmetricBackend)
			if !ok {
				handleError(fmt.Errorf("backend does not support symmetric encryption"))
				return
			}

			encrypter, err := symBackend.SymmetricEncrypter(attrs)
			if err != nil {
				handleError(fmt.Errorf("failed to get symmetric encrypter: %w", err))
				return
			}

			// Decode base64 inputs
			ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
			if err != nil {
				handleError(fmt.Errorf("failed to decode ciphertext: %w", err))
				return
			}

			nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
			if err != nil {
				handleError(fmt.Errorf("failed to decode nonce: %w", err))
				return
			}

			tagBytes, err := base64.StdEncoding.DecodeString(tag)
			if err != nil {
				handleError(fmt.Errorf("failed to decode tag: %w", err))
				return
			}

			// Build EncryptedData
			encrypted := &types.EncryptedData{
				Ciphertext: ciphertextBytes,
				Nonce:      nonceBytes,
				Tag:        tagBytes,
				Algorithm:  string(attrs.SymmetricAlgorithm),
			}

			// Prepare decryption options
			opts := &types.DecryptOptions{}
			if aad != "" {
				opts.AdditionalData = []byte(aad)
			}

			// Decrypt
			plaintext, err := encrypter.Decrypt(encrypted, opts)
			if err != nil {
				handleError(fmt.Errorf("failed to decrypt data: %w", err))
				return
			}

			// Output plaintext as base64
			plaintextBase64 := base64.StdEncoding.EncodeToString(plaintext)

			if err := printer.PrintDecryptedData(plaintextBase64); err != nil {
				handleError(err)
			}
			return
		}

		// Asymmetric decryption
		decrypter, err := be.Decrypter(attrs)
		if err != nil {
			handleError(fmt.Errorf("failed to get decrypter: %w", err))
			return
		}

		// Decode ciphertext from base64
		ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
		if err != nil {
			handleError(fmt.Errorf("failed to decode ciphertext: %w", err))
			return
		}

		printVerbose("Ciphertext size: %d bytes", len(ciphertextBytes))

		// Decrypt the data
		plaintext, err := decrypter.Decrypt(nil, ciphertextBytes, nil)
		if err != nil {
			handleError(fmt.Errorf("failed to decrypt data: %w", err))
			return
		}

		// Encode plaintext as base64 for output
		plaintextBase64 := base64.StdEncoding.EncodeToString(plaintext)

		if err := printer.PrintDecryptedData(plaintextBase64); err != nil {
			handleError(err)
		}
	},
}

// keyImportCmd imports a wrapped key
var keyImportCmd = &cobra.Command{
	Use:   "import <key-id> <wrapped-key-file>",
	Short: "Import a wrapped key",
	Long:  `Import externally generated key material that has been wrapped for secure transport`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		wrappedKeyFile := args[1]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")

		printVerbose("Importing wrapped key: %s from file: %s", keyID, wrappedKeyFile)

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// Check if backend supports import/export
		importExportBe, ok := be.(backend.ImportExportBackend)
		if !ok {
			handleError(fmt.Errorf("backend does not support import operations"))
			return
		}

		// Build key attributes
		attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve)
		if err != nil {
			handleError(fmt.Errorf("invalid key parameters: %w", err))
			return
		}

		// Read wrapped key from file (JSON format)
		cleanPath := filepath.Clean(wrappedKeyFile)
		if !filepath.IsAbs(cleanPath) && false { // Path validation disabled in CLI context
			handleError(fmt.Errorf("file path must be absolute: %s", wrappedKeyFile))
			return
		}
		wrappedKeyData, err := os.ReadFile(cleanPath)
		if err != nil {
			handleError(fmt.Errorf("failed to read wrapped key file: %w", err))
			return
		}

		printVerbose("Wrapped key file size: %d bytes", len(wrappedKeyData))

		// Deserialize WrappedKeyMaterial from JSON
		var wrapped backend.WrappedKeyMaterial
		if err := json.Unmarshal(wrappedKeyData, &wrapped); err != nil {
			handleError(fmt.Errorf("failed to deserialize wrapped key material: %w", err))
			return
		}

		printVerbose("Wrapped key algorithm: %s", wrapped.Algorithm)

		// Import the key
		if err := importExportBe.ImportKey(attrs, &wrapped); err != nil {
			handleError(fmt.Errorf("failed to import key: %w", err))
			return
		}

		if err := printer.PrintSuccess(fmt.Sprintf("Successfully imported key: %s", keyID)); err != nil {
			handleError(err)
		}
	},
}

// keyExportCmd exports a key in wrapped form
var keyExportCmd = &cobra.Command{
	Use:   "export <key-id> <output-file>",
	Short: "Export a key in wrapped form",
	Long:  `Export a key in wrapped form for secure transport to another system`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		outputFile := args[1]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")
		algorithmStr, _ := cmd.Flags().GetString("algorithm")

		printVerbose("Exporting key: %s to file: %s", keyID, outputFile)

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// Check if backend supports import/export
		importExportBe, ok := be.(backend.ImportExportBackend)
		if !ok {
			handleError(fmt.Errorf("backend does not support export operations"))
			return
		}

		// Build key attributes
		attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve)
		if err != nil {
			handleError(fmt.Errorf("invalid key parameters: %w", err))
			return
		}

		// Parse wrapping algorithm
		algorithm := backend.WrappingAlgorithm(algorithmStr)
		printVerbose("Using wrapping algorithm: %s", algorithm)

		// Export the key
		wrapped, err := importExportBe.ExportKey(attrs, algorithm)
		if err != nil {
			handleError(fmt.Errorf("failed to export key: %w", err))
			return
		}

		printVerbose("Wrapped key size: %d bytes", len(wrapped.WrappedKey))

		// Serialize to JSON and write to file
		wrappedData, err := json.MarshalIndent(wrapped, "", "  ")
		if err != nil {
			handleError(fmt.Errorf("failed to serialize wrapped key: %w", err))
			return
		}

		if err := os.WriteFile(outputFile, wrappedData, 0600); err != nil {
			handleError(fmt.Errorf("failed to write wrapped key file: %w", err))
			return
		}

		if err := printer.PrintSuccess(fmt.Sprintf("Successfully exported key to: %s", outputFile)); err != nil {
			handleError(err)
		}
	},
}

// keyCopyCmd copies a key from one backend to another
var keyCopyCmd = &cobra.Command{
	Use:   "copy <key-id> <dest-key-id>",
	Short: "Copy a key from one backend to another",
	Long:  `Copy an exportable key from the current backend to a destination backend using secure wrapping`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		sourceKeyID := args[0]
		destKeyID := sourceKeyID // Default to same key ID
		if len(args) > 1 {
			destKeyID = args[1]
		}

		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		destBackend, _ := cmd.Flags().GetString("dest-backend")
		destKeyDir, _ := cmd.Flags().GetString("dest-keydir")
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")
		algorithmStr, _ := cmd.Flags().GetString("algorithm")

		printVerbose("Copying key: %s -> %s (backend: %s -> %s)", sourceKeyID, destKeyID, cfg.Backend, destBackend)

		// Step 1: Export from source backend
		printVerbose("Step 1: Exporting key from source backend (%s)", cfg.Backend)
		sourceBe, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create source backend: %w", err))
			return
		}
		defer func() { _ = sourceBe.Close() }()

		// Check if source backend supports import/export
		sourceImportExportBe, ok := sourceBe.(backend.ImportExportBackend)
		if !ok {
			handleError(fmt.Errorf("source backend '%s' does not support export operations", cfg.Backend))
			return
		}

		// Build key attributes for source
		sourceAttrs, err := buildKeyAttributesFromFlags(sourceKeyID, keyType, keyAlgorithm, keySize, curve)
		if err != nil {
			handleError(fmt.Errorf("invalid key parameters: %w", err))
			return
		}

		// Parse wrapping algorithm
		algorithm := backend.WrappingAlgorithm(algorithmStr)
		printVerbose("Using wrapping algorithm: %s", algorithm)

		// Export the key
		wrapped, err := sourceImportExportBe.ExportKey(sourceAttrs, algorithm)
		if err != nil {
			handleError(fmt.Errorf("failed to export key from source backend: %w", err))
			return
		}

		printVerbose("Successfully exported key (%d bytes wrapped)", len(wrapped.WrappedKey))

		// Step 2: Import to destination backend
		printVerbose("Step 2: Importing key to destination backend (%s)", destBackend)

		// Create destination backend config
		destCfg := *cfg // Copy config
		destCfg.Backend = destBackend
		if destKeyDir != "" {
			destCfg.KeyDir = destKeyDir
		}

		destBe, err := destCfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create destination backend: %w", err))
			return
		}
		defer func() { _ = destBe.Close() }()

		// Check if destination backend supports import/export
		destImportExportBe, ok := destBe.(backend.ImportExportBackend)
		if !ok {
			handleError(fmt.Errorf("destination backend '%s' does not support import operations", destBackend))
			return
		}

		// Build key attributes for destination
		destAttrs, err := buildKeyAttributesFromFlags(destKeyID, keyType, keyAlgorithm, keySize, curve)
		if err != nil {
			handleError(fmt.Errorf("invalid destination key parameters: %w", err))
			return
		}

		// Import the key
		if err := destImportExportBe.ImportKey(destAttrs, wrapped); err != nil {
			handleError(fmt.Errorf("failed to import key to destination backend: %w", err))
			return
		}

		if err := printer.PrintSuccess(fmt.Sprintf("Successfully copied key from %s:%s to %s:%s",
			cfg.Backend, sourceKeyID, destBackend, destKeyID)); err != nil {
			handleError(err)
		}
	},
}

// keyGetImportParamsCmd gets import parameters for wrapping keys
var keyGetImportParamsCmd = &cobra.Command{
	Use:   "get-import-params <key-id>",
	Short: "Get parameters for importing a key",
	Long:  `Retrieve the wrapping public key and other parameters needed to import a key`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")
		algorithmStr, _ := cmd.Flags().GetString("algorithm")
		outputFile, _ := cmd.Flags().GetString("output")

		printVerbose("Getting import parameters for key: %s", keyID)

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// Check if backend supports import/export
		importExportBe, ok := be.(backend.ImportExportBackend)
		if !ok {
			handleError(fmt.Errorf("backend does not support import/export operations"))
			return
		}

		// Build key attributes
		attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve)
		if err != nil {
			handleError(fmt.Errorf("invalid key parameters: %w", err))
			return
		}

		// Parse wrapping algorithm
		algorithm := backend.WrappingAlgorithm(algorithmStr)
		printVerbose("Requesting parameters for algorithm: %s", algorithm)

		// Get import parameters
		params, err := importExportBe.GetImportParameters(attrs, algorithm)
		if err != nil {
			handleError(fmt.Errorf("failed to get import parameters: %w", err))
			return
		}

		printVerbose("Import parameters retrieved successfully")
		if params.ExpiresAt != nil {
			printVerbose("Parameters expire at: %s", params.ExpiresAt.String())
		}

		// If output file is specified, save params to file
		if outputFile != "" {
			paramsData, err := json.MarshalIndent(params, "", "  ")
			if err != nil {
				handleError(fmt.Errorf("failed to serialize import parameters: %w", err))
				return
			}

			if err := os.WriteFile(outputFile, paramsData, 0600); err != nil {
				handleError(fmt.Errorf("failed to write parameters file: %w", err))
				return
			}

			if err := printer.PrintSuccess(fmt.Sprintf("Import parameters saved to: %s", outputFile)); err != nil {
				handleError(err)
			}
		} else {
			// Print params in user-friendly format
			if err := printer.PrintImportParameters(params); err != nil {
				handleError(err)
			}
		}
	},
}

// keyWrapCmd wraps key material for secure transport
var keyWrapCmd = &cobra.Command{
	Use:   "wrap <key-material-file> <params-file> <output-file>",
	Short: "Wrap key material for secure transport",
	Long:  `Wrap raw key material using import parameters for secure transport`,
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		keyMaterialFile := args[0]
		paramsFile := args[1]
		outputFile := args[2]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Wrapping key material from: %s", keyMaterialFile)

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// Check if backend supports import/export
		importExportBe, ok := be.(backend.ImportExportBackend)
		if !ok {
			handleError(fmt.Errorf("backend does not support wrap operations"))
			return
		}

		// Read key material
		cleanPath := filepath.Clean(keyMaterialFile)
		keyMaterial, err := /* #nosec G304 */ os.ReadFile(cleanPath)
		if err != nil {
			handleError(fmt.Errorf("failed to read key material file: %w", err))
			return
		}

		printVerbose("Key material size: %d bytes", len(keyMaterial))

		// Read import parameters
		cleanPath = filepath.Clean(paramsFile)
		if !filepath.IsAbs(cleanPath) && false { // Path validation disabled in CLI context
			handleError(fmt.Errorf("file path must be absolute: %s", paramsFile))
			return
		}
		paramsData, err := os.ReadFile(cleanPath)
		if err != nil {
			handleError(fmt.Errorf("failed to read parameters file: %w", err))
			return
		}

		var params backend.ImportParameters
		if err := json.Unmarshal(paramsData, &params); err != nil {
			handleError(fmt.Errorf("failed to deserialize import parameters: %w", err))
			return
		}

		printVerbose("Using wrapping algorithm: %s", params.Algorithm)

		// Wrap the key material
		wrapped, err := importExportBe.WrapKey(keyMaterial, &params)
		if err != nil {
			handleError(fmt.Errorf("failed to wrap key material: %w", err))
			return
		}

		printVerbose("Wrapped key size: %d bytes", len(wrapped.WrappedKey))

		// Serialize and write wrapped key
		wrappedData, err := json.MarshalIndent(wrapped, "", "  ")
		if err != nil {
			handleError(fmt.Errorf("failed to serialize wrapped key: %w", err))
			return
		}

		if err := os.WriteFile(outputFile, wrappedData, 0600); err != nil {
			handleError(fmt.Errorf("failed to write wrapped key file: %w", err))
			return
		}

		if err := printer.PrintSuccess(fmt.Sprintf("Successfully wrapped key to: %s", outputFile)); err != nil {
			handleError(err)
		}
	},
}

// keyUnwrapCmd unwraps key material
var keyUnwrapCmd = &cobra.Command{
	Use:   "unwrap <wrapped-key-file> <params-file> <output-file>",
	Short: "Unwrap key material",
	Long:  `Unwrap key material that was previously wrapped`,
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		wrappedKeyFile := args[0]
		paramsFile := args[1]
		outputFile := args[2]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		printVerbose("Unwrapping key from: %s", wrappedKeyFile)

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// Check if backend supports import/export
		importExportBe, ok := be.(backend.ImportExportBackend)
		if !ok {
			handleError(fmt.Errorf("backend does not support unwrap operations"))
			return
		}

		// Read wrapped key
		cleanPath := filepath.Clean(wrappedKeyFile)
		if !filepath.IsAbs(cleanPath) && false { // Path validation disabled in CLI context
			handleError(fmt.Errorf("file path must be absolute: %s", wrappedKeyFile))
			return
		}
		wrappedData, err := os.ReadFile(cleanPath)
		if err != nil {
			handleError(fmt.Errorf("failed to read wrapped key file: %w", err))
			return
		}

		var wrapped backend.WrappedKeyMaterial
		if err := json.Unmarshal(wrappedData, &wrapped); err != nil {
			handleError(fmt.Errorf("failed to deserialize wrapped key: %w", err))
			return
		}

		printVerbose("Wrapped key size: %d bytes", len(wrapped.WrappedKey))

		// Read import parameters
		cleanPath = filepath.Clean(paramsFile)
		if !filepath.IsAbs(cleanPath) && false { // Path validation disabled in CLI context
			handleError(fmt.Errorf("file path must be absolute: %s", paramsFile))
			return
		}
		paramsData, err := os.ReadFile(cleanPath)
		if err != nil {
			handleError(fmt.Errorf("failed to read parameters file: %w", err))
			return
		}

		var params backend.ImportParameters
		if err := json.Unmarshal(paramsData, &params); err != nil {
			handleError(fmt.Errorf("failed to deserialize import parameters: %w", err))
			return
		}

		printVerbose("Using wrapping algorithm: %s", params.Algorithm)

		// Unwrap the key material
		keyMaterial, err := importExportBe.UnwrapKey(&wrapped, &params)
		if err != nil {
			handleError(fmt.Errorf("failed to unwrap key material: %w", err))
			return
		}

		printVerbose("Unwrapped key material size: %d bytes", len(keyMaterial))

		// Write unwrapped key material
		if err := os.WriteFile(outputFile, keyMaterial, 0600); err != nil {
			handleError(fmt.Errorf("failed to write key material file: %w", err))
			return
		}

		if err := printer.PrintSuccess(fmt.Sprintf("Successfully unwrapped key to: %s", outputFile)); err != nil {
			handleError(err)
		}
	},
}

// keyVerifyCmd verifies a signature
var keyVerifyCmd = &cobra.Command{
	Use:   "verify <key-id> <data> <signature>",
	Short: "Verify a signature",
	Long:  `Verify that a signature is valid for the given data`,
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		data := args[1]
		signatureBase64 := args[2]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")
		hashAlg, _ := cmd.Flags().GetString("hash")

		printVerbose("Verifying signature with key: %s", keyID)

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// Build key attributes
		attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve)
		if err != nil {
			handleError(fmt.Errorf("invalid key parameters: %w", err))
			return
		}

		// Parse hash algorithm
		if hashAlgParsed, ok := types.AvailableHashes()[hashAlg]; ok {
			attrs.Hash = hashAlgParsed
		} else {
			handleError(fmt.Errorf("invalid hash algorithm: %s", hashAlg))
			return
		}

		// Get the key to extract public key
		key, err := be.GetKey(attrs)
		if err != nil {
			handleError(fmt.Errorf("failed to get key: %w", err))
			return
		}

		// Extract public key
		var publicKey crypto.PublicKey
		switch k := key.(type) {
		case crypto.Signer:
			publicKey = k.Public()
		default:
			handleError(fmt.Errorf("key does not support verification"))
			return
		}

		// Hash the data
		hash := attrs.Hash
		hasher := hash.New()
		hasher.Write([]byte(data))
		digest := hasher.Sum(nil)

		printVerbose("Data digest (hex): %x", digest)

		// Decode signature from base64
		signature, err := base64.StdEncoding.DecodeString(signatureBase64)
		if err != nil {
			handleError(fmt.Errorf("failed to decode signature: %w", err))
			return
		}

		printVerbose("Signature size: %d bytes", len(signature))

		// Verify the signature based on key algorithm
		var valid bool
		switch pub := publicKey.(type) {
		case *rsa.PublicKey:
			// Verify RSA signature (PKCS1v15 or PSS)
			err := rsa.VerifyPKCS1v15(pub, hash, digest, signature)
			if err != nil {
				// Try PSS if PKCS1v15 fails
				pssOpts := &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthAuto,
					Hash:       hash,
				}
				err = rsa.VerifyPSS(pub, hash, digest, signature, pssOpts)
				if err != nil {
					handleError(fmt.Errorf("signature verification failed: %w", err))
					return
				}
			}
			valid = true

		case *ecdsa.PublicKey:
			// Verify ECDSA signature
			valid = ecdsa.VerifyASN1(pub, digest, signature)

		case ed25519.PublicKey:
			// Verify Ed25519 signature (Ed25519 signs the whole message, not a hash)
			valid = ed25519.Verify(pub, []byte(data), signature)

		default:
			handleError(fmt.Errorf("unsupported public key type for verification: %T", pub))
			return
		}

		if valid {
			if err := printer.PrintSuccess("Signature is valid"); err != nil {
				handleError(err)
			}
		} else {
			handleError(fmt.Errorf("signature is invalid"))
		}
	},
}

// keyEncryptAsymCmd encrypts data with RSA public key
var keyEncryptAsymCmd = &cobra.Command{
	Use:   "encrypt-asym <key-id> <plaintext>",
	Short: "Encrypt data with asymmetric (RSA) key",
	Long:  `Encrypt data using RSA public key encryption (OAEP)`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		plaintext := args[1]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")
		hashAlg, _ := cmd.Flags().GetString("hash")

		printVerbose("Encrypting data with key: %s", keyID)

		// Create backend
		be, err := cfg.CreateBackend()
		if err != nil {
			handleError(fmt.Errorf("failed to create backend: %w", err))
			return
		}
		defer func() { _ = be.Close() }()

		// Build key attributes
		attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve)
		if err != nil {
			handleError(fmt.Errorf("invalid key parameters: %w", err))
			return
		}

		// Parse hash algorithm
		var hash crypto.Hash
		if hashAlgParsed, ok := types.AvailableHashes()[hashAlg]; ok {
			hash = hashAlgParsed
		} else {
			handleError(fmt.Errorf("invalid hash algorithm: %s", hashAlg))
			return
		}

		// Get the key to extract public key
		key, err := be.GetKey(attrs)
		if err != nil {
			handleError(fmt.Errorf("failed to get key: %w", err))
			return
		}

		// Extract public key
		var publicKey crypto.PublicKey
		switch k := key.(type) {
		case crypto.Signer:
			publicKey = k.Public()
		default:
			handleError(fmt.Errorf("key does not support public key extraction"))
			return
		}

		// Encrypt based on key type
		var ciphertext []byte
		switch pub := publicKey.(type) {
		case *rsa.PublicKey:
			// RSA OAEP encryption
			ciphertext, err = rsa.EncryptOAEP(
				hash.New(),
				rand.Reader,
				pub,
				[]byte(plaintext),
				nil, // no label
			)
			if err != nil {
				handleError(fmt.Errorf("failed to encrypt data: %w", err))
				return
			}

		default:
			handleError(fmt.Errorf("asymmetric encryption only supported for RSA keys, got: %T", pub))
			return
		}

		printVerbose("Ciphertext size: %d bytes", len(ciphertext))

		// Encode ciphertext as base64
		ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)

		if err := printer.PrintEncryptedAsym(ciphertextBase64); err != nil {
			handleError(err)
		}
	},
}

func init() {
	// Add key subcommands
	keyCmd.AddCommand(keyGenerateCmd)
	keyCmd.AddCommand(keyListCmd)
	keyCmd.AddCommand(keyGetCmd)
	keyCmd.AddCommand(keyDeleteCmd)
	keyCmd.AddCommand(keySignCmd)
	keyCmd.AddCommand(keyRotateCmd)
	keyCmd.AddCommand(keyEncryptCmd)
	keyCmd.AddCommand(keyDecryptCmd)
	keyCmd.AddCommand(keyImportCmd)
	keyCmd.AddCommand(keyExportCmd)
	keyCmd.AddCommand(keyCopyCmd)
	keyCmd.AddCommand(keyGetImportParamsCmd)
	keyCmd.AddCommand(keyWrapCmd)
	keyCmd.AddCommand(keyUnwrapCmd)
	keyCmd.AddCommand(keyVerifyCmd)
	keyCmd.AddCommand(keyEncryptAsymCmd)

	// Flags for generate command
	keyGenerateCmd.Flags().String("key-type", "tls", "Key type (tls, signing, encryption, aes)")
	keyGenerateCmd.Flags().String("algorithm", "", "Algorithm (aes-128-gcm, aes-192-gcm, aes-256-gcm)")
	keyGenerateCmd.Flags().String("key-algorithm", "rsa", "Key algorithm (rsa, ecdsa, ed25519)")
	keyGenerateCmd.Flags().Int("key-size", 2048, "Key size in bits (128, 192, 256 for AES; 2048+ for RSA)")
	keyGenerateCmd.Flags().String("curve", "P-256", "Elliptic curve (for ECDSA: P-256, P-384, P-521)")

	// Flags for get command
	keyGetCmd.Flags().String("key-type", "tls", "Key type")
	keyGetCmd.Flags().String("key-algorithm", "rsa", "Key algorithm")
	keyGetCmd.Flags().Int("key-size", 2048, "Key size in bits (for RSA)")
	keyGetCmd.Flags().String("curve", "P-256", "Elliptic curve (for ECDSA: P-256, P-384, P-521)")

	// Flags for delete command
	keyDeleteCmd.Flags().String("key-type", "tls", "Key type")
	keyDeleteCmd.Flags().String("key-algorithm", "rsa", "Key algorithm")
	keyDeleteCmd.Flags().Int("key-size", 2048, "Key size in bits (for RSA)")
	keyDeleteCmd.Flags().String("curve", "P-256", "Elliptic curve (for ECDSA: P-256, P-384, P-521)")

	// Flags for sign command
	keySignCmd.Flags().String("key-type", "tls", "Key type")
	keySignCmd.Flags().String("key-algorithm", "rsa", "Key algorithm")
	keySignCmd.Flags().Int("key-size", 2048, "Key size in bits (for RSA)")
	keySignCmd.Flags().String("curve", "P-256", "Elliptic curve (for ECDSA: P-256, P-384, P-521)")
	keySignCmd.Flags().String("hash", "sha256", "Hash algorithm (sha256, sha384, sha512)")

	// Flags for rotate command
	keyRotateCmd.Flags().String("key-type", "tls", "Key type")
	keyRotateCmd.Flags().String("key-algorithm", "rsa", "Key algorithm")
	keyRotateCmd.Flags().Int("key-size", 2048, "Key size in bits (for RSA)")
	keyRotateCmd.Flags().String("curve", "P-256", "Elliptic curve (for ECDSA: P-256, P-384, P-521)")

	// Flags for encrypt command
	keyEncryptCmd.Flags().String("key-type", "encryption", "Key type")
	keyEncryptCmd.Flags().String("key-algorithm", "aes256-gcm", "Key algorithm (aes128-gcm, aes192-gcm, aes256-gcm)")
	keyEncryptCmd.Flags().Int("key-size", 256, "Key size in bits (128, 192, 256)")
	keyEncryptCmd.Flags().String("aad", "", "Additional authenticated data (optional)")

	// Flags for decrypt command
	keyDecryptCmd.Flags().String("key-type", "tls", "Key type")
	keyDecryptCmd.Flags().String("key-algorithm", "rsa", "Key algorithm")
	keyDecryptCmd.Flags().Int("key-size", 2048, "Key size in bits (for RSA)")
	keyDecryptCmd.Flags().String("curve", "P-256", "Elliptic curve (for ECDSA: P-256, P-384, P-521)")
	keyDecryptCmd.Flags().String("aad", "", "Additional authenticated data (for symmetric decryption)")
	keyDecryptCmd.Flags().String("nonce", "", "Nonce/IV (base64, required for symmetric decryption)")
	keyDecryptCmd.Flags().String("tag", "", "Authentication tag (base64, required for symmetric decryption)")

	// Flags for import command
	keyImportCmd.Flags().String("key-type", "tls", "Key type")
	keyImportCmd.Flags().String("key-algorithm", "rsa", "Key algorithm")
	keyImportCmd.Flags().Int("key-size", 2048, "Key size in bits (for RSA)")
	keyImportCmd.Flags().String("curve", "P-256", "Elliptic curve (for ECDSA: P-256, P-384, P-521)")

	// Flags for export command
	keyExportCmd.Flags().String("key-type", "tls", "Key type")
	keyExportCmd.Flags().String("key-algorithm", "rsa", "Key algorithm")
	keyExportCmd.Flags().Int("key-size", 2048, "Key size in bits (for RSA)")
	keyExportCmd.Flags().String("curve", "P-256", "Elliptic curve (for ECDSA: P-256, P-384, P-521)")
	keyExportCmd.Flags().String("algorithm", "RSAES_OAEP_SHA_256", "Wrapping algorithm")

	// Flags for copy command
	keyCopyCmd.Flags().String("dest-backend", "pkcs8", "Destination backend (pkcs8, pkcs11, tpm2, awskms, etc.)")
	keyCopyCmd.Flags().String("dest-keydir", "", "Destination key directory (for file-based backends)")
	keyCopyCmd.Flags().String("key-type", "tls", "Key type")
	keyCopyCmd.Flags().String("key-algorithm", "rsa", "Key algorithm")
	keyCopyCmd.Flags().Int("key-size", 2048, "Key size in bits (for RSA)")
	keyCopyCmd.Flags().String("curve", "P-256", "Elliptic curve (for ECDSA: P-256, P-384, P-521)")
	keyCopyCmd.Flags().String("algorithm", "RSAES_OAEP_SHA_256", "Wrapping algorithm")

	// Flags for get-import-params command
	keyGetImportParamsCmd.Flags().String("key-type", "tls", "Key type")
	keyGetImportParamsCmd.Flags().String("key-algorithm", "rsa", "Key algorithm")
	keyGetImportParamsCmd.Flags().Int("key-size", 2048, "Key size in bits (for RSA)")
	keyGetImportParamsCmd.Flags().String("curve", "P-256", "Elliptic curve (for ECDSA: P-256, P-384, P-521)")
	keyGetImportParamsCmd.Flags().String("algorithm", "RSAES_OAEP_SHA_256", "Wrapping algorithm")
	keyGetImportParamsCmd.Flags().String("output", "", "Output file for import parameters (JSON)")

	// Flags for verify command
	keyVerifyCmd.Flags().String("key-type", "tls", "Key type")
	keyVerifyCmd.Flags().String("key-algorithm", "rsa", "Key algorithm")
	keyVerifyCmd.Flags().Int("key-size", 2048, "Key size in bits (for RSA)")
	keyVerifyCmd.Flags().String("curve", "P-256", "Elliptic curve (for ECDSA: P-256, P-384, P-521)")
	keyVerifyCmd.Flags().String("hash", "sha256", "Hash algorithm (sha256, sha384, sha512)")

	// Flags for encrypt-asym command
	keyEncryptAsymCmd.Flags().String("key-type", "tls", "Key type")
	keyEncryptAsymCmd.Flags().String("key-algorithm", "rsa", "Key algorithm")
	keyEncryptAsymCmd.Flags().Int("key-size", 2048, "Key size in bits (for RSA)")
	keyEncryptAsymCmd.Flags().String("curve", "P-256", "Elliptic curve (for ECDSA: P-256, P-384, P-521)")
	keyEncryptAsymCmd.Flags().String("hash", "sha256", "Hash algorithm for OAEP (sha256, sha384, sha512)")
}

// buildKeyAttributes creates KeyAttributes from command line parameters
func buildKeyAttributes(keyID, keyType string, keySize int, curve string) (*types.KeyAttributes, error) {
	// Parse key algorithm from keyType flag
	var keyAlgorithm x509.PublicKeyAlgorithm
	switch keyType {
	case "rsa":
		keyAlgorithm = x509.RSA
	case "ecdsa":
		keyAlgorithm = x509.ECDSA
	case "ed25519":
		keyAlgorithm = x509.Ed25519
	default:
		keyAlgorithm = x509.RSA
	}

	attrs := &types.KeyAttributes{
		CN:           keyID,
		KeyType:      types.KeyTypeTLS,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: keyAlgorithm,
		Hash:         crypto.SHA256,
	}

	// Set algorithm-specific attributes
	switch keyAlgorithm {
	case x509.RSA:
		if keySize < 2048 {
			return nil, fmt.Errorf("RSA key size must be at least 2048 bits")
		}
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: keySize,
		}

	case x509.ECDSA:
		parsedCurve, err := types.ParseCurve(curve)
		if err != nil {
			return nil, fmt.Errorf("invalid curve: %s", curve)
		}
		attrs.ECCAttributes = &types.ECCAttributes{
			Curve: parsedCurve,
		}

	case x509.Ed25519:
		// Ed25519 has no configurable parameters
	}

	// Validate the attributes
	if err := attrs.Validate(); err != nil {
		return nil, err
	}

	return attrs, nil
}

// buildKeyAttributesFromFlags creates KeyAttributes from separate key type and algorithm flags
func buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm string, keySize int, curve string) (*types.KeyAttributes, error) {
	// Parse key type and algorithm
	kt := types.ParseKeyType(keyType)
	if kt == 0 {
		return nil, fmt.Errorf("invalid key type: %s", keyType)
	}

	ka, err := types.ParseKeyAlgorithm(keyAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("invalid key algorithm: %s", keyAlgorithm)
	}

	attrs := &types.KeyAttributes{
		CN:           keyID,
		KeyType:      kt,
		StoreType:    types.StorePKCS8,
		KeyAlgorithm: ka,
		Hash:         crypto.SHA256,
	}

	// Set algorithm-specific attributes
	switch ka {
	case x509.RSA:
		if keySize < 2048 {
			return nil, fmt.Errorf("RSA key size must be at least 2048 bits")
		}
		attrs.RSAAttributes = &types.RSAAttributes{
			KeySize: keySize,
		}

	case x509.ECDSA:
		parsedCurve, err := types.ParseCurve(curve)
		if err != nil {
			return nil, fmt.Errorf("invalid curve: %s", curve)
		}
		attrs.ECCAttributes = &types.ECCAttributes{
			Curve: parsedCurve,
		}

	case x509.Ed25519:
		// Ed25519 has no configurable parameters
	}

	// Validate the attributes
	if err := attrs.Validate(); err != nil {
		return nil, err
	}

	return attrs, nil
}

// parseKeySize converts a string key size to an integer

// parseCurve validates and returns an ECC curve name

// buildSymmetricKeyAttributes creates KeyAttributes for symmetric (AES) keys
func buildSymmetricKeyAttributes(keyID, algorithm string, keySize int) (*types.KeyAttributes, error) {
	// Determine algorithm from either algorithm flag or keySize
	var symmetricAlgorithm types.SymmetricAlgorithm

	if algorithm != "" {
		// Parse algorithm string
		symmetricAlgorithm = types.SymmetricAlgorithm(algorithm)
		if !symmetricAlgorithm.IsValid() {
			return nil, fmt.Errorf("invalid algorithm: %s", algorithm)
		}
	} else {
		// Derive from key size
		switch keySize {
		case 128:
			symmetricAlgorithm = types.SymmetricAES128GCM
		case 192:
			symmetricAlgorithm = types.SymmetricAES192GCM
		case 256:
			symmetricAlgorithm = types.SymmetricAES256GCM
		default:
			return nil, fmt.Errorf("invalid AES key size: %d (valid: 128, 192, 256)", keySize)
		}
	}

	attrs := &types.KeyAttributes{
		CN:                 keyID,
		KeyType:            types.KeyTypeEncryption,
		StoreType:          types.StorePKCS8,
		SymmetricAlgorithm: symmetricAlgorithm,
		AESAttributes: &types.AESAttributes{
			KeySize: keySize,
		},
	}

	// Validate the attributes
	if err := attrs.Validate(); err != nil {
		return nil, err
	}

	return attrs, nil
}
