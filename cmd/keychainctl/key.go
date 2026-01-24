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

package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	client "github.com/jeremyhahn/go-keychain/sdk/go"
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
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")
		exportable, _ := cmd.Flags().GetBool("exportable")

		printVerbose("Generating %s key with ID: %s (exportable: %v)", keyType, keyID, exportable)

		generateKey(cfg, printer, keyID, keyType, algorithm, keyAlgorithm, keySize, curve, exportable)
	},
}

// generateKey generates a key using the SDK client
func generateKey(cfg *Config, printer *Printer, keyID, keyType, algorithm, keyAlgorithm string, keySize int, curve string, exportable bool) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to keychaind")

	// For symmetric keys, don't set algorithm - handlers use defaults based on key_size
	// For asymmetric keys, use the provided algorithm
	algoForRequest := keyAlgorithm
	isSymmetric := types.AlgorithmSymmetric.Equals(keyType) || types.AlgorithmAES.Equals(keyType) ||
		types.AEADAES128GCM.Equals(algorithm) || types.AEADAES192GCM.Equals(algorithm) || types.AEADAES256GCM.Equals(algorithm)
	if isSymmetric {
		// Let the server handlers determine the algorithm based on key_size
		algoForRequest = ""
		// Normalize key type to "symmetric" for the server
		keyType = "symmetric"
	}

	req := &client.GenerateKeyRequest{
		KeyID:      keyID,
		Backend:    cfg.Backend,
		KeyType:    keyType,
		KeySize:    keySize,
		Curve:      curve,
		Algorithm:  algoForRequest,
		Exportable: exportable,
	}

	printVerbose("Generating key with exportable=%v", exportable)

	resp, err := cl.GenerateKey(ctx, req)
	if err != nil {
		handleError(fmt.Errorf("failed to generate key: %w", err))
		return
	}

	printVerbose("Key generated: %s", resp.KeyID)
	if err := printer.PrintSuccess(fmt.Sprintf("Successfully generated %s key: %s", keyType, keyID)); err != nil {
		handleError(err)
	}
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

		listKeys(cfg, printer)
	},
}

// listKeys lists keys using the SDK client
func listKeys(cfg *Config, printer *Printer) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to keychaind")

	resp, err := cl.ListKeys(ctx, cfg.Backend)
	if err != nil {
		handleError(fmt.Errorf("failed to list keys: %w", err))
		return
	}

	printVerbose("Found %d keys", len(resp.Keys))

	// Convert client.KeyInfo to types.KeyAttributes for printing
	keys := make([]*types.KeyAttributes, len(resp.Keys))
	for i, key := range resp.Keys {
		keys[i] = &types.KeyAttributes{
			CN:      key.KeyID,
			KeyType: types.ParseKeyType(key.KeyType),
		}
	}

	if err := printer.PrintKeyList(keys); err != nil {
		handleError(err)
	}
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

		printVerbose("Getting key info for: %s", keyID)

		getKey(cfg, printer, keyID)
	},
}

// getKey gets key info using the SDK client
func getKey(cfg *Config, printer *Printer, keyID string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to keychaind")

	resp, err := cl.GetKey(ctx, cfg.Backend, keyID)
	if err != nil {
		handleError(fmt.Errorf("failed to get key: %w", err))
		return
	}

	// Convert to KeyAttributes for printing
	attrs := &types.KeyAttributes{
		CN:      resp.KeyID,
		KeyType: types.ParseKeyType(resp.KeyType),
	}

	if err := printer.PrintKeyInfo(attrs); err != nil {
		handleError(err)
	}
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

		printVerbose("Deleting key: %s", keyID)

		deleteKey(cfg, printer, keyID)
	},
}

// deleteKey deletes a key using the SDK client
func deleteKey(cfg *Config, printer *Printer, keyID string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to keychaind")

	resp, err := cl.DeleteKey(ctx, cfg.Backend, keyID)
	if err != nil {
		handleError(fmt.Errorf("failed to delete key: %w", err))
		return
	}

	if resp.Success {
		if err := printer.PrintSuccess(fmt.Sprintf("Successfully deleted key: %s", keyID)); err != nil {
			handleError(err)
		}
	} else {
		handleError(fmt.Errorf("failed to delete key: %s", resp.Message))
	}
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

		hashAlg, _ := cmd.Flags().GetString("hash")

		printVerbose("Signing data with key: %s", keyID)

		sign(cfg, printer, keyID, data, hashAlg)
	},
}

// sign signs data using the SDK client
func sign(cfg *Config, printer *Printer, keyID, data, hashAlg string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to keychaind")

	req := &client.SignRequest{
		Backend: cfg.Backend,
		KeyID:   keyID,
		Data:    []byte(data),
		Hash:    hashAlg,
	}

	resp, err := cl.Sign(ctx, req)
	if err != nil {
		handleError(fmt.Errorf("failed to sign data: %w", err))
		return
	}

	sigBase64 := base64.StdEncoding.EncodeToString(resp.Signature)

	if err := printer.PrintSignature(sigBase64); err != nil {
		handleError(err)
	}
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

		hashAlg, _ := cmd.Flags().GetString("hash")

		printVerbose("Verifying signature with key: %s", keyID)

		verify(cfg, printer, keyID, data, signatureBase64, hashAlg)
	},
}

// verify verifies a signature using the SDK client
func verify(cfg *Config, printer *Printer, keyID, data, signatureBase64, hashAlg string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to keychaind")

	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		handleError(fmt.Errorf("failed to decode signature: %w", err))
		return
	}

	req := &client.VerifyRequest{
		Backend:   cfg.Backend,
		KeyID:     keyID,
		Data:      []byte(data),
		Signature: signature,
		Hash:      hashAlg,
	}

	resp, err := cl.Verify(ctx, req)
	if err != nil {
		handleError(fmt.Errorf("failed to verify signature: %w", err))
		return
	}

	if resp.Valid {
		if err := printer.PrintSuccess("Signature is valid"); err != nil {
			handleError(err)
		}
	} else {
		handleError(fmt.Errorf("signature is invalid: %s", resp.Message))
	}
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

		aad, _ := cmd.Flags().GetString("aad")

		printVerbose("Encrypting data with key: %s", keyID)

		encrypt(cfg, printer, keyID, plaintext, aad)
	},
}

// encrypt encrypts data using the SDK client
func encrypt(cfg *Config, printer *Printer, keyID, plaintext, aad string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to keychaind")

	req := &client.EncryptRequest{
		Backend:   cfg.Backend,
		KeyID:     keyID,
		Plaintext: []byte(plaintext),
	}
	if aad != "" {
		req.AdditionalData = []byte(aad)
	}

	resp, err := cl.Encrypt(ctx, req)
	if err != nil {
		handleError(fmt.Errorf("failed to encrypt data: %w", err))
		return
	}

	printVerbose("Encrypted data: ciphertext=%d bytes, nonce=%d bytes, tag=%d bytes",
		len(resp.Ciphertext), len(resp.Nonce), len(resp.Tag))

	encrypted := &types.EncryptedData{
		Ciphertext: resp.Ciphertext,
		Nonce:      resp.Nonce,
		Tag:        resp.Tag,
	}

	if err := printer.PrintEncryptedData(encrypted); err != nil {
		handleError(err)
	}
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

		aad, _ := cmd.Flags().GetString("aad")
		nonce, _ := cmd.Flags().GetString("nonce")
		tag, _ := cmd.Flags().GetString("tag")

		printVerbose("Decrypting data with key: %s", keyID)

		decrypt(cfg, printer, keyID, ciphertext, aad, nonce, tag)
	},
}

// decrypt decrypts data using the SDK client
func decrypt(cfg *Config, printer *Printer, keyID, ciphertext, aad, nonce, tag string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to keychaind")

	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		handleError(fmt.Errorf("failed to decode ciphertext: %w", err))
		return
	}

	req := &client.DecryptRequest{
		Backend:    cfg.Backend,
		KeyID:      keyID,
		Ciphertext: ciphertextBytes,
	}

	if aad != "" {
		req.AdditionalData = []byte(aad)
	}

	if nonce != "" {
		nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
		if err != nil {
			handleError(fmt.Errorf("failed to decode nonce: %w", err))
			return
		}
		req.Nonce = nonceBytes
	}

	if tag != "" {
		tagBytes, err := base64.StdEncoding.DecodeString(tag)
		if err != nil {
			handleError(fmt.Errorf("failed to decode tag: %w", err))
			return
		}
		req.Tag = tagBytes
	}

	resp, err := cl.Decrypt(ctx, req)
	if err != nil {
		handleError(fmt.Errorf("failed to decrypt data: %w", err))
		return
	}

	plaintextBase64 := base64.StdEncoding.EncodeToString(resp.Plaintext)

	if err := printer.PrintDecryptedData(plaintextBase64); err != nil {
		handleError(err)
	}
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

		hashAlg, _ := cmd.Flags().GetString("hash")

		printVerbose("Encrypting data with key: %s", keyID)

		encryptAsym(cfg, printer, keyID, plaintext, hashAlg)
	},
}

// encryptAsym encrypts data using the SDK client
func encryptAsym(cfg *Config, printer *Printer, keyID, plaintext, hashAlg string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to keychaind")

	req := &client.EncryptAsymRequest{
		Backend:   cfg.Backend,
		KeyID:     keyID,
		Plaintext: []byte(plaintext),
		Hash:      hashAlg,
	}

	resp, err := cl.EncryptAsym(ctx, req)
	if err != nil {
		handleError(fmt.Errorf("failed to encrypt data: %w", err))
		return
	}

	printVerbose("Ciphertext size: %d bytes", len(resp.Ciphertext))

	ciphertextBase64 := base64.StdEncoding.EncodeToString(resp.Ciphertext)

	if err := printer.PrintEncryptedAsym(ciphertextBase64); err != nil {
		handleError(err)
	}
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

		printVerbose("Rotating key: %s", keyID)

		rotateKey(cfg, printer, keyID)
	},
}

// rotateKey rotates a key using the SDK client
func rotateKey(cfg *Config, printer *Printer, keyID string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to keychaind")

	req := &client.RotateKeyRequest{
		Backend: cfg.Backend,
		KeyID:   keyID,
	}

	_, err = cl.RotateKey(ctx, req)
	if err != nil {
		handleError(fmt.Errorf("failed to rotate key: %w", err))
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Successfully rotated key: %s", keyID)); err != nil {
		handleError(err)
	}
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

		printVerbose("Importing wrapped key: %s from file: %s", keyID, wrappedKeyFile)

		// Read wrapped key from file (JSON format)
		cleanPath := filepath.Clean(wrappedKeyFile)
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

		importKey(cfg, printer, keyID, &wrapped)
	},
}

// importKey imports a wrapped key using the SDK client
func importKey(cfg *Config, printer *Printer, keyID string, wrapped *backend.WrappedKeyMaterial) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to keychaind")

	req := &client.ImportKeyRequest{
		Backend:            cfg.Backend,
		KeyID:              keyID,
		WrappedKeyMaterial: wrapped.WrappedKey,
		Algorithm:          string(wrapped.Algorithm),
	}

	_, err = cl.ImportKey(ctx, req)
	if err != nil {
		handleError(fmt.Errorf("failed to import key: %w", err))
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Successfully imported key: %s", keyID)); err != nil {
		handleError(err)
	}
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

		algorithmStr, _ := cmd.Flags().GetString("algorithm")

		printVerbose("Exporting key: %s to file: %s", keyID, outputFile)

		algorithm := backend.WrappingAlgorithm(algorithmStr)
		printVerbose("Using wrapping algorithm: %s", algorithm)

		exportKey(cfg, printer, keyID, outputFile, algorithm)
	},
}

// exportKey exports a key using the SDK client
func exportKey(cfg *Config, printer *Printer, keyID, outputFile string, algorithm backend.WrappingAlgorithm) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to keychaind")

	req := &client.ExportKeyRequest{
		Backend:   cfg.Backend,
		KeyID:     keyID,
		Algorithm: string(algorithm),
	}

	resp, err := cl.ExportKey(ctx, req)
	if err != nil {
		handleError(fmt.Errorf("failed to export key: %w", err))
		return
	}

	printVerbose("Wrapped key size: %d bytes", len(resp.WrappedKeyMaterial))

	// Create WrappedKeyMaterial structure for file output
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: resp.WrappedKeyMaterial,
		Algorithm:  algorithm,
	}

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

		destBackend, _ := cmd.Flags().GetString("dest-backend")
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")
		algorithmStr, _ := cmd.Flags().GetString("algorithm")

		printVerbose("Copying key: %s -> %s (backend: %s -> %s)", sourceKeyID, destKeyID, cfg.Backend, destBackend)

		algorithm := backend.WrappingAlgorithm(algorithmStr)
		printVerbose("Using wrapping algorithm: %s", algorithm)

		copyKey(cfg, printer, sourceKeyID, destKeyID, destBackend, keyType, keyAlgorithm, keySize, curve, algorithm)
	},
}

// copyKey copies a key using the SDK client
func copyKey(cfg *Config, printer *Printer, sourceKeyID, destKeyID, destBackend, keyType, keyAlgorithm string, keySize int, curve string, algorithm backend.WrappingAlgorithm) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to keychaind")

	// Determine the key type to use (prefer key-algorithm if provided, fall back to key-type)
	keyTypeForRequest := keyAlgorithm
	if keyTypeForRequest == "" {
		keyTypeForRequest = keyType
	}

	req := &client.CopyKeyRequest{
		SourceBackend: cfg.Backend,
		SourceKeyID:   sourceKeyID,
		DestBackend:   destBackend,
		DestKeyID:     destKeyID,
		Algorithm:     string(algorithm),
		KeyType:       keyTypeForRequest,
		KeySize:       keySize,
		Curve:         curve,
	}

	_, err = cl.CopyKey(ctx, req)
	if err != nil {
		handleError(fmt.Errorf("failed to copy key: %w", err))
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Successfully copied key from %s:%s to %s:%s",
		cfg.Backend, sourceKeyID, destBackend, destKeyID)); err != nil {
		handleError(err)
	}
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

		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")
		algorithmStr, _ := cmd.Flags().GetString("algorithm")
		outputFile, _ := cmd.Flags().GetString("output")

		printVerbose("Getting import parameters for key: %s", keyID)

		algorithm := backend.WrappingAlgorithm(algorithmStr)
		printVerbose("Requesting parameters for algorithm: %s", algorithm)

		getImportParams(cfg, printer, keyID, keyType, keyAlgorithm, keySize, curve, algorithm, outputFile)
	},
}

// getImportParams gets import parameters using the SDK client
func getImportParams(cfg *Config, printer *Printer, keyID, keyType, keyAlgorithm string, keySize int, curve string, algorithm backend.WrappingAlgorithm, outputFile string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to keychaind")

	// Determine the key type to use (use key-algorithm if provided, fall back to key-type)
	keyTypeForRequest := keyAlgorithm
	if keyTypeForRequest == "" {
		keyTypeForRequest = keyType
	}

	req := &client.GetImportParametersRequest{
		Backend:   cfg.Backend,
		KeyID:     keyID,
		Algorithm: string(algorithm),
		KeyType:   keyTypeForRequest,
		KeySize:   keySize,
		Curve:     curve,
	}

	resp, err := cl.GetImportParameters(ctx, req)
	if err != nil {
		handleError(fmt.Errorf("failed to get import parameters: %w", err))
		return
	}

	printVerbose("Import parameters retrieved successfully")
	if resp.ExpiresAt != "" {
		printVerbose("Parameters expire at: %s", resp.ExpiresAt)
	}

	// Convert to backend.ImportParameters for output
	params := &backend.ImportParameters{
		WrappingPublicKey: resp.WrappingPublicKey,
		Algorithm:         algorithm,
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

		// Read key material
		cleanPath := filepath.Clean(keyMaterialFile)
		keyMaterial, err := os.ReadFile(cleanPath)
		if err != nil {
			handleError(fmt.Errorf("failed to read key material file: %w", err))
			return
		}

		printVerbose("Key material size: %d bytes", len(keyMaterial))

		// Read import parameters
		cleanPath = filepath.Clean(paramsFile)
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

		wrapKey(cfg, printer, keyMaterial, &params, outputFile)
	},
}

// wrapKey wraps key material using the SDK client
func wrapKey(cfg *Config, printer *Printer, keyMaterial []byte, params *backend.ImportParameters, outputFile string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to keychaind")

	// Prepare wrap key request - params.WrappingPublicKey should already be in the right format
	var wrappingPubKeyBytes []byte
	if pubKey, ok := params.WrappingPublicKey.([]byte); ok {
		wrappingPubKeyBytes = pubKey
	} else {
		handleError(fmt.Errorf("wrapping public key has unexpected type: %T", params.WrappingPublicKey))
		return
	}

	req := &client.WrapKeyRequest{
		Backend:           cfg.Backend,
		KeyMaterial:       keyMaterial,
		WrappingPublicKey: wrappingPubKeyBytes,
		Algorithm:         string(params.Algorithm),
	}

	resp, err := cl.WrapKey(ctx, req)
	if err != nil {
		handleError(fmt.Errorf("failed to wrap key material: %w", err))
		return
	}

	printVerbose("Wrapped key size: %d bytes", len(resp.WrappedKeyMaterial))

	// Create WrappedKeyMaterial structure for file output
	wrapped := &backend.WrappedKeyMaterial{
		WrappedKey: resp.WrappedKeyMaterial,
		Algorithm:  params.Algorithm,
	}

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

		// Read wrapped key
		cleanPath := filepath.Clean(wrappedKeyFile)
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

		unwrapKey(cfg, printer, &wrapped, &params, outputFile)
	},
}

// unwrapKey unwraps key material using the SDK client
func unwrapKey(cfg *Config, printer *Printer, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters, outputFile string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect: %w", err))
		return
	}

	printVerbose("Connected to keychaind")

	req := &client.UnwrapKeyRequest{
		Backend:            cfg.Backend,
		WrappedKeyMaterial: wrapped.WrappedKey,
		Algorithm:          string(params.Algorithm),
	}

	resp, err := cl.UnwrapKey(ctx, req)
	if err != nil {
		handleError(fmt.Errorf("failed to unwrap key material: %w", err))
		return
	}

	printVerbose("Unwrapped key material size: %d bytes", len(resp.KeyMaterial))

	// Write unwrapped key material
	if err := os.WriteFile(outputFile, resp.KeyMaterial, 0600); err != nil {
		handleError(fmt.Errorf("failed to write key material file: %w", err))
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Successfully unwrapped key to: %s", outputFile)); err != nil {
		handleError(err)
	}
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
	keyGenerateCmd.Flags().String("key-type", "tls", "Key type (tls, signing, encryption, symmetric)")
	keyGenerateCmd.Flags().String("algorithm", "", "Algorithm (aes-128-gcm, aes-192-gcm, aes-256-gcm)")
	keyGenerateCmd.Flags().String("key-algorithm", "rsa", "Key algorithm (rsa, ecdsa, ed25519)")
	keyGenerateCmd.Flags().Int("key-size", 2048, "Key size in bits (128, 192, 256 for AES; 2048+ for RSA)")
	keyGenerateCmd.Flags().String("curve", "P-256", "Elliptic curve (for ECDSA: P-256, P-384, P-521)")
	keyGenerateCmd.Flags().Bool("exportable", false, "Allow the key to be exported")

	// Flags for get command (simplified - no longer needs algorithm params for SDK)
	keyGetCmd.Flags().String("key-type", "tls", "Key type")

	// Flags for delete command (simplified - no longer needs algorithm params for SDK)
	keyDeleteCmd.Flags().String("key-type", "tls", "Key type")

	// Flags for sign command
	keySignCmd.Flags().String("hash", "sha256", "Hash algorithm (sha256, sha384, sha512)")

	// Flags for rotate command (simplified)
	keyRotateCmd.Flags().String("key-type", "tls", "Key type")

	// Flags for encrypt command
	keyEncryptCmd.Flags().String("aad", "", "Additional authenticated data (optional)")

	// Flags for decrypt command
	keyDecryptCmd.Flags().String("aad", "", "Additional authenticated data (for symmetric decryption)")
	keyDecryptCmd.Flags().String("nonce", "", "Nonce/IV (base64, required for symmetric decryption)")
	keyDecryptCmd.Flags().String("tag", "", "Authentication tag (base64, required for symmetric decryption)")

	// Flags for import command (simplified)
	keyImportCmd.Flags().String("key-type", "tls", "Key type")

	// Flags for export command
	keyExportCmd.Flags().String("algorithm", "RSAES_OAEP_SHA_256", "Wrapping algorithm")

	// Flags for copy command
	keyCopyCmd.Flags().String("dest-backend", "software", "Destination backend (software, pkcs11, tpm2, awskms, etc.)")
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
	keyVerifyCmd.Flags().String("hash", "sha256", "Hash algorithm (sha256, sha384, sha512)")

	// Flags for encrypt-asym command
	keyEncryptAsymCmd.Flags().String("hash", "sha256", "Hash algorithm for OAEP (sha256, sha384, sha512)")
}

// buildKeyAttributesFromFlags creates KeyAttributes from separate key type and algorithm flags.
// This helper function is used by tests and other commands (e.g., tls.go) that need to build
// KeyAttributes from command-line flags.
func buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm string, keySize int, curve string, exportable bool) (*types.KeyAttributes, error) {
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
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: ka,
		Hash:         crypto.SHA256,
		Exportable:   exportable,
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

// buildSymmetricKeyAttributes creates KeyAttributes for symmetric (AES) keys.
// This helper function is used by tests that need to build KeyAttributes for symmetric keys.
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
		KeyType:            types.KeyTypeSecret, // Symmetric keys use KeyTypeSecret
		StoreType:          types.StoreSoftware,
		SymmetricAlgorithm: symmetricAlgorithm,
	}

	// Validate the attributes
	if err := attrs.Validate(); err != nil {
		return nil, err
	}

	return attrs, nil
}

// isSymmetricAlgorithm checks if the algorithm string is a symmetric (AES) algorithm.
// This helper function is used by tests to determine if an algorithm is symmetric.
func isSymmetricAlgorithm(algorithm string) bool {
	symAlg := types.SymmetricAlgorithm(algorithm)
	return symAlg.IsValid()
}
