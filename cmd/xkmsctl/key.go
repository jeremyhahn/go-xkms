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

package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
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
		sensitive, _ := cmd.Flags().GetBool("sensitive")

		printVerbose("Generating %s key with ID: %s (exportable: %v, sensitive: %v)",
			keyType, keyID, exportable, sensitive)

		generateKey(cfg, printer, keyID, keyType, algorithm, keyAlgorithm, keySize, curve, exportable, sensitive)
	},
}

// generateKey generates a key using the SDK client
func generateKey(cfg *Config, printer *Printer, keyID, keyType, algorithm, keyAlgorithm string, keySize int, curve string, exportable, sensitive bool) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

	// For symmetric keys, don't set algorithm - handlers use defaults based on key_size
	// For asymmetric keys, use the provided algorithm
	algoForRequest := keyAlgorithm
	isSymmetric := client.AlgorithmSymmetric.Equals(keyType) || client.AlgorithmAES.Equals(keyType) ||
		client.AEADAES128GCM.Equals(algorithm) || client.AEADAES192GCM.Equals(algorithm) || client.AEADAES256GCM.Equals(algorithm)
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
		Sensitive:  sensitive,
	}

	printVerbose("Generating key with exportable=%v sensitive=%v", exportable, sensitive)

	resp, err := cl.GenerateKey(ctx, req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGenerateKeyFailed, Err: err})
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
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

	resp, err := cl.ListKeys(ctx, cfg.Backend)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrListKeysFailed, Err: err})
		return
	}

	printVerbose("Found %d keys", len(resp.Keys))

	// Convert client.KeyInfo to client.KeyAttributes for printing
	keys := make([]*client.KeyAttributes, len(resp.Keys))
	for i, key := range resp.Keys {
		keys[i] = &client.KeyAttributes{
			CN:      key.KeyID,
			KeyType: client.ParseKeyType(key.KeyType),
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
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

	resp, err := cl.GetKey(ctx, cfg.Backend, keyID)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrGetKeyFailed, Err: err})
		return
	}

	// Convert to KeyAttributes for printing
	attrs := &client.KeyAttributes{
		CN:      resp.KeyID,
		KeyType: client.ParseKeyType(resp.KeyType),
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
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

	resp, err := cl.DeleteKey(ctx, cfg.Backend, keyID)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrDeleteKeyFailed, Err: err})
		return
	}

	if resp.Success {
		if err := printer.PrintSuccess(fmt.Sprintf("Successfully deleted key: %s", keyID)); err != nil {
			handleError(err)
		}
	} else {
		handleError(&WrappedDetailError{Sentinel: ErrDeleteKeyFailed, Detail: resp.Message})
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
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

	req := &client.SignRequest{
		Backend: cfg.Backend,
		KeyID:   keyID,
		Data:    []byte(data),
		Hash:    hashAlg,
	}

	resp, err := cl.Sign(ctx, req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrSignDataFailed, Err: err})
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
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrDecodeSignatureFailed, Err: err})
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
		handleError(&WrappedError{Sentinel: ErrVerifySignatureFailed, Err: err})
		return
	}

	if resp.Valid {
		if err := printer.PrintSuccess("Signature is valid"); err != nil {
			handleError(err)
		}
	} else {
		handleError(&WrappedDetailError{Sentinel: ErrSignatureInvalid, Detail: resp.Message})
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
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

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
		handleError(&WrappedError{Sentinel: ErrEncryptDataFailed, Err: err})
		return
	}

	printVerbose("Encrypted data: ciphertext=%d bytes, nonce=%d bytes, tag=%d bytes",
		len(resp.Ciphertext), len(resp.Nonce), len(resp.Tag))

	encrypted := &client.EncryptedData{
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
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrDecodeCiphertextFailed, Err: err})
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
			handleError(&WrappedError{Sentinel: ErrNonceDecode, Err: err})
			return
		}
		req.Nonce = nonceBytes
	}

	if tag != "" {
		tagBytes, err := base64.StdEncoding.DecodeString(tag)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrDecodeTagFailed, Err: err})
			return
		}
		req.Tag = tagBytes
	}

	resp, err := cl.Decrypt(ctx, req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrDecryptDataFailed, Err: err})
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
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

	req := &client.EncryptAsymRequest{
		Backend:   cfg.Backend,
		KeyID:     keyID,
		Plaintext: []byte(plaintext),
		Hash:      hashAlg,
	}

	resp, err := cl.EncryptAsym(ctx, req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrEncryptDataFailed, Err: err})
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
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

	req := &client.RotateKeyRequest{
		Backend: cfg.Backend,
		KeyID:   keyID,
	}

	_, err = cl.RotateKey(ctx, req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrRotateKeyFailed, Err: err})
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
			handleError(&WrappedError{Sentinel: ErrReadWrappedKeyFileFailed, Err: err})
			return
		}

		printVerbose("Wrapped key file size: %d bytes", len(wrappedKeyData))

		// Deserialize WrappedKeyMaterial from JSON
		var wrapped client.WrappedKeyMaterial
		if err := json.Unmarshal(wrappedKeyData, &wrapped); err != nil {
			handleError(&WrappedError{Sentinel: ErrDeserializeWrappedKeyMaterialFailed, Err: err})
			return
		}

		printVerbose("Wrapped key algorithm: %s", wrapped.Algorithm)

		importKeyType, _ := cmd.Flags().GetString("key-type")
		importKeySize, _ := cmd.Flags().GetInt("key-size")
		importAESKeySize, _ := cmd.Flags().GetInt("aes-key-size")
		importCurve, _ := cmd.Flags().GetString("curve")
		importHash, _ := cmd.Flags().GetString("hash")
		importPartition, _ := cmd.Flags().GetString("partition")

		spec := importKeySpec{
			keyType:    strings.TrimSpace(importKeyType),
			keySize:    importKeySize,
			aesKeySize: importAESKeySize,
			curve:      strings.TrimSpace(importCurve),
			hash:       strings.TrimSpace(importHash),
			partition:  strings.TrimSpace(importPartition),
		}
		if spec.keyType == "" {
			handleError(ErrImportKeyTypeRequired)
			return
		}

		importKey(cfg, printer, keyID, &wrapped, spec)
	},
}

// importKeySpec carries the key's own parameters, which the wrapped material
// cannot supply. The server receives ciphertext and an unwrapping key; nothing
// in that describes the algorithm, modulus size or curve of what is inside, so
// the caller has to state it.
type importKeySpec struct {
	keyType    string
	keySize    int
	aesKeySize int
	curve      string
	hash       string
	partition  string
}

// importKey imports a wrapped key using the SDK client
func importKey(cfg *Config, printer *Printer, keyID string, wrapped *client.WrappedKeyMaterial, spec importKeySpec) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

	req := &client.ImportKeyRequest{
		Backend:            cfg.Backend,
		KeyID:              keyID,
		WrappedKeyMaterial: wrapped.WrappedKey,
		Algorithm:          string(wrapped.Algorithm),
		KeyType:            spec.keyType,
		KeySize:            spec.keySize,
		AESKeySize:         spec.aesKeySize,
		Curve:              spec.curve,
		Hash:               spec.hash,
		Partition:          spec.partition,
	}

	_, err = cl.ImportKey(ctx, req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrImportKeyFailed, Err: err})
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

		algorithm := client.WrappingAlgorithm(algorithmStr)
		printVerbose("Using wrapping algorithm: %s", algorithm)

		exportKey(cfg, printer, keyID, outputFile, algorithm)
	},
}

// exportKey exports a key using the SDK client
func exportKey(cfg *Config, printer *Printer, keyID, outputFile string, algorithm client.WrappingAlgorithm) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

	req := &client.ExportKeyRequest{
		Backend:   cfg.Backend,
		KeyID:     keyID,
		Algorithm: string(algorithm),
	}

	resp, err := cl.ExportKey(ctx, req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrExportKeyFailed, Err: err})
		return
	}

	printVerbose("Wrapped key size: %d bytes", len(resp.WrappedKeyMaterial))

	// Create WrappedKeyMaterial structure for file output
	wrapped := &client.WrappedKeyMaterial{
		WrappedKey: resp.WrappedKeyMaterial,
		Algorithm:  algorithm,
	}

	// Serialize to JSON and write to file
	wrappedData, err := json.MarshalIndent(wrapped, "", "  ")
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrSerializeWrappedKeyFailed, Err: err})
		return
	}

	if err := os.WriteFile(outputFile, wrappedData, 0600); err != nil {
		handleError(&WrappedError{Sentinel: ErrWriteWrappedKeyFileFailed, Err: err})
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

		algorithm := client.WrappingAlgorithm(algorithmStr)
		printVerbose("Using wrapping algorithm: %s", algorithm)

		copyKey(cfg, printer, sourceKeyID, destKeyID, destBackend, keyType, keyAlgorithm, keySize, curve, algorithm)
	},
}

// copyKey copies a key using the SDK client
func copyKey(cfg *Config, printer *Printer, sourceKeyID, destKeyID, destBackend, keyType, keyAlgorithm string, keySize int, curve string, algorithm client.WrappingAlgorithm) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

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
		handleError(&WrappedError{Sentinel: ErrCopyKeyFailed, Err: err})
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

		algorithm := client.WrappingAlgorithm(algorithmStr)
		printVerbose("Requesting parameters for algorithm: %s", algorithm)

		getImportParams(cfg, printer, keyID, keyType, keyAlgorithm, keySize, curve, algorithm, outputFile)
	},
}

// getImportParams gets import parameters using the SDK client
func getImportParams(cfg *Config, printer *Printer, keyID, keyType, keyAlgorithm string, keySize int, curve string, algorithm client.WrappingAlgorithm, outputFile string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

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
		handleError(&WrappedError{Sentinel: ErrGetImportParametersFailed, Err: err})
		return
	}

	printVerbose("Import parameters retrieved successfully")
	if resp.ExpiresAt != "" {
		printVerbose("Parameters expire at: %s", resp.ExpiresAt)
	}

	// Convert to client.ImportParameters for output
	params := &client.ImportParameters{
		WrappingPublicKey: resp.WrappingPublicKey,
		Algorithm:         algorithm,
	}

	// If output file is specified, save params to file
	if outputFile != "" {
		paramsData, err := json.MarshalIndent(params, "", "  ")
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrSerializeImportParametersFailed, Err: err})
			return
		}

		if err := os.WriteFile(outputFile, paramsData, 0600); err != nil {
			handleError(&WrappedError{Sentinel: ErrWriteParametersFileFailed, Err: err})
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
			handleError(&WrappedError{Sentinel: ErrReadKeyMaterialFileFailed, Err: err})
			return
		}

		printVerbose("Key material size: %d bytes", len(keyMaterial))

		// Read import parameters
		cleanPath = filepath.Clean(paramsFile)
		paramsData, err := os.ReadFile(cleanPath)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrReadParametersFileFailed, Err: err})
			return
		}

		var params client.ImportParameters
		if err := json.Unmarshal(paramsData, &params); err != nil {
			handleError(&WrappedError{Sentinel: ErrDeserializeImportParametersFailed, Err: err})
			return
		}

		printVerbose("Using wrapping algorithm: %s", params.Algorithm)

		wrapKey(cfg, printer, keyMaterial, &params, outputFile)
	},
}

// wrapKey wraps key material using the SDK client
func wrapKey(cfg *Config, printer *Printer, keyMaterial []byte, params *client.ImportParameters, outputFile string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

	// Prepare wrap key request - params.WrappingPublicKey should already be in the right format
	var wrappingPubKeyBytes []byte
	if pubKey, ok := params.WrappingPublicKey.([]byte); ok {
		wrappingPubKeyBytes = pubKey
	} else {
		handleError(&WrappedDetailError{Sentinel: ErrWrappingKeyUnexpectedType, Detail: fmt.Sprintf("%T", params.WrappingPublicKey)})
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
		handleError(&WrappedError{Sentinel: ErrWrapKeyMaterialFailed, Err: err})
		return
	}

	printVerbose("Wrapped key size: %d bytes", len(resp.WrappedKeyMaterial))

	// Create WrappedKeyMaterial structure for file output
	wrapped := &client.WrappedKeyMaterial{
		WrappedKey: resp.WrappedKeyMaterial,
		Algorithm:  params.Algorithm,
	}

	// Serialize and write wrapped key
	wrappedData, err := json.MarshalIndent(wrapped, "", "  ")
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrSerializeWrappedKeyFailed, Err: err})
		return
	}

	if err := os.WriteFile(outputFile, wrappedData, 0600); err != nil {
		handleError(&WrappedError{Sentinel: ErrWriteWrappedKeyFileFailed, Err: err})
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
			handleError(&WrappedError{Sentinel: ErrReadWrappedKeyFileFailed, Err: err})
			return
		}

		var wrapped client.WrappedKeyMaterial
		if err := json.Unmarshal(wrappedData, &wrapped); err != nil {
			handleError(&WrappedError{Sentinel: ErrDeserializeWrappedKeyFailed, Err: err})
			return
		}

		printVerbose("Wrapped key size: %d bytes", len(wrapped.WrappedKey))

		// Read import parameters
		cleanPath = filepath.Clean(paramsFile)
		paramsData, err := os.ReadFile(cleanPath)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrReadParametersFileFailed, Err: err})
			return
		}

		var params client.ImportParameters
		if err := json.Unmarshal(paramsData, &params); err != nil {
			handleError(&WrappedError{Sentinel: ErrDeserializeImportParametersFailed, Err: err})
			return
		}

		printVerbose("Using wrapping algorithm: %s", params.Algorithm)

		unwrapKey(cfg, printer, &wrapped, &params, outputFile)
	},
}

// unwrapKey unwraps key material using the SDK client
func unwrapKey(cfg *Config, printer *Printer, wrapped *client.WrappedKeyMaterial, params *client.ImportParameters, outputFile string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

	req := &client.UnwrapKeyRequest{
		Backend:            cfg.Backend,
		WrappedKeyMaterial: wrapped.WrappedKey,
		Algorithm:          string(params.Algorithm),
	}

	resp, err := cl.UnwrapKey(ctx, req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrUnwrapKeyMaterialFailed, Err: err})
		return
	}

	printVerbose("Unwrapped key material size: %d bytes", len(resp.KeyMaterial))

	// Write unwrapped key material
	if err := os.WriteFile(outputFile, resp.KeyMaterial, 0600); err != nil {
		handleError(&WrappedError{Sentinel: ErrWriteKeyMaterialFileFailed, Err: err})
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Successfully unwrapped key to: %s", outputFile)); err != nil {
		handleError(err)
	}
}

// keyAttestCmd requests key attestation from a backend.
var keyAttestCmd = &cobra.Command{
	Use:   "attest <key-id>",
	Short: "Attest that a key resides in hardware",
	Long: `Request a key attestation statement from the backend, proving the
key was created in hardware (TPM 2.0, TEE/StrongBox, etc.) and never
left the secure boundary.

A random 32-byte nonce is generated for freshness unless --nonce is
provided (base64).

Examples:
  xkmsctl key attest my-key --backend tpm2
  xkmsctl key attest my-key --backend tpm2 --output attestation.json`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		nonceBase64, _ := cmd.Flags().GetString("nonce")
		outputFile, _ := cmd.Flags().GetString("output")

		var nonce []byte
		if nonceBase64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(nonceBase64)
			if err != nil {
				handleError(&WrappedError{Sentinel: ErrInvalidBase64Nonce, Err: err})
				return
			}
			nonce = decoded
		} else {
			nonce = make([]byte, 32)
			if _, err := rand.Read(nonce); err != nil {
				handleError(&WrappedError{Sentinel: ErrGenerateNonceFailed, Err: err})
				return
			}
		}

		printVerbose("Requesting attestation for key: %s", keyID)

		attestKey(cfg, printer, keyID, nonce, outputFile)
	},
}

// attestKey requests key attestation using the SDK client.
func attestKey(cfg *Config, printer *Printer, keyID string, nonce []byte, outputFile string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

	req := &client.AttestKeyRequest{
		Backend: cfg.Backend,
		KeyID:   keyID,
		Nonce:   nonce,
	}

	resp, err := cl.AttestKey(ctx, req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrAttestKeyFailed, Err: err})
		return
	}

	if outputFile != "" {
		data, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrJSONMarshalFailed, Err: err})
			return
		}
		if err := os.WriteFile(outputFile, data, 0600); err != nil {
			handleError(&WrappedError{Sentinel: ErrWriteAttestationFileFailed, Err: err})
			return
		}
		if err := printer.PrintSuccess(fmt.Sprintf("Attestation written to: %s", outputFile)); err != nil {
			handleError(err)
		}
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		_, _ = fmt.Fprintf(printer.writer, "Key Attestation:\n")
		_, _ = fmt.Fprintf(printer.writer, "  Backend:      %s\n", resp.Backend)
		_, _ = fmt.Fprintf(printer.writer, "  Format:       %s\n", resp.Format)
		if resp.SignatureAlgorithm != "" {
			_, _ = fmt.Fprintf(printer.writer, "  Sig Alg:      %s\n", resp.SignatureAlgorithm)
		}
		_, _ = fmt.Fprintf(printer.writer, "  Nonce:        %s\n", base64.StdEncoding.EncodeToString(resp.Nonce))
		_, _ = fmt.Fprintf(printer.writer, "  Data:         %s\n", base64.StdEncoding.EncodeToString(resp.AttestationData))
		_, _ = fmt.Fprintf(printer.writer, "  Signature:    %s\n", base64.StdEncoding.EncodeToString(resp.Signature))
		_, _ = fmt.Fprintf(printer.writer, "  Certificates: %d\n", len(resp.CertificateChain))
	}
}

// keyDeriveECDHCmd performs ECDH key agreement and derives a symmetric key.
var keyDeriveECDHCmd = &cobra.Command{
	Use:   "derive-ecdh <key-id>",
	Short: "Derive a symmetric key via ECDH key agreement",
	Long: `Perform ECDH key agreement between the named private key and a peer
public key, then derive a symmetric key with the selected KDF. The
private key never leaves the backend's secure boundary.

The peer public key file must contain the key in DER or uncompressed
point format on the same curve as the private key.

Examples:
  xkmsctl key derive-ecdh my-ec-key --peer-key peer.der
  xkmsctl key derive-ecdh my-ec-key --peer-key peer.der --kdf HKDF --kdf-hash SHA-384 --length 32`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		peerKeyFile, _ := cmd.Flags().GetString("peer-key")
		kdf, _ := cmd.Flags().GetString("kdf")
		kdfHash, _ := cmd.Flags().GetString("kdf-hash")
		saltBase64, _ := cmd.Flags().GetString("salt")
		info, _ := cmd.Flags().GetString("info")
		label, _ := cmd.Flags().GetString("label")
		keyLength, _ := cmd.Flags().GetInt("length")
		outputFile, _ := cmd.Flags().GetString("output")

		if peerKeyFile == "" {
			handleError(ErrPeerPublicKeyRequired)
			return
		}

		peerKey, err := os.ReadFile(filepath.Clean(peerKeyFile))
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrReadPublicKeyFileFailed, Err: err})
			return
		}

		var salt []byte
		if saltBase64 != "" {
			decoded, decodeErr := base64.StdEncoding.DecodeString(saltBase64)
			if decodeErr != nil {
				handleError(&WrappedError{Sentinel: ErrInvalidSalt, Err: decodeErr})
				return
			}
			salt = decoded
		}

		printVerbose("Deriving key via ECDH with key: %s", keyID)

		req := &client.DeriveKeyECDHRequest{
			KeyID:         keyID,
			Backend:       cfg.Backend,
			PeerPublicKey: peerKey,
			KDFAlgorithm:  kdf,
			KDFHash:       kdfHash,
			KDFSalt:       salt,
			KeyLength:     keyLength,
		}
		if info != "" {
			req.KDFInfo = []byte(info)
		}
		if label != "" {
			req.KDFLabel = []byte(label)
		}

		deriveKeyECDH(cfg, printer, req, outputFile)
	},
}

// deriveKeyECDH derives a key via ECDH using the SDK client.
func deriveKeyECDH(cfg *Config, printer *Printer, req *client.DeriveKeyECDHRequest, outputFile string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

	resp, err := cl.DeriveKeyECDH(ctx, req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrDeriveKeyECDHFailed, Err: err})
		return
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, resp.DerivedKey, 0600); err != nil {
			handleError(&WrappedError{Sentinel: ErrWriteDerivedKeyFileFailed, Err: err})
			return
		}
		if err := printer.PrintSuccess(fmt.Sprintf("Derived key written to: %s", outputFile)); err != nil {
			handleError(err)
		}
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(map[string]interface{}{
			"derived_key": base64.StdEncoding.EncodeToString(resp.DerivedKey),
			"length":      len(resp.DerivedKey),
		}); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		_, _ = fmt.Fprintf(printer.writer, "Derived Key (%d bytes):\n", len(resp.DerivedKey))
		_, _ = fmt.Fprintf(printer.writer, "  %s\n", base64.StdEncoding.EncodeToString(resp.DerivedKey))
	}
}

// keyWrapByIDCmd wraps a server-side key using another server-side key.
var keyWrapByIDCmd = &cobra.Command{
	Use:   "wrap-by-id <target-key-id>",
	Short: "Wrap a key using another key, both identified by ID",
	Long: `Wrap an extractable target key using a wrapping key (Key
Encryption Key); both keys are identified by their server-side IDs.
This is the CLI equivalent of PKCS#11 C_WrapKey.

The target backend defaults to the wrapping key backend (--backend).

Examples:
  xkmsctl key wrap-by-id data-key --wrapping-key kek --algorithm AES_KEY_WRAP
  xkmsctl key wrap-by-id data-key --wrapping-key kek --output wrapped.bin`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetKeyID := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		wrappingKeyID, _ := cmd.Flags().GetString("wrapping-key")
		wrappingBackend, _ := cmd.Flags().GetString("wrapping-backend")
		targetBackend, _ := cmd.Flags().GetString("target-backend")
		algorithm, _ := cmd.Flags().GetString("algorithm")
		outputFile, _ := cmd.Flags().GetString("output")

		if wrappingKeyID == "" {
			handleError(ErrWrappingKeyIDRequired)
			return
		}
		if wrappingBackend == "" {
			wrappingBackend = cfg.Backend
		}
		if targetBackend == "" {
			targetBackend = cfg.Backend
		}

		printVerbose("Wrapping key %s with %s", targetKeyID, wrappingKeyID)

		wrapKeyByID(cfg, printer, &client.WrapKeyByIDRequest{
			WrappingKeyID:      wrappingKeyID,
			WrappingKeyBackend: wrappingBackend,
			TargetKeyID:        targetKeyID,
			TargetKeyBackend:   targetBackend,
			Algorithm:          algorithm,
		}, outputFile)
	},
}

// wrapKeyByID wraps a key by ID using the SDK client.
func wrapKeyByID(cfg *Config, printer *Printer, req *client.WrapKeyByIDRequest, outputFile string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

	resp, err := cl.WrapKeyByID(ctx, req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrWrapKeyByIDFailed, Err: err})
		return
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, resp.WrappedKey, 0600); err != nil {
			handleError(&WrappedError{Sentinel: ErrWriteWrappedKeyFileFailed, Err: err})
			return
		}
		if err := printer.PrintSuccess(fmt.Sprintf("Wrapped key written to: %s", outputFile)); err != nil {
			handleError(err)
		}
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(map[string]interface{}{
			"wrapped_key": base64.StdEncoding.EncodeToString(resp.WrappedKey),
			"algorithm":   resp.Algorithm,
		}); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		_, _ = fmt.Fprintf(printer.writer, "Wrapped Key (%s):\n", resp.Algorithm)
		_, _ = fmt.Fprintf(printer.writer, "  %s\n", base64.StdEncoding.EncodeToString(resp.WrappedKey))
	}
}

// keyUnwrapByIDCmd unwraps key material and imports it as a new key.
var keyUnwrapByIDCmd = &cobra.Command{
	Use:   "unwrap-by-id <new-key-id>",
	Short: "Unwrap key material and import it as a new key",
	Long: `Unwrap wrapped key material using a server-side unwrapping key and
import the result as a new key. This is the CLI equivalent of PKCS#11
C_UnwrapKey.

The wrapped material is read from --wrapped-file (as produced by
"key wrap-by-id --output").

Examples:
  xkmsctl key unwrap-by-id restored-key --wrapped-file wrapped.bin --unwrapping-key kek
  xkmsctl key unwrap-by-id restored-key --wrapped-file wrapped.bin --unwrapping-key kek \
    --key-type symmetric --key-size 256 --exportable`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		newKeyID := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		wrappedFile, _ := cmd.Flags().GetString("wrapped-file")
		unwrappingKeyID, _ := cmd.Flags().GetString("unwrapping-key")
		unwrappingBackend, _ := cmd.Flags().GetString("unwrapping-backend")
		targetBackend, _ := cmd.Flags().GetString("target-backend")
		algorithm, _ := cmd.Flags().GetString("algorithm")
		keyType, _ := cmd.Flags().GetString("key-type")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")
		exportable, _ := cmd.Flags().GetBool("exportable")

		if wrappedFile == "" {
			handleError(ErrWrappedKeyFileRequired)
			return
		}
		if unwrappingKeyID == "" {
			handleError(ErrUnwrappingKeyIDRequired)
			return
		}
		if unwrappingBackend == "" {
			unwrappingBackend = cfg.Backend
		}
		if targetBackend == "" {
			targetBackend = cfg.Backend
		}

		wrappedKey, err := os.ReadFile(filepath.Clean(wrappedFile))
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrReadWrappedKeyFileFailed, Err: err})
			return
		}

		printVerbose("Unwrapping key material into %s with %s", newKeyID, unwrappingKeyID)

		unwrapKeyByID(cfg, printer, &client.UnwrapKeyByIDRequest{
			WrappedKey:           wrappedKey,
			UnwrappingKeyID:      unwrappingKeyID,
			UnwrappingKeyBackend: unwrappingBackend,
			Algorithm:            algorithm,
			TargetKeyID:          newKeyID,
			TargetKeyBackend:     targetBackend,
			TargetKeyType:        keyType,
			TargetKeySize:        keySize,
			TargetCurve:          curve,
			TargetExportable:     exportable,
		})
	},
}

// unwrapKeyByID unwraps key material by ID using the SDK client.
func unwrapKeyByID(cfg *Config, printer *Printer, req *client.UnwrapKeyByIDRequest) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

	resp, err := cl.UnwrapKeyByID(ctx, req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrUnwrapKeyByIDFailed, Err: err})
		return
	}

	if !resp.Success {
		handleError(&WrappedDetailError{Sentinel: ErrUnwrapKeyByIDFailed, Detail: resp.Message})
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Successfully unwrapped key material into %s:%s",
		resp.Backend, resp.KeyID)); err != nil {
		handleError(err)
	}
}

// keyExportMaterialCmd exports raw symmetric key bytes.
var keyExportMaterialCmd = &cobra.Command{
	Use:   "export-material <key-id>",
	Short: "Export raw symmetric key material (plaintext)",
	Long: `Export the raw bytes of an extractable symmetric key.

SECURITY WARNING: This returns PLAINTEXT key material without any
cryptographic protection. Prefer "key export" (wrapped export) for
transport between systems.

Examples:
  xkmsctl key export-material my-aes-key --output key.bin
  xkmsctl key export-material my-aes-key`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyID := args[0]
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		outputFile, _ := cmd.Flags().GetString("output")

		printVerbose("Exporting raw key material for: %s", keyID)

		exportKeyMaterial(cfg, printer, keyID, outputFile)
	},
}

// exportKeyMaterial exports raw key material using the SDK client.
func exportKeyMaterial(cfg *Config, printer *Printer, keyID, outputFile string) {
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrCreateClientFailed, Err: err})
		return
	}
	defer func() { _ = cl.Close() }()

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(&WrappedError{Sentinel: ErrConnectFailed, Err: err})
		return
	}

	printVerbose("Connected to xkmsd")

	req := &client.ExportKeyMaterialRequest{
		Backend: cfg.Backend,
		KeyID:   keyID,
	}

	resp, err := cl.ExportKeyMaterial(ctx, req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrExportKeyMaterialFailed, Err: err})
		return
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, resp.KeyMaterial, 0600); err != nil {
			handleError(&WrappedError{Sentinel: ErrWriteKeyMaterialFileFailed, Err: err})
			return
		}
		if err := printer.PrintSuccess(fmt.Sprintf("Key material written to: %s", outputFile)); err != nil {
			handleError(err)
		}
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(map[string]interface{}{
			"key_material": base64.StdEncoding.EncodeToString(resp.KeyMaterial),
			"key_type":     resp.KeyType,
			"key_size":     resp.KeySize,
		}); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		_, _ = fmt.Fprintf(printer.writer, "Key Material (%s, %d bits):\n", resp.KeyType, resp.KeySize)
		_, _ = fmt.Fprintf(printer.writer, "  %s\n", base64.StdEncoding.EncodeToString(resp.KeyMaterial))
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
	keyCmd.AddCommand(keyAttestCmd)
	keyCmd.AddCommand(keyDeriveECDHCmd)
	keyCmd.AddCommand(keyWrapByIDCmd)
	keyCmd.AddCommand(keyUnwrapByIDCmd)
	keyCmd.AddCommand(keyExportMaterialCmd)

	// Flags for generate command
	keyGenerateCmd.Flags().String("key-type", "tls", "Key type (tls, signing, encryption, symmetric)")
	keyGenerateCmd.Flags().String("algorithm", "", "Algorithm (aes-128-gcm, aes-192-gcm, aes-256-gcm)")
	keyGenerateCmd.Flags().String("key-algorithm", "rsa", "Key algorithm (rsa, ecdsa, ed25519)")
	keyGenerateCmd.Flags().Int("key-size", 2048, "Key size in bits (128, 192, 256 for AES; 2048+ for RSA)")
	keyGenerateCmd.Flags().String("curve", "P-256", "Elliptic curve (for ECDSA: P-256, P-384, P-521)")
	keyGenerateCmd.Flags().Bool("exportable", false, "Allow the key to be exported")
	// --sensitive is PKCS#11 CKA_SENSITIVE and is independent of --exportable:
	// a sensitive key may still be wrapped out under another key, but its
	// plaintext is never released. Without this flag a key generated through the
	// CLI could never be marked sensitive, so the protection was reachable only
	// from the PKCS#11 module.
	keyGenerateCmd.Flags().Bool("sensitive", false,
		"Never release the key's plaintext (PKCS#11 CKA_SENSITIVE); the key may still be wrapped if --exportable")

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

	// Flags for import command. --key-type names the ALGORITHM of the material
	// being imported, not a purpose: the server receives opaque wrapped bytes
	// and cannot infer it. There is deliberately no default -- guessing "rsa"
	// would store Ed25519 material under the wrong algorithm and report it as
	// RSA rather than failing.
	keyImportCmd.Flags().String("key-type", "", "Algorithm of the imported key: rsa, ecdsa, ed25519, aes (required)")
	keyImportCmd.Flags().Int("key-size", 0, "RSA modulus size in bits (2048, 3072, 4096); required for rsa")
	keyImportCmd.Flags().Int("aes-key-size", 0, "AES key size in bits (128, 192, 256); required for aes")
	keyImportCmd.Flags().String("curve", "", "ECDSA curve (P-256, P-384, P-521); required for ecdsa")
	keyImportCmd.Flags().String("hash", "", "Signing hash to associate with the key (e.g. SHA-256)")
	keyImportCmd.Flags().String("partition", "", "Backend partition to import into")

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

	// Flags for attest command
	keyAttestCmd.Flags().String("nonce", "", "Attestation nonce (base64; random 32 bytes when omitted)")
	keyAttestCmd.Flags().String("output", "", "Write the attestation statement to a JSON file")

	// Flags for derive-ecdh command
	keyDeriveECDHCmd.Flags().String("peer-key", "", "Peer public key file (DER or uncompressed point, required)")
	keyDeriveECDHCmd.Flags().String("kdf", "HKDF", "KDF algorithm (HKDF, SP800-108-COUNTER, SP800-108-FEEDBACK, SP800-56A, X963)")
	keyDeriveECDHCmd.Flags().String("kdf-hash", "SHA-256", "KDF hash algorithm (SHA-256, SHA-384, SHA-512)")
	keyDeriveECDHCmd.Flags().String("salt", "", "KDF salt (base64, optional)")
	keyDeriveECDHCmd.Flags().String("info", "", "KDF context/info string (optional)")
	keyDeriveECDHCmd.Flags().String("label", "", "SP 800-108 label for domain separation (optional)")
	keyDeriveECDHCmd.Flags().Int("length", 32, "Derived key length in bytes")
	keyDeriveECDHCmd.Flags().String("output", "", "Write the derived key bytes to a file (mode 0600)")

	// Flags for wrap-by-id command
	keyWrapByIDCmd.Flags().String("wrapping-key", "", "Wrapping key ID (Key Encryption Key, required)")
	keyWrapByIDCmd.Flags().String("wrapping-backend", "", "Backend containing the wrapping key (default: --backend)")
	keyWrapByIDCmd.Flags().String("target-backend", "", "Backend containing the target key (default: --backend)")
	keyWrapByIDCmd.Flags().String("algorithm", "AES_KEY_WRAP", "Wrapping algorithm (AES_KEY_WRAP, RSAES_OAEP_SHA_256, ...)")
	keyWrapByIDCmd.Flags().String("output", "", "Write the wrapped key bytes to a file (mode 0600)")

	// Flags for unwrap-by-id command
	keyUnwrapByIDCmd.Flags().String("wrapped-file", "", "File containing the wrapped key bytes (required)")
	keyUnwrapByIDCmd.Flags().String("unwrapping-key", "", "Unwrapping key ID (required)")
	keyUnwrapByIDCmd.Flags().String("unwrapping-backend", "", "Backend containing the unwrapping key (default: --backend)")
	keyUnwrapByIDCmd.Flags().String("target-backend", "", "Backend to store the new key (default: --backend)")
	keyUnwrapByIDCmd.Flags().String("algorithm", "AES_KEY_WRAP", "Unwrapping algorithm (must match the wrap)")
	keyUnwrapByIDCmd.Flags().String("key-type", "symmetric", "New key type (symmetric, rsa, ecdsa, ed25519)")
	keyUnwrapByIDCmd.Flags().Int("key-size", 256, "New key size in bits")
	keyUnwrapByIDCmd.Flags().String("curve", "", "Curve for ECDSA keys (P-256, P-384, P-521)")
	keyUnwrapByIDCmd.Flags().Bool("exportable", false, "Allow the new key to be exported")

	// Flags for export-material command
	keyExportMaterialCmd.Flags().String("output", "", "Write the raw key bytes to a file (mode 0600)")
}

// buildKeyAttributesFromFlags creates KeyAttributes from separate key type and algorithm flags.
// This helper function is used by tests and other commands (e.g., tls.go) that need to build
// KeyAttributes from command-line flags.
func buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm string, keySize int, curve string, exportable bool) (*client.KeyAttributes, error) {
	// Parse key type and algorithm
	kt := client.ParseKeyType(keyType)
	if kt == 0 {
		return nil, &WrappedDetailError{Sentinel: ErrInvalidKeyType, Detail: keyType}
	}

	ka, err := client.ParseKeyAlgorithm(keyAlgorithm)
	if err != nil {
		return nil, &WrappedDetailError{Sentinel: ErrInvalidKeyAlgorithm, Detail: keyAlgorithm}
	}

	attrs := &client.KeyAttributes{
		CN:           keyID,
		KeyType:      kt,
		StoreType:    client.StoreSoftware,
		KeyAlgorithm: ka,
		Hash:         crypto.SHA256,
		Exportable:   exportable,
	}

	// Set algorithm-specific attributes
	switch ka {
	case x509.RSA:
		if keySize < 2048 {
			return nil, ErrRSAKeySizeTooSmall
		}
		attrs.RSAAttributes = &client.RSAAttributes{
			KeySize: keySize,
		}

	case x509.ECDSA:
		parsedCurve, err := client.ParseCurve(curve)
		if err != nil {
			return nil, &WrappedDetailError{Sentinel: ErrInvalidCurve, Detail: curve}
		}
		attrs.ECCAttributes = &client.ECCAttributes{
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
func buildSymmetricKeyAttributes(keyID, algorithm string, keySize int) (*client.KeyAttributes, error) {
	// Determine algorithm from either algorithm flag or keySize
	var symmetricAlgorithm client.SymmetricAlgorithm

	if algorithm != "" {
		// Parse algorithm string
		symmetricAlgorithm = client.SymmetricAlgorithm(algorithm)
		if !symmetricAlgorithm.IsValid() {
			return nil, &WrappedDetailError{Sentinel: ErrInvalidAlgorithm, Detail: algorithm}
		}
	} else {
		// Derive from key size
		switch keySize {
		case 128:
			symmetricAlgorithm = client.SymmetricAES128GCM
		case 192:
			symmetricAlgorithm = client.SymmetricAES192GCM
		case 256:
			symmetricAlgorithm = client.SymmetricAES256GCM
		default:
			return nil, &WrappedDetailError{Sentinel: ErrInvalidAESKeySize, Detail: fmt.Sprintf("%d (valid: 128, 192, 256)", keySize)}
		}
	}

	attrs := &client.KeyAttributes{
		CN:                 keyID,
		KeyType:            client.KeyTypeSecret, // Symmetric keys use KeyTypeSecret
		StoreType:          client.StoreSoftware,
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
	symAlg := client.SymmetricAlgorithm(algorithm)
	return symAlg.IsValid()
}
