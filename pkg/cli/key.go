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
	"context"
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
	"github.com/jeremyhahn/go-keychain/pkg/client"
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
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")
		exportable, _ := cmd.Flags().GetBool("exportable")

		printVerbose("Generating %s key with ID: %s (exportable: %v)", keyType, keyID, exportable)

		// Use client or backend based on --local flag
		if cfg.IsLocal() {
			generateKeyLocal(cfg, printer, keyID, keyType, algorithm, keyAlgorithm, keySize, curve, exportable)
		} else {
			generateKeyRemote(cfg, printer, keyID, keyType, algorithm, keyAlgorithm, keySize, curve, exportable)
		}
	},
}

// generateKeyLocal generates a key using direct backend access
func generateKeyLocal(cfg *Config, printer *Printer, keyID, keyType, algorithm, keyAlgorithm string, keySize int, curve string, exportable bool) {
	// Create backend
	be, err := cfg.CreateBackend()
	if err != nil {
		handleError(fmt.Errorf("failed to create backend: %w", err))
		return
	}
	defer func() { _ = be.Close() }()

	// Check if this is a symmetric key
	if types.AlgorithmSymmetric.Equals(keyType) || types.AlgorithmAES.Equals(keyType) || types.AEADAES128GCM.Equals(algorithm) || types.AEADAES192GCM.Equals(algorithm) || types.AEADAES256GCM.Equals(algorithm) {
		// Generate symmetric key
		attrs, err := buildSymmetricKeyAttributes(keyID, algorithm, keySize)
		if err != nil {
			handleError(fmt.Errorf("invalid symmetric key parameters: %w", err))
			return
		}

		printVerbose("Symmetric key attributes: %+v", attrs)

		// Cast backend to SymmetricBackend for symmetric key generation
		symBackend, ok := be.(types.SymmetricBackend)
		if !ok {
			handleError(fmt.Errorf("backend does not support symmetric key generation"))
			return
		}

		// Generate the symmetric key
		_, err = symBackend.GenerateSymmetricKey(attrs)
		if err != nil {
			handleError(fmt.Errorf("failed to generate symmetric key: %w", err))
			return
		}

		if err := printer.PrintSuccess(fmt.Sprintf("Successfully generated AES-%d key: %s", keySize, keyID)); err != nil {
			handleError(err)
		}
		return
	}

	// Build asymmetric key attributes using the key-algorithm flag
	attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve, exportable)
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
}

// generateKeyRemote generates a key using the client to communicate with keychaind
func generateKeyRemote(cfg *Config, printer *Printer, keyID, keyType, algorithm, keyAlgorithm string, keySize int, curve string, exportable bool) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// For symmetric keys, don't set algorithm - handlers use defaults based on key_size
	// For asymmetric keys, use the provided algorithm
	algoForRequest := keyAlgorithm
	isSymmetric := types.AlgorithmSymmetric.Equals(keyType) || types.AlgorithmAES.Equals(keyType)
	if isSymmetric {
		// Let the server handlers determine the algorithm based on key_size
		algoForRequest = ""
		// Normalize key type to "symmetric" for the server
		keyType = "symmetric"
	}

	// Prepare generate key request
	req := &client.GenerateKeyRequest{
		KeyID:      keyID,
		Backend:    cfg.Backend,
		KeyType:    keyType,
		KeySize:    keySize,
		Curve:      curve,
		Algorithm:  algoForRequest,
		Exportable: exportable,
	}

	printVerbose("CLI generateKeyRemote: creating request with exportable=%v", exportable)

	// Generate the key
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

		// Use client or backend based on --local flag
		if cfg.IsLocal() {
			listKeysLocal(cfg, printer)
		} else {
			listKeysRemote(cfg, printer)
		}
	},
}

// listKeysLocal lists keys using direct backend access
func listKeysLocal(cfg *Config, printer *Printer) {
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
}

// listKeysRemote lists keys using the client
func listKeysRemote(cfg *Config, printer *Printer) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// List keys
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

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")

		printVerbose("Getting key info for: %s", keyID)

		// Use client or backend based on --local flag
		if cfg.IsLocal() {
			getKeyLocal(cfg, printer, keyID, keyType, keyAlgorithm, keySize, curve)
		} else {
			getKeyRemote(cfg, printer, keyID)
		}
	},
}

// getKeyLocal gets key info using direct backend access
func getKeyLocal(cfg *Config, printer *Printer, keyID, keyType, keyAlgorithm string, keySize int, curve string) {
	// Create backend
	be, err := cfg.CreateBackend()
	if err != nil {
		handleError(fmt.Errorf("failed to create backend: %w", err))
		return
	}
	defer func() { _ = be.Close() }()

	// Build key attributes with algorithm-specific params
	attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve, false)
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
}

// getKeyRemote gets key info using the client
func getKeyRemote(cfg *Config, printer *Printer, keyID string) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Get key info
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

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")

		printVerbose("Deleting key: %s", keyID)

		// Use client or backend based on --local flag
		if cfg.IsLocal() {
			deleteKeyLocal(cfg, printer, keyID, keyType, keyAlgorithm, keySize, curve)
		} else {
			deleteKeyRemote(cfg, printer, keyID)
		}
	},
}

// deleteKeyLocal deletes a key using direct backend access
func deleteKeyLocal(cfg *Config, printer *Printer, keyID, keyType, keyAlgorithm string, keySize int, curve string) {
	// Create backend
	be, err := cfg.CreateBackend()
	if err != nil {
		handleError(fmt.Errorf("failed to create backend: %w", err))
		return
	}
	defer func() { _ = be.Close() }()

	// Build key attributes - check if symmetric (AES) key
	var attrs *types.KeyAttributes
	if isSymmetricAlgorithm(keyAlgorithm) {
		attrs, err = buildSymmetricKeyAttributes(keyID, keyAlgorithm, keySize)
	} else {
		attrs, err = buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve, false)
	}
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
}

// deleteKeyRemote deletes a key using the client
func deleteKeyRemote(cfg *Config, printer *Printer, keyID string) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Delete the key
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

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")
		hashAlg, _ := cmd.Flags().GetString("hash")

		printVerbose("Signing data with key: %s", keyID)

		// Use client or backend based on --local flag
		if cfg.IsLocal() {
			signLocal(cfg, printer, keyID, data, keyType, keyAlgorithm, keySize, curve, hashAlg)
		} else {
			signRemote(cfg, printer, keyID, data, hashAlg)
		}
	},
}

// signLocal signs data using direct backend access
func signLocal(cfg *Config, printer *Printer, keyID, data, keyType, keyAlgorithm string, keySize int, curve, hashAlg string) {
	// Create backend
	be, err := cfg.CreateBackend()
	if err != nil {
		handleError(fmt.Errorf("failed to create backend: %w", err))
		return
	}
	defer func() { _ = be.Close() }()

	// Build key attributes with algorithm-specific params
	attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve, false)
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

	var signature []byte
	// Ed25519 requires the raw message, not a hash
	if attrs.KeyAlgorithm == x509.Ed25519 {
		printVerbose("Ed25519: signing raw message")
		// For Ed25519, pass raw message and crypto.Hash(0)
		signature, err = signer.Sign(nil, []byte(data), crypto.Hash(0))
	} else {
		// For RSA and ECDSA, hash the data first
		hash := attrs.Hash
		hasher := hash.New()
		hasher.Write([]byte(data))
		digest := hasher.Sum(nil)

		printVerbose("Data digest (hex): %x", digest)

		signature, err = signer.Sign(nil, digest, hash)
	}
	if err != nil {
		handleError(fmt.Errorf("failed to sign data: %w", err))
		return
	}

	// Encode signature as base64
	sigBase64 := base64.StdEncoding.EncodeToString(signature)

	if err := printer.PrintSignature(sigBase64); err != nil {
		handleError(err)
	}
}

// signRemote signs data using the client
func signRemote(cfg *Config, printer *Printer, keyID, data, hashAlg string) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Prepare sign request
	req := &client.SignRequest{
		Backend: cfg.Backend,
		KeyID:   keyID,
		Data:    []byte(data),
		Hash:    hashAlg,
	}

	// Sign the data
	resp, err := cl.Sign(ctx, req)
	if err != nil {
		handleError(fmt.Errorf("failed to sign data: %w", err))
		return
	}

	// Encode signature as base64
	sigBase64 := base64.StdEncoding.EncodeToString(resp.Signature)

	if err := printer.PrintSignature(sigBase64); err != nil {
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

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")

		printVerbose("Rotating key: %s", keyID)

		// Use client or backend based on --local flag
		if cfg.IsLocal() {
			rotateKeyLocal(cfg, printer, keyID, keyType, keyAlgorithm, keySize, curve)
		} else {
			rotateKeyRemote(cfg, printer, keyID)
		}
	},
}

// rotateKeyLocal rotates a key using direct backend access
func rotateKeyLocal(cfg *Config, printer *Printer, keyID, keyType, keyAlgorithm string, keySize int, curve string) {
	// Create backend
	be, err := cfg.CreateBackend()
	if err != nil {
		handleError(fmt.Errorf("failed to create backend: %w", err))
		return
	}
	defer func() { _ = be.Close() }()

	// Build key attributes with algorithm-specific params
	attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve, false)
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
}

// rotateKeyRemote rotates a key using the client
func rotateKeyRemote(cfg *Config, printer *Printer, keyID string) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Prepare rotate key request
	req := &client.RotateKeyRequest{
		Backend: cfg.Backend,
		KeyID:   keyID,
	}

	// Rotate the key
	_, err = cl.RotateKey(ctx, req)
	if err != nil {
		handleError(fmt.Errorf("failed to rotate key: %w", err))
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Successfully rotated key: %s", keyID)); err != nil {
		handleError(err)
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

		// Get flags
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		aad, _ := cmd.Flags().GetString("aad")

		printVerbose("Encrypting data with key: %s", keyID)

		// Use client or backend based on --local flag
		if cfg.IsLocal() {
			encryptLocal(cfg, printer, keyID, plaintext, keyAlgorithm, keySize, aad)
		} else {
			encryptRemote(cfg, printer, keyID, plaintext, aad)
		}
	},
}

// encryptLocal encrypts data using direct backend access
func encryptLocal(cfg *Config, printer *Printer, keyID, plaintext, keyAlgorithm string, keySize int, aad string) {
	// Create backend
	be, err := cfg.CreateBackend()
	if err != nil {
		handleError(fmt.Errorf("failed to create backend: %w", err))
		return
	}
	defer func() { _ = be.Close() }()

	// Build symmetric key attributes (encrypt is for symmetric keys)
	attrs, err := buildSymmetricKeyAttributes(keyID, keyAlgorithm, keySize)
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
}

// encryptRemote encrypts data using the client
func encryptRemote(cfg *Config, printer *Printer, keyID, plaintext, aad string) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Prepare encrypt request
	req := &client.EncryptRequest{
		Backend:   cfg.Backend,
		KeyID:     keyID,
		Plaintext: []byte(plaintext),
	}
	if aad != "" {
		req.AdditionalData = []byte(aad)
	}

	// Encrypt the data
	resp, err := cl.Encrypt(ctx, req)
	if err != nil {
		handleError(fmt.Errorf("failed to encrypt data: %w", err))
		return
	}

	printVerbose("Encrypted data: ciphertext=%d bytes, nonce=%d bytes, tag=%d bytes",
		len(resp.Ciphertext), len(resp.Nonce), len(resp.Tag))

	// Convert to EncryptedData for printing
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

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")
		aad, _ := cmd.Flags().GetString("aad")
		nonce, _ := cmd.Flags().GetString("nonce")
		tag, _ := cmd.Flags().GetString("tag")
		hashAlg, _ := cmd.Flags().GetString("hash")

		printVerbose("Decrypting data with key: %s", keyID)

		// Use client or backend based on --local flag
		if cfg.IsLocal() {
			decryptLocal(cfg, printer, keyID, ciphertext, keyType, keyAlgorithm, keySize, curve, aad, nonce, tag, hashAlg)
		} else {
			decryptRemote(cfg, printer, keyID, ciphertext, aad, nonce, tag)
		}
	},
}

// decryptLocal decrypts data using direct backend access
func decryptLocal(cfg *Config, printer *Printer, keyID, ciphertext, keyType, keyAlgorithm string, keySize int, curve, aad, nonce, tag, hashAlg string) {
	// Create backend
	be, err := cfg.CreateBackend()
	if err != nil {
		handleError(fmt.Errorf("failed to create backend: %w", err))
		return
	}
	defer func() { _ = be.Close() }()

	// Check if this is symmetric decryption (nonce and tag present)
	if nonce != "" && tag != "" {
		// Build symmetric key attributes
		attrs, err := buildSymmetricKeyAttributes(keyID, keyAlgorithm, keySize)
		if err != nil {
			handleError(fmt.Errorf("invalid key parameters: %w", err))
			return
		}
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
	// Build key attributes with algorithm-specific params
	attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve, false)
	if err != nil {
		handleError(fmt.Errorf("invalid key parameters: %w", err))
		return
	}

	// Decode ciphertext from base64
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		handleError(fmt.Errorf("failed to decode ciphertext: %w", err))
		return
	}

	printVerbose("Ciphertext size: %d bytes", len(ciphertextBytes))

	var plaintext []byte

	// If hash is specified, use RSA OAEP decryption directly
	if hashAlg != "" {
		var hash crypto.Hash
		if hashAlgParsed, ok := types.AvailableHashes()[hashAlg]; ok {
			hash = hashAlgParsed
		} else {
			handleError(fmt.Errorf("invalid hash algorithm: %s", hashAlg))
			return
		}

		// Get the key to get the private key for OAEP decryption
		key, err := be.GetKey(attrs)
		if err != nil {
			handleError(fmt.Errorf("failed to get key: %w", err))
			return
		}

		// Extract RSA private key
		var rsaPrivKey *rsa.PrivateKey
		switch k := key.(type) {
		case *rsa.PrivateKey:
			rsaPrivKey = k
		case crypto.Signer:
			// Try to get from decrypter interface
			if d, ok := k.(crypto.Decrypter); ok {
				if priv, ok := d.(*rsa.PrivateKey); ok {
					rsaPrivKey = priv
				}
			}
		}

		if rsaPrivKey != nil {
			// RSA OAEP decryption
			plaintext, err = rsa.DecryptOAEP(
				hash.New(),
				rand.Reader,
				rsaPrivKey,
				ciphertextBytes,
				nil, // no label
			)
			if err != nil {
				handleError(fmt.Errorf("failed to decrypt data: %w", err))
				return
			}
		} else {
			// Fallback to decrypter with OAEP options
			decrypter, err := be.Decrypter(attrs)
			if err != nil {
				handleError(fmt.Errorf("failed to get decrypter: %w", err))
				return
			}
			opts := &rsa.OAEPOptions{Hash: hash}
			plaintext, err = decrypter.Decrypt(rand.Reader, ciphertextBytes, opts)
			if err != nil {
				handleError(fmt.Errorf("failed to decrypt data: %w", err))
				return
			}
		}
	} else {
		// Use backend's decrypter (PKCS1v15 or default)
		decrypter, err := be.Decrypter(attrs)
		if err != nil {
			handleError(fmt.Errorf("failed to get decrypter: %w", err))
			return
		}
		plaintext, err = decrypter.Decrypt(nil, ciphertextBytes, nil)
		if err != nil {
			handleError(fmt.Errorf("failed to decrypt data: %w", err))
			return
		}
	}

	// Encode plaintext as base64 for output
	plaintextBase64 := base64.StdEncoding.EncodeToString(plaintext)

	if err := printer.PrintDecryptedData(plaintextBase64); err != nil {
		handleError(err)
	}
}

// decryptRemote decrypts data using the client
func decryptRemote(cfg *Config, printer *Printer, keyID, ciphertext, aad, nonce, tag string) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Decode ciphertext from base64
	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		handleError(fmt.Errorf("failed to decode ciphertext: %w", err))
		return
	}

	// Prepare decrypt request
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

	// Decrypt the data
	resp, err := cl.Decrypt(ctx, req)
	if err != nil {
		handleError(fmt.Errorf("failed to decrypt data: %w", err))
		return
	}

	// Encode plaintext as base64 for output
	plaintextBase64 := base64.StdEncoding.EncodeToString(resp.Plaintext)

	if err := printer.PrintDecryptedData(plaintextBase64); err != nil {
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

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")

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

		// Use client or backend based on --local flag
		if cfg.IsLocal() {
			importKeyLocal(cfg, printer, keyID, keyType, keyAlgorithm, keySize, curve, &wrapped)
		} else {
			importKeyRemote(cfg, printer, keyID, &wrapped)
		}
	},
}

// importKeyLocal imports a wrapped key using direct backend access
func importKeyLocal(cfg *Config, printer *Printer, keyID, keyType, keyAlgorithm string, keySize int, curve string, wrapped *backend.WrappedKeyMaterial) {
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
	attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve, false)
	if err != nil {
		handleError(fmt.Errorf("invalid key parameters: %w", err))
		return
	}

	// Import the key
	if err := importExportBe.ImportKey(attrs, wrapped); err != nil {
		handleError(fmt.Errorf("failed to import key: %w", err))
		return
	}

	if err := printer.PrintSuccess(fmt.Sprintf("Successfully imported key: %s", keyID)); err != nil {
		handleError(err)
	}
}

// importKeyRemote imports a wrapped key using the client
func importKeyRemote(cfg *Config, printer *Printer, keyID string, wrapped *backend.WrappedKeyMaterial) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Prepare import key request
	req := &client.ImportKeyRequest{
		Backend:            cfg.Backend,
		KeyID:              keyID,
		WrappedKeyMaterial: wrapped.WrappedKey,
		Algorithm:          string(wrapped.Algorithm),
	}

	// Import the key
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

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")
		algorithmStr, _ := cmd.Flags().GetString("algorithm")

		printVerbose("Exporting key: %s to file: %s", keyID, outputFile)

		// Parse wrapping algorithm
		algorithm := backend.WrappingAlgorithm(algorithmStr)
		printVerbose("Using wrapping algorithm: %s", algorithm)

		// Use client or backend based on --local flag
		if cfg.IsLocal() {
			exportKeyLocal(cfg, printer, keyID, outputFile, keyType, keyAlgorithm, keySize, curve, algorithm)
		} else {
			exportKeyRemote(cfg, printer, keyID, outputFile, algorithm)
		}
	},
}

// exportKeyLocal exports a key using direct backend access
func exportKeyLocal(cfg *Config, printer *Printer, keyID, outputFile, keyType, keyAlgorithm string, keySize int, curve string, algorithm backend.WrappingAlgorithm) {
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

	// Build key attributes - export operations require Exportable=true
	attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve, true)
	if err != nil {
		handleError(fmt.Errorf("invalid key parameters: %w", err))
		return
	}

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
}

// exportKeyRemote exports a key using the client
func exportKeyRemote(cfg *Config, printer *Printer, keyID, outputFile string, algorithm backend.WrappingAlgorithm) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Prepare export key request
	req := &client.ExportKeyRequest{
		Backend:   cfg.Backend,
		KeyID:     keyID,
		Algorithm: string(algorithm),
	}

	// Export the key
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

		// Get flags
		destBackend, _ := cmd.Flags().GetString("dest-backend")
		destKeyDir, _ := cmd.Flags().GetString("dest-keydir")
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")
		algorithmStr, _ := cmd.Flags().GetString("algorithm")

		printVerbose("Copying key: %s -> %s (backend: %s -> %s)", sourceKeyID, destKeyID, cfg.Backend, destBackend)

		// Parse wrapping algorithm
		algorithm := backend.WrappingAlgorithm(algorithmStr)
		printVerbose("Using wrapping algorithm: %s", algorithm)

		// Use client or backend based on --local flag
		if cfg.IsLocal() {
			copyKeyLocal(cfg, printer, sourceKeyID, destKeyID, destBackend, destKeyDir, keyType, keyAlgorithm, keySize, curve, algorithm)
		} else {
			copyKeyRemote(cfg, printer, sourceKeyID, destKeyID, destBackend, keyType, keyAlgorithm, keySize, curve, algorithm)
		}
	},
}

// copyKeyLocal copies a key using direct backend access
func copyKeyLocal(cfg *Config, printer *Printer, sourceKeyID, destKeyID, destBackend, destKeyDir, keyType, keyAlgorithm string, keySize int, curve string, algorithm backend.WrappingAlgorithm) {
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

	// Build key attributes for source (requires Exportable=true for export operation)
	sourceAttrs, err := buildKeyAttributesFromFlags(sourceKeyID, keyType, keyAlgorithm, keySize, curve, true)
	if err != nil {
		handleError(fmt.Errorf("invalid key parameters: %w", err))
		return
	}

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
	destAttrs, err := buildKeyAttributesFromFlags(destKeyID, keyType, keyAlgorithm, keySize, curve, false)
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
}

// copyKeyRemote copies a key using the client
func copyKeyRemote(cfg *Config, printer *Printer, sourceKeyID, destKeyID, destBackend, keyType, keyAlgorithm string, keySize int, curve string, algorithm backend.WrappingAlgorithm) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Determine the key type to use (prefer key-algorithm if provided, fall back to key-type)
	keyTypeForRequest := keyAlgorithm
	if keyTypeForRequest == "" {
		keyTypeForRequest = keyType
	}

	// Prepare copy key request
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

	// Copy the key
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

		// Get flags
		keyType, _ := cmd.Flags().GetString("key-type")
		keyAlgorithm, _ := cmd.Flags().GetString("key-algorithm")
		keySize, _ := cmd.Flags().GetInt("key-size")
		curve, _ := cmd.Flags().GetString("curve")
		algorithmStr, _ := cmd.Flags().GetString("algorithm")
		outputFile, _ := cmd.Flags().GetString("output")

		printVerbose("Getting import parameters for key: %s", keyID)

		// Parse wrapping algorithm
		algorithm := backend.WrappingAlgorithm(algorithmStr)
		printVerbose("Requesting parameters for algorithm: %s", algorithm)

		// Use client or backend based on --local flag
		if cfg.IsLocal() {
			getImportParamsLocal(cfg, printer, keyID, keyType, keyAlgorithm, keySize, curve, algorithm, outputFile)
		} else {
			getImportParamsRemote(cfg, printer, keyID, keyType, keyAlgorithm, keySize, curve, algorithm, outputFile)
		}
	},
}

// getImportParamsLocal gets import parameters using direct backend access
func getImportParamsLocal(cfg *Config, printer *Printer, keyID, keyType, keyAlgorithm string, keySize int, curve string, algorithm backend.WrappingAlgorithm, outputFile string) {
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
	attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve, false)
	if err != nil {
		handleError(fmt.Errorf("invalid key parameters: %w", err))
		return
	}

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
}

// getImportParamsRemote gets import parameters using the client
func getImportParamsRemote(cfg *Config, printer *Printer, keyID, keyType, keyAlgorithm string, keySize int, curve string, algorithm backend.WrappingAlgorithm, outputFile string) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Prepare get import parameters request
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

	// Get import parameters
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

		// Use client or backend based on --local flag
		if cfg.IsLocal() {
			wrapKeyLocal(cfg, printer, keyMaterial, &params, outputFile)
		} else {
			wrapKeyRemote(cfg, printer, keyMaterial, &params, outputFile)
		}
	},
}

// wrapKeyLocal wraps key material using direct backend access
func wrapKeyLocal(cfg *Config, printer *Printer, keyMaterial []byte, params *backend.ImportParameters, outputFile string) {
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

	// Wrap the key material
	wrapped, err := importExportBe.WrapKey(keyMaterial, params)
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
}

// wrapKeyRemote wraps key material using the client
func wrapKeyRemote(cfg *Config, printer *Printer, keyMaterial []byte, params *backend.ImportParameters, outputFile string) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Marshal the public key to DER format
	wrappingPubKeyDER, err := x509.MarshalPKIXPublicKey(params.WrappingPublicKey)
	if err != nil {
		handleError(fmt.Errorf("failed to marshal wrapping public key: %w", err))
		return
	}

	// Prepare wrap key request
	req := &client.WrapKeyRequest{
		KeyMaterial:       keyMaterial,
		WrappingPublicKey: wrappingPubKeyDER,
		Algorithm:         string(params.Algorithm),
	}

	// Wrap the key material
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

		// Use client or backend based on --local flag
		if cfg.IsLocal() {
			unwrapKeyLocal(cfg, printer, &wrapped, &params, outputFile)
		} else {
			unwrapKeyRemote(cfg, printer, &wrapped, &params, outputFile)
		}
	},
}

// unwrapKeyLocal unwraps key material using direct backend access
func unwrapKeyLocal(cfg *Config, printer *Printer, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters, outputFile string) {
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

	// Unwrap the key material
	keyMaterial, err := importExportBe.UnwrapKey(wrapped, params)
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
}

// unwrapKeyRemote unwraps key material using the client
func unwrapKeyRemote(cfg *Config, printer *Printer, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters, outputFile string) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Prepare unwrap key request
	req := &client.UnwrapKeyRequest{
		WrappedKeyMaterial: wrapped.WrappedKey,
		Algorithm:          string(params.Algorithm),
	}

	// Unwrap the key material
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

		// Use client or backend based on --local flag
		if cfg.IsLocal() {
			verifyLocal(cfg, printer, keyID, data, signatureBase64, keyType, keyAlgorithm, keySize, curve, hashAlg)
		} else {
			verifyRemote(cfg, printer, keyID, data, signatureBase64, hashAlg)
		}
	},
}

// verifyLocal verifies a signature using direct backend access
func verifyLocal(cfg *Config, printer *Printer, keyID, data, signatureBase64, keyType, keyAlgorithm string, keySize int, curve, hashAlg string) {
	// Create backend
	be, err := cfg.CreateBackend()
	if err != nil {
		handleError(fmt.Errorf("failed to create backend: %w", err))
		return
	}
	defer func() { _ = be.Close() }()

	// Build key attributes
	attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve, false)
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
}

// verifyRemote verifies a signature using the client
func verifyRemote(cfg *Config, printer *Printer, keyID, data, signatureBase64, hashAlg string) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Decode signature from base64
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		handleError(fmt.Errorf("failed to decode signature: %w", err))
		return
	}

	// Prepare verify request
	req := &client.VerifyRequest{
		Backend:   cfg.Backend,
		KeyID:     keyID,
		Data:      []byte(data),
		Signature: signature,
		Hash:      hashAlg,
	}

	// Verify the signature
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

		// Use client or backend based on --local flag
		if cfg.IsLocal() {
			encryptAsymLocal(cfg, printer, keyID, plaintext, keyType, keyAlgorithm, keySize, curve, hashAlg)
		} else {
			encryptAsymRemote(cfg, printer, keyID, plaintext, hashAlg)
		}
	},
}

// encryptAsymLocal encrypts data using direct backend access
func encryptAsymLocal(cfg *Config, printer *Printer, keyID, plaintext, keyType, keyAlgorithm string, keySize int, curve, hashAlg string) {
	// Create backend
	be, err := cfg.CreateBackend()
	if err != nil {
		handleError(fmt.Errorf("failed to create backend: %w", err))
		return
	}
	defer func() { _ = be.Close() }()

	// Build key attributes
	attrs, err := buildKeyAttributesFromFlags(keyID, keyType, keyAlgorithm, keySize, curve, false)
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
}

// encryptAsymRemote encrypts data using the client
func encryptAsymRemote(cfg *Config, printer *Printer, keyID, plaintext, hashAlg string) {
	// Create client
	cl, err := cfg.CreateClient()
	if err != nil {
		handleError(fmt.Errorf("failed to create client: %w", err))
		return
	}
	defer func() { _ = cl.Close() }()

	// Connect to server
	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		handleError(fmt.Errorf("failed to connect to keychaind: %w", err))
		return
	}

	printVerbose("Connected to keychaind server")

	// Prepare encrypt request
	req := &client.EncryptAsymRequest{
		Backend:   cfg.Backend,
		KeyID:     keyID,
		Plaintext: []byte(plaintext),
		Hash:      hashAlg,
	}

	// Encrypt the data
	resp, err := cl.EncryptAsym(ctx, req)
	if err != nil {
		handleError(fmt.Errorf("failed to encrypt data: %w", err))
		return
	}

	printVerbose("Ciphertext size: %d bytes", len(resp.Ciphertext))

	// Encode ciphertext as base64
	ciphertextBase64 := base64.StdEncoding.EncodeToString(resp.Ciphertext)

	if err := printer.PrintEncryptedAsym(ciphertextBase64); err != nil {
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
	keyDecryptCmd.Flags().String("hash", "", "Hash algorithm for RSA OAEP decryption (e.g., SHA-256)")
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

// buildKeyAttributesFromFlags creates KeyAttributes from separate key type and algorithm flags
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

// isSymmetricAlgorithm checks if the algorithm string is a symmetric (AES) algorithm
func isSymmetricAlgorithm(algorithm string) bool {
	symAlg := types.SymmetricAlgorithm(algorithm)
	return symAlg.IsValid()
}
