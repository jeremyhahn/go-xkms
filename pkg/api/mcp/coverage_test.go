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

package mcp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandler_UnwrapKey tests the unwrap key handler
func TestHandler_UnwrapKey(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("fails with invalid params", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.unwrapKey",
			Params:  json.RawMessage(`invalid json`),
			ID:      1,
		}

		_, err := server.handleUnwrapKey(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid params")
	})

	t.Run("fails with missing wrapped_key", func(t *testing.T) {
		params := UnwrapKeyParams{
			WrappingPublicKey: "some-key",
			Algorithm:         "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleUnwrapKey(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "wrapped_key is required")
	})

	t.Run("fails with missing wrapping_public_key", func(t *testing.T) {
		params := UnwrapKeyParams{
			WrappedKey: []byte("some-wrapped-data"),
			Algorithm:  "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleUnwrapKey(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "wrapping_public_key is required")
	})

	t.Run("fails with missing algorithm", func(t *testing.T) {
		params := UnwrapKeyParams{
			WrappedKey:        []byte("some-wrapped-data"),
			WrappingPublicKey: "some-key",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleUnwrapKey(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm is required")
	})

	t.Run("fails with invalid wrapping public key PEM", func(t *testing.T) {
		params := UnwrapKeyParams{
			WrappedKey:        []byte("some-wrapped-data"),
			WrappingPublicKey: "not a valid PEM",
			Algorithm:         "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleUnwrapKey(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid wrapping public key PEM")
	})

	t.Run("fails with malformed public key", func(t *testing.T) {
		// Create a valid PEM but with invalid key data
		invalidPEM := "-----BEGIN PUBLIC KEY-----\naW52YWxpZCBrZXkgZGF0YQ==\n-----END PUBLIC KEY-----"

		params := UnwrapKeyParams{
			WrappedKey:        []byte("some-wrapped-data"),
			WrappingPublicKey: invalidPEM,
			Algorithm:         "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleUnwrapKey(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse wrapping public key")
	})

	t.Run("fails with valid public key but unwrap error", func(t *testing.T) {
		// Generate a valid RSA key
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
		require.NoError(t, err)

		pubKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		})

		params := UnwrapKeyParams{
			WrappedKey:        []byte("invalid-wrapped-data"),
			WrappingPublicKey: string(pubKeyPEM),
			Algorithm:         "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.unwrapKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err = server.handleUnwrapKey(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unwrap key")
	})
}

// TestHandler_GetTLSCertificate_InvalidBackend tests the getTLSCertificate handler with invalid backend
func TestHandler_GetTLSCertificate_InvalidBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("fails with invalid backend", func(t *testing.T) {
		params := GetTLSCertificateParams{
			KeyID:   "test-key",
			Backend: "nonexistent",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.getTLSCertificate",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleGetTLSCertificate(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid backend")
	})
}

// TestHandler_RotateKey_InvalidBackend tests the rotateKey handler with invalid backend
func TestHandler_RotateKey_InvalidBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate a key first
	genParams := GenerateKeyParams{
		KeyID:   "test-rotate-invalid-backend",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
	require.NoError(t, err)

	t.Run("fails with invalid backend", func(t *testing.T) {
		params := RotateKeyParams{
			KeyID:   "test-rotate-invalid-backend",
			Backend: "nonexistent",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.rotateKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleRotateKey(context.Background(), req)
		require.Error(t, err)
		// The wording is the service layer's, shared with sign/verify/encrypt
		// in this package. It used to be a local "invalid backend: <name>"
		// produced by a types.ParseStoreType gate, which also rejected every
		// registered backend name that is not itself a store type. What is
		// under test is that an unregistered backend is refused rather than
		// quietly served by the default one.
		assert.Contains(t, err.Error(), "backend not found")
	})
}

// TestHandler_AsymmetricEncrypt_InvalidBackend tests the asymmetricEncrypt handler with invalid backend
func TestHandler_AsymmetricEncrypt_InvalidBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate an RSA key first
	genParams := GenerateKeyParams{
		KeyID:   "test-asym-enc-invalid-backend",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
	require.NoError(t, err)

	t.Run("fails with invalid backend", func(t *testing.T) {
		params := AsymmetricEncryptParams{
			KeyID:     "test-asym-enc-invalid-backend",
			Backend:   "nonexistent",
			Plaintext: []byte("secret"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.asymmetricEncrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleAsymmetricEncrypt(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid backend")
	})
}

// TestHandler_AsymmetricDecrypt_InvalidBackend tests the asymmetricDecrypt handler with invalid backend
func TestHandler_AsymmetricDecrypt_InvalidBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate an RSA key first
	genParams := GenerateKeyParams{
		KeyID:   "test-asym-dec-invalid-backend",
		Backend: "software",
		KeyType: "rsa", Algorithm: "rsa",
		KeySize: 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
	require.NoError(t, err)

	t.Run("fails with invalid backend", func(t *testing.T) {
		params := AsymmetricDecryptParams{
			KeyID:      "test-asym-dec-invalid-backend",
			Backend:    "nonexistent",
			Ciphertext: []byte("ciphertext"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.asymmetricDecrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleAsymmetricDecrypt(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid backend")
	})
}

// TestHandler_CopyKey_AdditionalErrors tests additional error paths in copyKey handler
func TestHandler_CopyKey_AdditionalErrors(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("fails with invalid source backend type", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "unknown-backend-type",
			SourceKeyID:   "test-key",
			DestBackend:   "software",
			DestKeyID:     "dest-key",
			Algorithm:     "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.copyKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleCopyKey(context.Background(), req)
		require.Error(t, err)
		assertCopyKeyBackendError(t, err, "source")
	})

	t.Run("fails with invalid dest backend type", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "software",
			SourceKeyID:   "test-key",
			DestBackend:   "unknown-backend-type",
			DestKeyID:     "dest-key",
			Algorithm:     "RSA_OAEP_SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.copyKey",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleCopyKey(context.Background(), req)
		require.Error(t, err)
		assertCopyKeyBackendError(t, err, "destination")
	})
}

// TestHandler_SaveCertChain_InvalidPEM tests additional error paths in saveCertChain handler
func TestHandler_SaveCertChain_InvalidPEM(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("fails with invalid PEM at middle index", func(t *testing.T) {
		// Generate a valid certificate
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "test-chain-cert"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
		}

		certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
		require.NoError(t, err)

		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})

		params := SaveCertChainParams{
			KeyID:     "test-chain-invalid-middle",
			ChainPEMs: []string{string(certPEM), "invalid-pem", string(certPEM)},
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.saveCertChain",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err = server.handleSaveCertChain(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse certificate at index 1")
	})

	t.Run("fails with malformed certificate data", func(t *testing.T) {
		// Create a PEM with invalid certificate data
		invalidCertPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("not a valid certificate"),
		})

		params := SaveCertChainParams{
			KeyID:     "test-chain-malformed",
			ChainPEMs: []string{string(invalidCertPEM)},
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.saveCertChain",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleSaveCertChain(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse certificate at index 0")
	})
}

// TestHandler_ListCerts_EmptyResult tests the listCerts handler with empty result
func TestHandler_ListCerts_EmptyResult(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("returns empty list when no certs exist", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.listCerts",
			ID:      1,
		}

		result, err := server.handleListCerts(context.Background(), req)
		require.NoError(t, err)

		listResult, ok := result.(ListCertsResult)
		require.True(t, ok)
		assert.NotNil(t, listResult.KeyIDs)
	})
}

// TestHandler_DeleteKey_SearchSymmetricBackend tests deleteKey searching symmetric backend
func TestHandler_DeleteKey_SearchSymmetricBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate a symmetric key
	genParams := GenerateKeyParams{
		KeyID:     "test-delete-sym-search",
		Backend:   "software",
		KeyType:   "symmetric",
		Algorithm: "aes256-gcm",
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
	require.NoError(t, err)

	t.Run("deletes key from symmetric backend without specifying backend", func(t *testing.T) {
		params := DeleteKeyParams{
			KeyID: "test-delete-sym-search",
			// No backend specified - should search
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.deleteKey",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleDeleteKey(context.Background(), req)
		require.NoError(t, err)

		deleteResult, ok := result.(map[string]interface{})
		require.True(t, ok)
		assert.True(t, deleteResult["success"].(bool))
	})
}

// TestHandler_Decrypt_SearchSymmetricBackend tests decrypt searching symmetric backend
func TestHandler_Decrypt_SearchSymmetricBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Generate a symmetric key and encrypt data
	genParams := GenerateKeyParams{
		KeyID:     "test-decrypt-sym-search",
		Backend:   "software",
		KeyType:   "symmetric",
		Algorithm: "aes256-gcm",
	}
	genParamsJSON, _ := json.Marshal(genParams)
	genReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genParamsJSON, ID: 1}
	_, err := server.handleGenerateKey(context.Background(), genReq)
	require.NoError(t, err)

	// Encrypt data
	encryptParams := EncryptParams{
		KeyID:     "test-decrypt-sym-search",
		Backend:   "software",
		Plaintext: []byte("secret data"),
	}
	encryptParamsJSON, _ := json.Marshal(encryptParams)
	encryptReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.encrypt", Params: encryptParamsJSON, ID: 1}
	encryptResult, err := server.handleEncrypt(context.Background(), encryptReq)
	require.NoError(t, err)

	encResult := encryptResult.(EncryptResult)

	t.Run("decrypts without specifying backend - searches backends", func(t *testing.T) {
		params := DecryptParams{
			KeyID:        "test-decrypt-sym-search",
			Ciphertext:   encResult.Ciphertext,
			Nonce:        encResult.Nonce,
			Tag:          encResult.Tag,
			GCMNonceMode: encResult.GCMNonceMode,
			// No backend specified - should search
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.decrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		result, err := server.handleDecrypt(context.Background(), req)
		require.NoError(t, err)

		decResult, ok := result.(DecryptResult)
		require.True(t, ok)
		assert.Equal(t, []byte("secret data"), decResult.Plaintext)
	})
}

// TestHandler_Decrypt_NotFoundInAnyBackend tests decrypt when key not found in any backend
func TestHandler_Decrypt_NotFoundInAnyBackend(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	t.Run("fails when key not found in any backend", func(t *testing.T) {
		params := DecryptParams{
			KeyID:      "non-existent-key-for-decrypt",
			Ciphertext: []byte("some ciphertext"),
			Nonce:      []byte("some nonce"),
			// No backend specified
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.decrypt",
			Params:  paramsJSON,
			ID:      1,
		}

		_, err := server.handleDecrypt(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key not found")
	})
}
