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
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestXKMS initializes the xkms service for tests and returns it.
// Callers must pass the returned service into Config.XKMSService when
// constructing a Server, since NewServer requires an injected service.
func setupTestXKMS(t *testing.T) *xkms.XKMSService {
	t.Helper()

	// Reset any previous state
	xkms.Reset()

	// Create in-memory storage
	keyStorage := storage.New()
	certStorage := storage.New()

	// Create software backend
	backend, err := software.NewBackend(&software.Config{
		KeyStorage: keyStorage,
	})
	require.NoError(t, err)

	// Create keystore
	ks, err := xkms.New(&xkms.BackendConfig{
		Backend:     backend,
		CertStorage: certStorage,
	})
	require.NoError(t, err)

	// Initialize the xkms service with software backend as default
	err = xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software":  ks,
			"symmetric": ks, // Use same backend for symmetric tests
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	svc, err := xkms.Get()
	require.NoError(t, err)
	return svc
}

// cleanupXKMS resets the xkms after tests
func cleanupXKMS() {
	xkms.Reset()
}

func TestNewServer_Success(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	config := &Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		XKMSService:   svc,
	}

	server, err := NewServer(config)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.NotNil(t, server.authenticator)
	assert.NotNil(t, server.logger)
}

func TestNewServer_WithAuthenticator(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	authenticator := auth.NewNoOpAuthenticator()
	config := &Config{
		Authenticator: authenticator,
		XKMSService:   svc,
	}

	server, err := NewServer(config)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.Equal(t, "noop", server.authenticator.Name())
}

func TestNewServer_NotInitialized(t *testing.T) {
	// Ensure xkms is not initialized
	xkms.Reset()

	config := &Config{
		Authenticator: auth.NewNoOpAuthenticator(),
	}

	_, err := NewServer(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "xkms service is required")
}

func TestServer_HandleRequest_MethodNotFound(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "unknown.method",
		ID:      1,
	}

	resp := invokeRequest(server, context.Background(), req)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeMethodNotFound, resp.Error.Code)
}

func TestServer_RouteFrostMethods_NonFrostMethod(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.health",
		ID:      1,
	}

	_, _, handled := server.routeFrostMethods(context.Background(), req)
	assert.False(t, handled) // Non-frost method should not be handled by frost router
}

// TestServer_HandleRequest_AllMethods tests that InvokeMethod routes to various handlers
func TestServer_HandleRequest_AllMethods(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	ctx := context.Background()

	// Test xkms.listBackends through InvokeMethod
	t.Run("routes xkms.listBackends", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.listBackends",
			ID:      1,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
		assert.NotNil(t, resp.Result)
	})

	// Test xkms.listKeys through InvokeMethod
	t.Run("routes xkms.listKeys", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.listKeys",
			ID:      2,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	// Test xkms.listCerts through InvokeMethod
	t.Run("routes xkms.listCerts", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.listCerts",
			ID:      3,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	// Test with error from handler through InvokeMethod
	t.Run("returns error from handler", func(t *testing.T) {
		params := map[string]string{} // Missing required params
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.generateKey",
			Params:  paramsJSON,
			ID:      4,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
		assert.Equal(t, ErrCodeInternalError, resp.Error.Code)
	})
}

// TestServer_HandleRequest_MoreMethods tests additional method routing
func TestServer_HandleRequest_MoreMethods(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	ctx := context.Background()

	// First generate a key to use in subsequent tests
	genParams := map[string]interface{}{
		"key_id":   "test-req-key",
		"backend":  "software",
		"key_type": "rsa",
		"key_size": 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)

	genReq := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.generateKey",
		Params:  genParamsJSON,
		ID:      1,
	}

	resp := invokeRequest(server, ctx, genReq)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)

	// Test xkms.getKey through InvokeMethod
	t.Run("routes xkms.getKey", func(t *testing.T) {
		params := map[string]string{
			"key_id":  "test-req-key",
			"backend": "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.getKey",
			Params:  paramsJSON,
			ID:      2,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	// Test xkms.sign through InvokeMethod
	t.Run("routes xkms.sign", func(t *testing.T) {
		params := SignParams{
			KeyID:   "test-req-key",
			Backend: "software",
			Data:    []byte("test data"),
			Hash:    "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.sign",
			Params:  paramsJSON,
			ID:      3,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	// Test xkms.deleteKey through InvokeMethod
	t.Run("routes xkms.deleteKey", func(t *testing.T) {
		// First generate a key to delete
		delParams := map[string]interface{}{
			"key_id":   "test-delete-req-key",
			"backend":  "software",
			"key_type": "rsa",
			"key_size": 2048,
		}
		delParamsJSON, _ := json.Marshal(delParams)

		genReq := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.generateKey",
			Params:  delParamsJSON,
			ID:      10,
		}
		invokeRequest(server, ctx, genReq)

		params := map[string]string{
			"key_id":  "test-delete-req-key",
			"backend": "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.deleteKey",
			Params:  paramsJSON,
			ID:      4,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})
}

// TestServer_HandleRequest_EncryptDecrypt tests encrypt/decrypt routing
func TestServer_HandleRequest_EncryptDecrypt(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	ctx := context.Background()

	// Generate a symmetric key first
	genParams := map[string]interface{}{
		"key_id":    "test-sym-req-key",
		"backend":   "software",
		"key_type":  "symmetric",
		"algorithm": "aes256-gcm",
	}
	genParamsJSON, _ := json.Marshal(genParams)

	genReq := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.generateKey",
		Params:  genParamsJSON,
		ID:      1,
	}

	resp := invokeRequest(server, ctx, genReq)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)

	t.Run("routes xkms.encrypt", func(t *testing.T) {
		params := EncryptParams{
			KeyID:     "test-sym-req-key",
			Backend:   "software",
			Plaintext: []byte("secret data"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.encrypt",
			Params:  paramsJSON,
			ID:      2,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})
}

// TestServer_HandleRequest_AsymmetricOps tests asymmetric operations routing
func TestServer_HandleRequest_AsymmetricOps(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	ctx := context.Background()

	// Generate an RSA key first
	genParams := map[string]interface{}{
		"key_id":   "test-asym-req-key",
		"backend":  "software",
		"key_type": "rsa",
		"key_size": 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)

	genReq := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.generateKey",
		Params:  genParamsJSON,
		ID:      1,
	}

	resp := invokeRequest(server, ctx, genReq)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)

	t.Run("routes xkms.asymmetricEncrypt", func(t *testing.T) {
		params := AsymmetricEncryptParams{
			KeyID:     "test-asym-req-key",
			Backend:   "software",
			Plaintext: []byte("secret data"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.asymmetricEncrypt",
			Params:  paramsJSON,
			ID:      2,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	t.Run("routes xkms.rotateKey", func(t *testing.T) {
		params := RotateKeyParams{
			KeyID:   "test-asym-req-key",
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.rotateKey",
			Params:  paramsJSON,
			ID:      3,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})
}

// TestServer_HandleRequest_CertOps tests certificate operations routing
func TestServer_HandleRequest_CertOps(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a test certificate
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	t.Run("routes xkms.saveCert", func(t *testing.T) {
		params := SaveCertParams{
			KeyID:   "test-cert-req",
			CertPEM: string(certPEM),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.saveCert",
			Params:  paramsJSON,
			ID:      1,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	t.Run("routes xkms.getCert", func(t *testing.T) {
		params := GetCertParams{KeyID: "test-cert-req"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.getCert",
			Params:  paramsJSON,
			ID:      2,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	t.Run("routes xkms.certExists", func(t *testing.T) {
		params := CertExistsParams{KeyID: "test-cert-req"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.certExists",
			Params:  paramsJSON,
			ID:      3,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	t.Run("routes xkms.deleteCert", func(t *testing.T) {
		params := DeleteCertParams{KeyID: "test-cert-req"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.deleteCert",
			Params:  paramsJSON,
			ID:      4,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})
}

// TestServer_HandleRequest_VerifyRoute tests verify method routing
func TestServer_HandleRequest_VerifyRoute(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	ctx := context.Background()

	// Generate an RSA key first
	genParams := map[string]interface{}{
		"key_id":   "test-verify-route-key",
		"backend":  "software",
		"key_type": "rsa",
		"key_size": 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)

	genReq := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.generateKey",
		Params:  genParamsJSON,
		ID:      1,
	}

	resp := invokeRequest(server, ctx, genReq)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)

	// Sign data
	signParams := SignParams{
		KeyID:   "test-verify-route-key",
		Backend: "software",
		Data:    []byte("data to sign"),
		Hash:    "SHA256",
	}
	signParamsJSON, _ := json.Marshal(signParams)
	signReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.sign", Params: signParamsJSON, ID: 2}
	signResp := invokeRequest(server, ctx, signReq)
	require.NotNil(t, signResp)
	require.Nil(t, signResp.Error)

	signResult := signResp.Result.(SignResult)

	t.Run("routes xkms.verify", func(t *testing.T) {
		params := VerifyParams{
			KeyID:     "test-verify-route-key",
			Backend:   "software",
			Data:      []byte("data to sign"),
			Signature: signResult.Signature,
			Hash:      "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.verify",
			Params:  paramsJSON,
			ID:      3,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})
}

// TestServer_HandleRequest_DecryptRoute tests decrypt method routing
func TestServer_HandleRequest_DecryptRoute(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	ctx := context.Background()

	// Generate a symmetric key
	genParams := map[string]interface{}{
		"key_id":    "test-decrypt-route-key",
		"backend":   "software",
		"key_type":  "symmetric",
		"algorithm": "aes256-gcm",
	}
	genParamsJSON, _ := json.Marshal(genParams)

	genReq := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.generateKey",
		Params:  genParamsJSON,
		ID:      1,
	}

	resp := invokeRequest(server, ctx, genReq)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)

	// Encrypt data
	encryptParams := EncryptParams{
		KeyID:     "test-decrypt-route-key",
		Backend:   "software",
		Plaintext: []byte("secret data"),
	}
	encryptParamsJSON, _ := json.Marshal(encryptParams)
	encryptReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.encrypt", Params: encryptParamsJSON, ID: 2}
	encryptResp := invokeRequest(server, ctx, encryptReq)
	require.NotNil(t, encryptResp)
	require.Nil(t, encryptResp.Error)

	encResult := encryptResp.Result.(EncryptResult)

	t.Run("routes xkms.decrypt", func(t *testing.T) {
		params := DecryptParams{
			KeyID:      "test-decrypt-route-key",
			Backend:    "software",
			Ciphertext: encResult.Ciphertext,
			Nonce:      encResult.Nonce,
			Tag:        encResult.Tag,
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.decrypt",
			Params:  paramsJSON,
			ID:      3,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})
}

// TestServer_HandleRequest_AsymmetricDecryptRoute tests asymmetric decrypt method routing
func TestServer_HandleRequest_AsymmetricDecryptRoute(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	ctx := context.Background()

	// Generate an RSA key
	genParams := map[string]interface{}{
		"key_id":   "test-asym-dec-route-key",
		"backend":  "software",
		"key_type": "rsa",
		"key_size": 2048,
	}
	genParamsJSON, _ := json.Marshal(genParams)

	genReq := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.generateKey",
		Params:  genParamsJSON,
		ID:      1,
	}

	resp := invokeRequest(server, ctx, genReq)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)

	// Get signer to get public key for encryption
	attrs, err := server.findKeyByCN(context.Background(), "test-asym-dec-route-key")
	require.NoError(t, err)

	signer, err := server.keystore.Signer(context.Background(), attrs)
	require.NoError(t, err)

	rsaPubKey, ok := signer.Public().(*rsa.PublicKey)
	require.True(t, ok)

	// Encrypt using standard PKCS1v15 which matches the decrypt path
	plaintext := []byte("asymmetric secret")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPubKey, plaintext, nil)
	require.NoError(t, err)

	t.Run("routes xkms.asymmetricDecrypt", func(t *testing.T) {
		params := AsymmetricDecryptParams{
			KeyID:      "test-asym-dec-route-key",
			Backend:    "software",
			Ciphertext: ciphertext,
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.asymmetricDecrypt",
			Params:  paramsJSON,
			ID:      3,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})
}

// TestServer_HandleRequest_ImportExportRoutes tests import/export method routing
func TestServer_HandleRequest_ImportExportRoutes(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("routes xkms.getImportParameters", func(t *testing.T) {
		params := GetImportParametersParams{
			KeyID:     "test-import-route-key",
			Backend:   "software",
			Algorithm: "RSAES_OAEP_SHA_256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.getImportParameters",
			Params:  paramsJSON,
			ID:      1,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	t.Run("routes xkms.wrapKey with invalid data", func(t *testing.T) {
		params := WrapKeyParams{
			KeyMaterial:          []byte("key"),
			WrappingPublicKeyPEM: "invalid",
			Algorithm:            "RSAES_OAEP_SHA_256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.wrapKey",
			Params:  paramsJSON,
			ID:      2,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
	})

	t.Run("routes xkms.importKey with invalid data", func(t *testing.T) {
		params := ImportKeyParams{
			KeyID:      "test-import",
			Backend:    "software",
			WrappedKey: []byte("invalid"),
			Algorithm:  "RSAES_OAEP_SHA_256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.importKey",
			Params:  paramsJSON,
			ID:      3,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
	})

	t.Run("routes xkms.exportKey with non-existent key", func(t *testing.T) {
		params := ExportKeyParams{
			KeyID:     "non-existent-export-route",
			Backend:   "software",
			Algorithm: "RSAES_OAEP_SHA_256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.exportKey",
			Params:  paramsJSON,
			ID:      4,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
	})

	t.Run("routes xkms.copyKey with missing params", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "software",
			// Missing other required params
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.copyKey",
			Params:  paramsJSON,
			ID:      5,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
	})
}

// TestServer_HandleRequest_CertChainRoutes tests certificate chain method routing
func TestServer_HandleRequest_CertChainRoutes(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	ctx := context.Background()

	// Create a test certificate
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	t.Run("routes xkms.saveCertChain", func(t *testing.T) {
		params := SaveCertChainParams{
			KeyID:     "test-chain-route",
			ChainPEMs: []string{string(certPEM)},
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.saveCertChain",
			Params:  paramsJSON,
			ID:      1,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	t.Run("routes xkms.getCertChain", func(t *testing.T) {
		params := GetCertChainParams{KeyID: "test-chain-route"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.getCertChain",
			Params:  paramsJSON,
			ID:      2,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	t.Run("routes xkms.getTLSCertificate with missing key", func(t *testing.T) {
		params := GetTLSCertificateParams{
			KeyID:   "non-existent-tls-key",
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "xkms.getTLSCertificate",
			Params:  paramsJSON,
			ID:      3,
		}

		resp := invokeRequest(server, ctx, req)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
	})
}

// TestServer_StopWithoutStart proves Stop is safe to call on a server that
// never dispatched a request -- the only shape a *Server can have now that
// there is no listener to have started.
func TestServer_StopWithoutStart(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	err = server.Stop()
	require.NoError(t, err)
}

// TestServer_HandleRequest_FrostMethodWithError tests FROST method that returns error
func TestServer_HandleRequest_FrostMethodWithError(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	ctx := context.Background()

	// Test a FROST method that should return an error (when FROST is not compiled in)
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "frost.generateNonces",
		ID:      1,
	}

	resp := invokeRequest(server, ctx, req)
	require.NotNil(t, resp)
	assert.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeInternalError, resp.Error.Code)
}

// TestServer_HandleRequest_WithAuthenticatedIdentity tests request with identity in context
func TestServer_HandleRequest_WithAuthenticatedIdentity(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)

	// Create context with identity
	identity := &auth.Identity{
		Subject: "test-user",
	}
	ctx := auth.WithIdentity(context.Background(), identity)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "health",
		ID:      1,
	}

	resp := invokeRequest(server, ctx, req)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)
}
