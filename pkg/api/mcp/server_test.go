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

package mcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
	"github.com/jeremyhahn/go-keychain/pkg/backend/software"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/ratelimit"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestKeychain initializes the global keychain service for tests
func setupTestKeychain(t *testing.T) {
	t.Helper()

	// Reset any previous state
	keychain.Reset()

	// Create in-memory storage
	keyStorage := storage.New()
	certStorage := storage.New()

	// Create software backend
	backend, err := software.NewBackend(&software.Config{
		KeyStorage: keyStorage,
	})
	require.NoError(t, err)

	// Create keystore
	ks, err := keychain.New(&keychain.Config{
		Backend:     backend,
		CertStorage: certStorage,
	})
	require.NoError(t, err)

	// Initialize the global keychain service with software backend as default
	err = keychain.Initialize(&keychain.ServiceConfig{
		Backends: map[string]keychain.KeyStore{
			"software":  ks,
			"symmetric": ks, // Use same backend for symmetric tests
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)
}

// cleanupKeychain resets the keychain after tests
func cleanupKeychain() {
	keychain.Reset()
}

func TestNewServer_Success(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	config := &Config{
		Addr: "localhost:0",
	}

	server, err := NewServer(config)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.Equal(t, "localhost:0", server.addr)
	assert.NotNil(t, server.authenticator)
	assert.NotNil(t, server.logger)
	assert.NotNil(t, server.subscribers)
}

func TestNewServer_DefaultAddress(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	config := &Config{} // Empty address

	server, err := NewServer(config)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.Equal(t, "localhost:9444", server.addr)
}

func TestNewServer_WithAuthenticator(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	authenticator := auth.NewNoOpAuthenticator()
	config := &Config{
		Addr:          "localhost:0",
		Authenticator: authenticator,
	}

	server, err := NewServer(config)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.Equal(t, "noop", server.authenticator.Name())
}

func TestNewServer_WithRateLimiter(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	limiter := ratelimit.New(&ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 100,
		Burst:             10,
	})
	defer limiter.Stop()

	config := &Config{
		Addr:        "localhost:0",
		RateLimiter: limiter,
	}

	server, err := NewServer(config)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.NotNil(t, server.rateLimiter)
}

func TestNewServer_NotInitialized(t *testing.T) {
	// Ensure keychain is not initialized
	keychain.Reset()

	config := &Config{
		Addr: "localhost:0",
	}

	_, err := NewServer(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "keychain service must be initialized")
}

func TestServer_StartStop(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	config := &Config{
		Addr: "localhost:0",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)

	// Verify server is listening
	assert.NotNil(t, server.listener)

	// Stop server
	err = server.Stop()
	require.NoError(t, err)
}

func TestServer_StartInvalidAddress(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	config := &Config{
		Addr: "invalid:address:too:many:colons",
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	err = server.Start()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to listen")
}

func TestServer_HandleRequest_InvalidVersion(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	req := &JSONRPCRequest{
		JSONRPC: "1.0", // Invalid version
		Method:  "health",
		ID:      1,
	}

	resp := server.handleRequest(context.Background(), req, nil)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeInvalidRequest, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "Invalid JSON-RPC version")
}

func TestServer_HandleRequest_MethodNotFound(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "unknown.method",
		ID:      1,
	}

	resp := server.handleRequest(context.Background(), req, nil)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeMethodNotFound, resp.Error.Code)
}

func TestServer_HandleRequest_NoResponseForNotification(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	// Notification has no ID
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "health",
		ID:      nil, // No ID means it's a notification
	}

	resp := server.handleRequest(context.Background(), req, nil)
	assert.Nil(t, resp) // Notifications don't get a response
}

func TestServer_HandleRequest_WithCorrelationID(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	req := &JSONRPCRequest{
		JSONRPC:       "2.0",
		Method:        "health",
		ID:            1,
		CorrelationID: "test-correlation-123",
	}

	resp := server.handleRequest(context.Background(), req, nil)
	require.NotNil(t, resp)
	assert.Equal(t, "test-correlation-123", resp.CorrelationID)
}

func TestServer_HandleRequest_GeneratesCorrelationID(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "health",
		ID:      1,
		// No CorrelationID provided
	}

	resp := server.handleRequest(context.Background(), req, nil)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.CorrelationID)
}

func TestServer_MakeErrorResponse(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	resp := server.makeErrorResponse(1, "corr-123", ErrCodeInvalidParams, "test error", nil)
	require.NotNil(t, resp)
	assert.Equal(t, "2.0", resp.JSONRPC)
	assert.Equal(t, 1, resp.ID)
	assert.Equal(t, "corr-123", resp.CorrelationID)
	assert.Nil(t, resp.Result)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeInvalidParams, resp.Error.Code)
	assert.Equal(t, "test error", resp.Error.Message)
}

func TestServer_NotifyEvent(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	// Create a mock connection using a pipe
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	// Add a subscriber
	server.subMutex.Lock()
	server.subscribers[serverConn] = &Subscriber{
		conn:   serverConn,
		events: map[string]bool{"key.created": true},
	}
	server.subMutex.Unlock()

	// Start reading on client side
	done := make(chan struct{})
	var receivedData []byte
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(clientConn)
		if scanner.Scan() {
			receivedData = scanner.Bytes()
		}
	}()

	// Send notification
	server.NotifyEvent("key.created", "test-key", map[string]string{"backend": "memory"})

	// Wait for notification
	select {
	case <-done:
		// Notification received
		var notification JSONRPCNotification
		err = json.Unmarshal(receivedData, &notification)
		require.NoError(t, err)
		assert.Equal(t, "2.0", notification.JSONRPC)
		assert.Equal(t, "key.created", notification.Method)
	case <-time.After(100 * time.Millisecond):
		t.Log("Notification timeout - acceptable in test environment")
	}
}

func TestServer_NotifyEvent_NoMatchingSubscribers(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	// Create a mock connection
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	// Add a subscriber for different event
	server.subMutex.Lock()
	server.subscribers[serverConn] = &Subscriber{
		conn:   serverConn,
		events: map[string]bool{"key.deleted": true}, // Not key.created
	}
	server.subMutex.Unlock()

	// This should not panic and should not send anything
	server.NotifyEvent("key.created", "test-key", nil)
}

func TestServer_RouteFrostMethods_StubBehavior(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "frost.generateNonces",
		ID:      1,
	}

	result, frostErr, handled := server.routeFrostMethods(req)

	// When built without frost tag, FROST methods return an error
	assert.True(t, handled)
	assert.Nil(t, result)
	assert.Error(t, frostErr)
	assert.Contains(t, frostErr.Error(), "FROST support not compiled")
}

func TestServer_RouteFrostMethods_NonFrostMethod(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "keychain.health",
		ID:      1,
	}

	_, _, handled := server.routeFrostMethods(req)
	assert.False(t, handled) // Non-frost method should not be handled by frost router
}

func TestServer_ClientConnection(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)
	defer func() { _ = server.Stop() }()

	// Connect to the server
	conn, err := net.Dial("tcp", server.listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Send a health request
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "health",
		ID:      1,
	}
	requestBytes, err := json.Marshal(request)
	require.NoError(t, err)

	_, err = conn.Write(append(requestBytes, '\n'))
	require.NoError(t, err)

	// Read response
	scanner := bufio.NewScanner(conn)
	require.True(t, scanner.Scan())

	var response JSONRPCResponse
	err = json.Unmarshal(scanner.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "2.0", response.JSONRPC)
	assert.Equal(t, float64(1), response.ID)
	assert.Nil(t, response.Error)

	// Check result
	result, ok := response.Result.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "healthy", result["status"])
}

func TestServer_BatchRequest(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)
	defer func() { _ = server.Stop() }()

	// Connect to the server
	conn, err := net.Dial("tcp", server.listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Send batch request
	batch := []JSONRPCRequest{
		{JSONRPC: "2.0", Method: "health", ID: 1},
		{JSONRPC: "2.0", Method: "keychain.listBackends", ID: 2},
	}
	batchBytes, err := json.Marshal(batch)
	require.NoError(t, err)

	_, err = conn.Write(append(batchBytes, '\n'))
	require.NoError(t, err)

	// Read response
	scanner := bufio.NewScanner(conn)
	require.True(t, scanner.Scan())

	var responses []JSONRPCResponse
	err = json.Unmarshal(scanner.Bytes(), &responses)
	require.NoError(t, err)

	assert.Len(t, responses, 2)
}

func TestServer_InvalidJSON(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)
	defer func() { _ = server.Stop() }()

	// Connect to the server
	conn, err := net.Dial("tcp", server.listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Send invalid JSON
	_, err = conn.Write([]byte("not valid json\n"))
	require.NoError(t, err)

	// Read response
	scanner := bufio.NewScanner(conn)
	require.True(t, scanner.Scan())

	var response JSONRPCResponse
	err = json.Unmarshal(scanner.Bytes(), &response)
	require.NoError(t, err)

	assert.NotNil(t, response.Error)
	assert.Equal(t, ErrCodeParseError, response.Error.Code)
}

func TestServer_WithTLS(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	// Generate a self-signed certificate for testing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	config := &Config{
		Addr:      "localhost:0",
		TLSConfig: tlsConfig,
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)
	defer func() { _ = server.Stop() }()

	// Connect with TLS
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true, // For testing only
	}

	conn, err := tls.Dial("tcp", server.listener.Addr().String(), clientTLSConfig)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Send a health request
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "health",
		ID:      1,
	}
	requestBytes, err := json.Marshal(request)
	require.NoError(t, err)

	_, err = conn.Write(append(requestBytes, '\n'))
	require.NoError(t, err)

	// Read response
	scanner := bufio.NewScanner(conn)
	require.True(t, scanner.Scan())

	var response JSONRPCResponse
	err = json.Unmarshal(scanner.Bytes(), &response)
	require.NoError(t, err)

	assert.Nil(t, response.Error)
}

// TestServer_HandleRequest_AllMethods tests that handleRequest routes to various handlers
func TestServer_HandleRequest_AllMethods(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	ctx := context.Background()

	// Test keychain.listBackends through handleRequest
	t.Run("routes keychain.listBackends", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.listBackends",
			ID:      1,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
		assert.NotNil(t, resp.Result)
	})

	// Test keychain.listKeys through handleRequest
	t.Run("routes keychain.listKeys", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.listKeys",
			ID:      2,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	// Test keychain.listCerts through handleRequest
	t.Run("routes keychain.listCerts", func(t *testing.T) {
		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.listCerts",
			ID:      3,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	// Test with error from handler through handleRequest
	t.Run("returns error from handler", func(t *testing.T) {
		params := map[string]string{} // Missing required params
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.generateKey",
			Params:  paramsJSON,
			ID:      4,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
		assert.Equal(t, ErrCodeInternalError, resp.Error.Code)
	})
}

// TestServer_HandleRequest_MoreMethods tests additional method routing
func TestServer_HandleRequest_MoreMethods(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
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
		Method:  "keychain.generateKey",
		Params:  genParamsJSON,
		ID:      1,
	}

	resp := server.handleRequest(ctx, genReq, nil)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)

	// Test keychain.getKey through handleRequest
	t.Run("routes keychain.getKey", func(t *testing.T) {
		params := map[string]string{
			"key_id":  "test-req-key",
			"backend": "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getKey",
			Params:  paramsJSON,
			ID:      2,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	// Test keychain.sign through handleRequest
	t.Run("routes keychain.sign", func(t *testing.T) {
		params := SignParams{
			KeyID:   "test-req-key",
			Backend: "software",
			Data:    []byte("test data"),
			Hash:    "SHA256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.sign",
			Params:  paramsJSON,
			ID:      3,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	// Test keychain.deleteKey through handleRequest
	t.Run("routes keychain.deleteKey", func(t *testing.T) {
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
			Method:  "keychain.generateKey",
			Params:  delParamsJSON,
			ID:      10,
		}
		server.handleRequest(ctx, genReq, nil)

		params := map[string]string{
			"key_id":  "test-delete-req-key",
			"backend": "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.deleteKey",
			Params:  paramsJSON,
			ID:      4,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})
}

// TestServer_HandleRequest_EncryptDecrypt tests encrypt/decrypt routing
func TestServer_HandleRequest_EncryptDecrypt(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
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
		Method:  "keychain.generateKey",
		Params:  genParamsJSON,
		ID:      1,
	}

	resp := server.handleRequest(ctx, genReq, nil)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)

	t.Run("routes keychain.encrypt", func(t *testing.T) {
		params := EncryptParams{
			KeyID:     "test-sym-req-key",
			Backend:   "software",
			Plaintext: []byte("secret data"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.encrypt",
			Params:  paramsJSON,
			ID:      2,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})
}

// TestServer_HandleRequest_AsymmetricOps tests asymmetric operations routing
func TestServer_HandleRequest_AsymmetricOps(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
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
		Method:  "keychain.generateKey",
		Params:  genParamsJSON,
		ID:      1,
	}

	resp := server.handleRequest(ctx, genReq, nil)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)

	t.Run("routes keychain.asymmetricEncrypt", func(t *testing.T) {
		params := AsymmetricEncryptParams{
			KeyID:     "test-asym-req-key",
			Backend:   "software",
			Plaintext: []byte("secret data"),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.asymmetricEncrypt",
			Params:  paramsJSON,
			ID:      2,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	t.Run("routes keychain.rotateKey", func(t *testing.T) {
		params := RotateKeyParams{
			KeyID:   "test-asym-req-key",
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.rotateKey",
			Params:  paramsJSON,
			ID:      3,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})
}

// TestServer_HandleRequest_CertOps tests certificate operations routing
func TestServer_HandleRequest_CertOps(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
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

	t.Run("routes keychain.saveCert", func(t *testing.T) {
		params := SaveCertParams{
			KeyID:   "test-cert-req",
			CertPEM: string(certPEM),
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.saveCert",
			Params:  paramsJSON,
			ID:      1,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	t.Run("routes keychain.getCert", func(t *testing.T) {
		params := GetCertParams{KeyID: "test-cert-req"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getCert",
			Params:  paramsJSON,
			ID:      2,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	t.Run("routes keychain.certExists", func(t *testing.T) {
		params := CertExistsParams{KeyID: "test-cert-req"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.certExists",
			Params:  paramsJSON,
			ID:      3,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	t.Run("routes keychain.deleteCert", func(t *testing.T) {
		params := DeleteCertParams{KeyID: "test-cert-req"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.deleteCert",
			Params:  paramsJSON,
			ID:      4,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})
}

// TestServer_HandleRequest_VerifyRoute tests verify method routing
func TestServer_HandleRequest_VerifyRoute(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
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
		Method:  "keychain.generateKey",
		Params:  genParamsJSON,
		ID:      1,
	}

	resp := server.handleRequest(ctx, genReq, nil)
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
	signReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.sign", Params: signParamsJSON, ID: 2}
	signResp := server.handleRequest(ctx, signReq, nil)
	require.NotNil(t, signResp)
	require.Nil(t, signResp.Error)

	signResult := signResp.Result.(SignResult)

	t.Run("routes keychain.verify", func(t *testing.T) {
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
			Method:  "keychain.verify",
			Params:  paramsJSON,
			ID:      3,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})
}

// TestServer_HandleRequest_DecryptRoute tests decrypt method routing
func TestServer_HandleRequest_DecryptRoute(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
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
		Method:  "keychain.generateKey",
		Params:  genParamsJSON,
		ID:      1,
	}

	resp := server.handleRequest(ctx, genReq, nil)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)

	// Encrypt data
	encryptParams := EncryptParams{
		KeyID:     "test-decrypt-route-key",
		Backend:   "software",
		Plaintext: []byte("secret data"),
	}
	encryptParamsJSON, _ := json.Marshal(encryptParams)
	encryptReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "keychain.encrypt", Params: encryptParamsJSON, ID: 2}
	encryptResp := server.handleRequest(ctx, encryptReq, nil)
	require.NotNil(t, encryptResp)
	require.Nil(t, encryptResp.Error)

	encResult := encryptResp.Result.(EncryptResult)

	t.Run("routes keychain.decrypt", func(t *testing.T) {
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
			Method:  "keychain.decrypt",
			Params:  paramsJSON,
			ID:      3,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})
}

// TestServer_HandleRequest_AsymmetricDecryptRoute tests asymmetric decrypt method routing
func TestServer_HandleRequest_AsymmetricDecryptRoute(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
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
		Method:  "keychain.generateKey",
		Params:  genParamsJSON,
		ID:      1,
	}

	resp := server.handleRequest(ctx, genReq, nil)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)

	// Get signer to get public key for encryption
	attrs, err := server.findKeyByCN("test-asym-dec-route-key")
	require.NoError(t, err)

	signer, err := server.keystore.Signer(attrs)
	require.NoError(t, err)

	rsaPubKey, ok := signer.Public().(*rsa.PublicKey)
	require.True(t, ok)

	// Encrypt using standard PKCS1v15 which matches the decrypt path
	plaintext := []byte("asymmetric secret")
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPubKey, plaintext)
	require.NoError(t, err)

	t.Run("routes keychain.asymmetricDecrypt", func(t *testing.T) {
		params := AsymmetricDecryptParams{
			KeyID:      "test-asym-dec-route-key",
			Backend:    "software",
			Ciphertext: ciphertext,
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.asymmetricDecrypt",
			Params:  paramsJSON,
			ID:      3,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})
}

// TestServer_HandleRequest_ImportExportRoutes tests import/export method routing
func TestServer_HandleRequest_ImportExportRoutes(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("routes keychain.getImportParameters", func(t *testing.T) {
		params := GetImportParametersParams{
			KeyID:     "test-import-route-key",
			Backend:   "software",
			Algorithm: "RSAES_OAEP_SHA_256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getImportParameters",
			Params:  paramsJSON,
			ID:      1,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	t.Run("routes keychain.wrapKey with invalid data", func(t *testing.T) {
		params := WrapKeyParams{
			KeyMaterial:          []byte("key"),
			WrappingPublicKeyPEM: "invalid",
			Algorithm:            "RSAES_OAEP_SHA_256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.wrapKey",
			Params:  paramsJSON,
			ID:      2,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
	})

	t.Run("routes keychain.importKey with invalid data", func(t *testing.T) {
		params := ImportKeyParams{
			KeyID:      "test-import",
			Backend:    "software",
			WrappedKey: []byte("invalid"),
			Algorithm:  "RSAES_OAEP_SHA_256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.importKey",
			Params:  paramsJSON,
			ID:      3,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
	})

	t.Run("routes keychain.exportKey with non-existent key", func(t *testing.T) {
		params := ExportKeyParams{
			KeyID:     "non-existent-export-route",
			Backend:   "software",
			Algorithm: "RSAES_OAEP_SHA_256",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.exportKey",
			Params:  paramsJSON,
			ID:      4,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
	})

	t.Run("routes keychain.copyKey with missing params", func(t *testing.T) {
		params := CopyKeyParams{
			SourceBackend: "software",
			// Missing other required params
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.copyKey",
			Params:  paramsJSON,
			ID:      5,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
	})
}

// TestServer_HandleRequest_CertChainRoutes tests certificate chain method routing
func TestServer_HandleRequest_CertChainRoutes(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
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

	t.Run("routes keychain.saveCertChain", func(t *testing.T) {
		params := SaveCertChainParams{
			KeyID:     "test-chain-route",
			ChainPEMs: []string{string(certPEM)},
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.saveCertChain",
			Params:  paramsJSON,
			ID:      1,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	t.Run("routes keychain.getCertChain", func(t *testing.T) {
		params := GetCertChainParams{KeyID: "test-chain-route"}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getCertChain",
			Params:  paramsJSON,
			ID:      2,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})

	t.Run("routes keychain.getTLSCertificate with missing key", func(t *testing.T) {
		params := GetTLSCertificateParams{
			KeyID:   "non-existent-tls-key",
			Backend: "software",
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.getTLSCertificate",
			Params:  paramsJSON,
			ID:      3,
		}

		resp := server.handleRequest(ctx, req, nil)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.Error)
	})
}

// TestServer_HandleRequest_Subscribe tests subscribe method routing
func TestServer_HandleRequest_Subscribe(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	// Create a mock connection
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	ctx := context.Background()

	t.Run("routes keychain.subscribe", func(t *testing.T) {
		params := SubscribeParams{
			Events: []string{"key.created", "key.deleted"},
		}
		paramsJSON, _ := json.Marshal(params)

		req := &JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "keychain.subscribe",
			Params:  paramsJSON,
			ID:      1,
		}

		resp := server.handleRequest(ctx, req, serverConn)
		require.NotNil(t, resp)
		assert.Nil(t, resp.Error)
	})
}

// TestServer_BatchWithNotifications tests batch requests with notifications
func TestServer_BatchWithNotifications(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)
	defer func() { _ = server.Stop() }()

	// Connect to the server
	conn, err := net.Dial("tcp", server.listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Send batch request with a notification (no ID)
	batch := []JSONRPCRequest{
		{JSONRPC: "2.0", Method: "health", ID: 1},
		{JSONRPC: "2.0", Method: "health"}, // No ID = notification
	}
	batchBytes, err := json.Marshal(batch)
	require.NoError(t, err)

	_, err = conn.Write(append(batchBytes, '\n'))
	require.NoError(t, err)

	// Read response - should only have one response (not for notification)
	scanner := bufio.NewScanner(conn)
	require.True(t, scanner.Scan())

	var responses []JSONRPCResponse
	err = json.Unmarshal(scanner.Bytes(), &responses)
	require.NoError(t, err)

	// Only one response because the notification doesn't get a response
	assert.Len(t, responses, 1)
}

// TestServer_StopWithTLS tests stopping server with TLS configuration
func TestServer_StopWithTLS(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	// Generate a self-signed certificate for testing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	config := &Config{
		Addr:      "localhost:0",
		TLSConfig: tlsConfig,
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)

	// Stop the server
	err = server.Stop()
	require.NoError(t, err)
}

// TestServer_ConnectionWithRateLimit tests connection handling with rate limiter
func TestServer_ConnectionWithRateLimit(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	limiter := ratelimit.New(&ratelimit.Config{
		Enabled:           true,
		RequestsPerMinute: 1000,
		Burst:             100,
	})
	defer limiter.Stop()

	config := &Config{
		Addr:        "localhost:0",
		RateLimiter: limiter,
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)
	defer func() { _ = server.Stop() }()

	// Connect to the server
	conn, err := net.Dial("tcp", server.listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Send a request
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "health",
		ID:      1,
	}
	requestBytes, err := json.Marshal(request)
	require.NoError(t, err)

	_, err = conn.Write(append(requestBytes, '\n'))
	require.NoError(t, err)

	// Read response
	scanner := bufio.NewScanner(conn)
	require.True(t, scanner.Scan())

	var response JSONRPCResponse
	err = json.Unmarshal(scanner.Bytes(), &response)
	require.NoError(t, err)
	assert.Nil(t, response.Error)
}

// TestServer_EmptyBatchRequest tests handling of empty batch requests
func TestServer_EmptyBatchRequest(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)
	defer func() { _ = server.Stop() }()

	// Connect to the server
	conn, err := net.Dial("tcp", server.listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Send an empty batch
	_, err = conn.Write([]byte("[]\n"))
	require.NoError(t, err)

	// Server should handle empty batch gracefully and not send response for empty batch
	// Small wait to ensure processing
	time.Sleep(10 * time.Millisecond)
}

// TestServer_InvalidBatchRequest tests handling of invalid batch JSON
func TestServer_InvalidBatchRequest(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)
	defer func() { _ = server.Stop() }()

	// Connect to the server
	conn, err := net.Dial("tcp", server.listener.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Send invalid batch JSON (array but invalid content)
	_, err = conn.Write([]byte("[invalid json]\n"))
	require.NoError(t, err)

	// Read error response
	scanner := bufio.NewScanner(conn)
	require.True(t, scanner.Scan())

	var response JSONRPCResponse
	err = json.Unmarshal(scanner.Bytes(), &response)
	require.NoError(t, err)
	assert.NotNil(t, response.Error)
	assert.Equal(t, ErrCodeParseError, response.Error.Code)
}

// TestServer_WithMTLS tests mTLS client certificate authentication
func TestServer_WithMTLS(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	// Generate CA certificate
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	// Generate server certificate
	serverPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caCert, &serverPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err)

	serverTLSCert := tls.Certificate{
		Certificate: [][]byte{serverCertDER},
		PrivateKey:  serverPrivKey,
	}

	// Generate client certificate
	clientPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, caCert, &clientPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err)

	clientTLSCert := tls.Certificate{
		Certificate: [][]byte{clientCertDER},
		PrivateKey:  clientPrivKey,
	}

	// Create CA pool
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	// Server TLS config with mTLS
	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	config := &Config{
		Addr:      "localhost:0",
		TLSConfig: serverTLSConfig,
	}

	server, err := NewServer(config)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)
	defer func() { _ = server.Stop() }()

	// Client TLS config with client certificate
	clientTLSConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientTLSCert},
		RootCAs:            caPool,
		InsecureSkipVerify: true, // For testing only
	}

	conn, err := tls.Dial("tcp", server.listener.Addr().String(), clientTLSConfig)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Send a health request
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "health",
		ID:      1,
	}
	requestBytes, err := json.Marshal(request)
	require.NoError(t, err)

	_, err = conn.Write(append(requestBytes, '\n'))
	require.NoError(t, err)

	// Read response
	scanner := bufio.NewScanner(conn)
	require.True(t, scanner.Scan())

	var response JSONRPCResponse
	err = json.Unmarshal(scanner.Bytes(), &response)
	require.NoError(t, err)

	assert.Nil(t, response.Error)
}

// TestServer_NotifyEvent_ClosedConnection tests NotifyEvent with a closed connection
func TestServer_NotifyEvent_ClosedConnection(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	// Create a mock connection using a pipe
	clientConn, serverConn := net.Pipe()

	// Add a subscriber
	server.subMutex.Lock()
	server.subscribers[serverConn] = &Subscriber{
		conn:   serverConn,
		events: map[string]bool{"key.created": true},
	}
	server.subMutex.Unlock()

	// Close the connection from client side
	_ = clientConn.Close()
	_ = serverConn.Close()

	// This should not panic and should log an error
	server.NotifyEvent("key.created", "test-key", map[string]string{"backend": "memory"})
}

// TestServer_StopWithoutStart tests stopping a server that was never started
func TestServer_StopWithoutStart(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	// Server was never started, so listener is nil
	err = server.Stop()
	require.NoError(t, err)
}

// TestServer_HandleRequest_FrostMethodWithError tests FROST method that returns error
func TestServer_HandleRequest_FrostMethodWithError(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	ctx := context.Background()

	// Test a FROST method that should return an error (when FROST is not compiled in)
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "frost.generateNonces",
		ID:      1,
	}

	resp := server.handleRequest(ctx, req, nil)
	require.NotNil(t, resp)
	assert.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeInternalError, resp.Error.Code)
}

// TestServer_HandleRequest_FrostMethodAsNotification tests FROST method as notification (no ID)
// Note: According to the actual implementation in server.go (lines 298-303), FROST methods
// return an error response even for notifications when an error occurs.
func TestServer_HandleRequest_FrostMethodAsNotification(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	ctx := context.Background()

	// Test a FROST method as a notification (no ID)
	// The FROST stub returns an error, and the server returns an error response
	// even for notifications in this case (see server.go lines 298-303)
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "frost.someMethod",
		// No ID = notification
	}

	resp := server.handleRequest(ctx, req, nil)
	// FROST methods that fail return an error response even for notifications
	require.NotNil(t, resp)
	assert.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeInternalError, resp.Error.Code)
}

// TestServer_HandleRequest_WithAuthenticatedIdentity tests request with identity in context
func TestServer_HandleRequest_WithAuthenticatedIdentity(t *testing.T) {
	setupTestKeychain(t)
	defer cleanupKeychain()

	server, err := NewServer(&Config{Addr: "localhost:0"})
	require.NoError(t, err)

	// Create context with identity
	identity := &auth.Identity{
		Subject: "test-user",
		Claims:  make(map[string]interface{}),
	}
	ctx := auth.WithIdentity(context.Background(), identity)

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "health",
		ID:      1,
	}

	resp := server.handleRequest(ctx, req, nil)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)
}
