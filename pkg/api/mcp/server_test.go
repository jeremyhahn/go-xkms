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
	"encoding/json"
	"testing"

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
	wireKeyVersionStore(t)
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
