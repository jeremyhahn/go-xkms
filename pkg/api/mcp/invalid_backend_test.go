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
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// invalidBackendHandlers are the five handlers that refuse a backend the
// service does not resolve before calling it, each with params that reach
// that check.
func invalidBackendHandlers(t *testing.T, server *Server) map[string]func(context.Context, *JSONRPCRequest) (interface{}, error) {
	t.Helper()
	// The asymmetric handlers look the key up before the backend check.
	genParams := GenerateKeyParams{KeyID: "invalid-backend-rsa", Algorithm: "RSA", KeySize: 2048}
	genJSON, err := json.Marshal(genParams)
	require.NoError(t, err)
	_, err = server.handleGenerateKey(context.Background(), &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.generateKey", Params: genJSON, ID: 1})
	require.NoError(t, err)

	return map[string]func(context.Context, *JSONRPCRequest) (interface{}, error){
		"xkms.getTLSCertificate":   server.handleGetTLSCertificate,
		"xkms.getImportParameters": server.handleGetImportParameters,
		"xkms.importKeyMaterial":   server.handleImportKeyMaterial,
		"xkms.asymmetricEncrypt":   server.handleAsymmetricEncrypt,
		"xkms.asymmetricDecrypt":   server.handleAsymmetricDecrypt,
	}
}

// backendRequest builds the one request shape every handler under test
// accepts, naming backend.
func backendRequest(t *testing.T, method, backend string) *JSONRPCRequest {
	t.Helper()
	paramsJSON, err := json.Marshal(map[string]any{
		"key_id":     "invalid-backend-rsa",
		"backend":    backend,
		"plaintext":  []byte("data"),
		"ciphertext": []byte("data"),
	})
	require.NoError(t, err)
	return &JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: paramsJSON, ID: 1}
}

// TestInvalidBackendRefusal_IsClassifiableAtEverySite proves that every
// "invalid backend" refusal on this transport is one typed error: errors.Is
// finds ErrInvalidBackend and, beneath it, the service's own reason; the
// JSON-RPC code is invalid-params; the message keeps the prefix a caller
// already matched on and names the backend (#176).
func TestInvalidBackendRefusal_IsClassifiableAtEverySite(t *testing.T) {
	server := createTestServer(t)
	for method, handler := range invalidBackendHandlers(t, server) {
		t.Run(method, func(t *testing.T) {
			_, err := handler(context.Background(), backendRequest(t, method, "nonexistent-backend-xyz"))
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidBackend), "%s: %v is not ErrInvalidBackend", method, err)
			assert.True(t, errors.Is(err, xkms.ErrBackendNotFound), "%s: the service's reason must be reachable: %v", method, err)
			var keyOp *KeyOpError
			require.True(t, errors.As(err, &keyOp), "%s: %T is not a KeyOpError", method, err)
			assert.Equal(t, ErrCodeInvalidParams, keyOp.Code)
			assert.True(t, strings.HasPrefix(err.Error(), "invalid backend: nonexistent-backend-xyz"), err.Error())
		})
	}
}

// TestInvalidBackendRefusal_ANameThatFailsValidationIsAlsoClassifiable proves
// that a spelling the service's name validation rejects (upper case, which
// types.ParseStoreType used to normalise away) is the same refusal, with the
// validation error as its cause: one mechanism decides, at every site.
func TestInvalidBackendRefusal_ANameThatFailsValidationIsAlsoClassifiable(t *testing.T) {
	server := createTestServer(t)
	for method, handler := range invalidBackendHandlers(t, server) {
		t.Run(method, func(t *testing.T) {
			_, err := handler(context.Background(), backendRequest(t, method, "SOFTWARE"))
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidBackend), "%s: %v", method, err)
			var validation *xkms.ErrBackendNameValidation
			assert.True(t, errors.As(err, &validation), "%s: the validation cause must be reachable: %v", method, err)
		})
	}
}

// TestInvalidBackendRefusal_ARegisteredNameThatIsNotAStoreTypeIsAccepted is
// the positive control: the fixture registers "symmetric", a backend name
// that is not a store-type keyword. Every handler must let it through to the
// service (whatever the operation then does), never refuse it as invalid,
// and the service must resolve it rather than report it missing.
func TestInvalidBackendRefusal_ARegisteredNameThatIsNotAStoreTypeIsAccepted(t *testing.T) {
	server := createTestServer(t)
	for method, handler := range invalidBackendHandlers(t, server) {
		t.Run(method, func(t *testing.T) {
			_, err := handler(context.Background(), backendRequest(t, method, "symmetric"))
			if err != nil {
				assert.False(t, errors.Is(err, ErrInvalidBackend), "%s refused a registered backend: %v", method, err)
				assert.False(t, errors.Is(err, xkms.ErrBackendNotFound), "%s did not resolve a registered backend: %v", method, err)
			}
		})
	}
}

// TestInvalidBackendRefusal_KnownBackendIsNotRefused proves the sentinel is
// not raised for the default backend's name either.
func TestInvalidBackendRefusal_KnownBackendIsNotRefused(t *testing.T) {
	server := createTestServer(t)
	for method, handler := range invalidBackendHandlers(t, server) {
		t.Run(method, func(t *testing.T) {
			_, err := handler(context.Background(), backendRequest(t, method, "software"))
			if err != nil {
				assert.False(t, errors.Is(err, ErrInvalidBackend), "%s refused a known backend: %v", method, err)
			}
		})
	}
}
