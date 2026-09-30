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

func TestHandleRequest_MethodNotFound(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "nonexistent.method",
		ID:      1,
	}

	resp := invokeRequest(server, ctx, req)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeMethodNotFound, resp.Error.Code)
}

func TestHandleRequest_HealthRoute(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "health",
		ID:      1,
	}

	resp := invokeRequest(server, ctx, req)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)
	assert.NotNil(t, resp.Result)
}

func TestHandleRequest_PasswordRoutes(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	passwordMethods := []string{
		"password.add",
		"password.get",
		"password.list",
		"password.update",
		"password.delete",
		"password.unlock",
		"password.lock",
		"password.status",
	}

	for _, method := range passwordMethods {
		t.Run(method, func(t *testing.T) {
			paramsJSON, _ := json.Marshal(map[string]string{"id": "test"})
			req := &JSONRPCRequest{
				JSONRPC: "2.0",
				Method:  method,
				Params:  paramsJSON,
				ID:      1,
			}

			resp := invokeRequest(server, ctx, req)
			require.NotNil(t, resp)
			if method == "password.status" {
				assert.Nil(t, resp.Error)
			} else {
				assert.NotNil(t, resp.Error)
			}
		})
	}
}

func TestHandleRequest_PasswordGenerate(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	params := map[string]int{"length": 16}
	paramsJSON, _ := json.Marshal(params)
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "password.generate",
		Params:  paramsJSON,
		ID:      1,
	}

	resp := invokeRequest(server, ctx, req)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)
	assert.NotNil(t, resp.Result)
}

func TestHandleRequest_InitRoutes(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	initMethods := []string{
		"init.getStatus",
		"init.claimCertBegin",
		"init.claimCertComplete",
		"init.claimShareBegin",
		"init.claimShareComplete",
		"init.signCSR",
		"credentials.submit",
		"credentials.strategy",
	}

	for _, method := range initMethods {
		t.Run(method, func(t *testing.T) {
			paramsJSON, _ := json.Marshal(map[string]string{"name": "test"})
			req := &JSONRPCRequest{
				JSONRPC: "2.0",
				Method:  method,
				Params:  paramsJSON,
				ID:      1,
			}

			resp := invokeRequest(server, ctx, req)
			require.NotNil(t, resp)
		})
	}
}

func TestHandleRequest_BarrierRoutes(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	barrierMethods := []string{
		"barrier.initialize",
		"barrier.initializeShamir",
		"barrier.unseal",
		"barrier.unsealShare",
		"barrier.unsealShares",
		"barrier.seal",
		"barrier.status",
		"barrier.rekey",
		"barrier.generateRecoveryKeys",
		"barrier.recoverWithKeys",
		"barrier.deleteRecoveryKeys",
		"barrier.hasRecoveryKeys",
		"barrier.generateRootToken",
	}

	for _, method := range barrierMethods {
		t.Run(method, func(t *testing.T) {
			paramsJSON, _ := json.Marshal(map[string]string{"secret": "test"})
			req := &JSONRPCRequest{
				JSONRPC: "2.0",
				Method:  method,
				Params:  paramsJSON,
				ID:      1,
			}

			resp := invokeRequest(server, ctx, req)
			require.NotNil(t, resp)
			assert.NotNil(t, resp.Error)
		})
	}
}

func TestHandleRequest_PIVRoutes(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	pivMethods := []string{
		"xkms.listPIVSlots",
		"xkms.getPIVCertificate",
		"xkms.storePIVCertificate",
		"xkms.deletePIVCertificate",
		"xkms.generatePIVKey",
		"xkms.importPIVCertificate",
		"xkms.exportPIVCertificate",
		"xkms.generatePIVCSR",
	}

	for _, method := range pivMethods {
		t.Run(method, func(t *testing.T) {
			paramsJSON, _ := json.Marshal(map[string]string{"backend": "software", "slot": "9a"})
			req := &JSONRPCRequest{
				JSONRPC: "2.0",
				Method:  method,
				Params:  paramsJSON,
				ID:      1,
			}

			resp := invokeRequest(server, ctx, req)
			require.NotNil(t, resp)
			assert.NotNil(t, resp.Error)
		})
	}
}

func TestHandleRequest_CARoutes(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	caMethods := []string{
		"xkms.ca.bundle",
		"xkms.ca.certificate",
		"xkms.ca.sign-csr",
		"xkms.ca.issue",
		"xkms.ca.revoke",
		"xkms.ca.crl",
		"xkms.ca.is-revoked",
		"xkms.ca.tcg.issue-ek",
		"xkms.ca.tcg.issue-ak",
		"xkms.ca.tcg.sign-csr",
		"xkms.ca.tcg.enroll",
	}

	for _, method := range caMethods {
		t.Run(method, func(t *testing.T) {
			paramsJSON, _ := json.Marshal(map[string]string{"pem": "test"})
			req := &JSONRPCRequest{
				JSONRPC: "2.0",
				Method:  method,
				Params:  paramsJSON,
				ID:      1,
			}

			resp := invokeRequest(server, ctx, req)
			require.NotNil(t, resp)
			assert.NotNil(t, resp.Error)
		})
	}
}

// TestHandleRequest_ErrorLogging pins go-xkms#774: malformed params report
// Invalid params (-32602), not Internal error (-32603). handleGenerateKey
// used to decode with a bare json.Unmarshal and return the failure as a
// plain *errs.Wrapped, which is not a *KeyOpError, so invokeRequest's
// errors.As never matched and every malformed xkms.generateKey request
// reached the caller as an indistinguishable internal fault. It now decodes
// through the shared decodeParams helper (utils.go), which always returns a
// *KeyOpError carrying ErrCodeInvalidParams.
func TestHandleRequest_ErrorLogging(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	ctx := context.Background()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "xkms.generateKey",
		Params:  json.RawMessage(`invalid json`),
		ID:      1,
	}

	resp := invokeRequest(server, ctx, req)
	require.NotNil(t, resp)
	assert.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeInvalidParams, resp.Error.Code)
}

func TestHandleListCertsWithPagination(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	// Save some certs first
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		template := x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject:      pkix.Name{CommonName: "cert-" + string(rune('a'+i))},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
		}
		certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
		require.NoError(t, err)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

		saveParams := SaveCertParams{
			KeyID:   template.Subject.CommonName,
			CertPEM: string(certPEM),
		}
		saveJSON, _ := json.Marshal(saveParams)
		saveReq := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.saveCert", Params: saveJSON, ID: 1}
		_, err = server.handleSaveCert(context.Background(), saveReq)
		require.NoError(t, err)
	}

	t.Run("lists all certs without pagination", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.listCerts", ID: 1}
		result, err := server.handleListCerts(context.Background(), req)
		require.NoError(t, err)

		listResult, ok := result.(ListCertsResult)
		require.True(t, ok)
		assert.GreaterOrEqual(t, len(listResult.KeyIDs), 3)
	})

	t.Run("lists certs with pagination params", func(t *testing.T) {
		params := map[string]int{"page": 1, "page_size": 2}
		paramsJSON, _ := json.Marshal(params)
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.listCerts", Params: paramsJSON, ID: 1}
		result, err := server.handleListCerts(context.Background(), req)
		require.NoError(t, err)

		listResult, ok := result.(ListCertsResult)
		require.True(t, ok)
		assert.NotNil(t, listResult.Pagination)
	})
}
