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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

const (
	otaTestBoard   = "stm32-h7"
	otaTestTenant  = "tenant-a"
	otaTestBackend = "software"
)

// newOTAImageServer returns an MCP server over a software backend with the
// key-version store wired, and the service behind it.
func newOTAImageServer(t *testing.T) (*Server, *xkms.XKMSService) {
	t.Helper()
	svc := setupTestXKMS(t)
	t.Cleanup(cleanupXKMS)
	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)
	return server, svc
}

// callOTA dispatches method through the registration table as the test tenant.
func callOTA(t *testing.T, server *Server, method string, params interface{}) (interface{}, error) {
	t.Helper()
	entry, ok := rpcMethods[method]
	require.True(t, ok, "%s must be registered", method)
	return entry.handler(server, tenantContext(otaTestTenant), keyOpsRequest(t, method, params))
}

// otaPublicKey parses an ECDSA public key from a result's PEM.
func otaPublicKey(t *testing.T, pemText string) *ecdsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemText))
	require.NotNil(t, block, "result carries no public key PEM")
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	ec, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok, "public key is %T, not ECDSA", pub)
	return ec
}

// verifyOTASignature checks an ES256 OTA_AUTH signature in the RFC 9053
// §2.1 encoding: 32-byte big-endian r, then 32-byte big-endian s.
func verifyOTASignature(t *testing.T, pub *ecdsa.PublicKey, digest, sig []byte) bool {
	t.Helper()
	require.Len(t, sig, 64, "an ES256 OTA signature is r || s, 64 bytes")
	return ecdsa.Verify(pub, digest, new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

func TestOTAImageKeyMethods_Registered(t *testing.T) {
	for method, action := range map[string]string{
		"xkms.createOTAImageKey": auth.ActionCreate,
		"xkms.rotateOTAImageKey": auth.ActionRotate,
		"xkms.signOTAImage":      auth.ActionSign,
		"xkms.exportOTAImageKey": auth.ActionGet,
	} {
		entry, ok := rpcMethods[method]
		require.True(t, ok, "%s must be registered", method)
		assert.Equal(t, auth.ResourceKeys+":"+action, string(entry.perm), method)
	}
}

func TestOTAImageKeyMethods_CreateRotateSign(t *testing.T) {
	server, _ := newOTAImageServer(t)

	result, err := callOTA(t, server, "xkms.createOTAImageKey",
		OTAImageKeyParams{BoardID: otaTestBoard, Backend: otaTestBackend, Algorithm: "ES256"})
	require.NoError(t, err)
	created, ok := result.(GenerateKeyResult)
	require.True(t, ok, "result is %T", result)
	assert.Equal(t, "ota-image-"+otaTestBoard, created.KeyID)
	assert.Equal(t, elliptic.P256(), otaPublicKey(t, created.PublicKeyPEM).Curve)

	result, err = callOTA(t, server, "xkms.rotateOTAImageKey",
		OTAImageKeyParams{BoardID: otaTestBoard, Backend: otaTestBackend})
	require.NoError(t, err)
	rotated, ok := result.(RotateKeyResult)
	require.True(t, ok, "result is %T", result)
	assert.Equal(t, uint32(2), rotated.KeyVersion)

	digest := sha256.Sum256([]byte("firmware image"))
	result, err = callOTA(t, server, "xkms.signOTAImage",
		OTAImageSignParams{BoardID: otaTestBoard, Backend: otaTestBackend, Data: digest[:], DataIsDigest: true})
	require.NoError(t, err)
	signed, ok := result.(SignResult)
	require.True(t, ok, "result is %T", result)
	assert.Equal(t, uint32(2), signed.KeyVersion, "signs with the current version")
	signature, ok := signed.Signature.([]byte)
	require.True(t, ok, "signature is %T", signed.Signature)
	assert.True(t, verifyOTASignature(t, otaPublicKey(t, rotated.PublicKeyPEM), digest[:], signature),
		"signature does not verify under the rotated key")

	result, err = callOTA(t, server, "xkms.exportOTAImageKey",
		OTAImageKeyParams{BoardID: otaTestBoard, Backend: otaTestBackend})
	require.NoError(t, err)
	exported, ok := result.(*transport.ExportOTAImageKeyResponse)
	require.True(t, ok, "result is %T", result)
	assert.Equal(t, uint32(2), exported.KeyVersion, "exports the current version")
	rotatedPoint, err := otaPublicKey(t, rotated.PublicKeyPEM).ECDH()
	require.NoError(t, err)
	assert.Equal(t, rotatedPoint.Bytes()[1:], exported.PublicKey, "X || Y of the rotated key")
	assert.NotEmpty(t, exported.COSEKey)
}

func TestOTAImageKeyMethods_InvalidParams(t *testing.T) {
	server, svc := newOTAImageServer(t)

	// A key created outside the OTA path under a board's key ID, on P-384.
	scoped, err := svc.LookupTenantBackend(otaTestBackend, otaTestTenant)
	require.NoError(t, err)
	_, err = scoped.GenerateECDSA(context.Background(), &types.KeyAttributes{
		CN:            "ota-image-p384-board",
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P384()},
	})
	require.NoError(t, err)

	tests := []struct {
		name   string
		method string
		params interface{}
	}{
		{"create malformed board id", "xkms.createOTAImageKey", OTAImageKeyParams{BoardID: "Bad--Board", Backend: otaTestBackend}},
		{"create non-ES256 algorithm", "xkms.createOTAImageKey", OTAImageKeyParams{BoardID: otaTestBoard, Backend: otaTestBackend, Algorithm: "RS256"}},
		{"rotate malformed board id", "xkms.rotateOTAImageKey", OTAImageKeyParams{BoardID: "bad--board", Backend: otaTestBackend}},
		{"rotate non-ES256 algorithm", "xkms.rotateOTAImageKey", OTAImageKeyParams{BoardID: otaTestBoard, Backend: otaTestBackend, Algorithm: "PS256"}},
		{"rotate non-ES256 key", "xkms.rotateOTAImageKey", OTAImageKeyParams{BoardID: "p384-board", Backend: otaTestBackend}},
		{"sign malformed board id", "xkms.signOTAImage", OTAImageSignParams{BoardID: "-board", Backend: otaTestBackend, Data: []byte("image")}},
		{"sign non-ES256 key", "xkms.signOTAImage", OTAImageSignParams{BoardID: "p384-board", Backend: otaTestBackend, Data: []byte("image")}},
		{"export malformed board id", "xkms.exportOTAImageKey", OTAImageKeyParams{BoardID: "Board", Backend: otaTestBackend}},
		{"export non-ES256 key", "xkms.exportOTAImageKey", OTAImageKeyParams{BoardID: "p384-board", Backend: otaTestBackend}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := callOTA(t, server, tc.method, tc.params)
			var opErr *KeyOpError
			require.True(t, errors.As(err, &opErr), "error %v is not a KeyOpError", err)
			assert.Equal(t, ErrCodeInvalidParams, opErr.Code)
		})
	}
}

func TestOTAImageKeyMethods_MalformedParams(t *testing.T) {
	server, _ := newOTAImageServer(t)

	for _, method := range []string{"xkms.createOTAImageKey", "xkms.rotateOTAImageKey", "xkms.signOTAImage", "xkms.exportOTAImageKey"} {
		t.Run(method, func(t *testing.T) {
			_, err := rpcMethods[method].handler(server, tenantContext(otaTestTenant),
				&JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: []byte("{not json"), ID: 1})
			var opErr *KeyOpError
			require.True(t, errors.As(err, &opErr), "error %v is not a KeyOpError", err)
			assert.Equal(t, ErrCodeInvalidParams, opErr.Code)
		})
	}
}

func TestOTAImageKeyMethods_UnknownBoardKey(t *testing.T) {
	server, _ := newOTAImageServer(t)

	_, err := callOTA(t, server, "xkms.rotateOTAImageKey",
		OTAImageKeyParams{BoardID: otaTestBoard, Backend: otaTestBackend})
	var opErr *KeyOpError
	require.True(t, errors.As(err, &opErr), "error %v is not a KeyOpError", err)
	assert.NotEqual(t, ErrCodeInvalidParams, opErr.Code, "a missing board key is not malformed input")

	_, err = callOTA(t, server, "xkms.exportOTAImageKey",
		OTAImageKeyParams{BoardID: otaTestBoard, Backend: otaTestBackend})
	require.True(t, errors.As(err, &opErr), "error %v is not a KeyOpError", err)
	assert.NotEqual(t, ErrCodeInvalidParams, opErr.Code, "a missing board key is not malformed input")
}
