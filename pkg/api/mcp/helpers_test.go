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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/stretchr/testify/require"
)

// mcpCtxWithPeerCert returns a context carrying a throwaway self-signed leaf
// as the mTLS peer certificate, mirroring what the MCP server installs after a
// successful handshake.
func mcpCtxWithPeerCert(t *testing.T) context.Context {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "officer-A"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return auth.WithTLSState(context.Background(), &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
	})
}

// makeReq creates a JSONRPCRequest with the given method and params.
func makeReq(method string, params interface{}) *JSONRPCRequest {
	var paramsJSON json.RawMessage
	if params != nil {
		data, _ := json.Marshal(params)
		paramsJSON = data
	}
	return &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  paramsJSON,
		ID:      1,
	}
}
