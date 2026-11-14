// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// TestSigningKeyTools_SignCoRIM proves attestation.signing_key.sign_corim
// returns a CoRIM signed with the tenant release key, draft-ietf-rats-corim-11
// §4.2.
func TestSigningKeyTools_SignCoRIM(t *testing.T) {
	s, pub := newReleaseKeyMCP(t)
	unsigned, err := appraisaltest.UnsignedCoRIM(map[uint32][]byte{0: make([]byte, 32)})
	require.NoError(t, err)

	var signed transport.SignedCoRIM
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.signing_key.sign_corim",
		transport.SignCoRIMRequest{Repository: "acme/app", CoRIM: unsigned, SignerName: "Acme"}, &signed))
	assert.Equal(t, appraisal.ReleaseSigningKeyID, signed.Key.KeyID)
	m, err := refvalue.VerifySigned(signed.CoRIM, refvalue.VerifyOptions{PublicKey: pub})
	require.NoError(t, err)
	assert.Equal(t, "Acme", m.Signer)
}

// newReleaseKeyMCP returns an MCP server whose acme tenant holds its release
// signing key, and that key's public half.
func newReleaseKeyMCP(t *testing.T) (*Server, crypto.PublicKey) {
	t.Helper()
	s := newSigningKeyMCP(t)
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "alice", TenantID: "acme"})
	key, err := s.xkmsService.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID: appraisal.ReleaseSigningKeyID, Backend: "software", KeyType: "signing", Algorithm: "ecdsa", Curve: "P-256", TenantID: "acme",
	})
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(key.PublicKeyPEM))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	return s, pub
}

// TestSigningKeyTools_SignCoRIMErrors proves malformed params, a malformed
// CoRIM and a server without the verifier each fail as a KeyOpError.
func TestSigningKeyTools_SignCoRIMErrors(t *testing.T) {
	s, _ := newReleaseKeyMCP(t)
	for name, params := range map[string]any{
		"malformed params": "not an object",
		"malformed corim":  transport.SignCoRIMRequest{Repository: "acme/app", CoRIM: []byte{0xff}, SignerName: "Acme"},
	} {
		var out map[string]any
		err := invokeOIDC(t, s, "acme", "alice", "attestation.signing_key.sign_corim", params, &out)
		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr, name)
		assert.Equal(t, ErrCodeInvalidParams, keyErr.Code, name)
	}

	var out map[string]any
	err := invokeOIDC(t, createTestServer(t), "acme", "alice", "attestation.signing_key.sign_corim",
		transport.SignCoRIMRequest{Repository: "acme/app", CoRIM: []byte{0xff}, SignerName: "Acme"}, &out)
	var keyErr *KeyOpError
	assert.ErrorAs(t, err, &keyErr)
}
