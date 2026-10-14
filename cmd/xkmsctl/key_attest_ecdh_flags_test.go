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

// key_attest_ecdh_flags_test.go pins how key attest and key derive-ecdh turn
// their flags into requests and render the answers.
package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

func TestKeyAttestCmd_ForwardsGivenNonce(t *testing.T) {
	mock := &mockKeyExtClient{attestResp: &transport.AttestKeyResponse{
		Backend: "tpm2", Format: "tpm2", SignatureAlgorithm: "ECDSA-SHA256", Nonce: []byte("fresh"),
	}}

	out, code, stderr := runVerb(t, newKeyExtConfig(mock), keyAttestCmd, []string{"my-key"},
		verbFlag{"nonce", base64.StdEncoding.EncodeToString([]byte("fresh"))})
	require.Equal(t, -1, code, stderr)
	assert.Equal(t, []byte("fresh"), mock.gotAttestReq.Nonce)
	assert.Contains(t, out, "  Sig Alg:      ECDSA-SHA256")
	assert.Contains(t, out, "  Nonce:        "+base64.StdEncoding.EncodeToString([]byte("fresh")))
}

func TestKeyAttestCmd_JSON(t *testing.T) {
	mock := &mockKeyExtClient{attestResp: &transport.AttestKeyResponse{Backend: "tpm2", Format: "tpm2"}}
	cfg := newKeyExtConfig(mock)
	cfg.OutputFormat = "json"

	out, code, stderr := runVerb(t, cfg, keyAttestCmd, []string{"my-key"})
	require.Equal(t, -1, code, stderr)
	assert.Equal(t, "tpm2", lastJSONObject(t, out)["format"])
}

func TestKeyAttestCmd_RefusesBadNonce(t *testing.T) {
	mock := &mockKeyExtClient{}

	out, code, stderr := runVerb(t, newKeyExtConfig(mock), keyAttestCmd, []string{"my-key"}, verbFlag{"nonce", "!not base64!"})
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, ErrInvalidBase64Nonce.Error())
	assert.Empty(t, out)
	assert.Nil(t, mock.gotAttestReq, "no attestation is requested with a bad nonce")
}

func TestKeyDeriveECDHCmd_ForwardsKDFInputs(t *testing.T) {
	peer := filepath.Join(t.TempDir(), "peer.der")
	require.NoError(t, os.WriteFile(peer, []byte("peer-point"), 0600))
	mock := &mockKeyExtClient{deriveResp: &transport.DeriveKeyECDHResponse{DerivedKey: []byte("0123456789abcdef")}}
	cfg := newKeyExtConfig(mock)
	cfg.OutputFormat = "json"

	out, code, stderr := runVerb(t, cfg, keyDeriveECDHCmd, []string{"my-key"},
		verbFlag{"peer-key", peer}, verbFlag{"kdf", "HKDF"}, verbFlag{"kdf-hash", "SHA-384"},
		verbFlag{"salt", base64.StdEncoding.EncodeToString([]byte("salt"))},
		verbFlag{"info", "ctx-info"}, verbFlag{"label", "ctx-label"}, verbFlag{"length", "16"})
	require.Equal(t, -1, code, stderr)

	got := mock.gotDeriveReq
	require.NotNil(t, got)
	assert.Equal(t, []byte("peer-point"), got.PeerPublicKey)
	assert.Equal(t, "HKDF", got.KDFAlgorithm)
	assert.Equal(t, "SHA-384", got.KDFHash)
	assert.Equal(t, []byte("salt"), got.KDFSalt)
	assert.Equal(t, []byte("ctx-info"), got.KDFInfo)
	assert.Equal(t, []byte("ctx-label"), got.KDFLabel)
	assert.Equal(t, 16, got.KeyLength)

	result := lastJSONObject(t, out)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")), result["derived_key"])
	assert.Equal(t, float64(16), result["length"])
}

func TestKeyDeriveECDHCmd_Refusals(t *testing.T) {
	peer := filepath.Join(t.TempDir(), "peer.der")
	require.NoError(t, os.WriteFile(peer, []byte("peer-point"), 0600))

	cases := []struct {
		name     string
		flags    []verbFlag
		sentinel error
	}{
		{"unreadable peer key", []verbFlag{{"peer-key", filepath.Join(t.TempDir(), "absent.der")}}, ErrReadPublicKeyFileFailed},
		{"salt not base64", []verbFlag{{"peer-key", peer}, {"salt", "!not base64!"}}, ErrInvalidSalt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockKeyExtClient{}
			out, code, stderr := runVerb(t, newKeyExtConfig(mock), keyDeriveECDHCmd, []string{"my-key"}, tc.flags...)
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, tc.sentinel.Error())
			assert.Empty(t, out)
			assert.Nil(t, mock.gotDeriveReq, "nothing is derived from refused input")
		})
	}
}
