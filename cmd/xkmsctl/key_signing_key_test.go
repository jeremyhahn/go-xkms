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

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

var errReleaseSign = errors.New("release signing refused")

// mockReleaseSigningClient records the release CoRIM sign request and
// answers with the CoRIM prefixed by "signed:".
type mockReleaseSigningClient struct {
	mockBackendsClient

	fail bool
	req  *client.SignReleaseCoRIMRequest
}

func (m *mockReleaseSigningClient) SignReleaseCoRIM(_ context.Context, req *client.SignReleaseCoRIMRequest) (*client.SignReleaseCoRIMResponse, error) {
	m.req = req
	if m.fail {
		return nil, errReleaseSign
	}
	return &client.SignReleaseCoRIMResponse{SignedCoRIM: append([]byte("signed:"), req.CoRIM...), KeyID: "release-signing"}, nil
}

func TestKeySigningKeyCmds_RegisteredUnderKey(t *testing.T) {
	found, _, err := keyCmd.Find([]string{"signing-key"})
	require.NoError(t, err)
	assert.Same(t, keySigningKeyCmd, found)
	sub, _, err := keySigningKeyCmd.Find([]string{"sign"})
	require.NoError(t, err)
	assert.Equal(t, "sign", sub.Name())
}

func TestKeySigningKeySignCmd(t *testing.T) {
	mock := &mockReleaseSigningClient{}
	corim := writeOTAImage(t, "corim")

	out, _, code := runOTAImageCmd(t, mock, keySigningKeySignCmd, []string{"acme/app", corim}, nil)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, base64.StdEncoding.EncodeToString([]byte("signed:corim")))
	assert.Contains(t, out, "release-signing")
	assert.Equal(t, &client.SignReleaseCoRIMRequest{Repository: "acme/app", CoRIM: []byte("corim")}, mock.req)

	_, _, code = runOTAImageCmd(t, mock, keySigningKeySignCmd, []string{"acme/app", corim}, map[string]string{"signer": "ci"})
	assert.Equal(t, -1, code)
	assert.Equal(t, "ci", mock.req.SignerName, "--signer names the signer in the request")
}

func TestKeySigningKeySignCmd_WritesOutFile(t *testing.T) {
	mock := &mockReleaseSigningClient{}
	corim := writeOTAImage(t, "corim")
	outPath := filepath.Join(t.TempDir(), "signed.cbor")

	out, _, code := runOTAImageCmd(t, mock, keySigningKeySignCmd, []string{"acme/app", corim}, map[string]string{"out": outPath})
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "release-signing")
	signed, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Equal(t, []byte("signed:corim"), signed)
}

func TestKeySigningKeySignCmd_MissingCoRIMFile(t *testing.T) {
	mock := &mockReleaseSigningClient{}
	_, _, code := runOTAImageCmd(t, mock, keySigningKeySignCmd, []string{"acme/app", filepath.Join(t.TempDir(), "absent")}, nil)
	assert.NotEqual(t, -1, code)
	assert.Nil(t, mock.req, "no request without a CoRIM")
}

func TestKeySigningKeySignCmd_ServerRefuses(t *testing.T) {
	mock := &mockReleaseSigningClient{fail: true}
	corim := writeOTAImage(t, "corim")
	_, stderr, code := runOTAImageCmd(t, mock, keySigningKeySignCmd, []string{"acme/app", corim}, nil)
	assert.NotEqual(t, -1, code)
	assert.Contains(t, stderr, ErrSignReleaseCoRIMFailed.Error())
}
