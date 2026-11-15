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

// mockSigningKeyClient records the signing-key binding requests and answers
// from bindings, or refuses every call when fail is set.
type mockSigningKeyClient struct {
	mockBackendsClient

	fail     bool
	set      *client.SetAttestationSigningKeyBindingRequest
	get      *client.GetAttestationSigningKeyBindingRequest
	deleted  *client.DeleteAttestationSigningKeyBindingRequest
	resolve  *client.ResolveAttestationSigningKeyRequest
	bindings []*client.AttestationSigningKeyBinding
}

func (m *mockSigningKeyClient) SetSigningKeyBinding(_ context.Context, req *client.SetAttestationSigningKeyBindingRequest) (*client.AttestationSigningKeyBinding, error) {
	m.set = req
	if m.fail {
		return nil, errReleaseSign
	}
	return &client.AttestationSigningKeyBinding{Repository: req.Repository, KeyID: req.KeyID, Backend: req.Backend}, nil
}

func (m *mockSigningKeyClient) GetSigningKeyBinding(_ context.Context, req *client.GetAttestationSigningKeyBindingRequest) (*client.AttestationSigningKeyBinding, error) {
	m.get = req
	if m.fail {
		return nil, errReleaseSign
	}
	return &client.AttestationSigningKeyBinding{Repository: req.Repository, KeyID: "app-key", Backend: "pkcs11"}, nil
}

func (m *mockSigningKeyClient) ListSigningKeyBindings(context.Context) (*client.ListAttestationSigningKeyBindingsResponse, error) {
	if m.fail {
		return nil, errReleaseSign
	}
	return &client.ListAttestationSigningKeyBindingsResponse{Bindings: m.bindings}, nil
}

func (m *mockSigningKeyClient) DeleteSigningKeyBinding(_ context.Context, req *client.DeleteAttestationSigningKeyBindingRequest) error {
	m.deleted = req
	if m.fail {
		return errReleaseSign
	}
	return nil
}

func (m *mockSigningKeyClient) ResolveSigningKey(_ context.Context, req *client.ResolveAttestationSigningKeyRequest) (*client.AttestationSigningKeyResolution, error) {
	m.resolve = req
	if m.fail {
		return nil, errReleaseSign
	}
	return &client.AttestationSigningKeyResolution{Repository: req.Repository, KeyID: "release-signing", Default: true}, nil
}

func TestKeySigningKeyBindingCmds_Registered(t *testing.T) {
	for _, name := range []string{"set", "get", "list", "delete", "resolve"} {
		sub, _, err := keySigningKeyCmd.Find([]string{name})
		require.NoError(t, err)
		assert.Equal(t, name, sub.Name())
	}
}

func TestKeySigningKeySetCmd(t *testing.T) {
	mock := &mockSigningKeyClient{}
	out, _, code := runOTAImageCmd(t, mock, keySigningKeySetCmd, []string{"acme/app", "app-key"}, map[string]string{"key-backend": "pkcs11"})
	assert.Equal(t, -1, code)
	assert.Equal(t, &client.SetAttestationSigningKeyBindingRequest{Repository: "acme/app", KeyID: "app-key", Backend: "pkcs11"}, mock.set)
	assert.Contains(t, out, "acme/app")
	assert.Contains(t, out, "app-key")
}

func TestKeySigningKeyGetCmd(t *testing.T) {
	mock := &mockSigningKeyClient{}
	out, _, code := runOTAImageCmd(t, mock, keySigningKeyGetCmd, []string{"acme/app"}, nil)
	assert.Equal(t, -1, code)
	assert.Equal(t, &client.GetAttestationSigningKeyBindingRequest{Repository: "acme/app"}, mock.get)
	assert.Contains(t, out, "app-key")
	assert.Contains(t, out, "pkcs11")
}

func TestKeySigningKeyListCmd(t *testing.T) {
	mock := &mockSigningKeyClient{bindings: []*client.AttestationSigningKeyBinding{
		{Repository: "acme/app", KeyID: "app-key"},
		{Repository: "acme/web", KeyID: "web-key", Backend: "pkcs11"},
	}}
	out, _, code := runOTAImageCmd(t, mock, keySigningKeyListCmd, nil, nil)
	assert.Equal(t, -1, code)
	for _, want := range []string{"acme/app", "app-key", "acme/web", "web-key"} {
		assert.Contains(t, out, want)
	}

	out, _, code = runOTAImageCmd(t, &mockSigningKeyClient{}, keySigningKeyListCmd, nil, nil)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "No signing-key bindings")
}

func TestKeySigningKeyDeleteCmd(t *testing.T) {
	mock := &mockSigningKeyClient{}
	out, _, code := runOTAImageCmd(t, mock, keySigningKeyDeleteCmd, []string{"acme/app"}, nil)
	assert.Equal(t, -1, code)
	assert.Equal(t, &client.DeleteAttestationSigningKeyBindingRequest{Repository: "acme/app"}, mock.deleted)
	assert.Contains(t, out, "acme/app")
}

func TestKeySigningKeyResolveCmd(t *testing.T) {
	mock := &mockSigningKeyClient{}
	out, _, code := runOTAImageCmd(t, mock, keySigningKeyResolveCmd, []string{"acme/app"}, nil)
	assert.Equal(t, -1, code)
	assert.Equal(t, &client.ResolveAttestationSigningKeyRequest{Repository: "acme/app"}, mock.resolve)
	assert.Contains(t, out, "release-signing")
	assert.Contains(t, out, "release key")
}

func TestKeySigningKeyBindingCmds_ServerRefuses(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		sentinel error
	}{
		{"set", []string{"acme/app", "app-key"}, ErrSetSigningKeyBindingFailed},
		{"get", []string{"acme/app"}, ErrGetSigningKeyBindingFailed},
		{"list", nil, ErrListSigningKeyBindingsFailed},
		{"delete", []string{"acme/app"}, ErrDeleteSigningKeyBindingFailed},
		{"resolve", []string{"acme/app"}, ErrResolveSigningKeyFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd, _, err := keySigningKeyCmd.Find([]string{tc.name})
			require.NoError(t, err)
			_, stderr, code := runOTAImageCmd(t, &mockSigningKeyClient{fail: true}, cmd, tc.args, nil)
			assert.NotEqual(t, -1, code)
			assert.Contains(t, stderr, tc.sentinel.Error())
		})
	}
}
