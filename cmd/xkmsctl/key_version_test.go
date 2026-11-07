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
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// mockKeyVersionClient serves the key-version API and the versioned key
// operations of client.Client from canned answers and records every
// request; every other method comes from the embedded base.
type mockKeyVersionClient struct {
	mockBackendsClient

	listed  *client.ListKeyVersionsResponse
	state   *client.KeyVersionStateResponse
	all     *client.AllKeyVersionsResponse
	scope   *client.RotateScopeKeysResponse
	rotated *client.RotateKeyResponse
	err     error

	requests map[string]any
}

func (m *mockKeyVersionClient) record(method string, req any) error {
	if m.requests == nil {
		m.requests = map[string]any{}
	}
	m.requests[method] = req
	return m.err
}

func (m *mockKeyVersionClient) ListKeyVersions(_ context.Context, req *client.ListKeyVersionsRequest) (*client.ListKeyVersionsResponse, error) {
	return m.listed, m.record("list", req)
}
func (m *mockKeyVersionClient) EnableKeyVersion(_ context.Context, req *client.KeyVersionRequest) (*client.KeyVersionStateResponse, error) {
	return m.state, m.record("enable", req)
}
func (m *mockKeyVersionClient) DisableKeyVersion(_ context.Context, req *client.KeyVersionRequest) (*client.KeyVersionStateResponse, error) {
	return m.state, m.record("disable", req)
}
func (m *mockKeyVersionClient) RetireKeyVersion(_ context.Context, req *client.KeyVersionRequest) (*client.KeyVersionStateResponse, error) {
	return m.state, m.record("retire", req)
}
func (m *mockKeyVersionClient) EnableAllKeyVersions(_ context.Context, req *client.AllKeyVersionsRequest) (*client.AllKeyVersionsResponse, error) {
	return m.all, m.record("enable-all", req)
}
func (m *mockKeyVersionClient) DisableAllKeyVersions(_ context.Context, req *client.AllKeyVersionsRequest) (*client.AllKeyVersionsResponse, error) {
	return m.all, m.record("disable-all", req)
}
func (m *mockKeyVersionClient) RotateScopeKeys(_ context.Context, req *client.RotateScopeKeysRequest) (*client.RotateScopeKeysResponse, error) {
	return m.scope, m.record("rotate-all", req)
}
func (m *mockKeyVersionClient) RotateKey(_ context.Context, req *client.RotateKeyRequest) (*client.RotateKeyResponse, error) {
	return m.rotated, m.record("rotate", req)
}
func (m *mockKeyVersionClient) Verify(_ context.Context, req *client.VerifyRequest) (*client.VerifyResponse, error) {
	return &client.VerifyResponse{Valid: true, KeyVersion: 1}, m.record("verify", req)
}
func (m *mockKeyVersionClient) Decrypt(_ context.Context, req *client.DecryptRequest) (*client.DecryptResponse, error) {
	return &client.DecryptResponse{Plaintext: []byte("plain"), KeyVersion: req.KeyVersion}, m.record("decrypt", req)
}

// runKeyVersionCmd runs cmd with args and flags over mock, in format, and
// returns its output and exit code (-1 when it did not exit).
func runKeyVersionCmd(t *testing.T, mock *mockKeyVersionClient, format string, cmd *cobra.Command, args []string, flags map[string]string) (string, int) {
	t.Helper()
	resetCmdFlags(t, cmd)
	t.Cleanup(func() { resetCmdFlags(t, cmd) })
	withGlobalConfig(t, &Config{
		OutputFormat:  format,
		Backend:       "software",
		ClientFactory: func(*Config) (client.Client, error) { return mock, nil },
	})
	for name, value := range flags {
		require.NoError(t, cmd.Flags().Set(name, value))
	}
	code := -1
	out := captureStdout(t, func() {
		code = captureExit(t, func() { cmd.Run(cmd, args) })
	})
	return out, code
}

// TestKeyVersionsCmd lists the versions of the key named, in the configured
// backend, as a table and as JSON.
func TestKeyVersionsCmd(t *testing.T) {
	mock := &mockKeyVersionClient{listed: &client.ListKeyVersionsResponse{
		KeyID: "k", CurrentVersion: 2,
		Versions: []client.KeyVersionInfo{
			{Version: 1, State: "disabled"},
			{Version: 2, State: "enabled", Current: true, CreatedAt: "2026-09-30T12:00:00Z", CreatedBy: "alice"},
		},
	}}
	out, code := runKeyVersionCmd(t, mock, "text", keyVersionsCmd, []string{"k"}, nil)
	assert.Equal(t, -1, code)
	assert.Equal(t, &client.ListKeyVersionsRequest{Backend: "software", KeyID: "k"}, mock.requests["list"])
	assert.Contains(t, out, "current version 2")
	assert.Contains(t, out, "disabled")
	assert.Contains(t, out, "alice")

	out, _ = runKeyVersionCmd(t, mock, "json", keyVersionsCmd, []string{"k"}, nil)
	assert.Contains(t, out, `"current_version": 2`)
}

// TestKeyVersionStateCmds sends the version named to each state command and
// reports whether it changed.
func TestKeyVersionStateCmds(t *testing.T) {
	for name, cmd := range map[string]*cobra.Command{
		"enable": keyVersionEnableCmd, "disable": keyVersionDisableCmd, "retire": keyVersionRetireCmd,
	} {
		t.Run(name, func(t *testing.T) {
			mock := &mockKeyVersionClient{state: &client.KeyVersionStateResponse{KeyID: "k", Version: 1, State: name + "d", Changed: true}}
			out, code := runKeyVersionCmd(t, mock, "text", cmd, []string{"k", "1"}, nil)
			assert.Equal(t, -1, code)
			assert.Equal(t, &client.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1}, mock.requests[name])
			assert.Contains(t, out, "is now")

			mock.state.Changed = false
			out, _ = runKeyVersionCmd(t, mock, "text", cmd, []string{"k", "1"}, nil)
			assert.Contains(t, out, "was already")
		})
	}
}

// TestKeyVersionStateCmds_Refusals exits non-zero for a version that is not
// a positive integer, before any request, and for a server refusal.
func TestKeyVersionStateCmds_Refusals(t *testing.T) {
	mock := &mockKeyVersionClient{}
	for _, bad := range []string{"0", "-1", "two", "4294967296"} {
		_, code := runKeyVersionCmd(t, mock, "text", keyVersionDisableCmd, []string{"k", bad}, nil)
		assert.NotEqual(t, -1, code, bad)
	}
	assert.Empty(t, mock.requests, "no request is sent for a malformed version")

	mock.err = errTPMRunBoom
	_, code := runKeyVersionCmd(t, mock, "text", keyVersionDisableCmd, []string{"k", "1"}, nil)
	assert.NotEqual(t, -1, code)
}

// TestAllKeyVersionsCmds sends the key named to the bulk commands and prints
// the versions reached.
func TestAllKeyVersionsCmds(t *testing.T) {
	mock := &mockKeyVersionClient{all: &client.AllKeyVersionsResponse{KeyID: "k", State: "disabled", Versions: []uint32{1, 2}, Count: 2}}
	out, code := runKeyVersionCmd(t, mock, "text", keyVersionDisableAllCmd, []string{"k"}, nil)
	assert.Equal(t, -1, code)
	assert.Equal(t, &client.AllKeyVersionsRequest{Backend: "software", KeyID: "k"}, mock.requests["disable-all"])
	assert.Contains(t, out, "[1 2]")

	mock.all = &client.AllKeyVersionsResponse{KeyID: "k", State: "enabled"}
	out, code = runKeyVersionCmd(t, mock, "text", keyVersionEnableAllCmd, []string{"k"}, nil)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "No version")
}

// TestKeyRotateAllCmd sends the tenant flag and prints each key's result,
// succeeding when keys were only skipped and exiting non-zero when a key
// failed.
func TestKeyRotateAllCmd(t *testing.T) {
	mock := &mockKeyVersionClient{scope: &client.RotateScopeKeysResponse{
		TenantID: "acme", Rotated: 1, Skipped: 1,
		Results: []client.KeyRotationResult{
			{Backend: "software", KeyID: "k", State: client.KeyRotationRotated, KeyVersion: 3},
			{Backend: "software", KeyID: "tls", State: client.KeyRotationSkipped, Reason: "has a certificate; re-issue after rotating it explicitly"},
		},
	}}
	out, code := runKeyVersionCmd(t, mock, "text", keyRotateAllCmd, nil, map[string]string{"tenant": "acme"})
	assert.Equal(t, -1, code, "a skipped key is not a failure")
	assert.Equal(t, &client.RotateScopeKeysRequest{TenantID: "acme"}, mock.requests["rotate-all"])
	assert.Contains(t, out, "1 rotated, 1 skipped, 0 failed")
	assert.Contains(t, out, "has a certificate")

	mock.scope.Failed = 1
	mock.scope.Results = append(mock.scope.Results, client.KeyRotationResult{Backend: "software", KeyID: "x", State: client.KeyRotationFailed, Error: "cannot be rotated"})
	out, code = runKeyVersionCmd(t, mock, "text", keyRotateAllCmd, nil, nil)
	assert.NotEqual(t, -1, code, "a partial rotation fails the command")
	assert.Contains(t, out, "cannot be rotated")
}

// TestKeyRotateCmd_ReportsTheNewVersion prints the version the rotation made
// current.
func TestKeyRotateCmd_ReportsTheNewVersion(t *testing.T) {
	mock := &mockKeyVersionClient{rotated: &client.RotateKeyResponse{KeyID: "k", KeyVersion: 2}}
	out, code := runKeyVersionCmd(t, mock, "text", keyRotateCmd, []string{"k"}, nil)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "current version 2")
	assert.NotContains(t, out, "re-issue")

	mock.rotated.CertificateReissueRequired = true
	out, code = runKeyVersionCmd(t, mock, "text", keyRotateCmd, []string{"k"}, nil)
	assert.Equal(t, -1, code, "a certificate to re-issue is a warning, not a failure")
	assert.Contains(t, out, "re-issue it for version 2")

	mock.err = errTPMRunBoom
	_, code = runKeyVersionCmd(t, mock, "text", keyRotateCmd, []string{"k"}, nil)
	assert.NotEqual(t, -1, code)
}

// TestVerifyAndDecryptCmds_SendKeyVersion sends --key-version with verify
// and decrypt, and leaves it zero when not given.
func TestVerifyAndDecryptCmds_SendKeyVersion(t *testing.T) {
	mock := &mockKeyVersionClient{}
	sig := base64.StdEncoding.EncodeToString([]byte("sig"))
	out, code := runKeyVersionCmd(t, mock, "text", keyVerifyCmd, []string{"k", "data", sig}, map[string]string{"key-version": "1"})
	assert.Equal(t, -1, code)
	assert.Equal(t, uint32(1), mock.requests["verify"].(*client.VerifyRequest).KeyVersion)
	assert.Contains(t, out, "key version 1")

	ct := base64.StdEncoding.EncodeToString([]byte("ct"))
	_, code = runKeyVersionCmd(t, mock, "text", keyDecryptCmd, []string{"k", ct}, map[string]string{"key-version": "3"})
	assert.Equal(t, -1, code)
	assert.Equal(t, uint32(3), mock.requests["decrypt"].(*client.DecryptRequest).KeyVersion)

	_, code = runKeyVersionCmd(t, mock, "text", keyDecryptCmd, []string{"k", ct}, nil)
	assert.Equal(t, -1, code)
	assert.Zero(t, mock.requests["decrypt"].(*client.DecryptRequest).KeyVersion)
}

// TestKeyDecryptCmd_HashSelectsOAEP pins that --hash decrypts RSA-OAEP with
// that digest, matching what encrypt-asym produced, instead of the PKCS#1
// v1.5 fallback the server refuses by policy.
func TestKeyDecryptCmd_HashSelectsOAEP(t *testing.T) {
	mock := &mockKeyVersionClient{}
	ct := base64.StdEncoding.EncodeToString([]byte("ct"))

	_, code := runKeyVersionCmd(t, mock, "text", keyDecryptCmd, []string{"k", ct}, map[string]string{"hash": "sha384"})
	assert.Equal(t, -1, code)
	req := mock.requests["decrypt"].(*client.DecryptRequest)
	assert.Equal(t, "oaep", req.Padding)
	assert.Equal(t, "sha384", req.Hash)
}

// TestKeyDecryptCmd_NoHashLeavesPaddingUnset pins that a decrypt without
// --hash names no RSA padding, so symmetric decryption is unchanged.
func TestKeyDecryptCmd_NoHashLeavesPaddingUnset(t *testing.T) {
	mock := &mockKeyVersionClient{}
	ct := base64.StdEncoding.EncodeToString([]byte("ct"))

	_, code := runKeyVersionCmd(t, mock, "text", keyDecryptCmd, []string{"k", ct}, nil)
	assert.Equal(t, -1, code)
	req := mock.requests["decrypt"].(*client.DecryptRequest)
	assert.Empty(t, req.Padding)
	assert.Empty(t, req.Hash)
}

// TestPrinters_KeyVersion prints the key version in JSON beside a signature
// and ciphertext, keeps the text signature bare, and adds a line to the text
// encryption.
func TestPrinters_KeyVersion(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, NewPrinter("json", &buf).PrintSignature("sig", 2))
	assert.Contains(t, buf.String(), `"key_version": 2`)

	buf.Reset()
	require.NoError(t, NewPrinter("text", &buf).PrintSignature("sig", 2))
	assert.Equal(t, "sig\n", buf.String(), "the text signature can still be piped")

	buf.Reset()
	require.NoError(t, NewPrinter("text", &buf).PrintEncryptedData(&client.EncryptedData{Ciphertext: []byte("c")}, 3))
	assert.Contains(t, buf.String(), "Key version: 3")

	buf.Reset()
	require.NoError(t, NewPrinter("json", &buf).PrintEncryptedAsym("ct", 0))
	assert.NotContains(t, buf.String(), "key_version", "no version is reported when the server gave none")
}
