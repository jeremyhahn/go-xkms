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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

var errEndorsementStore = errors.New("endorsement store unavailable")

// mockEndorsementClient records the last endorsement request of each verb.
type mockEndorsementClient struct {
	mockBackendsClient

	fail    bool
	calls   int
	putReq  *client.PutAttestationEndorsementRequest
	listReq *client.ListAttestationEndorsementsRequest
	delReq  *client.DeleteAttestationEndorsementRequest
}

func (m *mockEndorsementClient) PutAttestationEndorsement(_ context.Context, req *client.PutAttestationEndorsementRequest) (*client.AttestationEndorsement, error) {
	m.calls++
	m.putReq = req
	if m.fail {
		return nil, errEndorsementStore
	}
	return &client.AttestationEndorsement{Name: req.Name, Kind: req.Kind, CertificatePEM: req.CertificatePEM, PublicKeyPEM: req.PublicKeyPEM}, nil
}

func (m *mockEndorsementClient) ListAttestationEndorsements(_ context.Context, req *client.ListAttestationEndorsementsRequest) (*client.ListAttestationEndorsementsResponse, error) {
	m.calls++
	m.listReq = req
	if m.fail {
		return nil, errEndorsementStore
	}
	return &client.ListAttestationEndorsementsResponse{Endorsements: []*client.AttestationEndorsement{
		{Name: "signer1", Kind: client.AttestationEndorsementReferenceSigner},
		{Name: "signer2", Kind: client.AttestationEndorsementReferenceSigner},
	}}, nil
}

func (m *mockEndorsementClient) DeleteAttestationEndorsement(_ context.Context, req *client.DeleteAttestationEndorsementRequest) error {
	m.calls++
	m.delReq = req
	if m.fail {
		return errEndorsementStore
	}
	return nil
}

// runEndorsementCmd runs cmd against mock in the given output format and
// returns stdout, stderr and the exit code (-1 when the command did not exit).
func runEndorsementCmd(t *testing.T, mock client.Client, cmd *cobra.Command, format string, args []string, flags map[string]string) (string, string, int) {
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
	var out string
	stderr := captureStderr(t, func() {
		out = captureStdout(t, func() {
			code = captureExit(t, func() { cmd.Run(cmd, args) })
		})
	})
	return out, stderr, code
}

func writeEndorsementPEM(t *testing.T) (string, []byte) {
	t.Helper()
	data := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	path := filepath.Join(t.TempDir(), "anchor.pem")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path, data
}

func hasSubcommand(parent, child *cobra.Command) bool {
	for _, c := range parent.Commands() {
		if c == child {
			return true
		}
	}
	return false
}

func TestAttestationEndorsementCmds_Registered(t *testing.T) {
	assert.True(t, hasSubcommand(rootCmd, attestationCmd), "attestation is on the root command")
	assert.True(t, hasSubcommand(attestationCmd, attestationEndorsementCmd), "endorsement is under attestation")
	for _, verb := range []*cobra.Command{attestationEndorsementPutCmd, attestationEndorsementListCmd, attestationEndorsementDeleteCmd} {
		assert.True(t, hasSubcommand(attestationEndorsementCmd, verb), verb.Name())
	}
}

func TestAttestationEndorsementPutCmd(t *testing.T) {
	path, data := writeEndorsementPEM(t)

	mock := &mockEndorsementClient{}
	out, _, code := runEndorsementCmd(t, mock, attestationEndorsementPutCmd, "text", []string{"ak1"},
		map[string]string{"kind": "ak-root", "cert": path})
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "ak1")
	assert.Equal(t, &client.PutAttestationEndorsementRequest{Name: "ak1", Kind: client.AttestationEndorsementAKRoot, CertificatePEM: data}, mock.putReq)

	mock = &mockEndorsementClient{}
	_, _, code = runEndorsementCmd(t, mock, attestationEndorsementPutCmd, "text", []string{"signer1"},
		map[string]string{"kind": "reference-signer", "public-key": path})
	assert.Equal(t, -1, code)
	assert.Equal(t, &client.PutAttestationEndorsementRequest{Name: "signer1", Kind: client.AttestationEndorsementReferenceSigner, PublicKeyPEM: data}, mock.putReq)
}

func TestAttestationEndorsementPutCmd_Refusals(t *testing.T) {
	path, _ := writeEndorsementPEM(t)
	cases := map[string]map[string]string{
		"both cert and public key": {"kind": "ak-root", "cert": path, "public-key": path},
		"neither":                  {"kind": "ak-root"},
		"unknown kind":             {"kind": "ek-root", "cert": path},
		"no kind":                  {"cert": path},
		"missing file":             {"kind": "ak-root", "cert": filepath.Join(t.TempDir(), "absent.pem")},
	}
	for name, flags := range cases {
		t.Run(name, func(t *testing.T) {
			mock := &mockEndorsementClient{}
			_, _, code := runEndorsementCmd(t, mock, attestationEndorsementPutCmd, "text", []string{"ak1"}, flags)
			assert.NotEqual(t, -1, code, "the command exits")
			assert.NotEqual(t, 0, code, "the exit is non-zero")
			assert.Zero(t, mock.calls, "no call is made")
		})
	}
}

func TestAttestationEndorsementListCmd(t *testing.T) {
	mock := &mockEndorsementClient{}
	out, _, code := runEndorsementCmd(t, mock, attestationEndorsementListCmd, "text", nil,
		map[string]string{"kind": "reference-signer"})
	assert.Equal(t, -1, code)
	assert.Equal(t, &client.ListAttestationEndorsementsRequest{Kind: client.AttestationEndorsementReferenceSigner}, mock.listReq)
	for _, want := range []string{"signer1", "signer2", "reference-signer"} {
		assert.Contains(t, out, want)
	}

	mock = &mockEndorsementClient{}
	out, _, code = runEndorsementCmd(t, mock, attestationEndorsementListCmd, "json", nil, nil)
	assert.Equal(t, -1, code)
	assert.Equal(t, &client.ListAttestationEndorsementsRequest{}, mock.listReq)
	var resp client.ListAttestationEndorsementsResponse
	require.NoError(t, json.Unmarshal([]byte(out), &resp), out)
	require.Len(t, resp.Endorsements, 2)
	assert.Equal(t, "signer1", resp.Endorsements[0].Name)

	mock = &mockEndorsementClient{}
	_, _, code = runEndorsementCmd(t, mock, attestationEndorsementListCmd, "text", nil,
		map[string]string{"kind": "ek-root"})
	assert.NotEqual(t, -1, code)
	assert.NotEqual(t, 0, code)
	assert.Zero(t, mock.calls)
}

func TestAttestationEndorsementDeleteCmd(t *testing.T) {
	mock := &mockEndorsementClient{}
	out, _, code := runEndorsementCmd(t, mock, attestationEndorsementDeleteCmd, "text", []string{"ak1"}, nil)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "ak1")
	assert.Equal(t, &client.DeleteAttestationEndorsementRequest{Name: "ak1"}, mock.delReq)

	mock = &mockEndorsementClient{fail: true}
	_, stderr, code := runEndorsementCmd(t, mock, attestationEndorsementDeleteCmd, "text", []string{"ak1"}, nil)
	assert.NotEqual(t, -1, code)
	assert.NotEqual(t, 0, code)
	assert.Contains(t, stderr, ErrDeleteAttestationEndorsementFailed.Error())
}
