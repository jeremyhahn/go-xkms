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

// list_printers_test.go pins the output of the bootstrap listener keys, the
// cluster member list and the password list in every output format.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

var errListBoom = errors.New("list boom")

// mockBootstrapClient serves a fixed bootstrap listener keys response.
type mockBootstrapClient struct {
	mockBackendsClient
	keysResp *transport.BootstrapListenerKeysResponse
	keysErr  error
}

func (m *mockBootstrapClient) BootstrapListenerKeys(context.Context) (*transport.BootstrapListenerKeysResponse, error) {
	return m.keysResp, m.keysErr
}

// runShowKeys runs the show-keys command against mock in the given format
// and returns its output and error.
func runShowKeys(t *testing.T, mock *mockBootstrapClient, format string) (string, error) {
	t.Helper()
	withGlobalConfig(t, &Config{
		OutputFormat:  format,
		ClientFactory: func(*Config) (client.Client, error) { return mock, nil },
	})
	var buf bytes.Buffer
	cmd := &cobra.Command{Use: "show-keys"}
	cmd.SetOut(&buf)
	err := runBootstrapShowKeysCmd(cmd, nil)
	return buf.String(), err
}

func TestBootstrapShowKeys_Text(t *testing.T) {
	out, err := runShowKeys(t, &mockBootstrapClient{keysResp: &transport.BootstrapListenerKeysResponse{
		NoisePublicKey: "noise-pub", P256PublicKey: "p256-pub",
	}}, "text")
	require.NoError(t, err)
	assert.Contains(t, out, "Noise_NK Public Key (--noise-key): noise-pub")
	assert.Contains(t, out, "P-256 Public Key (--p256-key):     p256-pub")
}

func TestBootstrapShowKeys_JSONOmitsAbsentKeys(t *testing.T) {
	out, err := runShowKeys(t, &mockBootstrapClient{keysResp: &transport.BootstrapListenerKeysResponse{
		NoisePublicKey: "noise-pub",
	}}, "json")
	require.NoError(t, err)
	assert.JSONEq(t, `{"noise_public_key":"noise-pub"}`, out)

	out, err = runShowKeys(t, &mockBootstrapClient{keysResp: &transport.BootstrapListenerKeysResponse{
		P256PublicKey: "p256-pub",
	}}, "json")
	require.NoError(t, err)
	assert.JSONEq(t, `{"p256_public_key":"p256-pub"}`, out)
}

func TestBootstrapShowKeys_Failures(t *testing.T) {
	cases := []struct {
		name     string
		mock     *mockBootstrapClient
		format   string
		sentinel error
	}{
		{"connect", &mockBootstrapClient{mockBackendsClient: mockBackendsClient{connectErr: errListBoom}}, "text", ErrConnectFailed},
		{"sdk call", &mockBootstrapClient{keysErr: errListBoom}, "text", ErrGetBootstrapListenerKeysFailed},
		{"unknown format", &mockBootstrapClient{keysResp: &transport.BootstrapListenerKeysResponse{}}, "yaml", ErrUnknownOutputFormat},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runShowKeys(t, tc.mock, tc.format)
			assert.ErrorIs(t, err, tc.sentinel)
			assert.Empty(t, out)
		})
	}
}

func clusterMembers() []qrdbsdk.Member {
	return []qrdbsdk.Member{
		{ReplicaID: 1, Address: "10.0.0.1:7000", IsLeader: true, APIEndpoints: map[qrdbsdk.APIProtocol]string{"quic": "10.0.0.1:8443", "grpc": "10.0.0.1:9090"}},
		{ReplicaID: 2, Address: "10.0.0.2:7000"},
	}
}

func TestPrintClusterMembers_Text(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, NewPrinter("text", &buf).PrintClusterMembers(clusterMembers()))
	assert.Contains(t, buf.String(), "  - replica 1 at 10.0.0.1:7000 [leader] (api: grpc=10.0.0.1:9090,quic=10.0.0.1:8443)")
	assert.Contains(t, buf.String(), "  - replica 2 at 10.0.0.2:7000 (api: -)")
}

func TestPrintClusterMembers_Table(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, NewPrinter("table", &buf).PrintClusterMembers(clusterMembers()))
	out := buf.String()
	assert.Contains(t, out, "REPLICA ID")
	assert.Contains(t, out, "API ENDPOINTS")
	assert.Regexp(t, `1\s+10\.0\.0\.1:7000\s+true\s+grpc=10\.0\.0\.1:9090,quic=10\.0\.0\.1:8443`, out)
	assert.Regexp(t, `2\s+10\.0\.0\.2:7000\s+false\s+-`, out)
}

func TestPrintClusterMembers_Empty(t *testing.T) {
	for _, format := range []string{"text", "table"} {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			require.NoError(t, NewPrinter(format, &buf).PrintClusterMembers(nil))
			assert.Equal(t, "No members found\n", buf.String())
		})
	}
}

func TestPrintClusterMembers_UnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	err := NewPrinter("yaml", &buf).PrintClusterMembers(clusterMembers())
	assert.ErrorIs(t, err, ErrUnknownOutputFormat)
	assert.Empty(t, buf.String())
}

// runPasswordList runs passwordList against mock in the given format and
// returns the printed output, the exit code and stderr.
func runPasswordList(t *testing.T, mock *mockPasswordClient, format string) (string, int, string) {
	t.Helper()
	cfg := newPasswordConfig(mock)
	cfg.OutputFormat = format
	withGlobalConfig(t, cfg)
	var buf bytes.Buffer
	code, stderr := runKeyExt(t, func() {
		passwordList(cfg, NewPrinter(format, &buf), &client.PasswordListRequest{})
	})
	return buf.String(), code, stderr
}

func passwordListMock() *mockPasswordClient {
	return &mockPasswordClient{listResp: &transport.PasswordListResponse{Passwords: []transport.PasswordGetResponse{
		{ID: "id-1", Name: "github", Username: "octocat", FolderPath: "/work/source-control/hosted"},
	}}}
}

func TestPasswordList_Table(t *testing.T) {
	out, code, _ := runPasswordList(t, passwordListMock(), "table")
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "USERNAME")
	assert.Regexp(t, `id-1\s+github\s+octocat\s+/work/source-cont\.\.\.`, out)
	assert.Contains(t, out, "Total: 1 password(s)")
}

func TestPasswordList_JSON(t *testing.T) {
	out, code, _ := runPasswordList(t, passwordListMock(), "json")
	assert.Equal(t, -1, code)
	var got struct {
		Passwords []transport.PasswordGetResponse `json:"passwords"`
		Total     int                             `json:"total"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, 1, got.Total)
	require.Len(t, got.Passwords, 1)
	assert.Equal(t, "github", got.Passwords[0].Name)
}

func TestPasswordList_Empty(t *testing.T) {
	for _, format := range []string{"text", "table"} {
		t.Run(format, func(t *testing.T) {
			out, code, _ := runPasswordList(t, &mockPasswordClient{listResp: &transport.PasswordListResponse{}}, format)
			assert.Equal(t, -1, code)
			assert.Equal(t, "No passwords found\n", out)
		})
	}
}

func TestPasswordList_ConnectFailure(t *testing.T) {
	mock := &mockPasswordClient{mockBackendsClient: mockBackendsClient{connectErr: errListBoom}}
	out, code, stderr := runPasswordList(t, mock, "text")
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, ErrConnectFailed.Error())
	assert.Empty(t, out)
}
