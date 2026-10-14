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

// record_output_test.go pins the platform secret list and store status,
// a password entry, and the certificate binding report.
package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// runPlatform runs fn against mock in the given format and returns the
// printed output, the exit code and stderr.
func runPlatform(t *testing.T, mock *mockPlatformClient, format string, fn func(*Config, *Printer)) (string, int, string) {
	t.Helper()
	cfg := newPlatformConfig(mock)
	cfg.OutputFormat = format
	withGlobalConfig(t, cfg)
	var buf bytes.Buffer
	code, stderr := runKeyExt(t, func() { fn(cfg, NewPrinter(format, &buf)) })
	return buf.String(), code, stderr
}

func TestPlatformList_Outputs(t *testing.T) {
	names := &mockPlatformClient{listResp: &transport.SealStoreListResponse{Names: []string{"db-password", "tls-key"}}}

	out, code, _ := runPlatform(t, names, "table", platformList)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "  - tls-key")
	assert.Contains(t, out, "Total: 2 secret(s)")

	out, code, _ = runPlatform(t, names, "json", platformList)
	assert.Equal(t, -1, code)
	assert.JSONEq(t, `{"names":["db-password","tls-key"],"total":2}`, out)

	out, code, _ = runPlatform(t, &mockPlatformClient{listResp: &transport.SealStoreListResponse{}}, "text", platformList)
	assert.Equal(t, -1, code)
	assert.Equal(t, "No secrets stored\n", out)
}

func TestPlatformStatus_Outputs(t *testing.T) {
	mock := &mockPlatformClient{statusResp: &transport.SealStoreStatusResponse{
		Available: true, SealerID: "tpm2-pcr", SecretCount: 1, SecretNames: []string{"db-password"},
	}}

	out, code, _ := runPlatform(t, mock, "text", platformStatus)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "  Available: true")
	assert.Contains(t, out, "  Sealer:    tpm2-pcr")
	assert.Contains(t, out, "    - db-password")

	out, code, _ = runPlatform(t, mock, "json", platformStatus)
	assert.Equal(t, -1, code)
	var got transport.SealStoreStatusResponse
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, "tpm2-pcr", got.SealerID)

	out, _, _ = runPlatform(t, &mockPlatformClient{statusResp: &transport.SealStoreStatusResponse{}}, "text", platformStatus)
	assert.NotContains(t, out, "Sealer:", "an unsealed store names no sealer")
}

func TestPlatformListAndStatus_Failures(t *testing.T) {
	cases := []struct {
		name     string
		run      func(*Config, *Printer)
		mock     *mockPlatformClient
		sentinel error
	}{
		{"list connect", platformList, &mockPlatformClient{mockBackendsClient: mockBackendsClient{connectErr: errListBoom}}, ErrConnectFailed},
		{"list sdk call", platformList, &mockPlatformClient{listErr: errListBoom}, ErrListPlatformSecretsFailed},
		{"status connect", platformStatus, &mockPlatformClient{mockBackendsClient: mockBackendsClient{connectErr: errListBoom}}, ErrConnectFailed},
		{"status sdk call", platformStatus, &mockPlatformClient{statusErr: errListBoom}, ErrPlatformStoreStatusFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code, stderr := runPlatform(t, tc.mock, "text", tc.run)
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, tc.sentinel.Error())
			assert.Empty(t, out)
		})
	}
}

func TestPrintPasswordEntry_OptionalFields(t *testing.T) {
	full := &client.PasswordGetResponse{
		ID: "id-1", Name: "github", Username: "octocat", Password: "hunter2",
		URL: "https://github.com", Notes: "2FA on", FolderPath: "/work",
		ExpiresAt: "2027-01-01T00:00:00Z", CreatedAt: "c", UpdatedAt: "u",
	}
	var buf bytes.Buffer
	printPasswordEntry(NewPrinter("text", &buf), full)
	for _, want := range []string{
		"  Username: octocat", "  Password: hunter2", "  URL:      https://github.com",
		"  Notes:    2FA on", "  Folder:   /work", "  Expires:  2027-01-01T00:00:00Z",
	} {
		assert.Contains(t, buf.String(), want)
	}

	buf.Reset()
	printPasswordEntry(NewPrinter("text", &buf), &client.PasswordGetResponse{ID: "id-2", Name: "bare"})
	for _, absent := range []string{"Username:", "Password:", "URL:", "Notes:", "Folder:", "Expires:"} {
		assert.NotContains(t, buf.String(), absent)
	}
}

func TestPrintPasswordEntry_JSON(t *testing.T) {
	var buf bytes.Buffer
	printPasswordEntry(NewPrinter("json", &buf), &client.PasswordGetResponse{ID: "id-1", Name: "github"})
	var got client.PasswordGetResponse
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, "github", got.Name)
}

// runBindCert runs userBindCert against mock and returns stdout plus the
// printer output, the exit code and stderr.
func runBindCert(t *testing.T, mock *mockUserExtClient, format string, notAfter int64) (string, int, string) {
	t.Helper()
	cfg := &Config{OutputFormat: format, ClientFactory: func(*Config) (client.Client, error) { return mock, nil }}
	withGlobalConfig(t, cfg)
	var buf bytes.Buffer
	var code int
	var stderr string
	stdout := captureStdout(t, func() {
		code, stderr = runKeyExt(t, func() { userBindCert(cfg, NewPrinter(format, &buf), "alice", "tp-1", notAfter) })
	})
	return stdout + buf.String(), code, stderr
}

func TestUserBindCert_Outputs(t *testing.T) {
	mock := &mockUserExtClient{}
	out, code, _ := runBindCert(t, mock, "text", 1793102400)
	assert.Equal(t, -1, code)
	assert.Equal(t, "alice", mock.gotBindUsername)
	assert.Equal(t, "tp-1", mock.gotBindThumbprint)
	assert.Contains(t, out, "  Thumbprint: tp-1")
	assert.Contains(t, out, "  Not After:  2026-10-27T12:00:00Z")

	out, _, _ = runBindCert(t, &mockUserExtClient{}, "text", 0)
	assert.NotContains(t, out, "Not After", "an open-ended binding prints no expiry")

	out, code, _ = runBindCert(t, &mockUserExtClient{}, "json", 0)
	assert.Equal(t, -1, code)
	assert.JSONEq(t, `{"success":true,"username":"alice","thumbprint":"tp-1","not_after":0}`, out)
}

func TestUserBindCert_Failures(t *testing.T) {
	cases := []struct {
		name     string
		mock     *mockUserExtClient
		sentinel error
	}{
		{"connect", &mockUserExtClient{mockUserClient: mockUserClient{connectErr: errListBoom}}, ErrConnectFailed},
		{"bind", &mockUserExtClient{bindErr: errListBoom}, ErrBindCertFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code, stderr := runBindCert(t, tc.mock, "text", 0)
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, tc.sentinel.Error())
			assert.NotContains(t, out, "bound")
		})
	}
}
