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

// detail_printers_test.go pins the single-record outputs: a platform
// secret, the personal vault status, a user update, an activation invite,
// and the PEM certificate loader behind "user bind-cert".
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// runPlatformGet runs platformGet against mock and returns the printed
// output, the exit code and stderr.
func runPlatformGet(t *testing.T, mock *mockPlatformClient, format, outputFile string) (string, int, string) {
	t.Helper()
	cfg := newPlatformConfig(mock)
	cfg.OutputFormat = format
	withGlobalConfig(t, cfg)
	var buf bytes.Buffer
	code, stderr := runKeyExt(t, func() { platformGet(cfg, NewPrinter(format, &buf), "db-password", outputFile) })
	return buf.String(), code, stderr
}

func platformSecretMock() *mockPlatformClient {
	return &mockPlatformClient{getResp: &transport.SealStoreGetResponse{Name: "db-password", Secret: []byte("s3cret")}}
}

func TestPlatformGet_Text(t *testing.T) {
	mock := platformSecretMock()
	out, code, _ := runPlatformGet(t, mock, "text", "")
	assert.Equal(t, -1, code)
	assert.Equal(t, "db-password", mock.gotGetReq.Name)
	assert.Contains(t, out, "  Name:   db-password")
	assert.Contains(t, out, "  Secret: "+base64.StdEncoding.EncodeToString([]byte("s3cret")))
}

func TestPlatformGet_JSON(t *testing.T) {
	out, code, _ := runPlatformGet(t, platformSecretMock(), "json", "")
	assert.Equal(t, -1, code)
	var got transport.SealStoreGetResponse
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, []byte("s3cret"), got.Secret)
}

func TestPlatformGet_WritesOutputFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.bin")
	out, code, _ := runPlatformGet(t, platformSecretMock(), "text", path)
	assert.Equal(t, -1, code)
	assert.NotContains(t, out, base64.StdEncoding.EncodeToString([]byte("s3cret")), "a secret written to a file is not echoed")

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, []byte("s3cret"), data)
}

func TestPlatformGet_Failures(t *testing.T) {
	cases := []struct {
		name     string
		mock     *mockPlatformClient
		output   func(t *testing.T) string
		sentinel error
	}{
		{"connect", &mockPlatformClient{mockBackendsClient: mockBackendsClient{connectErr: errListBoom}}, nil, ErrConnectFailed},
		{"sdk call", &mockPlatformClient{getErr: errListBoom}, nil, ErrGetPlatformSecretFailed},
		{"unwritable output", platformSecretMock(), func(t *testing.T) string {
			return filepath.Join(t.TempDir(), "missing", "secret.bin")
		}, ErrWriteSecretFileFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outputFile := ""
			if tc.output != nil {
				outputFile = tc.output(t)
			}
			out, code, stderr := runPlatformGet(t, tc.mock, "text", outputFile)
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, tc.sentinel.Error())
			assert.Empty(t, out)
		})
	}
}

// runVaultStatus runs passwordVaultStatus against resp in the given format.
func runVaultStatus(t *testing.T, resp *transport.PasswordVaultStatusResponse, format string) (string, int) {
	t.Helper()
	cfg := newPasswordConfig(&mockPasswordClient{vaultStatusResp: resp})
	cfg.OutputFormat = format
	withGlobalConfig(t, cfg)
	var buf bytes.Buffer
	code, _ := runKeyExt(t, func() { passwordVaultStatus(cfg, NewPrinter(format, &buf)) })
	return buf.String(), code
}

func TestPasswordVaultStatus_KeyFactorAndPasskeys(t *testing.T) {
	out, code := runVaultStatus(t, &transport.PasswordVaultStatusResponse{
		Initialized: true,
		Factors: []transport.PasswordVaultFactor{{
			ID: "f-2", Factor: "key", Label: "tpm", CreatedAt: "2026-10-14T00:00:00Z",
			KeyFingerprint: "0123456789abcdef0123",
			KeyRef:         transport.PasswordVaultKeyRef{Backend: "tpm2", KeyID: "vault-key", TPMPolicy: "pcr7"},
		}},
		PasskeyRPID: "console.example.com",
	}, "text")
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "      key tpm2/vault-key  fingerprint 0123456789abc...  pcr7")
	assert.Contains(t, out, "  Passkeys for: console.example.com")
}

func TestPasswordVaultStatus_NoFactors(t *testing.T) {
	out, code := runVaultStatus(t, &transport.PasswordVaultStatusResponse{}, "table")
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "  Factors:     none")
	assert.NotContains(t, out, "Passkeys for")
}

func TestPasswordVaultStatus_JSON(t *testing.T) {
	out, code := runVaultStatus(t, &transport.PasswordVaultStatusResponse{Initialized: true, Unlocked: false}, "json")
	assert.Equal(t, -1, code)
	var got transport.PasswordVaultStatusResponse
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.True(t, got.Initialized)
	assert.False(t, got.Unlocked)
}

func TestPasswordVaultStatus_ConnectFailure(t *testing.T) {
	cfg := newPasswordConfig(&mockPasswordClient{mockBackendsClient: mockBackendsClient{connectErr: errListBoom}})
	withGlobalConfig(t, cfg)
	var buf bytes.Buffer
	code, stderr := runKeyExt(t, func() { passwordVaultStatus(cfg, NewPrinter("text", &buf)) })
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, ErrConnectFailed.Error())
	assert.Empty(t, buf.String())
}

// runUserUpdate runs userUpdate against mock and returns stdout plus the
// printer output, the exit code and stderr.
func runUserUpdate(t *testing.T, mock *mockUserClient, format string, enable bool) (string, int, string) {
	t.Helper()
	cfg := &Config{
		OutputFormat:  format,
		ClientFactory: func(*Config) (client.Client, error) { return mock, nil },
	}
	withGlobalConfig(t, cfg)
	var buf bytes.Buffer
	var code int
	var stderr string
	stdout := captureStdout(t, func() {
		code, stderr = runKeyExt(t, func() { userUpdate(cfg, NewPrinter(format, &buf), "alice", enable) })
	})
	return stdout + buf.String(), code, stderr
}

func updatedUserMock(enabled bool) *mockUserClient {
	return &mockUserClient{getUserResp: &transport.GetUserResponse{User: transport.UserInfo{Username: "alice", Enabled: enabled}}}
}

func TestUserUpdate_ReportsServerState(t *testing.T) {
	out, code, _ := runUserUpdate(t, updatedUserMock(true), "text", true)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "User 'alice' updated (enabled: true).")

	out, code, _ = runUserUpdate(t, updatedUserMock(false), "text", false)
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "User 'alice' updated (enabled: false).")
}

func TestUserUpdate_JSON(t *testing.T) {
	out, code, _ := runUserUpdate(t, updatedUserMock(false), "json", false)
	assert.Equal(t, -1, code)
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, true, got["success"])
	assert.Equal(t, "alice", got["username"])
	assert.Equal(t, false, got["enabled"])
	assert.Contains(t, got, "roles")
}

func TestUserUpdate_Failures(t *testing.T) {
	cases := []struct {
		name     string
		mock     *mockUserClient
		enable   bool
		sentinel error
	}{
		{"connect", &mockUserClient{connectErr: errListBoom}, true, ErrConnectFailed},
		{"enable", &mockUserClient{enableUserErr: errListBoom}, true, ErrEnableUserFailed},
		{"disable", &mockUserClient{disableUserErr: errListBoom}, false, ErrDisableUserFailed},
		{"read back", &mockUserClient{getUserErr: errListBoom}, true, ErrGetUserFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code, stderr := runUserUpdate(t, tc.mock, "text", tc.enable)
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, tc.sentinel.Error())
			assert.NotContains(t, out, "updated")
		})
	}
}

func TestUserUpdate_ClientFactoryFailure(t *testing.T) {
	cfg := &Config{OutputFormat: "text", ClientFactory: func(*Config) (client.Client, error) { return nil, errListBoom }}
	withGlobalConfig(t, cfg)
	code, stderr := runKeyExt(t, func() { userUpdate(cfg, NewPrinter("text", &bytes.Buffer{}), "alice", true) })
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, ErrCreateClientFailed.Error())
}

func testInvite() *client.InviteInfo {
	return &client.InviteInfo{
		Token:     "inv-token",
		URL:       "https://console.example.com/invite/inv-token",
		ExpiresAt: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC),
	}
}

func TestPrintInvite_Text(t *testing.T) {
	cfg := &Config{OutputFormat: "text"}
	var err error
	out := captureStdout(t, func() { err = printInvite(NewPrinter("text", &bytes.Buffer{}), cfg, testInvite()) })
	require.NoError(t, err)
	assert.Contains(t, out, "  Token:      inv-token")
	assert.Contains(t, out, "  Link:       https://console.example.com/invite/inv-token")
	assert.Contains(t, out, "  Expires:    2026-10-21T12:00:00Z")

	invite := testInvite()
	invite.URL = ""
	out = captureStdout(t, func() { err = printInvite(NewPrinter("text", &bytes.Buffer{}), cfg, invite) })
	require.NoError(t, err)
	assert.NotContains(t, out, "Link:", "an invite without a URL prints no link line")
}

func TestPrintInvite_JSON(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, printInvite(NewPrinter("json", &buf), &Config{OutputFormat: "json"}, testInvite()))
	assert.JSONEq(t, `{"invite_token":"inv-token","invite_url":"https://console.example.com/invite/inv-token","invite_expires_at":"2026-10-21T12:00:00Z"}`, buf.String())
}

func TestPrintInvite_NilPrintsNothing(t *testing.T) {
	var buf bytes.Buffer
	var err error
	out := captureStdout(t, func() { err = printInvite(NewPrinter("json", &buf), &Config{OutputFormat: "json"}, nil) })
	require.NoError(t, err)
	assert.Empty(t, out)
	assert.Empty(t, buf.String())
}

// writePEMCertificate writes a self-signed certificate to dir and returns
// its path.
func writePEMCertificate(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "alice"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	path := filepath.Join(dir, "alice.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	return path
}

func TestLoadPEMCertificate(t *testing.T) {
	cert, err := loadPEMCertificate(writePEMCertificate(t, t.TempDir()))
	require.NoError(t, err)
	assert.Equal(t, "alice", cert.Subject.CommonName)
}

func TestLoadPEMCertificate_Errors(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(notPEM, []byte("not a certificate"), 0600))
	badDER := filepath.Join(dir, "bad.pem")
	require.NoError(t, os.WriteFile(badDER, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}), 0600))

	_, err := loadPEMCertificate(filepath.Join(dir, "absent.pem"))
	var readErr *CertFileReadError
	assert.ErrorAs(t, err, &readErr)

	_, err = loadPEMCertificate(notPEM)
	var decodeErr *PEMBlockDecodeError
	assert.ErrorAs(t, err, &decodeErr)

	_, err = loadPEMCertificate(badDER)
	var parseErr *CertFileParseError
	assert.ErrorAs(t, err, &parseErr)
}
