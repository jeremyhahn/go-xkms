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

package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTestCSR generates a real PKCS#10 CSR for commonName and writes it,
// PEM-encoded, to a file under t.TempDir(), returning the path.
func writeTestCSR(t *testing.T, commonName string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "request.csr")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	require.NoError(t, os.WriteFile(path, pemBytes, 0600))
	return path
}

// --- ca info ---

func TestRunCAInfo_Success(t *testing.T) {
	isolateXKMSdEndpoint(t)
	address, _ := startTestXKMSd(t)
	xkmsdURL = address

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	require.NoError(t, runCAInfo(cmd, nil))

	out := buf.String()
	assert.Contains(t, out, "xkey harness root CA")
	assert.Contains(t, out, "Is CA:         true")
}

func TestRunCAInfo_MissingServer(t *testing.T) {
	isolateXKMSdEndpoint(t)
	address, cleanup := startTestXKMSd(t)
	xkmsdURL = address
	cleanup() // stop the server before the command ever dials it

	cmd := &cobra.Command{}
	err := runCAInfo(cmd, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCAInfoFailed))
	assert.True(t, errors.Is(err, ErrXKMSdConnectFailed), "want ErrXKMSdConnectFailed, got %v", err)
}

// --- ca issue ---

func TestRunCAIssue_Success(t *testing.T) {
	isolateXKMSdEndpoint(t)
	address, _ := startTestXKMSd(t)
	xkmsdURL = address

	cmd := newCAIssueCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "profile", "server"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "cn", "issue.example.com"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "san", "DNS:issue.example.com,IP:127.0.0.1"))
	outputPath := filepath.Join(t.TempDir(), "issued.pem")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "output", outputPath))

	require.NoError(t, runCAIssue(cmd, nil))

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block, "issued output must contain a PEM block")
	assert.Equal(t, "CERTIFICATE", block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "issue.example.com", cert.Subject.CommonName)
}

func TestRunCAIssue_ServerRejectsUnknownProfile(t *testing.T) {
	isolateXKMSdEndpoint(t)
	address, _ := startTestXKMSd(t)
	xkmsdURL = address

	cmd := newCAIssueCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "profile", "not-a-real-profile"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "cn", "issue.example.com"))

	err := runCAIssue(cmd, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCAIssueFailed))
}

// --- ca sign-csr ---

func TestRunCASignCSR_Success(t *testing.T) {
	isolateXKMSdEndpoint(t)
	address, _ := startTestXKMSd(t)
	xkmsdURL = address

	csrPath := writeTestCSR(t, "signed.example.com")
	outputPath := filepath.Join(t.TempDir(), "signed.pem")

	cmd := newCASignCSRCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "csr", csrPath))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "profile", "server"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "output", outputPath))

	require.NoError(t, runCASignCSR(cmd, nil))

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "signed.example.com", cert.Subject.CommonName)
}

func TestRunCASignCSR_ServerRejectsMalformedCSR(t *testing.T) {
	isolateXKMSdEndpoint(t)
	address, _ := startTestXKMSd(t)
	xkmsdURL = address

	badCSR := filepath.Join(t.TempDir(), "bad.csr")
	require.NoError(t, os.WriteFile(badCSR, []byte("-----BEGIN CERTIFICATE REQUEST-----\nnot-a-real-csr\n-----END CERTIFICATE REQUEST-----\n"), 0600))

	cmd := newCASignCSRCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "csr", badCSR))

	err := runCASignCSR(cmd, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCASignCSRFailed))
}

// --- ca revoke / check-revocation ---

// issueTestCertSerial issues a real certificate through the harness server
// and returns its serial number, for revoke/check-revocation tests that need
// a certificate the CA actually knows about.
func issueTestCertSerial(t *testing.T, cn string) string {
	t.Helper()

	cmd := newCAIssueCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "profile", "server"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "cn", cn))
	outputPath := filepath.Join(t.TempDir(), cn+".pem")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "output", outputPath))
	require.NoError(t, runCAIssue(cmd, nil))

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert.SerialNumber.Text(16)
}

func TestRunCARevoke_Success(t *testing.T) {
	isolateXKMSdEndpoint(t)
	address, _ := startTestXKMSd(t)
	xkmsdURL = address

	serial := issueTestCertSerial(t, "revoke-me.example.com")

	cmd := newCARevokeCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "reason", "key-compromise"))
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	require.NoError(t, runCARevoke(cmd, []string{serial}))
	assert.Contains(t, buf.String(), "revoked successfully")
}

// TestRunCARevoke_InvalidSerialFormat proves the server-side serial parser
// (not just the client) rejects a malformed identifier: revoking a serial
// the CA never issued is accepted (revocation is idempotent by design), but
// a serial that is not valid hex can never resolve to any certificate and
// the server reports it as a typed validation failure.
func TestRunCARevoke_InvalidSerialFormat(t *testing.T) {
	isolateXKMSdEndpoint(t)
	address, _ := startTestXKMSd(t)
	xkmsdURL = address

	cmd := newCARevokeCmd(t)
	err := runCARevoke(cmd, []string{"not-a-hex-serial!!"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCARevokeFailed))
}

func TestRunCACheckRevocation_NotRevoked(t *testing.T) {
	isolateXKMSdEndpoint(t)
	address, _ := startTestXKMSd(t)
	xkmsdURL = address

	serial := issueTestCertSerial(t, "still-valid.example.com")

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	require.NoError(t, runCACheckRevocation(cmd, []string{serial}))
	assert.Contains(t, buf.String(), "VALID (not revoked)")
}

func TestRunCACheckRevocation_Revoked(t *testing.T) {
	isolateXKMSdEndpoint(t)
	address, _ := startTestXKMSd(t)
	xkmsdURL = address

	serial := issueTestCertSerial(t, "will-be-revoked.example.com")

	revokeCmd := newCARevokeCmd(t)
	require.NoError(t, runCARevoke(revokeCmd, []string{serial}))

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, runCACheckRevocation(cmd, []string{serial}))
	assert.Contains(t, buf.String(), "REVOKED")
}

func TestRunCACheckRevocation_MissingServer(t *testing.T) {
	isolateXKMSdEndpoint(t)
	address, cleanup := startTestXKMSd(t)
	xkmsdURL = address
	cleanup()

	cmd := &cobra.Command{}
	err := runCACheckRevocation(cmd, []string{"deadbeef"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCACheckRevocationFailed))
	assert.True(t, errors.Is(err, ErrXKMSdConnectFailed))
}

// --- ca crl ---

func TestRunCACRL_Success(t *testing.T) {
	isolateXKMSdEndpoint(t)
	address, _ := startTestXKMSd(t)
	xkmsdURL = address

	outputPath := filepath.Join(t.TempDir(), "crl.pem")
	cmd := newCAOutputCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "output", outputPath))

	require.NoError(t, runCACRL(cmd, nil))

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	assert.Equal(t, "X509 CRL", block.Type)
}

func TestRunCACRL_MissingServer(t *testing.T) {
	isolateXKMSdEndpoint(t)
	address, cleanup := startTestXKMSd(t)
	xkmsdURL = address
	cleanup()

	cmd := newCAOutputCmd(t)
	err := runCACRL(cmd, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCACRLFailed))
	assert.True(t, errors.Is(err, ErrXKMSdConnectFailed))
}

// --- ca bundle ---

func TestRunCABundle_Success(t *testing.T) {
	isolateXKMSdEndpoint(t)
	address, _ := startTestXKMSd(t)
	xkmsdURL = address

	outputPath := filepath.Join(t.TempDir(), "bundle.pem")
	cmd := newCAOutputCmd(t)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "output", outputPath))

	require.NoError(t, runCABundle(cmd, nil))

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
}

func TestRunCABundle_MissingServer(t *testing.T) {
	isolateXKMSdEndpoint(t)
	address, cleanup := startTestXKMSd(t)
	xkmsdURL = address
	cleanup()

	cmd := newCAOutputCmd(t)
	err := runCABundle(cmd, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCABundleFailed))
	assert.True(t, errors.Is(err, ErrXKMSdConnectFailed))
}
