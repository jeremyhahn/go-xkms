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

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// TCG CA Command Structure Tests
// =============================================================================

func TestCATCGCmd_Exists(t *testing.T) {
	assert.NotNil(t, caTCGCmd)
	assert.Equal(t, "tcg", caTCGCmd.Use)
	assert.NotEmpty(t, caTCGCmd.Short)
}

func TestCATCGCmd_HasSubcommands(t *testing.T) {
	expected := []string{"issue-ek", "issue-ak", "sign-csr", "enroll"}
	found := make(map[string]bool)
	for _, cmd := range caTCGCmd.Commands() {
		found[cmd.Name()] = true
	}
	for _, name := range expected {
		assert.True(t, found[name], "expected subcommand %q not found", name)
	}
}

func TestCATCGIssueEKCmd_RequiredFlags(t *testing.T) {
	assert.NotNil(t, caTCGIssueEKCmd.Flags().Lookup("cn"))
	assert.NotNil(t, caTCGIssueEKCmd.Flags().Lookup("ek-pub"))
}

func TestCATCGIssueAKCmd_RequiredFlags(t *testing.T) {
	assert.NotNil(t, caTCGIssueAKCmd.Flags().Lookup("cn"))
	assert.NotNil(t, caTCGIssueAKCmd.Flags().Lookup("pub"))
}

func TestCATCGSignCSRCmd_RequiredFlags(t *testing.T) {
	assert.NotNil(t, caTCGSignCSRCmd.Flags().Lookup("cn"))
	assert.NotNil(t, caTCGSignCSRCmd.Flags().Lookup("csr"))
}

func TestCATCGEnrollCmd_RequiredFlags(t *testing.T) {
	assert.NotNil(t, caTCGEnrollCmd.Flags().Lookup("cn"))
	assert.NotNil(t, caTCGEnrollCmd.Flags().Lookup("packed-csr"))
}

// =============================================================================
// issueEKCertificate tests
// =============================================================================

func TestIssueEKCertificate_TextOutput_Success(t *testing.T) {
	mc := newMockCAClient()
	mc.issueEKResp = &transport.IssueEKCertificateResponse{
		CertificatePEM: []byte("ek-cert-pem"),
		SerialNumber:   "EK01",
	}
	cfg, _ := setupCATest(t, mc, "text")

	tmpDir := t.TempDir()
	ekPubFile := filepath.Join(tmpDir, "ek_pub.der")
	require.NoError(t, os.WriteFile(ekPubFile, []byte("ek-pub-key"), 0644))

	oldEKPub := tcgEKPubFile
	tcgEKPubFile = ekPubFile
	oldOutput := tcgOutputFile
	tcgOutputFile = ""
	defer func() { tcgEKPubFile = oldEKPub; tcgOutputFile = oldOutput }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	issueEKCertificate(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	assert.Contains(t, stdoutBuf.String(), "EK01")
	assert.Contains(t, stdoutBuf.String(), "ek-cert-pem")
}

func TestIssueEKCertificate_JSONOutput_Success(t *testing.T) {
	mc := newMockCAClient()
	mc.issueEKResp = &transport.IssueEKCertificateResponse{
		CertificatePEM: []byte("ek-pem"),
		SerialNumber:   "EK02",
	}
	cfg, _ := setupCATest(t, mc, "json")

	tmpDir := t.TempDir()
	ekPubFile := filepath.Join(tmpDir, "ek_pub.der")
	require.NoError(t, os.WriteFile(ekPubFile, []byte("key"), 0644))

	oldEKPub := tcgEKPubFile
	tcgEKPubFile = ekPubFile
	oldOutput := tcgOutputFile
	tcgOutputFile = ""
	defer func() { tcgEKPubFile = oldEKPub; tcgOutputFile = oldOutput }()

	var buf bytes.Buffer
	printer := NewPrinter("json", &buf)
	issueEKCertificate(cfg, printer)

	assert.Contains(t, buf.String(), "EK02")
	assert.Contains(t, buf.String(), "certificate_pem")
}

func TestIssueEKCertificate_WriteToFile(t *testing.T) {
	mc := newMockCAClient()
	mc.issueEKResp = &transport.IssueEKCertificateResponse{
		CertificatePEM: []byte("ek-cert-data"),
		SerialNumber:   "EK03",
	}
	cfg, _ := setupCATest(t, mc, "text")

	tmpDir := t.TempDir()
	ekPubFile := filepath.Join(tmpDir, "ek_pub.der")
	require.NoError(t, os.WriteFile(ekPubFile, []byte("key"), 0644))
	outFile := filepath.Join(tmpDir, "ek_cert.pem")

	oldEKPub := tcgEKPubFile
	tcgEKPubFile = ekPubFile
	oldOutput := tcgOutputFile
	tcgOutputFile = outFile
	defer func() { tcgEKPubFile = oldEKPub; tcgOutputFile = oldOutput }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	issueEKCertificate(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, "ek-cert-data", string(data))
}

func TestIssueEKCertificate_JSONOutput_WithOutputFile(t *testing.T) {
	mc := newMockCAClient()
	mc.issueEKResp = &transport.IssueEKCertificateResponse{
		CertificatePEM: []byte("pem"),
		SerialNumber:   "EK04",
	}
	cfg, _ := setupCATest(t, mc, "json")

	tmpDir := t.TempDir()
	ekPubFile := filepath.Join(tmpDir, "ek_pub.der")
	require.NoError(t, os.WriteFile(ekPubFile, []byte("key"), 0644))
	outFile := filepath.Join(tmpDir, "ek.pem")

	oldEKPub := tcgEKPubFile
	tcgEKPubFile = ekPubFile
	oldOutput := tcgOutputFile
	tcgOutputFile = outFile
	defer func() { tcgEKPubFile = oldEKPub; tcgOutputFile = oldOutput }()

	var buf bytes.Buffer
	printer := NewPrinter("json", &buf)
	issueEKCertificate(cfg, printer)

	assert.Contains(t, buf.String(), "cert_file")
}

func TestIssueEKCertificate_MissingKeyFile(t *testing.T) {
	mc := newMockCAClient()
	cfg, _ := setupCATest(t, mc, "text")

	oldEKPub := tcgEKPubFile
	tcgEKPubFile = "/nonexistent/key.der"
	defer func() { tcgEKPubFile = oldEKPub }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		issueEKCertificate(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestIssueEKCertificate_ClientError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(_ *Config) (client.Client, error) {
		return nil, errors.New("fail")
	}
	origConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = origConfig }()

	tmpDir := t.TempDir()
	ekPubFile := filepath.Join(tmpDir, "ek_pub.der")
	require.NoError(t, os.WriteFile(ekPubFile, []byte("key"), 0644))
	oldEKPub := tcgEKPubFile
	tcgEKPubFile = ekPubFile
	defer func() { tcgEKPubFile = oldEKPub }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		issueEKCertificate(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestIssueEKCertificate_ConnectError(t *testing.T) {
	mc := newMockCAClient()
	mc.connectErr = errors.New("connect fail")
	cfg, _ := setupCATest(t, mc, "text")

	tmpDir := t.TempDir()
	ekPubFile := filepath.Join(tmpDir, "ek_pub.der")
	require.NoError(t, os.WriteFile(ekPubFile, []byte("key"), 0644))
	oldEKPub := tcgEKPubFile
	tcgEKPubFile = ekPubFile
	defer func() { tcgEKPubFile = oldEKPub }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		issueEKCertificate(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestIssueEKCertificate_APIError(t *testing.T) {
	mc := newMockCAClient()
	mc.issueEKErr = errors.New("issue ek error")
	cfg, _ := setupCATest(t, mc, "text")

	tmpDir := t.TempDir()
	ekPubFile := filepath.Join(tmpDir, "ek_pub.der")
	require.NoError(t, os.WriteFile(ekPubFile, []byte("key"), 0644))
	oldEKPub := tcgEKPubFile
	tcgEKPubFile = ekPubFile
	defer func() { tcgEKPubFile = oldEKPub }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		issueEKCertificate(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

// =============================================================================
// issueAKCertificate tests
// =============================================================================

func TestIssueAKCertificate_TextOutput_Success(t *testing.T) {
	mc := newMockCAClient()
	mc.issueAKResp = &transport.IssueAKCertificateResponse{
		CertificatePEM: []byte("ak-cert-pem"),
		SerialNumber:   "AK01",
	}
	cfg, _ := setupCATest(t, mc, "text")

	tmpDir := t.TempDir()
	pubFile := filepath.Join(tmpDir, "ak_pub.der")
	require.NoError(t, os.WriteFile(pubFile, []byte("ak-key"), 0644))

	oldPub := tcgPubFile
	tcgPubFile = pubFile
	oldOutput := tcgOutputFile
	tcgOutputFile = ""
	defer func() { tcgPubFile = oldPub; tcgOutputFile = oldOutput }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	issueAKCertificate(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	assert.Contains(t, stdoutBuf.String(), "AK01")
}

func TestIssueAKCertificate_JSONOutput_Success(t *testing.T) {
	mc := newMockCAClient()
	mc.issueAKResp = &transport.IssueAKCertificateResponse{
		CertificatePEM: []byte("ak-pem"),
		SerialNumber:   "AK02",
	}
	cfg, _ := setupCATest(t, mc, "json")

	tmpDir := t.TempDir()
	pubFile := filepath.Join(tmpDir, "ak_pub.der")
	require.NoError(t, os.WriteFile(pubFile, []byte("key"), 0644))

	oldPub := tcgPubFile
	tcgPubFile = pubFile
	oldOutput := tcgOutputFile
	tcgOutputFile = ""
	defer func() { tcgPubFile = oldPub; tcgOutputFile = oldOutput }()

	var buf bytes.Buffer
	printer := NewPrinter("json", &buf)
	issueAKCertificate(cfg, printer)

	assert.Contains(t, buf.String(), "AK02")
}

func TestIssueAKCertificate_WriteToFile(t *testing.T) {
	mc := newMockCAClient()
	mc.issueAKResp = &transport.IssueAKCertificateResponse{
		CertificatePEM: []byte("ak-cert-data"),
		SerialNumber:   "AK03",
	}
	cfg, _ := setupCATest(t, mc, "text")

	tmpDir := t.TempDir()
	pubFile := filepath.Join(tmpDir, "ak_pub.der")
	require.NoError(t, os.WriteFile(pubFile, []byte("key"), 0644))
	outFile := filepath.Join(tmpDir, "ak_cert.pem")

	oldPub := tcgPubFile
	tcgPubFile = pubFile
	oldOutput := tcgOutputFile
	tcgOutputFile = outFile
	defer func() { tcgPubFile = oldPub; tcgOutputFile = oldOutput }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	issueAKCertificate(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Equal(t, "ak-cert-data", string(data))
}

func TestIssueAKCertificate_MissingKeyFile(t *testing.T) {
	mc := newMockCAClient()
	cfg, _ := setupCATest(t, mc, "text")

	oldPub := tcgPubFile
	tcgPubFile = "/nonexistent/key.der"
	defer func() { tcgPubFile = oldPub }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		issueAKCertificate(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestIssueAKCertificate_ClientError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(_ *Config) (client.Client, error) {
		return nil, errors.New("fail")
	}
	origConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = origConfig }()

	tmpDir := t.TempDir()
	pubFile := filepath.Join(tmpDir, "ak.der")
	require.NoError(t, os.WriteFile(pubFile, []byte("key"), 0644))
	oldPub := tcgPubFile
	tcgPubFile = pubFile
	defer func() { tcgPubFile = oldPub }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		issueAKCertificate(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestIssueAKCertificate_ConnectError(t *testing.T) {
	mc := newMockCAClient()
	mc.connectErr = errors.New("connect fail")
	cfg, _ := setupCATest(t, mc, "text")

	tmpDir := t.TempDir()
	pubFile := filepath.Join(tmpDir, "ak.der")
	require.NoError(t, os.WriteFile(pubFile, []byte("key"), 0644))
	oldPub := tcgPubFile
	tcgPubFile = pubFile
	defer func() { tcgPubFile = oldPub }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		issueAKCertificate(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestIssueAKCertificate_APIError(t *testing.T) {
	mc := newMockCAClient()
	mc.issueAKErr = errors.New("issue ak error")
	cfg, _ := setupCATest(t, mc, "text")

	tmpDir := t.TempDir()
	pubFile := filepath.Join(tmpDir, "ak.der")
	require.NoError(t, os.WriteFile(pubFile, []byte("key"), 0644))
	oldPub := tcgPubFile
	tcgPubFile = pubFile
	defer func() { tcgPubFile = oldPub }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		issueAKCertificate(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

// =============================================================================
// signTCGCSR tests
// =============================================================================

func TestSignTCGCSR_TextOutput_Success(t *testing.T) {
	mc := newMockCAClient()
	mc.signTCGResp = &transport.SignTCGCSRResponse{
		IAKCertDER:    []byte("iak-cert-der"),
		IDevIDCertDER: []byte("idevid-cert-der"),
	}
	cfg, _ := setupCATest(t, mc, "text")

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "tcg_csr.bin")
	require.NoError(t, os.WriteFile(csrFile, []byte("tcg-csr-data"), 0644))

	oldCSR := tcgCSRFile
	tcgCSRFile = csrFile
	oldOutput := tcgOutputFile
	tcgOutputFile = ""
	defer func() { tcgCSRFile = oldCSR; tcgOutputFile = oldOutput }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	signTCGCSR(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	output := stdoutBuf.String()
	assert.Contains(t, output, "IAK Certificate")
	assert.Contains(t, output, "IDevID Certificate")
}

func TestSignTCGCSR_JSONOutput_Success(t *testing.T) {
	mc := newMockCAClient()
	mc.signTCGResp = &transport.SignTCGCSRResponse{
		IAKCertDER:    []byte("iak"),
		IDevIDCertDER: []byte("idevid"),
	}
	cfg, _ := setupCATest(t, mc, "json")

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "tcg_csr.bin")
	require.NoError(t, os.WriteFile(csrFile, []byte("data"), 0644))

	oldCSR := tcgCSRFile
	tcgCSRFile = csrFile
	oldOutput := tcgOutputFile
	tcgOutputFile = ""
	defer func() { tcgCSRFile = oldCSR; tcgOutputFile = oldOutput }()

	var buf bytes.Buffer
	printer := NewPrinter("json", &buf)
	signTCGCSR(cfg, printer)

	assert.Contains(t, buf.String(), "iak_cert_size")
	assert.Contains(t, buf.String(), "idevid_cert_size")
}

func TestSignTCGCSR_WriteToDirectory(t *testing.T) {
	mc := newMockCAClient()
	mc.signTCGResp = &transport.SignTCGCSRResponse{
		IAKCertDER:    []byte("iak-data"),
		IDevIDCertDER: []byte("idevid-data"),
	}
	cfg, _ := setupCATest(t, mc, "text")

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "tcg_csr.bin")
	require.NoError(t, os.WriteFile(csrFile, []byte("csr"), 0644))
	outDir := filepath.Join(tmpDir, "output")

	oldCSR := tcgCSRFile
	tcgCSRFile = csrFile
	oldOutput := tcgOutputFile
	tcgOutputFile = outDir
	defer func() { tcgCSRFile = oldCSR; tcgOutputFile = oldOutput }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	signTCGCSR(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	iakData, err := os.ReadFile(filepath.Join(outDir, "iak_cert.der"))
	require.NoError(t, err)
	assert.Equal(t, "iak-data", string(iakData))

	idevidData, err := os.ReadFile(filepath.Join(outDir, "idevid_cert.der"))
	require.NoError(t, err)
	assert.Equal(t, "idevid-data", string(idevidData))
}

func TestSignTCGCSR_MissingCSRFile(t *testing.T) {
	mc := newMockCAClient()
	cfg, _ := setupCATest(t, mc, "text")

	oldCSR := tcgCSRFile
	tcgCSRFile = "/nonexistent/csr.bin"
	defer func() { tcgCSRFile = oldCSR }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		signTCGCSR(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestSignTCGCSR_ClientError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(_ *Config) (client.Client, error) {
		return nil, errors.New("fail")
	}
	origConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = origConfig }()

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "csr.bin")
	require.NoError(t, os.WriteFile(csrFile, []byte("data"), 0644))
	oldCSR := tcgCSRFile
	tcgCSRFile = csrFile
	defer func() { tcgCSRFile = oldCSR }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		signTCGCSR(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestSignTCGCSR_ConnectError(t *testing.T) {
	mc := newMockCAClient()
	mc.connectErr = errors.New("connect fail")
	cfg, _ := setupCATest(t, mc, "text")

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "csr.bin")
	require.NoError(t, os.WriteFile(csrFile, []byte("data"), 0644))
	oldCSR := tcgCSRFile
	tcgCSRFile = csrFile
	defer func() { tcgCSRFile = oldCSR }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		signTCGCSR(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestSignTCGCSR_APIError(t *testing.T) {
	mc := newMockCAClient()
	mc.signTCGErr = errors.New("sign error")
	cfg, _ := setupCATest(t, mc, "text")

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "csr.bin")
	require.NoError(t, os.WriteFile(csrFile, []byte("data"), 0644))
	oldCSR := tcgCSRFile
	tcgCSRFile = csrFile
	defer func() { tcgCSRFile = oldCSR }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		signTCGCSR(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestSignTCGCSR_JSONOutput_WithOutputDir(t *testing.T) {
	mc := newMockCAClient()
	mc.signTCGResp = &transport.SignTCGCSRResponse{
		IAKCertDER:    []byte("iak"),
		IDevIDCertDER: []byte("idevid"),
	}
	cfg, _ := setupCATest(t, mc, "json")

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "csr.bin")
	require.NoError(t, os.WriteFile(csrFile, []byte("data"), 0644))
	outDir := filepath.Join(tmpDir, "out")

	oldCSR := tcgCSRFile
	tcgCSRFile = csrFile
	oldOutput := tcgOutputFile
	tcgOutputFile = outDir
	defer func() { tcgCSRFile = oldCSR; tcgOutputFile = oldOutput }()

	var buf bytes.Buffer
	printer := NewPrinter("json", &buf)
	signTCGCSR(cfg, printer)

	assert.Contains(t, buf.String(), "iak_cert_file")
	assert.Contains(t, buf.String(), "idevid_cert_file")
}

// =============================================================================
// writeTCGCSROutput tests
// =============================================================================

func TestWriteTCGCSROutput_Success(t *testing.T) {
	tmpDir := t.TempDir()
	outDir := filepath.Join(tmpDir, "certs")

	err := writeTCGCSROutput(outDir, []byte("iak-data"), []byte("idevid-data"))
	require.NoError(t, err)

	iak, err := os.ReadFile(filepath.Join(outDir, "iak_cert.der"))
	require.NoError(t, err)
	assert.Equal(t, "iak-data", string(iak))

	idevid, err := os.ReadFile(filepath.Join(outDir, "idevid_cert.der"))
	require.NoError(t, err)
	assert.Equal(t, "idevid-data", string(idevid))
}

func TestWriteTCGCSROutput_InvalidDirectory(t *testing.T) {
	err := writeTCGCSROutput("/proc/nonexistent/impossible", []byte("a"), []byte("b"))
	assert.Error(t, err)
}

// =============================================================================
// enrollDevice tests
// =============================================================================

func TestEnrollDevice_TextOutput_Success(t *testing.T) {
	mc := newMockCAClient()
	mc.enrollResp = &transport.EnrollDeviceResponse{
		IAKCertDER:      []byte("iak"),
		IDevIDCertDER:   []byte("idevid"),
		CredentialBlob:  []byte("blob"),
		EncryptedSecret: []byte("secret"),
	}
	cfg, _ := setupCATest(t, mc, "text")

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "packed.bin")
	require.NoError(t, os.WriteFile(csrFile, []byte("packed-csr"), 0644))

	oldCSR := tcgPackedCSR
	tcgPackedCSR = csrFile
	oldOutput := tcgOutputFile
	tcgOutputFile = ""
	defer func() { tcgPackedCSR = oldCSR; tcgOutputFile = oldOutput }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	enrollDevice(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	output := stdoutBuf.String()
	assert.Contains(t, output, "Device Enrollment Complete")
	assert.Contains(t, output, "Credential Blob")
	assert.Contains(t, output, "Encrypted Secret")
}

func TestEnrollDevice_JSONOutput_Success(t *testing.T) {
	mc := newMockCAClient()
	mc.enrollResp = &transport.EnrollDeviceResponse{
		IAKCertDER:      []byte("iak"),
		IDevIDCertDER:   []byte("idevid"),
		CredentialBlob:  []byte("blob"),
		EncryptedSecret: []byte("secret"),
	}
	cfg, _ := setupCATest(t, mc, "json")

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "packed.bin")
	require.NoError(t, os.WriteFile(csrFile, []byte("data"), 0644))

	oldCSR := tcgPackedCSR
	tcgPackedCSR = csrFile
	oldOutput := tcgOutputFile
	tcgOutputFile = ""
	defer func() { tcgPackedCSR = oldCSR; tcgOutputFile = oldOutput }()

	var buf bytes.Buffer
	printer := NewPrinter("json", &buf)
	enrollDevice(cfg, printer)

	output := buf.String()
	assert.Contains(t, output, "iak_cert_size")
	assert.Contains(t, output, "has_challenge")
}

func TestEnrollDevice_WriteToDirectory(t *testing.T) {
	mc := newMockCAClient()
	mc.enrollResp = &transport.EnrollDeviceResponse{
		IAKCertDER:      []byte("iak-data"),
		IDevIDCertDER:   []byte("idevid-data"),
		CredentialBlob:  []byte("blob-data"),
		EncryptedSecret: []byte("secret-data"),
	}
	cfg, _ := setupCATest(t, mc, "text")

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "packed.bin")
	require.NoError(t, os.WriteFile(csrFile, []byte("csr"), 0644))
	outDir := filepath.Join(tmpDir, "enrollment")

	oldCSR := tcgPackedCSR
	tcgPackedCSR = csrFile
	oldOutput := tcgOutputFile
	tcgOutputFile = outDir
	defer func() { tcgPackedCSR = oldCSR; tcgOutputFile = oldOutput }()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	enrollDevice(cfg, printer)

	w.Close()
	os.Stdout = old
	var stdoutBuf bytes.Buffer
	stdoutBuf.ReadFrom(r)

	iak, err := os.ReadFile(filepath.Join(outDir, "iak_cert.der"))
	require.NoError(t, err)
	assert.Equal(t, "iak-data", string(iak))

	blob, err := os.ReadFile(filepath.Join(outDir, "credential_blob.bin"))
	require.NoError(t, err)
	assert.Equal(t, "blob-data", string(blob))

	secret, err := os.ReadFile(filepath.Join(outDir, "encrypted_secret.bin"))
	require.NoError(t, err)
	assert.Equal(t, "secret-data", string(secret))
}

func TestEnrollDevice_JSONOutput_WithOutputDir(t *testing.T) {
	mc := newMockCAClient()
	mc.enrollResp = &transport.EnrollDeviceResponse{
		IAKCertDER:    []byte("iak"),
		IDevIDCertDER: []byte("idevid"),
	}
	cfg, _ := setupCATest(t, mc, "json")

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "packed.bin")
	require.NoError(t, os.WriteFile(csrFile, []byte("data"), 0644))
	outDir := filepath.Join(tmpDir, "out")

	oldCSR := tcgPackedCSR
	tcgPackedCSR = csrFile
	oldOutput := tcgOutputFile
	tcgOutputFile = outDir
	defer func() { tcgPackedCSR = oldCSR; tcgOutputFile = oldOutput }()

	var buf bytes.Buffer
	printer := NewPrinter("json", &buf)
	enrollDevice(cfg, printer)

	assert.Contains(t, buf.String(), "output_dir")
}

func TestEnrollDevice_MissingCSRFile(t *testing.T) {
	mc := newMockCAClient()
	cfg, _ := setupCATest(t, mc, "text")

	oldCSR := tcgPackedCSR
	tcgPackedCSR = "/nonexistent/packed.bin"
	defer func() { tcgPackedCSR = oldCSR }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		enrollDevice(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestEnrollDevice_ClientError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.ClientFactory = func(_ *Config) (client.Client, error) {
		return nil, errors.New("fail")
	}
	origConfig := globalConfig
	globalConfig = cfg
	defer func() { globalConfig = origConfig }()

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "packed.bin")
	require.NoError(t, os.WriteFile(csrFile, []byte("data"), 0644))
	oldCSR := tcgPackedCSR
	tcgPackedCSR = csrFile
	defer func() { tcgPackedCSR = oldCSR }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		enrollDevice(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestEnrollDevice_ConnectError(t *testing.T) {
	mc := newMockCAClient()
	mc.connectErr = errors.New("connect fail")
	cfg, _ := setupCATest(t, mc, "text")

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "packed.bin")
	require.NoError(t, os.WriteFile(csrFile, []byte("data"), 0644))
	oldCSR := tcgPackedCSR
	tcgPackedCSR = csrFile
	defer func() { tcgPackedCSR = oldCSR }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		enrollDevice(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

func TestEnrollDevice_APIError(t *testing.T) {
	mc := newMockCAClient()
	mc.enrollErr = errors.New("enroll error")
	cfg, _ := setupCATest(t, mc, "text")

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "packed.bin")
	require.NoError(t, os.WriteFile(csrFile, []byte("data"), 0644))
	oldCSR := tcgPackedCSR
	tcgPackedCSR = csrFile
	defer func() { tcgPackedCSR = oldCSR }()

	var buf bytes.Buffer
	printer := NewPrinter("text", &buf)
	exitCode := captureExit(t, func() {
		enrollDevice(cfg, printer)
	})
	assert.Equal(t, 1, exitCode)
}

// =============================================================================
// writeEnrollmentOutput tests
// =============================================================================

func TestWriteEnrollmentOutput_Success(t *testing.T) {
	tmpDir := t.TempDir()
	outDir := filepath.Join(tmpDir, "enrollment")

	resp := &transport.EnrollDeviceResponse{
		IAKCertDER:      []byte("iak"),
		IDevIDCertDER:   []byte("idevid"),
		CredentialBlob:  []byte("blob"),
		EncryptedSecret: []byte("secret"),
	}

	err := writeEnrollmentOutput(outDir, resp)
	require.NoError(t, err)

	iak, err := os.ReadFile(filepath.Join(outDir, "iak_cert.der"))
	require.NoError(t, err)
	assert.Equal(t, "iak", string(iak))

	blob, err := os.ReadFile(filepath.Join(outDir, "credential_blob.bin"))
	require.NoError(t, err)
	assert.Equal(t, "blob", string(blob))

	secret, err := os.ReadFile(filepath.Join(outDir, "encrypted_secret.bin"))
	require.NoError(t, err)
	assert.Equal(t, "secret", string(secret))
}

func TestWriteEnrollmentOutput_NoBlob(t *testing.T) {
	tmpDir := t.TempDir()
	outDir := filepath.Join(tmpDir, "enrollment")

	resp := &transport.EnrollDeviceResponse{
		IAKCertDER:    []byte("iak"),
		IDevIDCertDER: []byte("idevid"),
	}

	err := writeEnrollmentOutput(outDir, resp)
	require.NoError(t, err)

	// Verify no blob/secret files
	_, err = os.Stat(filepath.Join(outDir, "credential_blob.bin"))
	assert.True(t, os.IsNotExist(err))
}

func TestWriteEnrollmentOutput_InvalidDirectory(t *testing.T) {
	resp := &transport.EnrollDeviceResponse{
		IAKCertDER:    []byte("iak"),
		IDevIDCertDER: []byte("idevid"),
	}
	err := writeEnrollmentOutput("/proc/nonexistent/impossible", resp)
	assert.Error(t, err)
}
