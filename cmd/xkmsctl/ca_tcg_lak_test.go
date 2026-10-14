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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// lakInputs points every LAK evidence flag at a file in a fresh directory
// and restores the flags when the test ends.
func lakInputs(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[*string]string{
		&tcgLAKIAKCertFile: "iak.der",
		&tcgLAKCertifyInfo: "certify.bin",
		&tcgLAKSignature:   "sig.bin",
		&tcgLAKPublicArea:  "lak.pub",
		&tcgLAKNonceFile:   "nonce.bin",
	}
	saved := map[*string]string{
		&tcgLAKSigAlgo: tcgLAKSigAlgo, &tcgLAKManufacturer: tcgLAKManufacturer,
		&tcgLAKModel: tcgLAKModel, &tcgLAKFirmware: tcgLAKFirmware, &tcgOutputFile: tcgOutputFile,
	}
	for flag, name := range files {
		saved[flag] = *flag
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(name), 0600))
		*flag = path
	}
	t.Cleanup(func() {
		for flag, value := range saved {
			*flag = value
		}
	})
	tcgLAKSigAlgo = "ECDSA-SHA256"
	tcgLAKManufacturer = "id:49465800"
	tcgLAKModel = "SLB9670"
	tcgLAKFirmware = "7.85"
	tcgOutputFile = ""
	return dir
}

func lakMock() *mockCAClient {
	mc := newMockCAClient()
	mc.issueLAKResp = &transport.IssueLAKCertificateResponse{CertificatePEM: []byte("lak-cert-pem"), SerialNumber: "LAK01"}
	return mc
}

func TestIssueLAKCertificate_SendsEvidence(t *testing.T) {
	mc := lakMock()
	cfg, _ := setupCATest(t, mc, "text")
	lakInputs(t)

	var buf bytes.Buffer
	stdout := captureStdout(t, func() { issueLAKCertificate(cfg, NewPrinter("text", &buf)) })

	req := mc.gotLAKReq
	require.NotNil(t, req)
	assert.Equal(t, "id:49465800", req.TPMManufacturer)
	assert.Equal(t, "SLB9670", req.TPMModel)
	assert.Equal(t, "7.85", req.TPMFirmwareVersion)
	assert.Equal(t, []byte("iak.der"), req.IAKCertificateDER)
	assert.Equal(t, []byte("certify.bin"), req.CertifyInfo)
	assert.Equal(t, []byte("sig.bin"), req.Signature)
	assert.Equal(t, []byte("lak.pub"), req.LAKPublicArea)
	assert.Equal(t, []byte("nonce.bin"), req.Nonce)
	assert.NotZero(t, req.SignatureAlgorithm)
	assert.Contains(t, stdout, "Serial Number: LAK01")
	assert.Contains(t, stdout, "lak-cert-pem")
}

func TestIssueLAKCertificate_NonceIsOptional(t *testing.T) {
	mc := lakMock()
	cfg, _ := setupCATest(t, mc, "text")
	lakInputs(t)
	tcgLAKNonceFile = ""

	code := captureExit(t, func() {
		captureStdout(t, func() { issueLAKCertificate(cfg, NewPrinter("text", &bytes.Buffer{})) })
	})
	assert.Equal(t, -1, code)
	require.NotNil(t, mc.gotLAKReq)
	assert.Nil(t, mc.gotLAKReq.Nonce)
}

func TestIssueLAKCertificate_WritesOutputFile(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			mc := lakMock()
			cfg, _ := setupCATest(t, mc, format)
			dir := lakInputs(t)
			tcgOutputFile = filepath.Join(dir, "lak.pem")

			var buf bytes.Buffer
			stdout := captureStdout(t, func() { issueLAKCertificate(cfg, NewPrinter(format, &buf)) })

			data, err := os.ReadFile(tcgOutputFile)
			require.NoError(t, err)
			assert.Equal(t, []byte("lak-cert-pem"), data)
			if format == "text" {
				assert.Contains(t, stdout, "Certificate:   "+tcgOutputFile)
				assert.NotContains(t, stdout, "lak-cert-pem")
				return
			}
			var got map[string]string
			require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
			assert.Equal(t, map[string]string{"serial_number": "LAK01", "cert_file": tcgOutputFile}, got)
		})
	}
}

func TestIssueLAKCertificate_JSONCarriesPEM(t *testing.T) {
	mc := lakMock()
	cfg, _ := setupCATest(t, mc, "json")
	lakInputs(t)

	var buf bytes.Buffer
	issueLAKCertificate(cfg, NewPrinter("json", &buf))

	var got map[string]string
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, map[string]string{"serial_number": "LAK01", "certificate_pem": "lak-cert-pem"}, got)
}

func TestIssueLAKCertificate_Failures(t *testing.T) {
	missing := func(flag *string) func(*mockCAClient, string) {
		return func(_ *mockCAClient, dir string) { *flag = filepath.Join(dir, "absent") }
	}
	cases := []struct {
		name     string
		sentinel error
		setup    func(mc *mockCAClient, dir string)
	}{
		{"missing IAK certificate", ErrReadIAKCertificateFileFailed, missing(&tcgLAKIAKCertFile)},
		{"missing certify info", ErrReadCertifyInfoFileFailed, missing(&tcgLAKCertifyInfo)},
		{"missing signature", ErrReadSignatureFileFailed, missing(&tcgLAKSignature)},
		{"missing LAK public area", ErrReadLAKPublicAreaFileFailed, missing(&tcgLAKPublicArea)},
		{"missing nonce", ErrReadNonceFileFailed, missing(&tcgLAKNonceFile)},
		{"unknown signature algorithm", ErrInvalidSignatureAlgorithm, func(*mockCAClient, string) { tcgLAKSigAlgo = "ROT13" }},
		{"connect", ErrConnectFailed, func(mc *mockCAClient, _ string) { mc.connectErr = errors.New("refused") }},
		{"issuance refused", ErrIssueLAKCertificateFailed, func(mc *mockCAClient, _ string) { mc.issueLAKErr = errors.New("evidence rejected") }},
		{"unwritable output", ErrWriteLAKCertificateFailed, func(_ *mockCAClient, dir string) {
			tcgOutputFile = filepath.Join(dir, "missing", "lak.pem")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc := lakMock()
			cfg, _ := setupCATest(t, mc, "text")
			tc.setup(mc, lakInputs(t))

			var code int
			var stdout string
			stderr := captureStderr(t, func() {
				code = captureExit(t, func() {
					stdout = captureStdout(t, func() { issueLAKCertificate(cfg, NewPrinter("text", &bytes.Buffer{})) })
				})
			})
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, tc.sentinel.Error())
			assert.NotContains(t, stdout, "LAK Certificate Issued")
		})
	}
}
