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

// ca_issue_write_refusals_test.go pins that ca issue reports a certificate
// or private key it cannot write, and prints no result.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

func TestIssueCACertificate_WriteRefusals(t *testing.T) {
	dir := t.TempDir()
	notDir := filepath.Join(dir, "plain.txt")
	require.NoError(t, os.WriteFile(notDir, []byte("x"), 0600))
	keyBlocked := filepath.Join(dir, "cert.pem")
	require.NoError(t, os.Mkdir(keyBlocked+".key", 0700))

	cases := []struct {
		name     string
		output   string
		sentinel error
	}{
		{"certificate", filepath.Join(notDir, "cert.pem"), ErrWriteCertificateFailed},
		{"private key", keyBlocked, ErrWritePrivateKeyFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mc := newMockCAClient()
			mc.issueResp = &transport.IssueCertificateResponse{CertificatePEM: []byte("cert"), PrivateKeyPEM: []byte("key"), SerialNumber: "44"}
			cfg, _ := setupCATest(t, mc, "json")
			oldSANs, oldOutput := caSANs, caOutputFile
			caSANs, caOutputFile = "", tc.output
			t.Cleanup(func() { caSANs, caOutputFile = oldSANs, oldOutput })
			var out bytes.Buffer

			code, stderr := runACMEVerb(t, func() { issueCACertificate(cfg, NewPrinter("json", &out)) })
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, tc.sentinel.Error())
			assert.NotContains(t, out.String(), "serial_number")
		})
	}
}
