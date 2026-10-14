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

// user_bind_cert_file_test.go pins that user bind-cert derives the binding
// from a certificate file with the canonical qrdb SPKI thumbprint.
package main

import (
	"path/filepath"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestUserBindCertCmd_CertFileJSON(t *testing.T) {
	certPath, _, cert, _ := writeCAFiles(t)
	mock := &mockUserExtClient{}
	cfg := &Config{OutputFormat: "json", ClientFactory: func(*Config) (client.Client, error) { return mock, nil }}

	out, code, stderr := runVerb(t, cfg, userBindCertCmd, []string{"alice"}, verbFlag{"cert-file", certPath})
	require.Equal(t, -1, code, stderr)
	want := qrdbsdk.ComputeSPKIThumbprint(cert)
	assert.Equal(t, want, mock.gotBindThumbprint)
	got := lastJSONObject(t, out)
	assert.Equal(t, want, got["thumbprint"])
	assert.Equal(t, float64(cert.NotAfter.Unix()), got["not_after"])
}

func TestUserBindCertCmd_Refusals(t *testing.T) {
	certPath, _, _, _ := writeCAFiles(t)
	cases := []struct {
		name  string
		cfg   *Config
		flags []verbFlag
	}{
		{"unreadable certificate", newUserTestConfig("text", &mockUserClient{}), []verbFlag{{"cert-file", filepath.Join(t.TempDir(), "absent.pem")}}},
		{"both sources", newUserTestConfig("text", &mockUserClient{}), []verbFlag{{"cert-file", certPath}, {"thumbprint", "9f3a"}}},
		{"client factory", &Config{OutputFormat: "text", ClientFactory: func(*Config) (client.Client, error) { return nil, errUserExtBoom }}, []verbFlag{{"thumbprint", "9f3a"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code, stderr := runVerb(t, tc.cfg, userBindCertCmd, []string{"alice"}, tc.flags...)
			assert.Equal(t, 1, code)
			assert.NotEmpty(t, stderr)
			assert.NotContains(t, out, "Certificate bound")
		})
	}
}
