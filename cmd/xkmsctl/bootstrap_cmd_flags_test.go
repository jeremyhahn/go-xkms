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

// bootstrap_cmd_flags_test.go runs the DANE and P-256 bootstrap verbs
// through their declared flags, pinning that each flag reaches the helper.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runBootstrapVerb runs cmd with flags set and returns stdout, the exit
// code (-1 when it never exited) and stderr.
func runBootstrapVerb(t *testing.T, cmd *cobra.Command, flags map[string]string) (string, int, string) {
	t.Helper()
	withGlobalConfig(t, NewConfig())
	resetVerbFlags(t, cmd)
	t.Cleanup(func() { resetVerbFlags(t, cmd) })
	for name, value := range flags {
		require.NoError(t, cmd.Flags().Set(name, value))
	}
	code := -1
	var stderr string
	stdout := captureStdout(t, func() {
		code, stderr = runKeyExt(t, func() { cmd.Run(cmd, nil) })
	})
	return stdout, code, stderr
}

func TestDaneGenerateTLSACmd_Flags(t *testing.T) {
	cert := generateTestCertForDANE(t)
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)

	out, code, _ := runBootstrapVerb(t, daneGenerateTLSACmd, map[string]string{
		"cert-file": writeCertPEM(t, cert), "hostname": "kms.example.com", "port": "8443",
		"usage": "3", "selector": "1", "matching-type": "1",
	})
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "_8443._tcp.kms.example.com.")
	assert.Contains(t, out, hex.EncodeToString(spki[:]))
}

func TestDaneVerifyTLSACmd_Flags(t *testing.T) {
	cert := generateTestCertForDANE(t)
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	mock := &mockResolver{records: []tlsaRecord{{
		Usage: TLSAUsageDomainIssuedCert, Selector: TLSASelectorSPKI, MatchingType: TLSAMatchSHA256,
		Data: hex.EncodeToString(spki[:]),
	}}}
	withMockResolver(t, mock)

	out, code, _ := runBootstrapVerb(t, daneVerifyTLSACmd, map[string]string{
		"cert-file": writeCertPEM(t, cert), "hostname": "kms.example.com", "port": "853", "dns-server": "192.0.2.53:53",
	})
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "Result: 1 of 1 record(s) matched")
	assert.Equal(t, "_853._tcp.kms.example.com.", mock.calledName)
	assert.Equal(t, "192.0.2.53:53", mock.calledServer)
}

func TestDaneShowTLSACmd_Flags(t *testing.T) {
	mock := &mockResolver{records: []tlsaRecord{{
		Usage: TLSAUsageDomainIssuedCert, Selector: TLSASelectorSPKI, MatchingType: TLSAMatchSHA256, Data: "abcd",
	}}}
	withMockResolver(t, mock)

	out, code, _ := runBootstrapVerb(t, daneShowTLSACmd, map[string]string{
		"hostname": "kms.example.com", "port": "25", "dns-server": "192.0.2.53:53",
	})
	assert.Equal(t, -1, code)
	assert.Contains(t, out, "abcd")
	assert.Equal(t, "_25._tcp.kms.example.com.", mock.calledName)
	assert.Equal(t, "192.0.2.53:53", mock.calledServer)
}

func TestP256ShowKeyCmd_Refusals(t *testing.T) {
	cases := []struct {
		name     string
		flags    map[string]string
		sentinel error
	}{
		{"no key", nil, ErrKeyInputRequired},
		{"short key", map[string]string{"key-hex": "abcd"}, ErrDecodeKeyFailed},
		{"unreadable key file", map[string]string{"key-file": filepath.Join(t.TempDir(), "absent")}, ErrReadKeyFileFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code, stderr := runBootstrapVerb(t, p256ShowKeyCmd, tc.flags)
			assert.Equal(t, 1, code)
			assert.Empty(t, out)
			assert.Contains(t, stderr, tc.sentinel.Error())
		})
	}
}

func TestP256GenerateKeyCmd_Flags(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "p256.key")

	out, code, stderr := runBootstrapVerb(t, p256GenerateKeyCmd, map[string]string{"output": keyFile})
	require.Equal(t, -1, code, stderr)
	assert.Contains(t, out, "Private key written to: "+keyFile)

	data, err := os.ReadFile(keyFile)
	require.NoError(t, err)
	shown, code, stderr := runBootstrapVerb(t, p256ShowKeyCmd, map[string]string{"key-hex": strings.TrimSpace(string(data))})
	require.Equal(t, -1, code, stderr)
	publicHex := strings.TrimSpace(strings.TrimPrefix(shown, "Public key:"))
	require.NotEmpty(t, publicHex)
	assert.Contains(t, out, publicHex, "the printed public key belongs to the written private key")
}

// TestBootstrapVerbs_UndeclaredFlag proves each verb reports a flag it
// cannot read instead of running with a zero value.
func TestBootstrapVerbs_UndeclaredFlag(t *testing.T) {
	for _, verb := range []*cobra.Command{daneGenerateTLSACmd, daneVerifyTLSACmd, daneShowTLSACmd, p256ShowKeyCmd, p256GenerateKeyCmd} {
		t.Run(verb.Use, func(t *testing.T) {
			withGlobalConfig(t, NewConfig())
			bare := &cobra.Command{Use: verb.Use}
			code, stderr := runKeyExt(t, func() { verb.Run(bare, nil) })
			assert.Equal(t, 1, code)
			assert.NotEmpty(t, stderr)
		})
	}
}
