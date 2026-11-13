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
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestACMERenewCallsClientAndWritesPEM(t *testing.T) {
	env := newACMETestEnv(t)
	certFile, oldCert := writeTestCert(t)
	_, renewed := writeTestCert(t)
	env.fake.renewed = renewed
	args := append([]string{"renew", "--cert", certFile, "--domain", "device.test"}, env.common()...)
	out, err := env.run(t, args...)
	if err != nil {
		t.Fatalf("renew: %v (%s)", err, out)
	}
	if env.fake.renewOld == nil || !env.fake.renewOld.Equal(oldCert) {
		t.Fatal("RenewCertificate not called with the parsed old certificate")
	}
	req := env.fake.renewReq
	if req == nil || req.AuthzValue != "device.test" || req.AuthzType != "dns" {
		t.Fatalf("request = %+v, want dns device.test", req)
	}
	block, _ := pem.Decode([]byte(out))
	if block == nil || block.Type != "CERTIFICATE" || string(block.Bytes) != string(renewed.Raw) {
		t.Fatalf("output is not the renewed PEM certificate: %q", out)
	}
	env.assertNoKeyMaterial(t, out)
}

func TestACMERenewWritesOutFileAndCSR(t *testing.T) {
	env := newACMETestEnv(t)
	certFile, _ := writeTestCert(t)
	_, renewed := writeTestCert(t)
	env.fake.renewed = renewed
	dir := t.TempDir()
	csr := filepath.Join(dir, "req.der")
	if err := os.WriteFile(csr, []byte{0x30, 0x01, 0x00}, 0o600); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(dir, "renewed.pem")
	args := append([]string{"renew", "--cert", certFile, "--domain", "10.0.0.1", "--authz-type", "ip",
		"--challenge", "http-01", "--csr", csr, "--out", outFile}, env.common()...)
	if out, err := env.run(t, args...); err != nil {
		t.Fatalf("renew: %v (%s)", err, out)
	}
	req := env.fake.renewReq
	if req.AuthzType != "ip" || req.ChallengeType != "http-01" || string(req.CSR) != "\x30\x01\x00" {
		t.Fatalf("request = %+v", req)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(data); block == nil || string(block.Bytes) != string(renewed.Raw) {
		t.Fatal("out file does not hold the renewed certificate")
	}
	env.assertNoKeyMaterial(t, string(data))
}

func TestACMERenewErrors(t *testing.T) {
	env := newACMETestEnv(t)
	certFile, _ := writeTestCert(t)
	notCert := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(notCert, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing.pem")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"missing cert flag", []string{"renew", "--domain", "x"}, "--cert"},
		{"missing domain", []string{"renew", "--cert", certFile}, "--domain"},
		{"missing cert file", []string{"renew", "--cert", missing, "--domain", "x"}, missing},
		{"not a certificate", []string{"renew", "--cert", notCert, "--domain", "x"}, "certificate"},
		{"pem not a csr", []string{"renew", "--cert", certFile, "--domain", "x", "--csr", certFile}, "certificate request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env.fake.renewOld = nil
			_, err := env.run(t, append(tc.args, env.common()...)...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			if env.fake.renewOld != nil {
				t.Fatal("RenewCertificate called on a failed check")
			}
		})
	}
}
