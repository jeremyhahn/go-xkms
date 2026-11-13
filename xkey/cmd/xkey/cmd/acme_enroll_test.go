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
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	sdkacme "github.com/jeremyhahn/go-xkms/sdk/go/acme"
)

// stubACMETPM satisfies sdkacme.ACMETPMModule; the fake client never calls it.
type stubACMETPM struct {
	sdkacme.ACMETPMModule
}

type tpmStubRecord struct {
	opened, released bool
	dataDir, device  string
	simulator        bool
	module           *stubACMETPM
}

func stubACMETPMModule(t *testing.T) *tpmStubRecord {
	t.Helper()
	rec := &tpmStubRecord{module: &stubACMETPM{}}
	prev := openACMETPMModuleFunc
	openACMETPMModuleFunc = func(_ *slog.Logger, dataDir, device string, sim bool) (sdkacme.ACMETPMModule, func() error, error) {
		rec.opened, rec.dataDir, rec.device, rec.simulator = true, dataDir, device, sim
		return rec.module, func() error { rec.released = true; return nil }, nil
	}
	t.Cleanup(func() { openACMETPMModuleFunc = prev })
	return rec
}

func TestACMEEnrollCallsClientWithConfig(t *testing.T) {
	env := newACMETestEnv(t)
	tpm := stubACMETPMModule(t)
	_, idevid := writeTestCert(t)
	_, iak := writeTestCert(t)
	_, ca := writeTestCert(t)
	env.fake.enrollResult = &sdkacme.ACMEEnrollmentResult{
		IDevIDCertificate: idevid, IAKCertificate: iak, Chain: []*x509.Certificate{ca},
	}
	args := append([]string{"enroll", "--challenge", sdkacme.ACMEChallengeTypeEnroll01, "--ip", "192.0.2.7",
		"--port", "9443", "--listen-host", "0.0.0.0", "--common-name", "dev-1", "--pcr", "0,7",
		"--timeout", "45s", "--tpm-device", "/dev/tpmrm0", "--tpm-simulator", "--data-dir", "/tmp/xk"}, env.common()...)
	out, err := env.run(t, args...)
	if err != nil {
		t.Fatalf("enroll: %v (%s)", err, out)
	}
	want := &sdkacme.ACMEEnrollmentConfig{
		Challenge: sdkacme.ACMEChallengeTypeEnroll01, IPAddress: "192.0.2.7", TPMModule: tpm.module,
		Port: "9443", ListenHost: "0.0.0.0", CommonName: "dev-1", PCRSelection: []int{0, 7}, Timeout: 45 * time.Second,
	}
	if !reflect.DeepEqual(env.fake.enrollConfig, want) {
		t.Fatalf("config = %+v, want %+v", env.fake.enrollConfig, want)
	}
	if tpm.device != "/dev/tpmrm0" || !tpm.simulator || tpm.dataDir != "/tmp/xk" || !tpm.released {
		t.Fatalf("tpm module = %+v", tpm)
	}
	rest := []byte(out)
	for _, c := range []*x509.Certificate{idevid, iak, ca} {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || string(block.Bytes) != string(c.Raw) {
			t.Fatalf("output is not idevid, iak, chain PEM: %q", out)
		}
	}
	env.assertNoKeyMaterial(t, out)
}

func TestACMEEnrollDeviceAttestNeedsNoIPAndWritesOutDir(t *testing.T) {
	env := newACMETestEnv(t)
	stubACMETPMModule(t)
	_, iak := writeTestCert(t)
	env.fake.enrollResult = &sdkacme.ACMEEnrollmentResult{IAKCertificate: iak}
	dir := filepath.Join(t.TempDir(), "out")
	args := append([]string{"enroll", "--challenge", sdkacme.ACMEChallengeTypeDeviceAttest01, "--out-dir", dir}, env.common()...)
	out, err := env.run(t, args...)
	if err != nil {
		t.Fatalf("enroll: %v (%s)", err, out)
	}
	cfg := env.fake.enrollConfig
	if cfg == nil || cfg.IPAddress != "" || cfg.Port != "8080" || cfg.Timeout != 30*time.Second {
		t.Fatalf("config = %+v", cfg)
	}
	data, err := os.ReadFile(filepath.Join(dir, "iak.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if block, _ := pem.Decode(data); block == nil || string(block.Bytes) != string(iak.Raw) {
		t.Fatal("iak.pem does not hold the IAK certificate")
	}
	if _, err := os.Stat(filepath.Join(dir, "idevid.pem")); !os.IsNotExist(err) {
		t.Fatalf("idevid.pem written without an IDevID certificate: %v", err)
	}
	env.assertNoKeyMaterial(t, out+string(data))
}

func TestACMEEnrollErrors(t *testing.T) {
	env := newACMETestEnv(t)
	tpm := stubACMETPMModule(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"missing challenge", []string{"enroll", "--ip", "192.0.2.7"}, "--challenge"},
		{"unknown challenge", []string{"enroll", "--challenge", "http-01", "--ip", "192.0.2.7"}, "http-01"},
		{"enroll-01 without ip", []string{"enroll", "--challenge", sdkacme.ACMEChallengeTypeEnroll01}, "--ip"},
		{"endorse-01 without ip", []string{"enroll", "--challenge", sdkacme.ACMEChallengeTypeEndorse01}, "--ip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env.fake.enrollConfig = nil
			tpm.opened = false
			_, err := env.run(t, append(tc.args, env.common()...)...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			if env.fake.enrollConfig != nil || tpm.opened {
				t.Fatal("client or TPM reached on a failed check")
			}
		})
	}
}
