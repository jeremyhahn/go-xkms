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
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	sdkacme "github.com/jeremyhahn/go-xkms/sdk/go/acme"
)

func TestACMEEndorseCallsClientWithConfig(t *testing.T) {
	env := newACMETestEnv(t)
	tpm := stubACMETPMModule(t)
	_, ek := writeTestCert(t)
	env.fake.endorseCert = ek
	args := append([]string{"endorse", "--ip", "192.0.2.9", "--port", "9444", "--listen-host", "0.0.0.0",
		"--common-name", "dev-2", "--timeout", "40s", "--tpm-device", "/dev/tpmrm0", "--tpm-simulator",
		"--data-dir", "/tmp/xk"}, env.common()...)
	out, err := env.run(t, args...)
	if err != nil {
		t.Fatalf("endorse: %v (%s)", err, out)
	}
	want := &sdkacme.ACMEEnrollmentConfig{
		Challenge: sdkacme.ACMEChallengeTypeEndorse01, IPAddress: "192.0.2.9", TPMModule: tpm.module,
		Port: "9444", ListenHost: "0.0.0.0", CommonName: "dev-2", Timeout: 40 * time.Second,
	}
	if !reflect.DeepEqual(env.fake.endorseConfig, want) {
		t.Fatalf("config = %+v, want %+v", env.fake.endorseConfig, want)
	}
	if tpm.device != "/dev/tpmrm0" || !tpm.simulator || tpm.dataDir != "/tmp/xk" || !tpm.released {
		t.Fatalf("tpm module = %+v", tpm)
	}
	block, rest := pem.Decode([]byte(out))
	if block == nil || block.Type != "CERTIFICATE" || string(block.Bytes) != string(ek.Raw) {
		t.Fatalf("output is not the EK certificate PEM: %q", out)
	}
	if strings.TrimSpace(string(rest)) != "" {
		t.Fatalf("unexpected output after the certificate: %q", rest)
	}
	env.assertNoKeyMaterial(t, out)
}

func TestACMEEndorseWritesOut(t *testing.T) {
	env := newACMETestEnv(t)
	stubACMETPMModule(t)
	_, ek := writeTestCert(t)
	env.fake.endorseCert = ek
	path := filepath.Join(t.TempDir(), "ek.pem")
	if _, err := env.run(t, append([]string{"endorse", "--ip", "192.0.2.9", "--out", path}, env.common()...)...); err != nil {
		t.Fatalf("endorse: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || string(block.Bytes) != string(ek.Raw) {
		t.Fatalf("--out is not the EK certificate PEM: %q", data)
	}
	if env.fake.endorseConfig.CommonName != "" || env.fake.endorseConfig.Port != "8080" {
		t.Fatalf("defaults = %+v", env.fake.endorseConfig)
	}
}

func TestACMEEndorseMissingIP(t *testing.T) {
	env := newACMETestEnv(t)
	tpm := stubACMETPMModule(t)
	_, err := env.run(t, append([]string{"endorse"}, env.common()...)...)
	if err == nil || !strings.Contains(err.Error(), "--ip") {
		t.Fatalf("err = %v, want it to mention --ip", err)
	}
	if env.fake.endorseConfig != nil || tpm.opened {
		t.Fatal("client or TPM reached without --ip")
	}
}

func TestACMEEndorseClientError(t *testing.T) {
	env := newACMETestEnv(t)
	stubACMETPMModule(t)
	env.fake.err = errors.New("endorse refused")
	path := filepath.Join(t.TempDir(), "ek.pem")
	_, err := env.run(t, append([]string{"endorse", "--ip", "192.0.2.9", "--out", path}, env.common()...)...)
	if err == nil || !strings.Contains(err.Error(), "endorse refused") {
		t.Fatalf("err = %v, want the client error", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("--out written on a client error: %v", statErr)
	}
}
