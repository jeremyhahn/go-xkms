//go:build tpm_simulator

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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// selfSignedDeviceCLICert mints a throwaway self-signed certificate for use
// as a canned Finalize response from testutil.FakeACMEDirectory.
func selfSignedDeviceCLICert(t *testing.T, cn string) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

// setDeviceCLIConfig points viper at a fake ACME directory and a single
// device spec named "edge01" whose TPM is left unset, so it opens and
// provisions the in-process simulator exactly as production configuration
// with no tpm section would.
func setDeviceCLIConfig(t *testing.T, directoryURL, port string) {
	t.Helper()

	viper.Reset()
	setDefaults()
	viper.Set("logging.level", "info")
	viper.Set("storage.options.path", t.TempDir())
	viper.Set("accounts", map[string]interface{}{
		"trusted-ca": map[string]interface{}{
			"directory": directoryURL,
			"email":     "device-cli-test@example.com",
			"key":       map[string]interface{}{"algorithm": "ECDSA", "store": "software"},
		},
	})
	viper.Set("devices", map[string]interface{}{
		"edge01": map[string]interface{}{
			"account":     "trusted-ca",
			"common-name": "edge01.example.com",
			"identifier":  "edge01.example.com",
			"challenge":   map[string]interface{}{"port": port, "timeout": "30s"},
		},
	})
}

// TestDeviceEnrollCmd_Success proves `device enroll <name>` drives a real
// enrollment — TPM 2.0 simulator open/provision plus an in-process fake ACME
// directory offering enroll-01 — end to end through the same service layer
// the daemon and GUI use.
func TestDeviceEnrollCmd_Success(t *testing.T) {
	iak := selfSignedDeviceCLICert(t, "cli-test-iak")
	idevid := selfSignedDeviceCLICert(t, "cli-test-idevid")
	server := testutil.NewFakeACMEDirectory(t,
		[]string{"http-01", "enroll-01", "device-attest-01"},
		[][]byte{iak, idevid})

	setDeviceCLIConfig(t, server.DirectoryURL(), "19821")

	cmd := deviceEnrollCmd
	cmd.SetContext(context.Background())
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := deviceEnrollCmd.RunE(cmd, []string{"edge01"}); err != nil {
		t.Fatalf("expected successful enrollment, got: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "enrolled successfully") {
		t.Errorf("expected success message, got: %q", out)
	}
	if !strings.Contains(out, "cli-test-idevid") {
		t.Errorf("expected IDevID subject in output: %q", out)
	}
}

// TestDeviceAttestCmd_Success proves `device attest <name>` drives a real
// attestation through the same TPM-simulator path plus a fake ACME
// directory offering device-attest-01.
func TestDeviceAttestCmd_Success(t *testing.T) {
	attestCert := selfSignedDeviceCLICert(t, "cli-test-attest")
	server := testutil.NewFakeACMEDirectory(t,
		[]string{"http-01", "enroll-01", "device-attest-01"},
		[][]byte{attestCert})

	setDeviceCLIConfig(t, server.DirectoryURL(), "19822")

	cmd := deviceAttestCmd
	cmd.SetContext(context.Background())
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := deviceAttestCmd.RunE(cmd, []string{"edge01"}); err != nil {
		t.Fatalf("expected successful attestation, got: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "attested successfully") {
		t.Errorf("expected success message, got: %q", out)
	}
	if !strings.Contains(out, "cli-test-attest") {
		t.Errorf("expected subject in output: %q", out)
	}
}
