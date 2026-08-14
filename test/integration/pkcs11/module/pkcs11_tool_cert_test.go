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

//go:build integration && pkcs11 && pkcs11_tool
// +build integration,pkcs11,pkcs11_tool

// Package module drives pkcs11-tool's --write-object and --read-object verbs
// against the go-xkms PKCS#11 shared library to exercise CKO_CERTIFICATE
// object storage end to end (T8).
//
// pkcs11-tool's certificate write/read CLI surface was verified directly
// against a SoftHSM2 token (a real, independent Cryptoki implementation)
// before this file was written:
//
//   - "--write-object <der-file> --type cert --label <label> --id <id>"
//     parses the DER certificate with OpenSSL to derive CKA_SUBJECT and
//     CKA_SERIAL_NUMBER itself, so a certificate with a real Subject DN (as
//     produced by crypto/x509.CreateCertificate below) is required; go-xkms's
//     C_CreateObject requires CKA_CERTIFICATE_TYPE plus CKA_SUBJECT for
//     CKO_CERTIFICATE objects, which is exactly what pkcs11-tool supplies
//     from parsing.
//   - "--read-object --type cert --label <label> --output-file <path>"
//     writes the object's raw CKA_VALUE, which for a certificate is the
//     original DER bytes, so a round trip must reproduce the input exactly.
//
// Build tags: integration,pkcs11,pkcs11_tool
package module

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pkcs11ToolCertGenerateSelfSigned builds a small self-signed X.509
// certificate over a fresh P-256 key and returns its DER encoding, for use as
// the input to pkcs11-tool --write-object --type cert.
func pkcs11ToolCertGenerateSelfSigned(t *testing.T, commonName string, serial int64) []byte {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate certificate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"go-xkms pkcs11-tool integration test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create self-signed certificate: %v", err)
	}
	return der
}

// TestPKCS11Tool_CertificateWriteReadback writes a self-signed X.509
// certificate to the token with pkcs11-tool --write-object, then reads it
// back with --read-object and --list-objects, asserting the round trip
// reproduces the original DER bytes exactly (T8).
func TestPKCS11Tool_CertificateWriteReadback(t *testing.T) {
	requireFilePersistence(t)
	requireTool(t)
	cfg := NewPKCS11ToolTestConfig(t)
	requireModule(t, cfg.ModulePath)

	SetupInitializedModule(t)

	t.Run("write_and_read_back_certificate", func(t *testing.T) {
		certLabel := "pkcs11-tool-cert-test"
		certID := "80"

		certDER := pkcs11ToolCertGenerateSelfSigned(t, certLabel, 1)
		certFile := writeTestDataFile(t, cfg.TempDir, "self_signed_cert.der", certDER)

		writeOutput, writeStderr, writeErr := runPKCS11ToolCommand(t, cfg,
			"--login", "--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--write-object", certFile,
			"--type", "cert",
			"--label", certLabel,
			"--id", certID,
		)
		if writeErr != nil {
			t.Fatalf("pkcs11-tool --write-object failed: %v\nstdout: %s\nstderr: %s", writeErr, writeOutput, writeStderr)
		}

		readBackFile := filepath.Join(cfg.TempDir, "cert_readback.der")
		readOutput, readStderr, readErr := runPKCS11ToolCommand(t, cfg,
			"--login", "--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--read-object",
			"--type", "cert",
			"--label", certLabel,
			"--output-file", readBackFile,
		)
		if readErr != nil {
			t.Fatalf("pkcs11-tool --read-object failed: %v\nstdout: %s\nstderr: %s", readErr, readOutput, readStderr)
		}

		readBackDER := readTestDataFile(t, readBackFile)
		if len(readBackDER) == 0 {
			t.Fatal("expected non-empty certificate bytes from --read-object")
		}
		if !bytes.Equal(certDER, readBackDER) {
			t.Fatalf("certificate read back from the token does not match what was written: "+
				"wrote %d bytes, read back %d bytes", len(certDER), len(readBackDER))
		}

		// Parse the round-tripped bytes to prove they remain a valid,
		// well-formed certificate rather than merely byte-identical opaque
		// data.
		parsed, err := x509.ParseCertificate(readBackDER)
		if err != nil {
			t.Fatalf("certificate read back from the token failed to parse: %v", err)
		}
		if parsed.Subject.CommonName != certLabel {
			t.Fatalf("expected parsed certificate CommonName %q, got %q", certLabel, parsed.Subject.CommonName)
		}

		listOutput := mustRunPKCS11ToolCommand(t, cfg,
			"--login", "--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--list-objects",
			"--type", "cert",
		)
		if !strings.Contains(listOutput, certLabel) {
			t.Fatalf("expected certificate label %q in --list-objects --type cert output:\n%s", certLabel, listOutput)
		}
		if !strings.Contains(listOutput, certID) {
			t.Fatalf("expected certificate ID %q in --list-objects --type cert output:\n%s", certID, listOutput)
		}
	})

	t.Run("write_and_read_back_second_certificate_distinct_label", func(t *testing.T) {
		// A second, differently labeled certificate must coexist with the
		// first and be individually addressable by --label, proving
		// --write-object/--read-object key off the object identity rather
		// than always returning whatever certificate happens to be first.
		certLabel := "pkcs11-tool-cert-test-2"
		certID := "81"

		certDER := pkcs11ToolCertGenerateSelfSigned(t, certLabel, 2)
		certFile := writeTestDataFile(t, cfg.TempDir, "self_signed_cert_2.der", certDER)

		writeOutput, writeStderr, writeErr := runPKCS11ToolCommand(t, cfg,
			"--login", "--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--write-object", certFile,
			"--type", "cert",
			"--label", certLabel,
			"--id", certID,
		)
		if writeErr != nil {
			t.Fatalf("pkcs11-tool --write-object failed: %v\nstdout: %s\nstderr: %s", writeErr, writeOutput, writeStderr)
		}

		readBackFile := filepath.Join(cfg.TempDir, "cert_readback_2.der")
		readOutput, readStderr, readErr := runPKCS11ToolCommand(t, cfg,
			"--login", "--pin", cfg.PIN,
			"--slot", cfg.SlotID,
			"--read-object",
			"--type", "cert",
			"--label", certLabel,
			"--output-file", readBackFile,
		)
		if readErr != nil {
			t.Fatalf("pkcs11-tool --read-object failed: %v\nstdout: %s\nstderr: %s", readErr, readOutput, readStderr)
		}

		readBackDER := readTestDataFile(t, readBackFile)
		if !bytes.Equal(certDER, readBackDER) {
			t.Fatal("second certificate read back from the token does not match what was written")
		}
	})
}
