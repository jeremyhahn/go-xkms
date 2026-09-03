// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fingerprintTestCert mints a self-signed P-256 certificate. Every algorithm it
// uses (P-256, ECDSA, SHA-256) is FIPS 140-3 approved, so the same helper works
// in the parent process and in the fips140=only child below.
func fingerprintTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(20260902),
		Subject:      pkix.Name{CommonName: "fingerprint-fixture"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestToString_PrintsSHA256AndNeverSHA1 pins both halves of the contract in
// every FIPS posture, because the output no longer depends on one.
//
// The SHA-1 line was removed outright rather than guarded by a FIPS predicate:
// no predicate available here can answer "is this a FIPS artifact" correctly
// (#219), so any guard would fail open for exactly the artifacts the policy
// cares about. With the line gone there is nothing to get wrong, and this test
// needs no mode awareness at all.
func TestToString_PrintsSHA256AndNeverSHA1(t *testing.T) {
	cert := fingerprintTestCert(t)
	out := ToString(cert)

	require.Contains(t, out,
		fmt.Sprintf("│  SHA-256 Fingerprint: %x\n", sha256.Sum256(cert.Raw)),
		"the SHA-256 fingerprint must be printed")
	require.NotContains(t, out, "SHA-1",
		"no SHA-1 thumbprint may appear in certificate display output")
}

// TestToString_UnderFIPSOnly is the regression test for go-xkms#197.
//
// crypto/sha1.Sum PANICS rather than returning an error under
// GODEBUG=fips140=only, and the FIPS posture is fixed when the process starts,
// so the crash path can only be exercised in a separate process. This mirrors
// the re-exec pattern already used by
// pkg/types.TestFIPSMode_RefusesNonApprovedAlgorithms.
//
// Before the fix the child did not merely fail — it panicked with
// "crypto/sha1: use of SHA-1 is not allowed in FIPS 140-only mode", which is
// precisely the production failure the issue reported.
func TestToString_UnderFIPSOnly(t *testing.T) {
	if os.Getenv("XKMS_FIPS_SUBPROCESS") == "1" {
		cert := fingerprintTestCert(t)

		out := ToString(cert)
		if strings.Contains(out, "SHA-1") {
			t.Error("FIPS 140-only output must not carry a SHA-1 thumbprint")
		}
		want := fmt.Sprintf("│  SHA-256 Fingerprint: %x\n", sha256.Sum256(cert.Raw))
		if !strings.Contains(out, want) {
			t.Errorf("FIPS 140-only output must carry the SHA-256 fingerprint\ngot:\n%s", out)
		}
		// A nil certificate must stay well-behaved in FIPS mode too.
		if got := ToString(nil); got != "<nil certificate>" {
			t.Errorf("ToString(nil) = %q, want %q", got, "<nil certificate>")
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestToString_UnderFIPSOnly", "-test.v")
	cmd.Env = append(os.Environ(), "XKMS_FIPS_SUBPROCESS=1", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fips140=only subprocess failed: %v\n%s", err, out)
	}
	require.Contains(t, string(out), "PASS", "fips140=only subprocess did not pass:\n%s", out)
}
