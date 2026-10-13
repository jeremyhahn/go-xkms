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
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
)

func TestBytesEqual(t *testing.T) {
	if !bytesEqual([]byte("abc"), []byte("abc")) {
		t.Fatal("equal slices compared unequal")
	}
	if bytesEqual([]byte("abc"), []byte("abd")) || bytesEqual([]byte("abc"), []byte("ab")) {
		t.Fatal("different slices compared equal")
	}
}

func TestParseChallenge(t *testing.T) {
	key := newKey(t)
	leafDER := attesttest.AttestedLeafDER(t, nil, key, []byte("our challenge"),
		xkms.AndroidSecurityLevelTrustedEnvironment, attesttest.AttestedBootState())
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	got, err := parseChallenge(leaf)
	if err != nil {
		t.Fatalf("parseChallenge: %v", err)
	}
	if string(got) != "our challenge" {
		t.Fatalf("challenge = %q", got)
	}

	plainDER, err := selfSignedCert("no attestation")
	if err != nil {
		t.Fatalf("selfSignedCert: %v", err)
	}
	plain, err := x509.ParseCertificate(plainDER)
	if err != nil {
		t.Fatalf("parse plain: %v", err)
	}
	if _, err := parseChallenge(plain); err == nil {
		t.Fatal("parseChallenge read a challenge from a certificate with no attestation")
	}
}

func TestCSRBindsToLeaf(t *testing.T) {
	key := newKey(t)
	leaf, err := x509.ParseCertificate(attesttest.AttestedLeafDER(t, nil, key, []byte("nonce"),
		xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState()))
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	csr := csrFor(t, key)

	if err := csrBindsToLeaf(csr, leaf); err != nil {
		t.Fatalf("csrBindsToLeaf(same key) = %v", err)
	}

	tampered := bytes.Clone(csr)
	tampered[len(tampered)-1] ^= 0xff
	tests := map[string][]byte{
		"CSR for another key": csrFor(t, newKey(t)),
		"CSR does not parse":  []byte("not a CSR"),
		"CSR signature bad":   tampered,
	}
	for name, der := range tests {
		t.Run(name, func(t *testing.T) {
			if err := csrBindsToLeaf(der, leaf); err == nil {
				t.Fatal("csrBindsToLeaf accepted it")
			}
		})
	}
}

func TestIssueProbeCredential_CertifiesTheCSRKeyForClientAuth(t *testing.T) {
	csrDER := csrFor(t, newKey(t))
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	certDER, err := issueProbeCredential(csrDER)
	if err != nil {
		t.Fatalf("issueProbeCredential: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		t.Fatal("the issued certificate is not for the CSR's key")
	}
	if cert.Subject.CommonName != "probe subject" {
		t.Fatalf("subject CN = %q, want the CSR's", cert.Subject.CommonName)
	}
	if cert.IsCA || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("issued a credential that is not a client-auth leaf: CA=%v EKU=%v", cert.IsCA, cert.ExtKeyUsage)
	}
}

func TestIssueProbeCredential_RefusesABadCSR(t *testing.T) {
	tampered := csrFor(t, newKey(t))
	tampered[len(tampered)-1] ^= 0xff

	for name, der := range map[string][]byte{
		"does not parse": []byte("not a CSR"),
		"bad signature":  tampered,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := issueProbeCredential(der); err == nil {
				t.Fatal("issueProbeCredential certified a CSR that proves nothing")
			}
		})
	}
}

func TestProbeStaticKey_GeneratesAFreshKeyWhenUnset(t *testing.T) {
	t.Setenv("XKEY_PROBE_STATIC_KEY", "")

	key, err := probeStaticKey()
	if err != nil {
		t.Fatalf("probeStaticKey: %v", err)
	}
	defer key.Destroy()
	if len(key.PublicBytes()) != 32 {
		t.Fatalf("public key is %d bytes, want 32", len(key.PublicBytes()))
	}
}

func TestProbeStaticKey_LoadsTheSuppliedKey(t *testing.T) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	want, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatalf("X25519 key: %v", err)
	}
	// Surrounding whitespace, as a value pasted into an env file carries.
	t.Setenv("XKEY_PROBE_STATIC_KEY", " "+b64(raw)+"\n")

	key, err := probeStaticKey()
	if err != nil {
		t.Fatalf("probeStaticKey: %v", err)
	}
	defer key.Destroy()
	if !bytes.Equal(key.PublicBytes(), want.PublicKey().Bytes()) {
		t.Fatal("the loaded key's public half is not the supplied key's")
	}
}

func TestProbeStaticKey_RefusesABadKey(t *testing.T) {
	for name, value := range map[string]string{
		"not base64":   "!!not-base64!!",
		"wrong length": b64([]byte("short")),
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("XKEY_PROBE_STATIC_KEY", value)
			if key, err := probeStaticKey(); err == nil {
				key.Destroy()
				t.Fatal("probeStaticKey accepted it")
			}
		})
	}
}
