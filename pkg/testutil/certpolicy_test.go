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

package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// issueForPolicy signs a certificate from the supplied template with a fresh
// key, so that two calls with the same template differ in every field the
// policy fingerprint is supposed to ignore.
func issueForPolicy(t *testing.T, template *x509.Certificate) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// policyTemplate returns a template exercising every field the fingerprint
// covers: key usage, extended key usage, basic constraints, path length, all
// four subject alternative name types and the revocation endpoints.
func policyTemplate(serial int64) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "policy.example.com", Organization: []string{"Test"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		DNSNames:              []string{"policy.example.com"},
		EmailAddresses:        []string{"admin@example.com"},
		IPAddresses:           []net.IP{net.ParseIP("10.0.0.1")},
		CRLDistributionPoints: []string{"http://crl.example.com/ca.crl"},
		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://aia.example.com/ca.cer"},
	}
}

// TestPolicyFingerprint_StableAcrossKeysSerialsAndTimes asserts the property
// the whole regression suite rests on: two certificates issued from the same
// policy but with different keys, serials and timestamps fingerprint the same.
func TestPolicyFingerprint_StableAcrossKeysSerialsAndTimes(t *testing.T) {
	first := issueForPolicy(t, policyTemplate(1))
	time.Sleep(2 * time.Millisecond)
	second := issueForPolicy(t, policyTemplate(999999))

	if first.SerialNumber.Cmp(second.SerialNumber) == 0 {
		t.Fatal("the two certificates should differ in serial number")
	}
	if first.NotBefore.Equal(second.NotBefore) {
		t.Log("timestamps coincided; the fingerprint must still match")
	}

	if got, want := PolicyFingerprint(second), PolicyFingerprint(first); got != want {
		t.Errorf("fingerprints differ for identical policy\nfirst:\n%s\nsecond:\n%s",
			RenderCertificatePolicy(first), RenderCertificatePolicy(second))
	}
}

// TestPolicyFingerprint_DetectsPolicyChanges asserts the fingerprint reacts to
// every kind of policy change a certificate-issuance refactor could make by
// accident.
func TestPolicyFingerprint_DetectsPolicyChanges(t *testing.T) {
	baseline := PolicyFingerprint(issueForPolicy(t, policyTemplate(1)))

	cases := map[string]func(*x509.Certificate){
		"key usage": func(tpl *x509.Certificate) {
			tpl.KeyUsage = x509.KeyUsageDigitalSignature
		},
		"extended key usage": func(tpl *x509.Certificate) {
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		},
		"extended key usage order": func(tpl *x509.Certificate) {
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		},
		"path length": func(tpl *x509.Certificate) {
			tpl.MaxPathLen = 0
			tpl.MaxPathLenZero = true
		},
		"basic constraints removed": func(tpl *x509.Certificate) {
			tpl.BasicConstraintsValid = false
			tpl.IsCA = false
		},
		"ocsp responder": func(tpl *x509.Certificate) {
			tpl.OCSPServer = []string{"http://other.example.com"}
		},
		"crl distribution point removed": func(tpl *x509.Certificate) {
			tpl.CRLDistributionPoints = nil
		},
		"ca issuer url removed": func(tpl *x509.Certificate) {
			tpl.IssuingCertificateURL = nil
		},
		"subject alternative name": func(tpl *x509.Certificate) {
			tpl.DNSNames = []string{"other.example.com"}
		},
		"subject": func(tpl *x509.Certificate) {
			tpl.Subject = pkix.Name{CommonName: "other.example.com"}
		},
		"validity duration": func(tpl *x509.Certificate) {
			tpl.NotAfter = tpl.NotBefore.AddDate(2, 0, 0)
		},
		"extra extension": func(tpl *x509.Certificate) {
			tpl.ExtraExtensions = []pkix.Extension{{
				Id:    []int{1, 3, 6, 1, 4, 1, 99999, 1},
				Value: []byte{0x05, 0x00},
			}}
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tpl := policyTemplate(1)
			mutate(tpl)
			if got := PolicyFingerprint(issueForPolicy(t, tpl)); got == baseline {
				t.Errorf("changing the %s did not change the fingerprint", name)
			}
		})
	}
}

// TestPolicyFingerprint_IgnoresKeyDerivedExtensionValues asserts that the
// subject and authority key identifiers, whose values are hashes of freshly
// generated keys, are elided rather than fingerprinted.
func TestPolicyFingerprint_IgnoresKeyDerivedExtensionValues(t *testing.T) {
	rendered := RenderCertificatePolicy(issueForPolicy(t, policyTemplate(1)))

	if !strings.Contains(rendered, "2.5.29.14 critical=false value=<key-derived>") {
		t.Errorf("subject key identifier value should be elided, got:\n%s", rendered)
	}
	if strings.Contains(rendered, "raw_subject=\n") {
		t.Error("the raw subject should be fingerprinted, not elided")
	}
}

// TestCertificatePolicyOf_NilCertificate asserts the extractor tolerates a nil
// certificate so table tests can compare against a missing path without
// nil-checking first.
func TestCertificatePolicyOf_NilCertificate(t *testing.T) {
	policy := CertificatePolicyOf(nil)
	if policy.Version != 0 || policy.RawSubject != "" || len(policy.Extensions) != 0 {
		t.Errorf("nil certificate should yield the zero policy, got %+v", policy)
	}

	// The fingerprint of a nil certificate must be stable, and must not equal
	// the fingerprint of a real one.
	if PolicyFingerprint(nil) != PolicyFingerprint(nil) {
		t.Error("the nil fingerprint should be stable")
	}
	if PolicyFingerprint(nil) == PolicyFingerprint(issueForPolicy(t, policyTemplate(1))) {
		t.Error("a nil certificate should not fingerprint the same as a real one")
	}
}

// TestCertificatePolicyOf_SortsUnorderedFields asserts that fields whose order
// is not a policy decision — subject alternative names and endpoint URLs — are
// normalized, while the extension sequence, which is encoded into the
// certificate, is not.
func TestCertificatePolicyOf_SortsUnorderedFields(t *testing.T) {
	tpl := policyTemplate(1)
	tpl.DNSNames = []string{"b.example.com", "a.example.com"}
	tpl.OCSPServer = []string{"http://z.example.com", "http://a.example.com"}
	first := CertificatePolicyOf(issueForPolicy(t, tpl))

	tpl = policyTemplate(1)
	tpl.DNSNames = []string{"a.example.com", "b.example.com"}
	tpl.OCSPServer = []string{"http://a.example.com", "http://z.example.com"}
	second := CertificatePolicyOf(issueForPolicy(t, tpl))

	if strings.Join(first.DNSNames, ",") != strings.Join(second.DNSNames, ",") {
		t.Errorf("DNS names should be normalized: %v vs %v", first.DNSNames, second.DNSNames)
	}
	if strings.Join(first.OCSPServer, ",") != strings.Join(second.OCSPServer, ",") {
		t.Errorf("OCSP responders should be normalized: %v vs %v", first.OCSPServer, second.OCSPServer)
	}
}
