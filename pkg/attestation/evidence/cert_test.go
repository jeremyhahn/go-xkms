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

package evidence

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

type certSpec struct {
	cn         string
	isCA       bool
	parent     *x509.Certificate
	parentKey  crypto.Signer
	key        crypto.Signer
	policies   []x509.OID
	unknownEKU []asn1.ObjectIdentifier
	anyEKU     bool
	extraExt   []pkix.Extension
	emptyName  bool
	notAfter   time.Time
}

var serial int64

func issue(t *testing.T, s certSpec) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key := s.key
	if key == nil {
		key = mustECDSA(t, elliptic.P256())
	}
	serial++
	notAfter := s.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: s.cn},
		NotBefore:             time.Now().Add(-2 * time.Hour),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  s.isCA,
		Policies:              s.policies,
		UnknownExtKeyUsage:    s.unknownEKU,
		ExtraExtensions:       s.extraExt,
	}
	if s.emptyName {
		tmpl.Subject = pkix.Name{}
	}
	if s.isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	if s.anyEKU {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	parent, parentKey := tmpl, key
	if s.parent != nil {
		parent, parentKey = s.parent, s.parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func pool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

func pemOf(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

func TestVerifyAKCertificate(t *testing.T) {
	root, rootKey := issue(t, certSpec{cn: "root", isCA: true})
	inter, interKey := issue(t, certSpec{cn: "inter", isCA: true, parent: root, parentKey: rootKey})
	ak, akKey := issue(t, certSpec{cn: "ak", parent: inter, parentKey: interKey, policies: []x509.OID{OIDTCGVerifiedTPMRestrictedPolicy}})

	leaf, extra, err := ParseCertificatesPEM(append(pemOf(ak), append(pem.EncodeToMemory(&pem.Block{Type: "OTHER", Bytes: []byte{1}}), pemOf(inter)...)...))
	if err != nil || len(extra) != 1 {
		t.Fatalf("ParseCertificatesPEM: %v (%d extra)", err, len(extra))
	}
	key, err := VerifyAKCertificate(leaf, extra, AKCertificateOptions{Roots: pool(root)})
	if err != nil {
		t.Fatalf("VerifyAKCertificate: %v", err)
	}
	if !key.(*ecdsa.PublicKey).Equal(akKey.Public()) {
		t.Fatal("returned key is not the AK")
	}
	// Intermediates supplied through the options, merged with evidence-carried ones.
	if _, err := VerifyAKCertificate(ak, []*x509.Certificate{root}, AKCertificateOptions{Roots: pool(root), Intermediates: pool(inter), Now: time.Now()}); err != nil {
		t.Fatalf("with option intermediates: %v", err)
	}

	unrestricted, _ := issue(t, certSpec{cn: "ak2", parent: root, parentKey: rootKey})
	_, err = VerifyAKCertificate(unrestricted, nil, AKCertificateOptions{Roots: pool(root)})
	wantClass(t, err, ClassForged, CheckAKCertificate, "verifiedTPMRestricted")
	if _, err := VerifyAKCertificate(unrestricted, nil, AKCertificateOptions{Roots: pool(root), AllowUnrestricted: true}); err != nil {
		t.Fatalf("AllowUnrestricted: %v", err)
	}

	stranger, _ := issue(t, certSpec{cn: "other root", isCA: true})
	_, err = VerifyAKCertificate(ak, []*x509.Certificate{inter}, AKCertificateOptions{Roots: pool(stranger)})
	wantClass(t, err, ClassForged, CheckAKCertificate, "does not chain")

	_, err = VerifyAKCertificate(ak, nil, AKCertificateOptions{})
	wantClass(t, err, ClassAbsent, CheckAKCertificate, "no trust anchors")
	_, err = VerifyAKCertificate(nil, nil, AKCertificateOptions{Roots: pool(root)})
	wantClass(t, err, ClassAbsent, CheckAKCertificate, "no attestation key certificate")

	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edAK, _ := issue(t, certSpec{cn: "ed", parent: root, parentKey: rootKey, key: edPriv, policies: []x509.OID{OIDTCGVerifiedTPMRestrictedPolicy}})
	_, err = VerifyAKCertificate(edAK, nil, AKCertificateOptions{Roots: pool(root)})
	wantClass(t, err, ClassForged, CheckAKCertificate, "unsupported public key")
}

func TestParseCertificatesPEM_Failures(t *testing.T) {
	_, _, err := ParseCertificatesPEM([]byte("not pem"))
	wantClass(t, err, ClassForged, CheckAKCertificate, "not a PEM CERTIFICATE")
	_, _, err = ParseCertificatesPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}))
	wantClass(t, err, ClassForged, CheckAKCertificate, "does not parse")
}

func TestCarriesVerifiedTPMRestricted(t *testing.T) {
	root, rootKey := issue(t, certSpec{cn: "root", isCA: true})
	ak, _ := issue(t, certSpec{cn: "ak", parent: root, parentKey: rootKey, policies: []x509.OID{OIDTCGVerifiedTPMRestrictedPolicy}})
	if !CarriesVerifiedTPMRestricted(ak) {
		t.Fatal("x509.OID form not recognised")
	}
	ak.Policies = nil
	ak.PolicyIdentifiers = []asn1.ObjectIdentifier{OIDTCGVerifiedTPMRestricted}
	if !CarriesVerifiedTPMRestricted(ak) {
		t.Fatal("legacy PolicyIdentifiers form not recognised")
	}
	ak.PolicyIdentifiers = nil
	if CarriesVerifiedTPMRestricted(ak) || CarriesVerifiedTPMRestricted(nil) {
		t.Fatal("certificate with no policies reported as Restricted")
	}
}

// directoryNameOnlySAN is a critical subjectAltName holding only a
// directoryName: the TPM-manufacturer EK encoding Go reports as an unhandled
// critical extension.
func directoryNameOnlySAN(t *testing.T) pkix.Extension {
	t.Helper()
	name, err := asn1.Marshal(pkix.Name{CommonName: "tpm"}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	gn, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: name})
	if err != nil {
		t.Fatal(err)
	}
	seq, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: gn})
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oidSubjectAltName, Critical: true, Value: seq}
}

func TestVerifyEKCertificate(t *testing.T) {
	root, rootKey := issue(t, certSpec{cn: "mfg root", isCA: true})
	inter, interKey := issue(t, certSpec{cn: "mfg inter", isCA: true, parent: root, parentKey: rootKey})
	ek, _ := issue(t, certSpec{parent: inter, parentKey: interKey, emptyName: true,
		unknownEKU: []asn1.ObjectIdentifier{OIDTCGKpEKCertificate},
		extraExt:   []pkix.Extension{directoryNameOnlySAN(t)}})
	if len(ek.UnhandledCriticalExtensions) == 0 {
		t.Fatal("fixture: the directoryName-only SAN should be an unhandled critical extension")
	}

	leaf, inters, err := ParseEKCertificateChain(append(pemOf(ek), pemOf(inter)...))
	if err != nil || len(inters) != 1 {
		t.Fatalf("ParseEKCertificateChain: %v", err)
	}
	if err := VerifyEKCertificate(leaf, inters, EKCertificateOptions{Roots: pool(root)}); err != nil {
		t.Fatalf("VerifyEKCertificate: %v", err)
	}

	der, _, err := ParseEKCertificateChain(ek.Raw)
	if err != nil || !der.Equal(ek) {
		t.Fatalf("DER form: %v", err)
	}

	noEKU, _ := issue(t, certSpec{cn: "not-ek", parent: root, parentKey: rootKey})
	wantClass(t, VerifyEKCertificate(noEKU, nil, EKCertificateOptions{Roots: pool(root)}), ClassForged, CheckEKCertificate, "tcg-kp-EKCertificate")

	stranger, _ := issue(t, certSpec{cn: "stranger", isCA: true})
	wantClass(t, VerifyEKCertificate(ek, []*x509.Certificate{inter}, EKCertificateOptions{Roots: pool(stranger), Now: time.Now()}), ClassForged, CheckEKCertificate, "does not chain")

	expired, _ := issue(t, certSpec{cn: "old", parent: root, parentKey: rootKey, anyEKU: true, notAfter: time.Now().Add(-time.Hour)})
	wantClass(t, VerifyEKCertificate(expired, nil, EKCertificateOptions{Roots: pool(root)}), ClassForged, CheckEKCertificate, "does not chain")

	wantClass(t, VerifyEKCertificate(ek, nil, EKCertificateOptions{}), ClassAbsent, CheckEKCertificate, "no endorsement key trust anchors")
	wantClass(t, VerifyEKCertificate(nil, nil, EKCertificateOptions{Roots: pool(root)}), ClassAbsent, CheckEKCertificate, "no endorsement key certificate")
}

func TestParseEKCertificateChain_Failures(t *testing.T) {
	root, _ := issue(t, certSpec{cn: "root", isCA: true})
	_, _, err := ParseEKCertificateChain(nil)
	wantClass(t, err, ClassAbsent, CheckEKCertificate, "no endorsement key certificate")
	_, _, err = ParseEKCertificateChain([]byte("not a certificate"))
	wantClass(t, err, ClassForged, CheckEKCertificate, "der:")
	_, _, err = ParseEKCertificateChain(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}))
	wantClass(t, err, ClassForged, CheckEKCertificate, "pem:")
	bundle := append(pemOf(root), pem.EncodeToMemory(&pem.Block{Type: "KEY", Bytes: []byte("skip")})...)
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")})...)
	_, _, err = ParseEKCertificateChain(bundle)
	wantClass(t, err, ClassForged, CheckEKCertificate, "pem intermediate")
}

func TestHasEKCertificateEKU(t *testing.T) {
	root, rootKey := issue(t, certSpec{cn: "root", isCA: true})
	anyEKU, _ := issue(t, certSpec{cn: "a", parent: root, parentKey: rootKey, anyEKU: true})
	standalone, _ := issue(t, certSpec{cn: "s", parent: root, parentKey: rootKey,
		extraExt: []pkix.Extension{{Id: OIDTCGKpEKCertificate, Value: []byte{0x05, 0x00}}}})
	none, _ := issue(t, certSpec{cn: "n", parent: root, parentKey: rootKey})
	if !HasEKCertificateEKU(anyEKU) || !HasEKCertificateEKU(standalone) {
		t.Fatal("accepted EKU encodings not recognised")
	}
	if HasEKCertificateEKU(none) || HasEKCertificateEKU(nil) {
		t.Fatal("certificate without the EKU accepted")
	}
}

func TestStripEKCertificateQuirks(t *testing.T) {
	other := asn1.ObjectIdentifier{1, 2, 3}
	cert := &x509.Certificate{UnhandledCriticalExtensions: []asn1.ObjectIdentifier{oidSubjectAltName, other}}
	StripEKCertificateQuirks(cert)
	if len(cert.UnhandledCriticalExtensions) != 1 || !cert.UnhandledCriticalExtensions[0].Equal(other) {
		t.Fatalf("UnhandledCriticalExtensions = %v, want only the non-SAN OID", cert.UnhandledCriticalExtensions)
	}
	StripEKCertificateQuirks(nil)
	StripEKCertificateQuirks(&x509.Certificate{})
}
