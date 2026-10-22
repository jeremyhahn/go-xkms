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

package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

// overlayFixture is a test CA plus two name-constrained subordinates: a
// tunnel intermediate confined to a fabric IPv4 /24 and a ULA /64, and a
// SPIFFE intermediate confined to one trust domain.
type overlayFixture struct {
	ca        *CA
	tunnel    *x509.Certificate
	tunnelKey crypto.Signer
	svid      *x509.Certificate
	svidKey   crypto.Signer
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return n
}

func newECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

func newOverlayFixture(t *testing.T) *overlayFixture {
	t.Helper()
	c := setupTestCA(t)
	ctx := context.Background()

	tunnelKey := newECKey(t, elliptic.P256())
	tunnel, err := c.IssueSubordinateCA(ctx, &SubordinateCARequest{
		Subject:   pkix.Name{CommonName: "Tunnel Intermediate"},
		PublicKey: tunnelKey.Public(),
		NameConstraints: &NameConstraints{
			Critical:          true,
			PermittedIPRanges: []*net.IPNet{mustCIDR(t, "10.4.0.0/24"), mustCIDR(t, "fd00:4::/64")},
		},
		Validity: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("issue tunnel subordinate: %v", err)
	}

	svidKey := newECKey(t, elliptic.P256())
	svid, err := c.IssueSubordinateCA(ctx, &SubordinateCARequest{
		Subject:   pkix.Name{CommonName: "SPIFFE Intermediate"},
		PublicKey: svidKey.Public(),
		NameConstraints: &NameConstraints{
			Critical:            true,
			PermittedURIDomains: []string{testTenant},
		},
	})
	if err != nil {
		t.Fatalf("issue svid subordinate: %v", err)
	}
	return &overlayFixture{ca: c, tunnel: tunnel, tunnelKey: tunnelKey, svid: svid, svidKey: svidKey}
}

// csrFor builds a CSR for key that names the given SANs and extensions, so a
// test can prove which of them reach the certificate.
func csrFor(t *testing.T, key crypto.Signer, cn string, ips []net.IP, uris []*url.URL, exts []pkix.Extension) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: cn},
		IPAddresses:     ips,
		URIs:            uris,
		ExtraExtensions: exts,
	}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func (f *overlayFixture) verify(t *testing.T, leaf, intermediate *x509.Certificate) error {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(f.ca.rootCert)
	inter := x509.NewCertPool()
	inter.AddCert(intermediate)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

func TestIssueSubordinateCA_EncodesNameConstraints(t *testing.T) {
	f := newOverlayFixture(t)

	if !f.tunnel.IsCA || !f.tunnel.MaxPathLenZero || f.tunnel.MaxPathLen != 0 {
		t.Fatalf("tunnel subordinate must be a CA with pathLen 0: IsCA=%v MaxPathLen=%d zero=%v",
			f.tunnel.IsCA, f.tunnel.MaxPathLen, f.tunnel.MaxPathLenZero)
	}
	if !f.tunnel.PermittedDNSDomainsCritical {
		t.Error("name constraints must be critical")
	}
	got := map[string]bool{}
	for _, n := range f.tunnel.PermittedIPRanges {
		got[n.String()] = true
	}
	if !got["10.4.0.0/24"] || !got["fd00:4::/64"] || len(got) != 2 {
		t.Errorf("PermittedIPRanges = %v", f.tunnel.PermittedIPRanges)
	}
	if len(f.svid.PermittedURIDomains) != 1 || f.svid.PermittedURIDomains[0] != testTenant {
		t.Errorf("PermittedURIDomains = %v", f.svid.PermittedURIDomains)
	}
	if err := f.tunnel.CheckSignatureFrom(f.ca.rootCert); err != nil {
		t.Errorf("subordinate not signed by the CA: %v", err)
	}
}

func TestIssueSubordinateCA_Refusals(t *testing.T) {
	c := setupTestCA(t)
	key := newECKey(t, elliptic.P256())
	nc := &NameConstraints{PermittedIPRanges: []*net.IPNet{mustCIDR(t, "10.0.0.0/8")}}

	cases := []struct {
		name string
		req  *SubordinateCARequest
		want error
	}{
		{"nil request", nil, ErrInvalidCertificate},
		{"no common name", &SubordinateCARequest{PublicKey: key.Public(), NameConstraints: nc}, ErrInvalidCertificate},
		{"no key", &SubordinateCARequest{Subject: pkix.Name{CommonName: "x"}, NameConstraints: nc}, ErrInvalidCertificate},
		{"no constraints", &SubordinateCARequest{Subject: pkix.Name{CommonName: "x"}, PublicKey: key.Public()}, ErrInvalidNameConstraints},
		{"only excluded", &SubordinateCARequest{Subject: pkix.Name{CommonName: "x"}, PublicKey: key.Public(),
			NameConstraints: &NameConstraints{ExcludedDNSDomains: []string{"example.com"}}}, ErrInvalidNameConstraints},
		{"host bits", &SubordinateCARequest{Subject: pkix.Name{CommonName: "x"}, PublicKey: key.Public(),
			NameConstraints: &NameConstraints{PermittedIPRanges: []*net.IPNet{{IP: net.ParseIP("10.0.0.1").To4(), Mask: net.CIDRMask(8, 32)}}}}, ErrInvalidNameConstraints},
		{"nil range", &SubordinateCARequest{Subject: pkix.Name{CommonName: "x"}, PublicKey: key.Public(),
			NameConstraints: &NameConstraints{PermittedIPRanges: []*net.IPNet{nil}}}, ErrInvalidNameConstraints},
		{"bad uri domain", &SubordinateCARequest{Subject: pkix.Name{CommonName: "x"}, PublicKey: key.Public(),
			NameConstraints: &NameConstraints{PermittedURIDomains: []string{"spiffe://example.org/x"}}}, ErrInvalidNameConstraints},
		{"negative validity", &SubordinateCARequest{Subject: pkix.Name{CommonName: "x"}, PublicKey: key.Public(), NameConstraints: nc, Validity: -time.Hour}, ErrInvalidValidity},
		{"outlives issuer", &SubordinateCARequest{Subject: pkix.Name{CommonName: "x"}, PublicKey: key.Public(), NameConstraints: nc, Validity: 100 * 365 * 24 * time.Hour}, ErrValidityExceedsIssuer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.IssueSubordinateCA(context.Background(), tc.req)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNameConstraintsOnlyOnCACertificates(t *testing.T) {
	c := setupTestCA(t)
	key := newECKey(t, elliptic.P256())
	signer, err := c.getSigner(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	iss := &Issuer{Signer: signer, Certificate: c.rootCert}
	_, err = iss.Template(&CertificateSpec{
		Serial:          bigOne(),
		Subject:         pkix.Name{CommonName: "leaf"},
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(time.Hour),
		PublicKey:       key.Public(),
		Profile:         NewServerProfile(),
		NameConstraints: &NameConstraints{PermittedDNSDomains: []string{"example.com"}},
	})
	if !errors.Is(err, ErrInvalidNameConstraints) {
		t.Fatalf("err = %v, want ErrInvalidNameConstraints", err)
	}
}

func TestIPsecVTEP_Shape(t *testing.T) {
	f := newOverlayFixture(t)
	key := newECKey(t, elliptic.P256())
	// The CSR asks for a name and an evidence extension of its own; neither
	// may reach the certificate.
	csrEvidence, err := CreateAttestationEvidenceExtension(AttestationEvidence{
		VerdictID: "forged", PCRDigestAlgorithm: crypto.SHA256, PCRDigest: make([]byte, 32), AttestedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	csr := csrFor(t, key, "attacker-chosen", []net.IP{net.ParseIP("10.4.0.99")}, nil, []pkix.Extension{csrEvidence})

	digest := sha256.Sum256([]byte("pcrs"))
	evidence, err := CreateAttestationEvidenceExtension(AttestationEvidence{
		VerdictID: "verdict-1", PCRDigestAlgorithm: crypto.SHA256, PCRDigest: digest[:], AttestedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}

	cert, err := f.ca.SignCSR(context.Background(), csr, &SignOptions{
		TenantID:        testTenant,
		Profile:         ProfileNameIPsecVTEP,
		Signer:          f.tunnelKey,
		IssuerCert:      f.tunnel,
		Subject:         &Subject{CommonName: "vtep-7"},
		SANS:            &SubjectAlternativeNames{IPs: []string{"10.4.0.7", "fd00:4::7"}},
		ExtraExtensions: []pkix.Extension{evidence},
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if cert.IsCA || !cert.BasicConstraintsValid {
		t.Error("ipsec-vtep must assert cA=false")
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v", cert.KeyUsage)
	}
	if len(cert.ExtKeyUsage) != 0 || len(cert.UnknownExtKeyUsage) != 1 || !cert.UnknownExtKeyUsage[0].Equal(OIDIPsecIKE) {
		t.Errorf("EKU = %v / %v, want only id-kp-ipsecIKE", cert.ExtKeyUsage, cert.UnknownExtKeyUsage)
	}
	if cert.Subject.CommonName != "vtep-7" {
		t.Errorf("subject %q taken from the CSR", cert.Subject.CommonName)
	}
	if len(cert.IPAddresses) != 2 || !cert.IPAddresses[0].Equal(net.ParseIP("10.4.0.7")) {
		t.Errorf("IPAddresses = %v, want the caller's names only", cert.IPAddresses)
	}
	got, ok, err := ParseAttestationEvidenceExtension(cert)
	if err != nil || !ok || got.VerdictID != "verdict-1" {
		t.Fatalf("evidence = %+v %v %v, want the caller's", got, ok, err)
	}
	if lifetime := cert.NotAfter.Sub(cert.NotBefore); lifetime != ipsecVTEPDefaultLifetime {
		t.Errorf("lifetime = %v, want %v", lifetime, ipsecVTEPDefaultLifetime)
	}
	if err := f.verify(t, cert, f.tunnel); err != nil {
		t.Errorf("chain verification: %v", err)
	}
}

func TestIPsecVTEP_Refusals(t *testing.T) {
	f := newOverlayFixture(t)
	ec := newECKey(t, elliptic.P256())
	p521 := newECKey(t, elliptic.P521())
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dup, _ := CreateAttestationEvidenceExtension(AttestationEvidence{
		VerdictID: "v", PCRDigestAlgorithm: crypto.SHA256, PCRDigest: make([]byte, 32), AttestedAt: time.Now(),
	})

	base := func() *SignOptions {
		return &SignOptions{
			TenantID: testTenant,
			Profile:  ProfileNameIPsecVTEP, Signer: f.tunnelKey, IssuerCert: f.tunnel,
			SANS: &SubjectAlternativeNames{IPs: []string{"10.4.0.7"}},
		}
	}
	cases := []struct {
		name   string
		key    crypto.Signer
		mutate func(*SignOptions)
		want   error
	}{
		{"no caller SANs even though the CSR has them", ec, func(o *SignOptions) { o.SANS = nil }, ErrCallerSANsRequired},
		{"dns only", ec, func(o *SignOptions) { o.SANS = &SubjectAlternativeNames{DNS: []string{"vtep.example.com"}} }, ErrInvalidSAN},
		{"uri refused", ec, func(o *SignOptions) { o.SANS.URIs = []string{"spiffe://example.org/x"} }, ErrInvalidSAN},
		{"unparseable ip", ec, func(o *SignOptions) { o.SANS.IPs = []string{"10.4.0.300"} }, ErrInvalidSAN},
		{"outside the tunnel constraints", ec, func(o *SignOptions) { o.SANS.IPs = []string{"192.0.2.1"} }, ErrNameConstraintViolation},
		{"tenant spiffe", ec, func(o *SignOptions) { o.SPIFFETrustDomain = "example.org"; o.TenantID = "t1" }, ErrTenantSPIFFEWithCallerSANs},
		{"above max lifetime", ec, func(o *SignOptions) { o.Validity = 91 * 24 * time.Hour }, ErrValidityExceedsProfile},
		{"negative validity", ec, func(o *SignOptions) { o.Validity = -time.Hour }, ErrInvalidValidity},
		{"P-521", p521, func(*SignOptions) {}, ErrUnsupportedProfileKey},
		{"Ed25519", edKey, func(*SignOptions) {}, ErrUnsupportedProfileKey},
		{"RSA-2048", rsa2048, func(*SignOptions) {}, ErrUnsupportedProfileKey},
		{"duplicate evidence", ec, func(o *SignOptions) { o.ExtraExtensions = []pkix.Extension{dup, dup} }, ErrInvalidAttestationEvidence},
		{"garbage evidence", ec, func(o *SignOptions) {
			o.ExtraExtensions = []pkix.Extension{{Id: OIDAttestationEvidence, Value: []byte{0x01}}}
		}, ErrInvalidAttestationEvidence},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := base()
			tc.mutate(opts)
			csr := csrFor(t, tc.key, "vtep", []net.IP{net.ParseIP("10.4.0.8")}, nil, nil)
			_, err := f.ca.SignCSR(context.Background(), csr, opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestIPsecVTEP_LeafOutsideConstraintsFailsPathValidation(t *testing.T) {
	// The pre-sign check and crypto/x509 must agree: a leaf the CA would
	// refuse is one a relying party rejects. Sign one by hand, bypassing the
	// CA, and confirm path validation fails.
	f := newOverlayFixture(t)
	key := newECKey(t, elliptic.P256())
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: bigOne(),
		Subject:      pkix.Name{CommonName: "rogue"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("192.0.2.1")},
	}, f.tunnel, key.Public(), f.tunnelKey)
	if err != nil {
		t.Fatal(err)
	}
	rogue, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.verify(t, rogue, f.tunnel); err == nil {
		t.Fatal("a leaf outside the subordinate's constraints verified")
	}
	if err := checkIssuerNameConstraints(f.tunnel, rogue); !errors.Is(err, ErrNameConstraintViolation) {
		t.Fatalf("pre-sign check = %v, want ErrNameConstraintViolation", err)
	}
}

func TestX509SVID_Shape(t *testing.T) {
	f := newOverlayFixture(t)
	key := newECKey(t, elliptic.P256())
	csr := csrFor(t, key, "csr-cn", nil, []*url.URL{{Scheme: "spiffe", Host: "example.org", Path: "/admin"}}, nil)

	cert, err := f.ca.SignCSR(context.Background(), csr, &SignOptions{
		TenantID:   testTenant,
		Profile:    ProfileNameX509SVID,
		Signer:     f.svidKey,
		IssuerCert: f.svid,
		SANS:       &SubjectAlternativeNames{URIs: []string{"spiffe://tenant-test/svc/web"}},
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if cert.IsCA || !cert.BasicConstraintsValid {
		t.Error("an SVID must assert cA=false")
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v", cert.KeyUsage)
	}
	if len(cert.ExtKeyUsage) != 2 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || cert.ExtKeyUsage[1] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v", cert.ExtKeyUsage)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://tenant-test/svc/web" {
		t.Errorf("URIs = %v, want only the caller's SPIFFE ID", cert.URIs)
	}
	if cert.Subject.CommonName != "" {
		t.Errorf("subject %q taken from the CSR", cert.Subject.CommonName)
	}
	if lifetime := cert.NotAfter.Sub(cert.NotBefore); lifetime != time.Hour {
		t.Errorf("lifetime = %v, want 1h", lifetime)
	}
	if err := f.verify(t, cert, f.svid); err != nil {
		t.Errorf("chain verification: %v", err)
	}
}

func TestX509SVID_RSAKeyAddsKeyEncipherment(t *testing.T) {
	f := newOverlayFixture(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := f.ca.SignCSR(context.Background(), csrFor(t, key, "", nil, nil, nil), &SignOptions{
		TenantID: testTenant,
		Profile:  ProfileNameX509SVID, Signer: f.svidKey, IssuerCert: f.svid, Validity: 10 * time.Minute,
		SANS: &SubjectAlternativeNames{URIs: []string{"spiffe://tenant-test/w"}},
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment {
		t.Errorf("KeyUsage = %v", cert.KeyUsage)
	}
	if cert.NotAfter.Sub(cert.NotBefore) != 10*time.Minute {
		t.Errorf("lifetime = %v, want the requested 10m", cert.NotAfter.Sub(cert.NotBefore))
	}
}

func TestX509SVID_Refusals(t *testing.T) {
	f := newOverlayFixture(t)
	ec := newECKey(t, elliptic.P256())
	cases := []struct {
		name string
		sans *SubjectAlternativeNames
		opts func(*SignOptions)
		want error
	}{
		{"no names", nil, nil, ErrCallerSANsRequired},
		{"two URIs", &SubjectAlternativeNames{URIs: []string{"spiffe://tenant-test/a", "spiffe://tenant-test/b"}}, nil, ErrInvalidSAN},
		{"dns only", &SubjectAlternativeNames{DNS: []string{"web.example.org"}}, nil, ErrInvalidSAN},
		{"not spiffe", &SubjectAlternativeNames{URIs: []string{"https://tenant-test/a"}}, nil, ErrInvalidSAN},
		{"bad segment", &SubjectAlternativeNames{URIs: []string{"spiffe://tenant-test/a/../b"}}, nil, ErrInvalidSAN},
		{"ip refused", &SubjectAlternativeNames{URIs: []string{"spiffe://tenant-test/a"}, IPs: []string{"10.0.0.1"}}, nil, ErrInvalidSAN},
		{"foreign trust domain", &SubjectAlternativeNames{URIs: []string{"spiffe://other.org/a"}}, nil, ErrNameConstraintViolation},
		{"trust domain is not the tenant", &SubjectAlternativeNames{URIs: []string{"spiffe://tenant-test/a"}}, func(o *SignOptions) { o.TenantID = "tenant-other" }, ErrInvalidSAN},
		{"above 24h", &SubjectAlternativeNames{URIs: []string{"spiffe://tenant-test/a"}}, func(o *SignOptions) { o.ValidityDays = 2 }, ErrValidityExceedsProfile},
		{"spiffe kind", &SubjectAlternativeNames{URIs: []string{"spiffe://tenant-test/a"}}, func(o *SignOptions) { o.SPIFFEKind = "svc" }, ErrTenantSPIFFEWithCallerSANs},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := &SignOptions{TenantID: testTenant, Profile: ProfileNameX509SVID, Signer: f.svidKey, IssuerCert: f.svid, SANS: tc.sans}
			if tc.opts != nil {
				tc.opts(opts)
			}
			_, err := f.ca.SignCSR(context.Background(), csrFor(t, ec, "", nil, nil, nil), opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestX509SVID_TenantIDAloneRecordsOwnership(t *testing.T) {
	// TenantID without the SPIFFE synthesis options adds no name; it only
	// records which tenant may later revoke the certificate.
	f := newOverlayFixture(t)
	ec := newECKey(t, elliptic.P256())
	cert, err := f.ca.SignCSR(context.Background(), csrFor(t, ec, "", nil, nil, nil), &SignOptions{
		Profile: ProfileNameX509SVID, Signer: f.svidKey, IssuerCert: f.svid, TenantID: testTenant,
		SANS: &SubjectAlternativeNames{URIs: []string{"spiffe://tenant-test/w"}},
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(cert.URIs) != 1 {
		t.Fatalf("URIs = %v", cert.URIs)
	}
}

func TestOverlayProfilesRegistered(t *testing.T) {
	reg := NewDefaultProfileRegistry()
	for _, name := range []string{ProfileNameIPsecVTEP, ProfileNameX509SVID} {
		p, err := reg.Get(name)
		if err != nil {
			t.Fatalf("%s not registered: %v", name, err)
		}
		if !isCallerSANProfile(p) {
			t.Errorf("%s must take caller-supplied names", name)
		}
		if _, ok := p.(LifetimeBoundedProfile); !ok {
			t.Errorf("%s must bound its lifetime", name)
		}
	}
	if isCallerSANProfile(NewServerProfile()) {
		t.Error("the server profile must keep copying CSR names")
	}
}

func TestIssueCertificateWithProfile_IPsecVTEP(t *testing.T) {
	// The keypair path builds its own CSR from the request's names and passes
	// the same names as caller SANs; the certificate carries them once.
	c := setupTestCA(t)
	issued, err := c.IssueCertificateWithProfile(context.Background(), &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "vtep-kp"},
		SANS:     &SubjectAlternativeNames{IPs: []string{"10.9.0.1"}},
		Signer:   newECKey(t, elliptic.P256()),
	}, ProfileNameIPsecVTEP)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	cert := issued.Certificate
	if len(cert.IPAddresses) != 1 || cert.Subject.CommonName != "vtep-kp" {
		t.Errorf("IPs = %v CN = %q", cert.IPAddresses, cert.Subject.CommonName)
	}
}

func bigOne() *big.Int { return big.NewInt(1) }

func TestKeyPolicy_RefusesMissingAndUnknownKeys(t *testing.T) {
	policy := NewX509SVIDProfile().(*x509SVIDProfile).keys
	for name, pub := range map[string]crypto.PublicKey{"nil": nil, "unknown type": struct{}{}} {
		if err := policy.check(ProfileNameX509SVID, pub); !errors.Is(err, ErrUnsupportedProfileKey) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.check(ProfileNameX509SVID, edPrivate); err == nil {
		t.Error("a private key value is not a public key and must be refused")
	}
	if err := policy.check(ProfileNameX509SVID, edPublic); err != nil {
		t.Errorf("x509-svid must certify Ed25519: %v", err)
	}
}

// TestSignCallerNamedCSR_RequiresSignOptions covers the guard for a
// caller-named profile reached with no SignOptions: there is nowhere for the
// caller's names to come from, so it is refused rather than dereferenced.
func TestSignCallerNamedCSR_RequiresSignOptions(t *testing.T) {
	ca := &CA{}
	_, err := ca.signCallerNamedCSR(context.Background(), &x509.CertificateRequest{}, nil, nil, &signContext{profile: NewIPsecVTEPProfile()})
	if !errors.Is(err, ErrCallerSANsRequired) {
		t.Fatalf("error = %v, want ErrCallerSANsRequired", err)
	}
}
