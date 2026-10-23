package linter

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/zmap/zlint/v3/lint"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// issuerKey and issuerCert are a test root that signs every leaf below.
var issuerKey, issuerCert = func() (*ecdsa.PrivateKey, *x509.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Country: []string{"US"}, Organization: []string{"Test"}, CommonName: "Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return key, cert
}()

// domainValidated is the CA/Browser Forum domain-validated policy,
// 2.23.140.1.2.1 (Baseline Requirements §7.1.6.1).
var domainValidated = func() x509.OID {
	oid, err := x509.OIDFromInts([]uint64{2, 23, 140, 1, 2, 1})
	if err != nil {
		panic(err)
	}
	return oid
}()

// leaf returns a Baseline Requirements TLS server certificate that mutate
// may change before it is signed.
func leaf(t *testing.T, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	return leafSignedBy(t, issuerCert, issuerKey, mutate)
}

// leafSignedBy returns leaf's certificate signed by issuer and issuerKey.
func leafSignedBy(t *testing.T, issuer *x509.Certificate, issuerKey crypto.Signer, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial.Add(serial, big.NewInt(1)),
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().AddDate(0, 0, 90),
		DNSNames:              []string{"www.example.com"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://ca.example.com/root.cer"},
		CRLDistributionPoints: []string{"http://ca.example.com/root.crl"},
		Policies:              []x509.OID{domainValidated},
	}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestLintPassesConformingCertificate(t *testing.T) {
	l, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := l.Lint(leaf(t, nil))
	if err != nil {
		t.Fatalf("Lint() = %v, want nil", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("Errors = %v, want none", result.Errors)
	}
}

func TestLintExcludesConfiguredLints(t *testing.T) {
	l, err := New(Config{ExcludeLints: []string{"e_server_cert_valid_time_longer_than_200_days"}})
	if err != nil {
		t.Fatal(err)
	}
	der := leaf(t, func(c *x509.Certificate) { c.NotAfter = c.NotBefore.AddDate(0, 0, 300) })
	if _, err := l.Lint(der); err != nil {
		t.Fatalf("Lint() = %v, want the excluded lint not to run", err)
	}
}

func TestNewRefusesUnknownLint(t *testing.T) {
	if _, err := New(Config{ExcludeLints: []string{"e_no_such_lint"}}); !errors.Is(err, ErrConfig) {
		t.Fatalf("New() = %v, want ErrConfig", err)
	}
}

func TestNewExcludesConfiguredSource(t *testing.T) {
	l, err := New(Config{ExcludeSources: []string{string(lint.CABFEVGuidelines)}})
	if err != nil {
		t.Fatal(err)
	}
	if lints := l.registry.BySource(lint.CABFEVGuidelines); len(lints) != 0 {
		t.Errorf("%d %s lints still run", len(lints), lint.CABFEVGuidelines)
	}
}

func TestNewRefusesUnknownSource(t *testing.T) {
	// zlint's Filter turns sources into a lookup set without checking them,
	// so a misspelt source would otherwise leave the real one running.
	if _, err := New(Config{ExcludeSources: []string{"CABF_EVG"}}); !errors.Is(err, ErrConfig) {
		t.Fatalf("New() = %v, want ErrConfig", err)
	}
}

func TestLintRefusesUnparsableCertificate(t *testing.T) {
	l, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Lint([]byte("not a certificate")); !errors.Is(err, ErrParse) {
		t.Fatalf("Lint() = %v, want ErrParse", err)
	}
}

func TestSummary(t *testing.T) {
	got := Summary([]Finding{{Lint: "e_a", Details: "bad"}, {Lint: "w_b"}})
	if want := "e_a: bad; w_b"; got != want {
		t.Fatalf("Summary() = %q, want %q", got, want)
	}
	if got := Summary(nil); got != "" {
		t.Fatalf("Summary(nil) = %q, want empty", got)
	}
}

func TestLintRefusesErrors(t *testing.T) {
	l, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	// Baseline Requirements §6.3.2: a TLS certificate issued from March 15,
	// 2026 is valid for at most 200 days.
	der := leaf(t, func(c *x509.Certificate) { c.NotAfter = c.NotBefore.AddDate(0, 0, 300) })
	result, err := l.Lint(der)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("Lint() = %v, want ErrRefused", err)
	}
	if !hasFinding(result.Errors, "e_server_cert_valid_time_longer_than_200_days") {
		t.Fatalf("Errors = %v, want the 200-day lint", result.Errors)
	}
}

func TestLintReturnsWarningsWithoutRefusing(t *testing.T) {
	l, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	der := leaf(t, func(c *x509.Certificate) { c.Subject.CommonName = "www.example.com" })
	result, err := l.Lint(der)
	if err != nil {
		t.Fatalf("Lint() = %v, want nil", err)
	}
	if !hasFinding(result.Warnings, "w_subject_common_name_included") {
		t.Fatalf("Warnings = %v, want w_subject_common_name_included", result.Warnings)
	}
}

func hasFinding(findings []Finding, name string) bool {
	for _, f := range findings {
		if f.Lint == name {
			return true
		}
	}
	return false
}

func TestPrivatePKIConfigExcludesRegisteredLints(t *testing.T) {
	config := PrivatePKIConfig()
	if len(config.ExcludeLints) == 0 {
		t.Fatal("PrivatePKIConfig excludes no lints")
	}
	for _, name := range config.ExcludeLints {
		if lint.GlobalRegistry().ByName(name) == nil {
			t.Errorf("PrivatePKIConfig excludes %q, which zlint does not register", name)
		}
	}
	l, err := New(config)
	if err != nil {
		t.Fatalf("New(PrivatePKIConfig()): %v", err)
	}
	for _, name := range config.ExcludeLints {
		if l.registry.ByName(name) != nil {
			t.Errorf("lint %q still runs", name)
		}
	}
}

// ed25519Issuer returns a test root with an Ed25519 key, which the CA
// supports for signing (pkg/ca determineSignatureAlgorithm).
func ed25519Issuer(t *testing.T) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{Country: []string{"US"}, Organization: []string{"Test"}, CommonName: "Test Ed25519 Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestPrivatePKIConfigAdmitsEd25519Issuer(t *testing.T) {
	issuer, key := ed25519Issuer(t)
	l, err := New(PrivatePKIConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Lint(leafSignedBy(t, issuer, key, nil)); err != nil {
		t.Fatalf("Lint() = %v, want an Ed25519-signed leaf to pass", err)
	}
}

func TestLintRefusesEd25519IssuerUnderTheBaselineRequirements(t *testing.T) {
	// The Baseline Requirements admit only RSA and ECDSA signatures, so the zero Config
	// refuses the leaf PrivatePKIConfig admits.
	issuer, key := ed25519Issuer(t)
	l, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := l.Lint(leafSignedBy(t, issuer, key, nil))
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("Lint() = %v, want ErrRefused", err)
	}
	if !hasFinding(result.Errors, "e_signature_algorithm_not_supported") {
		t.Errorf("errors = %v, want e_signature_algorithm_not_supported", result.Errors)
	}
}

// internalNames and reservedIPs make leaf's identifiers ones an identifier
// policy without RequirePublicSuffix or RejectReservedIPs authorizes.
func internalNames(c *x509.Certificate) {
	c.Subject = pkix.Name{CommonName: "db.internal"}
	c.DNSNames = []string{"db.internal", "localhost"}
}

func reservedIPs(c *x509.Certificate) {
	c.Subject = pkix.Name{CommonName: "10.0.0.1"}
	c.DNSNames = nil
	c.IPAddresses = []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("fd00::1")}
}

// deviceIdentity returns a mutation that adds a device-attest-01 identity as
// an RFC 4043 permanentIdentifier otherName to the subjectAltName.
func deviceIdentity(t *testing.T) func(*x509.Certificate) {
	t.Helper()
	identifier, err := ca.MarshalPermanentIdentifier("device-A", nil)
	if err != nil {
		t.Fatal(err)
	}
	return func(c *x509.Certificate) {
		san, err := ca.BuildSubjectAltName(c.Subject, c.DNSNames, nil, nil, nil,
			[]ca.OtherName{{TypeID: ca.OIDPermanentIdentifier, Value: identifier}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		c.ExtraExtensions = append(c.ExtraExtensions, san)
	}
}

func TestAdmitRunsNoLintRefusingAnAdmittedIdentifier(t *testing.T) {
	cases := map[string]struct {
		ids    Identifiers
		mutate func(*x509.Certificate)
	}{
		"internal names":  {Identifiers{InternalNames: true}, internalNames},
		"reserved IPs":    {Identifiers{ReservedIPs: true}, reservedIPs},
		"device identity": {Identifiers{DeviceIdentity: true}, deviceIdentity(t)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			l, err := New(PrivatePKIConfig().Admit(tc.ids))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := l.Lint(leaf(t, tc.mutate)); err != nil {
				t.Fatalf("Lint() = %v, want the admitted identifiers to pass", err)
			}
		})
	}
}

func TestAdmitKeepsTheLintsOfIdentifiersItDoesNotAdmit(t *testing.T) {
	cases := map[string]struct {
		ids    Identifiers
		mutate func(*x509.Certificate)
		lints  []string
	}{
		"internal names": {Identifiers{ReservedIPs: true}, internalNames, []string{"e_dnsname_not_valid_tld"}},
		"reserved IPs": {Identifiers{InternalNames: true}, reservedIPs, []string{
			"e_ext_san_contains_reserved_ip", "e_subject_contains_reserved_ip",
		}},
		"device identity": {Identifiers{InternalNames: true, ReservedIPs: true}, deviceIdentity(t),
			[]string{"e_ext_san_other_name_present"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			l, err := New(PrivatePKIConfig().Admit(tc.ids))
			if err != nil {
				t.Fatal(err)
			}
			result, err := l.Lint(leaf(t, tc.mutate))
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("Lint() = %v, want ErrRefused", err)
			}
			for _, lint := range tc.lints {
				if !hasFinding(result.Errors, lint) {
					t.Errorf("errors = %v, want %s", result.Errors, lint)
				}
			}
		})
	}
}
