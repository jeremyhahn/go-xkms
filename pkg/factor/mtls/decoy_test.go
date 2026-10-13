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

package mtls

import (
	"bytes"
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
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/factor/internal/decoy"
)

// decoyEnroller has the method set of go-qrdb's authfactors.DecoyEnroller,
// which go-qrdb/sdk/go does not re-export.
type decoyEnroller interface {
	DecoyEnrollment(seed []byte, userID string, like []*qrdbsdk.AuthFactorEnrollment) (*qrdbsdk.AuthFactorEnrollment, error)
}

var _ decoyEnroller = (*Factor)(nil)

var (
	decoySeed      = bytes.Repeat([]byte{0x11}, 32)
	otherDecoySeed = bytes.Repeat([]byte{0x22}, 32)
)

// decoyHolder is the user id of the enrolled holder a decoy imitates.
const decoyHolder = "custodian-1"

// testKeys generates a subject or issuer key of each named type.
var testKeys = map[string]func() (crypto.Signer, error){
	"p256":    func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) },
	"p384":    func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) },
	"rsa2048": func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 2048) },
	"ed25519": func() (crypto.Signer, error) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	},
}

func newKey(t *testing.T, kind string) crypto.Signer {
	t.Helper()
	key, err := testKeys[kind]()
	if err != nil {
		t.Fatalf("generate %s key: %v", kind, err)
	}
	return key
}

// testKeyID computes the subject key identifier crypto/x509 gives a CA: the
// SHA-256 of the key bits, truncated to 20 bytes.
func testKeyID(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		t.Fatalf("unmarshal public key: %v", err)
	}
	sum := sha256.Sum256(spki.Key.Bytes)
	return sum[:20]
}

// issue signs tmpl for pub as parent by signer and returns the certificate.
func issue(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// clientTemplate is a client certificate naming holder in its subject and in
// every textual form of subject alternative name, with a 20-byte serial.
func clientTemplate(t *testing.T, holder string) *x509.Certificate {
	t.Helper()
	serial := make([]byte, 20)
	if _, err := rand.Read(serial); err != nil {
		t.Fatalf("serial: %v", err)
	}
	serial[0] = 0x40 | serial[0]&0x3f
	uri, err := url.Parse("spiffe://example.com/user/" + holder)
	if err != nil {
		t.Fatalf("parse uri: %v", err)
	}
	notBefore := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	return &x509.Certificate{
		SerialNumber:   new(big.Int).SetBytes(serial),
		Subject:        pkix.Name{CommonName: holder, Organization: []string{"Example Corp"}, OrganizationalUnit: []string{"Custodians"}},
		DNSNames:       []string{holder + ".clients.example.com"},
		EmailAddresses: []string{holder + "@example.com"},
		URIs:           []*url.URL{uri},
		NotBefore:      notBefore,
		NotAfter:       notBefore.Add(90 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

// caIssued returns a client certificate for holder with a leafKind key,
// issued by a fresh CA with a caKind key. It carries crypto/x509-style
// subject and authority key identifiers.
func caIssued(t *testing.T, holder, caKind, leafKind string) []byte {
	t.Helper()
	caKey := newKey(t, caKind)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Client CA", Organization: []string{"Example Corp"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	ca := issue(t, caTmpl, caTmpl, caKey.Public(), caKey)

	leafKey := newKey(t, leafKind)
	tmpl := clientTemplate(t, holder)
	tmpl.SubjectKeyId = testKeyID(t, leafKey.Public())
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issue(t, tmpl, ca, leafKey.Public(), caKey).Raw})
}

// selfIssued returns a self-signed client certificate for holder with a kind
// key, after edit adjusts its template.
func selfIssued(t *testing.T, holder, kind string, edit func(tmpl *x509.Certificate, pub crypto.PublicKey)) []byte {
	t.Helper()
	key := newKey(t, kind)
	tmpl := clientTemplate(t, holder)
	edit(tmpl, key.Public())
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issue(t, tmpl, tmpl, key.Public(), key).Raw})
}

func enrollPEM(t *testing.T, f *Factor, userID string, certPEM []byte) *qrdbsdk.AuthFactorEnrollment {
	t.Helper()
	e, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID:       userID,
		MethodParams: map[string]any{"cert_pem": string(certPEM)},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return e
}

func enrollmentCert(t *testing.T, e *qrdbsdk.AuthFactorEnrollment) *x509.Certificate {
	t.Helper()
	cert, err := parseCertPEM(e.PublicKey)
	if err != nil {
		t.Fatalf("parse enrollment certificate: %v", err)
	}
	return cert
}

// observedShape is everything an enrollment's challenge reveals about how
// its certificate was issued, short of the key and names themselves.
type observedShape struct {
	key        decoy.KeyShape
	signature  x509.SignatureAlgorithm
	issuer     string
	extensions string
	serialSize int
	validity   time.Duration
	keyIDSize  int
	// authorityKeyID is the identifier as issued, or "self" when it names
	// the certificate's own key.
	authorityKeyID string
	// selfSignatureValid reports whether a self-signed certificate's
	// signature verifies under its own key.
	selfSignatureValid bool
	challenge          string
}

func observe(t *testing.T, f *Factor, e *qrdbsdk.AuthFactorEnrollment) observedShape {
	t.Helper()
	cert := enrollmentCert(t, e)
	key, ok := decoy.ShapeOfKey(cert.PublicKey)
	if !ok {
		t.Fatalf("unsupported key %T", cert.PublicKey)
	}
	selfSigned := bytes.Equal(cert.RawIssuer, cert.RawSubject)

	var extensions []string
	for _, ext := range cert.Extensions {
		value := hex.EncodeToString(ext.Value)
		if ext.Id.Equal(oidSubjectKeyID) || ext.Id.Equal(oidSubjectAltName) || ext.Id.Equal(oidAuthorityKeyID) && selfSigned {
			value = "-"
		}
		extensions = append(extensions, fmt.Sprintf("%s/%t/%s", ext.Id, ext.Critical, value))
	}
	issuer := string(cert.RawIssuer)
	if selfSigned {
		issuer = "self"
	}
	authorityKeyID := string(cert.AuthorityKeyId)
	if len(cert.AuthorityKeyId) > 0 && bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId) {
		authorityKeyID = "self"
	}

	ch, err := f.Challenge(context.Background(), e)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	var fields []string
	for _, k := range slices.Sorted(maps.Keys(ch.MethodData)) {
		fields = append(fields, fmt.Sprintf("%s:%T", k, ch.MethodData[k]))
	}

	return observedShape{
		key:                key,
		signature:          cert.SignatureAlgorithm,
		issuer:             issuer,
		extensions:         strings.Join(extensions, " "),
		serialSize:         cert.SerialNumber.BitLen()/8 + 1,
		validity:           cert.NotAfter.Sub(cert.NotBefore),
		keyIDSize:          len(cert.SubjectKeyId),
		authorityKeyID:     authorityKeyID,
		selfSignatureValid: selfSigned && cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil,
		challenge:          strings.Join(fields, " "),
	}
}

func TestDecoyEnrollmentIsDeterministic(t *testing.T) {
	f := New(Config{})
	like := []*qrdbsdk.AuthFactorEnrollment{enrollPEM(t, f, decoyHolder, caIssued(t, decoyHolder, "p384", "p256"))}

	first, err := f.DecoyEnrollment(decoySeed, "stranger", like)
	if err != nil {
		t.Fatalf("DecoyEnrollment: %v", err)
	}
	again, err := f.DecoyEnrollment(decoySeed, "stranger", like)
	if err != nil {
		t.Fatalf("DecoyEnrollment: %v", err)
	}
	if !reflect.DeepEqual(first, again) {
		t.Fatal("same seed and user derived different decoys")
	}
	otherSeed, err := f.DecoyEnrollment(otherDecoySeed, "stranger", like)
	if err != nil {
		t.Fatalf("DecoyEnrollment: %v", err)
	}
	otherUser, err := f.DecoyEnrollment(decoySeed, "someone-else", like)
	if err != nil {
		t.Fatalf("DecoyEnrollment: %v", err)
	}
	for name, other := range map[string]*qrdbsdk.AuthFactorEnrollment{"seed": otherSeed, "user": otherUser} {
		if other.Metadata["cert_spki_thumbprint"] == first.Metadata["cert_spki_thumbprint"] {
			t.Errorf("a different %s derived the same key", name)
		}
		if other.Metadata["cert_serial"] == first.Metadata["cert_serial"] {
			t.Errorf("a different %s derived the same serial", name)
		}
	}
}

func TestDecoyEnrollmentImitatesCertificateShape(t *testing.T) {
	cases := []struct {
		name  string
		issue func(t *testing.T, holder string) []byte
	}{
		{"ca-issued ecdsa", func(t *testing.T, holder string) []byte { return caIssued(t, holder, "p384", "p256") }},
		{"ca-issued rsa", func(t *testing.T, holder string) []byte { return caIssued(t, holder, "rsa2048", "rsa2048") }},
		{"ca-issued ed25519", func(t *testing.T, holder string) []byte { return caIssued(t, holder, "p256", "ed25519") }},
		{"self-signed ecdsa without key ids", func(t *testing.T, holder string) []byte {
			return selfIssued(t, holder, "p384", func(*x509.Certificate, crypto.PublicKey) {})
		}},
		{"self-signed ed25519 with key ids", func(t *testing.T, holder string) []byte {
			return selfIssued(t, holder, "ed25519", func(tmpl *x509.Certificate, pub crypto.PublicKey) {
				tmpl.SubjectKeyId = testKeyID(t, pub)
				aki, err := asn1.Marshal(authorityKeyID{ID: tmpl.SubjectKeyId})
				if err != nil {
					t.Fatalf("marshal aki: %v", err)
				}
				tmpl.ExtraExtensions = []pkix.Extension{{Id: oidAuthorityKeyID, Value: aki}}
			})
		}},
		{"self-signed ecdsa with an opaque key id", func(t *testing.T, holder string) []byte {
			return selfIssued(t, holder, "p256", func(tmpl *x509.Certificate, _ crypto.PublicKey) {
				tmpl.SubjectKeyId = []byte{1, 2, 3, 4, 5, 6, 7, 8}
			})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := New(Config{})
			real := enrollPEM(t, f, decoyHolder, tc.issue(t, decoyHolder))
			d, err := f.DecoyEnrollment(decoySeed, "stranger", []*qrdbsdk.AuthFactorEnrollment{real})
			if err != nil {
				t.Fatalf("DecoyEnrollment: %v", err)
			}
			if got, want := observe(t, f, d), observe(t, f, real); got != want {
				t.Errorf("decoy shape\n got %+v\nwant %+v", got, want)
			}
			if d.Metadata["cert_spki_thumbprint"] == real.Metadata["cert_spki_thumbprint"] {
				t.Error("decoy reuses the holder's key")
			}
			if want := slices.Sorted(maps.Keys(real.Metadata)); !slices.Equal(slices.Sorted(maps.Keys(d.Metadata)), want) {
				t.Errorf("decoy metadata keys = %v, want %v", slices.Sorted(maps.Keys(d.Metadata)), want)
			}
		})
	}
}

func TestDecoyEnrollmentDerivesKeyIDsLikeTheTemplate(t *testing.T) {
	f := New(Config{})
	real := enrollPEM(t, f, decoyHolder, caIssued(t, decoyHolder, "p256", "p256"))
	d, err := f.DecoyEnrollment(decoySeed, "stranger", []*qrdbsdk.AuthFactorEnrollment{real})
	if err != nil {
		t.Fatalf("DecoyEnrollment: %v", err)
	}
	cert := enrollmentCert(t, d)
	if want := testKeyID(t, cert.PublicKey); !bytes.Equal(cert.SubjectKeyId, want) {
		t.Errorf("subject key id = %x, want the truncated SHA-256 %x", cert.SubjectKeyId, want)
	}
	if want := enrollmentCert(t, real).AuthorityKeyId; !bytes.Equal(cert.AuthorityKeyId, want) {
		t.Errorf("authority key id = %x, want the issuer's %x", cert.AuthorityKeyId, want)
	}
}

func TestDecoyEnrollmentNamesTheUser(t *testing.T) {
	for _, userID := range []string{"stranger", "strängér"} {
		t.Run(userID, func(t *testing.T) {
			f := New(Config{})
			real := enrollPEM(t, f, decoyHolder, caIssued(t, decoyHolder, "p256", "p256"))
			d, err := f.DecoyEnrollment(decoySeed, userID, []*qrdbsdk.AuthFactorEnrollment{real})
			if err != nil {
				t.Fatalf("DecoyEnrollment: %v", err)
			}
			cert := enrollmentCert(t, d)
			escaped := url.PathEscape(userID)
			if cert.Subject.CommonName != userID || d.Metadata["cert_cn"] != userID {
				t.Errorf("common name = %q (metadata %q), want %q", cert.Subject.CommonName, d.Metadata["cert_cn"], userID)
			}
			if !slices.Equal(cert.Subject.Organization, []string{"Example Corp"}) || !slices.Equal(cert.Subject.OrganizationalUnit, []string{"Custodians"}) {
				t.Errorf("subject = %v, want the template's other attributes", cert.Subject)
			}
			if want := []string{escaped + ".clients.example.com"}; !slices.Equal(cert.DNSNames, want) {
				t.Errorf("dns names = %v, want %v", cert.DNSNames, want)
			}
			if want := []string{escaped + "@example.com"}; !slices.Equal(cert.EmailAddresses, want) {
				t.Errorf("email addresses = %v, want %v", cert.EmailAddresses, want)
			}
			if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://example.com/user/"+escaped {
				t.Errorf("uris = %v, want spiffe://example.com/user/%s", cert.URIs, escaped)
			}
			if bytes.Contains(cert.Raw, []byte(decoyHolder)) {
				t.Error("decoy certificate names the holder it imitates")
			}
		})
	}
}

func TestDecoyEnrollmentFollowsThePredominantCertificate(t *testing.T) {
	enroller := New(Config{ChallengeTTLSeconds: 60})
	like := []*qrdbsdk.AuthFactorEnrollment{
		enrollPEM(t, enroller, "holder-1", selfIssued(t, "holder-1", "ed25519", func(*x509.Certificate, crypto.PublicKey) {})),
		enrollPEM(t, enroller, "holder-2", caIssued(t, "holder-2", "p384", "p256")),
		enrollPEM(t, enroller, "holder-3", caIssued(t, "holder-3", "p384", "p256")),
	}
	// Both CAs carry the same name, so the CA-issued P-256 shape predominates
	// and the first certificate of that shape is the template.
	f := New(Config{})
	d, err := f.DecoyEnrollment(decoySeed, "stranger", like)
	if err != nil {
		t.Fatalf("DecoyEnrollment: %v", err)
	}
	if got, want := observe(t, f, d), observe(t, f, like[1]); got != want {
		t.Errorf("decoy shape\n got %+v\nwant %+v", got, want)
	}
	if d.Metadata["ttl"] != "60" {
		t.Errorf("ttl = %q, want the roster's 60", d.Metadata["ttl"])
	}

	for _, holder := range []string{"holder-4", "holder-5", "holder-6"} {
		like = append(like, enrollPEM(t, enroller, holder, selfIssued(t, holder, "p256", func(*x509.Certificate, crypto.PublicKey) {})))
	}
	d, err = f.DecoyEnrollment(decoySeed, "stranger", like)
	if err != nil {
		t.Fatalf("DecoyEnrollment: %v", err)
	}
	if got, want := observe(t, f, d), observe(t, f, like[3]); got != want {
		t.Errorf("decoy shape\n got %+v\nwant the predominant %+v", got, want)
	}
}

func TestDecoyEnrollmentDefaultForm(t *testing.T) {
	f := New(Config{})
	d, err := f.DecoyEnrollment(decoySeed, "stranger", nil)
	if err != nil {
		t.Fatalf("DecoyEnrollment: %v", err)
	}
	if d.FactorName != FactorName || d.UserID != "stranger" {
		t.Errorf("enrollment = %s/%s, want %s/stranger", d.FactorName, d.UserID, FactorName)
	}
	cert := enrollmentCert(t, d)
	shape := observe(t, f, d)
	if want := (decoy.KeyShape{Algorithm: decoy.AlgorithmECDSA, Curve: "P-256"}); shape.key != want || cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("key %+v signed %v, want %+v signed ECDSA-SHA256", shape.key, cert.SignatureAlgorithm, want)
	}
	if !shape.selfSignatureValid || cert.Subject.CommonName != "stranger" {
		t.Errorf("want a valid self-signed certificate for stranger, got %+v", shape)
	}
	if shape.serialSize != defaultSerialSize || shape.validity != defaultValidity {
		t.Errorf("serial size %d validity %v, want %d and %v", shape.serialSize, shape.validity, defaultSerialSize, defaultValidity)
	}
	from, to := decoy.NotBeforeSpan(nil)
	if cert.NotBefore.Before(from) || cert.NotBefore.After(to) {
		t.Errorf("not before %v outside [%v, %v]", cert.NotBefore, from, to)
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature || !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Errorf("key usage %v %v, want a client certificate", cert.KeyUsage, cert.ExtKeyUsage)
	}
	if d.Metadata["ttl"] != "300" {
		t.Errorf("ttl = %q, want the configured 300", d.Metadata["ttl"])
	}
}

func TestDecoyEnrollmentFallsBackForUnimitableCertificates(t *testing.T) {
	f := New(Config{})
	pss := selfIssued(t, decoyHolder, "rsa2048", func(tmpl *x509.Certificate, _ crypto.PublicKey) {
		tmpl.SignatureAlgorithm = x509.SHA256WithRSAPSS
	})
	like := []*qrdbsdk.AuthFactorEnrollment{
		nil,
		{FactorName: FactorName, UserID: "holder-2", PublicKey: []byte("not a certificate")},
		enrollPEM(t, f, decoyHolder, pss),
	}
	d, err := f.DecoyEnrollment(decoySeed, "stranger", like)
	if err != nil {
		t.Fatalf("DecoyEnrollment: %v", err)
	}
	cert := enrollmentCert(t, d)
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) || cert.Subject.CommonName != "stranger" || cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("want the default self-signed ECDSA certificate for stranger, got %v signed %v", cert.Subject, cert.SignatureAlgorithm)
	}
}

func TestDecoyEnrollmentFailsVerification(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	holderKey := newKey(t, "p256")
	tmpl := clientTemplate(t, decoyHolder)
	real := enrollPEM(t, f, decoyHolder, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issue(t, tmpl, tmpl, holderKey.Public(), holderKey).Raw}))
	d, err := f.DecoyEnrollment(decoySeed, "stranger", []*qrdbsdk.AuthFactorEnrollment{real})
	if err != nil {
		t.Fatalf("DecoyEnrollment: %v", err)
	}
	ch, err := f.Challenge(ctx, d)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	digest := sha256.Sum256(ch.Nonce)
	holderSig, err := holderKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	for name, sig := range map[string][]byte{"holder's signature": holderSig, "garbage": bytes.Repeat([]byte{0x30}, 72)} {
		var failed *qrdbsdk.AuthFactorVerificationFailedError
		if err := f.Verify(ctx, ch, &qrdbsdk.AuthFactorResponse{Value: sig}); !errors.As(err, &failed) {
			t.Errorf("Verify(%s) err = %v, want VerificationFailedError", name, err)
		}
	}
}

// TestDecoyChallengeExposesNoCASignature pins that a challenge for a
// CA-issued enrollment exposes nothing the CA's key can verify: a holder's
// certificate verifies under the CA and a decoy's cannot, so a challenge
// carrying the certificate would tell holders from decoys.
func TestDecoyChallengeExposesNoCASignature(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	caKey := newKey(t, "p256")
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Client CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	ca := issue(t, caTmpl, caTmpl, caKey.Public(), caKey)
	holderKey := newKey(t, "p256")
	leaf := issue(t, clientTemplate(t, decoyHolder), ca, holderKey.Public(), caKey)
	real := enrollPEM(t, f, decoyHolder, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	d, err := f.DecoyEnrollment(decoySeed, "stranger", []*qrdbsdk.AuthFactorEnrollment{real})
	if err != nil {
		t.Fatalf("DecoyEnrollment: %v", err)
	}
	holderCh, err := f.Challenge(ctx, real)
	if err != nil {
		t.Fatalf("Challenge(holder): %v", err)
	}
	decoyCh, err := f.Challenge(ctx, d)
	if err != nil {
		t.Fatalf("Challenge(decoy): %v", err)
	}

	if got, want := slices.Sorted(maps.Keys(decoyCh.MethodData)), slices.Sorted(maps.Keys(holderCh.MethodData)); !slices.Equal(got, want) {
		t.Errorf("decoy MethodData keys = %v, holder's = %v", got, want)
	}
	for name, ch := range map[string]*qrdbsdk.AuthFactorChallenge{"holder": holderCh, "decoy": decoyCh} {
		for key, v := range ch.MethodData {
			s, ok := v.(string)
			if !ok {
				t.Errorf("%s MethodData[%q] is %T, want string", name, key, v)
				continue
			}
			if block, _ := pem.Decode([]byte(s)); block != nil {
				t.Errorf("%s MethodData[%q] carries a PEM %s block", name, key, block.Type)
			}
			if der, err := base64.StdEncoding.DecodeString(s); err == nil {
				if _, err := x509.ParseCertificate(der); err == nil {
					t.Errorf("%s MethodData[%q] carries a certificate", name, key)
				}
			}
		}
		der, err := base64.StdEncoding.DecodeString(ch.MethodData[methodDataEnrolledKey].(string))
		if err != nil {
			t.Fatalf("%s %s: %v", name, methodDataEnrolledKey, err)
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			t.Fatalf("%s %s: %v", name, methodDataEnrolledKey, err)
		}
		if _, ok := pub.(*ecdsa.PublicKey); !ok {
			t.Errorf("%s enrolled key is %T, want *ecdsa.PublicKey", name, pub)
		}
	}

	sign := func(ch *qrdbsdk.AuthFactorChallenge) *qrdbsdk.AuthFactorResponse {
		digest := sha256.Sum256(ch.Nonce)
		sig, err := holderKey.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return &qrdbsdk.AuthFactorResponse{Value: sig}
	}
	if err := f.Verify(ctx, holderCh, sign(holderCh)); err != nil {
		t.Errorf("Verify(holder) = %v, want nil", err)
	}
	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if err := f.Verify(ctx, decoyCh, sign(decoyCh)); !errors.As(err, &failed) {
		t.Errorf("Verify(decoy) err = %v, want VerificationFailedError", err)
	}
}

func TestDecoyEnrollmentRejectsBadInput(t *testing.T) {
	f := New(Config{})
	var seedErr *decoy.SeedError
	if _, err := f.DecoyEnrollment(decoySeed[:4], "stranger", nil); !errors.As(err, &seedErr) {
		t.Errorf("short seed: want *decoy.SeedError, got %v", err)
	}
	var userErr *decoy.UserIDError
	if _, err := f.DecoyEnrollment(decoySeed, "", nil); !errors.As(err, &userErr) {
		t.Errorf("empty user: want *decoy.UserIDError, got %v", err)
	}
}

func TestSubstituteNamesRejectGarbage(t *testing.T) {
	var derr *decoy.DerivationError
	if _, err := substituteName([]byte{0x30, 0x03, 0x01}, decoyHolder, "stranger"); !errors.As(err, &derr) {
		t.Errorf("substituteName: want *decoy.DerivationError, got %v", err)
	}
	if _, err := substituteNames([]byte{0x04, 0x00}, decoyHolder, "stranger"); !errors.As(err, &derr) {
		t.Errorf("substituteNames: want *decoy.DerivationError, got %v", err)
	}
}

func TestSubstituteValue(t *testing.T) {
	cases := []struct {
		name string
		in   asn1.RawValue
		to   string
		want asn1.RawValue
	}{
		{
			"printable stays printable",
			asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: []byte("custodian-1")},
			"stranger",
			asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: []byte("stranger")},
		},
		{
			"printable becomes utf8",
			asn1.RawValue{Tag: asn1.TagPrintableString, Bytes: []byte("custodian-1")},
			"str_nger",
			asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte("str_nger")},
		},
		{
			"dns name is percent-encoded",
			asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("custodian-1.example.com")},
			"a b",
			asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("a%20b.example.com")},
		},
		{
			"other values are kept",
			asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 7, Bytes: []byte("custodian-1")},
			"stranger",
			asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 7, Bytes: []byte("custodian-1")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := substituteValue(tc.in, decoyHolder, tc.to); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("substituteValue = %+v, want %+v", got, tc.want)
			}
		})
	}
	if got := substituteValue(cases[0].in, "", "stranger"); !reflect.DeepEqual(got, cases[0].in) {
		t.Errorf("empty holder changed the value to %+v", got)
	}
}

func TestShapeOfCertRejectsUnsupportedSignatures(t *testing.T) {
	cert := enrollmentCert(t, &qrdbsdk.AuthFactorEnrollment{PublicKey: caIssued(t, decoyHolder, "p256", "p256")})
	if _, ok := shapeOfCert(cert); !ok {
		t.Fatal("a CA-issued ECDSA certificate is imitable")
	}
	cert.SignatureAlgorithm = x509.SHA256WithRSAPSS
	if _, ok := shapeOfCert(cert); ok {
		t.Error("an RSA-PSS issuer signature is not imitable")
	}
	cert.SignatureAlgorithm = x509.SHA256WithRSA
	cert.Signature = make([]byte, 128)
	if _, ok := shapeOfCert(cert); ok {
		t.Error("an RSA-1024 issuer is not imitable")
	}
}
