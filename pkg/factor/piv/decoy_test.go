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

package piv

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/factor/internal/decoy"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
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

// enrollHolder enrolls user on a fresh software-backed factor, so that every
// holder gets a key of their own.
func enrollHolder(t *testing.T, user string, params map[string]any) *qrdbsdk.AuthFactorEnrollment {
	t.Helper()
	e, err := New(Config{}).Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{UserID: user, TenantID: "tenant-t", MethodParams: params})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return e
}

func decoyFor(t *testing.T, f *Factor, seed []byte, user string, like []*qrdbsdk.AuthFactorEnrollment) *qrdbsdk.AuthFactorEnrollment {
	t.Helper()
	e, err := f.DecoyEnrollment(seed, user, like)
	if err != nil {
		t.Fatalf("DecoyEnrollment: %v", err)
	}
	return e
}

// A roster that mixes a legacy OU-less holder certificate with a stamped
// one yields decoys in the same mix: OU-less decoys in proportion to the
// OU-less holders, so the legacy holder does not stand out as the only
// certificate without a tenant OU.
func TestDecoyEnrollment_MirrorsMixedLegacyRoster(t *testing.T) {
	stamped := enrollHolder(t, "holder-stamped", nil)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	legacyPEM, err := issueSelfSignedCert(key, pkix.Name{CommonName: stamped.Metadata["cn"]}, big.NewInt(7), time.Now().UTC().Add(-30*24*time.Hour), defaultValidityDays)
	if err != nil {
		t.Fatalf("legacy certificate: %v", err)
	}
	roster := []*qrdbsdk.AuthFactorEnrollment{
		{UserID: "holder-legacy", FactorName: FactorName, PublicKey: legacyPEM, Metadata: stamped.Metadata},
		{UserID: stamped.UserID, FactorName: FactorName, PublicKey: stamped.PublicKey, Metadata: stamped.Metadata},
	}
	if ou := parseCert(t, legacyPEM).Subject.OrganizationalUnit; len(ou) != 0 {
		t.Fatalf("legacy holder OU = %v, want none", ou)
	}

	// The OU and the validity come from one roster cohort: an OU-bearing
	// decoy is never older than the oldest OU-bearing holder, and an
	// OU-less decoy is never newer than the newest OU-less (legacy) holder.
	stampedCert := parseCert(t, stamped.PublicKey)
	legacyCert := parseCert(t, legacyPEM)
	if !legacyCert.NotBefore.Before(stampedCert.NotBefore) {
		t.Fatalf("legacy NotBefore %v not before stamped %v", legacyCert.NotBefore, stampedCert.NotBefore)
	}

	f := New(Config{})
	const n = 200
	ouLess := 0
	for i := 0; i < n; i++ {
		d := decoyFor(t, f, decoySeed, "stranger-"+strconv.Itoa(i), roster)
		cert := parseCert(t, d.PublicKey)
		switch ou := cert.Subject.OrganizationalUnit; {
		case len(ou) == 0:
			ouLess++
			if cert.NotBefore.After(legacyCert.NotBefore) {
				t.Fatalf("OU-less decoy NotBefore %v after the newest OU-less holder %v", cert.NotBefore, legacyCert.NotBefore)
			}
		case !reflect.DeepEqual(ou, []string{"tenant-t"}):
			t.Fatalf("decoy OU = %v, want [tenant-t] or none", ou)
		default:
			if cert.NotBefore.Before(stampedCert.NotBefore) {
				t.Fatalf("OU decoy NotBefore %v before the oldest OU holder %v", cert.NotBefore, stampedCert.NotBefore)
			}
		}
		if got, want := cert.NotAfter.Sub(cert.NotBefore), legacyCert.NotAfter.Sub(legacyCert.NotBefore); got != want {
			t.Fatalf("decoy validity %v, want the roster's %v", got, want)
		}
	}
	// Half the roster is OU-less; the decoy share must match it, not be 0.
	if ouLess < n*3/10 || ouLess > n*7/10 {
		t.Fatalf("OU-less decoys = %d of %d, want about half (the roster's OU-less share)", ouLess, n)
	}
}

// TestDecoyEnrollment_ShapeFollowsOneExemplar pins that a decoy's OU, key
// algorithm and slot come from one roster holder together: with two legacy
// OU-less P-256/9a holders and one stamped Ed25519/9c holder, no decoy is a
// stamped P-256/9a or an OU-less Ed25519/9c, which no holder is.
func TestDecoyEnrollment_ShapeFollowsOneExemplar(t *testing.T) {
	stamped := enrollHolder(t, "holder-stamped", map[string]any{"algorithm": "ed25519", "slot": "9c"})
	if stamped.Metadata["algorithm"] != "ed25519" || stamped.Metadata["slot"] != "9c" {
		t.Fatalf("stamped holder metadata = %v, want ed25519 in 9c", stamped.Metadata)
	}
	legacy := func(user string, serial int64) *qrdbsdk.AuthFactorEnrollment {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		certPEM, err := issueSelfSignedCert(key, pkix.Name{CommonName: "PIV 9a"}, big.NewInt(serial), time.Now().UTC().Add(-30*24*time.Hour), defaultValidityDays)
		if err != nil {
			t.Fatalf("legacy certificate: %v", err)
		}
		return &qrdbsdk.AuthFactorEnrollment{UserID: user, FactorName: FactorName, PublicKey: certPEM, Metadata: map[string]string{
			"slot": "9a", "algorithm": "ecdsap256", "cn": "PIV 9a", "ttl": stamped.Metadata["ttl"],
		}}
	}
	roster := []*qrdbsdk.AuthFactorEnrollment{legacy("holder-legacy-1", 7), legacy("holder-legacy-2", 8), stamped}

	f := New(Config{})
	seen := map[string]int{}
	for i := 0; i < 200; i++ {
		d := decoyFor(t, f, decoySeed, "stranger-"+strconv.Itoa(i), roster)
		cert := parseCert(t, d.PublicKey)
		alg, slot := d.Metadata["algorithm"], d.Metadata["slot"]
		if shape, ok := decoy.ShapeOfKey(cert.PublicKey); !ok || shape != decoyShapes[alg] {
			t.Fatalf("decoy key shape %v does not match its algorithm %q", shape, alg)
		}
		var combo string
		switch ou := cert.Subject.OrganizationalUnit; {
		case len(ou) == 0 && alg == "ecdsap256" && slot == "9a":
			combo = "legacy"
		case reflect.DeepEqual(ou, []string{"tenant-t"}) && alg == "ed25519" && slot == "9c":
			combo = "stamped"
		default:
			t.Fatalf("decoy OU %v, algorithm %q, slot %q: no holder has this combination", ou, alg, slot)
		}
		if d.Metadata["cn"] != "PIV "+slot || cert.Subject.CommonName != "PIV "+slot {
			t.Fatalf("decoy cn %q / %q, want PIV %s", d.Metadata["cn"], cert.Subject.CommonName, slot)
		}
		seen[combo]++
	}
	if seen["legacy"] == 0 || seen["stamped"] == 0 {
		t.Fatalf("decoy shapes = %v, want both holder shapes", seen)
	}
}

// TestDecoyEnrollment_DerivationWorkIndependentOfExemplar: go-qrdb derives
// the decoy before it looks the holder up, so the key derivation work of a
// decoy must not follow the exemplar it picks. In a mixed RSA/ECDSA roster
// every username's decoy derives the same set of key shapes, in the same
// order, whichever holder it mirrors.
func TestDecoyEnrollment_DerivationWorkIndependentOfExemplar(t *testing.T) {
	holder := func(user string, serial int64, alg string, key crypto.Signer) *qrdbsdk.AuthFactorEnrollment {
		certPEM, err := issueSelfSignedCert(key, pkix.Name{CommonName: "PIV 9a"}, big.NewInt(serial), time.Now().UTC().Add(-30*24*time.Hour), defaultValidityDays)
		if err != nil {
			t.Fatalf("holder certificate: %v", err)
		}
		return &qrdbsdk.AuthFactorEnrollment{UserID: user, FactorName: FactorName, PublicKey: certPEM, Metadata: map[string]string{
			"slot": "9a", "algorithm": alg, "cn": "PIV 9a", "ttl": "60",
		}}
	}
	var roster []*qrdbsdk.AuthFactorEnrollment
	for i := 0; i < 3; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		roster = append(roster, holder("holder-ec-"+strconv.Itoa(i), int64(10+i), "ecdsap256", key))
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	roster = append(roster, holder("holder-rsa", 20, "rsa2048", rsaKey))

	var derived []decoy.KeyShape
	orig := deriveDecoyKey
	deriveDecoyKey = func(d *decoy.Deriver, purpose string, s decoy.KeyShape) (crypto.Signer, error) {
		derived = append(derived, s)
		return orig(d, purpose, s)
	}
	t.Cleanup(func() { deriveDecoyKey = orig })

	f := New(Config{})
	var want []decoy.KeyShape
	picked := map[string]int{}
	for i := 0; i < 24; i++ {
		derived = nil
		d := decoyFor(t, f, decoySeed, "stranger-"+strconv.Itoa(i), roster)
		alg := d.Metadata["algorithm"]
		picked[alg]++
		if shape, ok := decoy.ShapeOfKey(parseCert(t, d.PublicKey).PublicKey); !ok || shape != decoyShapes[alg] {
			t.Fatalf("decoy key shape %v does not match its algorithm %q", shape, alg)
		}
		if want == nil {
			want = append([]decoy.KeyShape(nil), derived...)
			continue
		}
		if !reflect.DeepEqual(derived, want) {
			t.Fatalf("decoy for stranger-%d (%s) derived %v, the first derived %v: the work follows the exemplar", i, alg, derived, want)
		}
	}
	if len(want) != 2 || !reflect.DeepEqual(map[decoy.KeyShape]bool{want[0]: true, want[1]: true},
		map[decoy.KeyShape]bool{decoyShapes["ecdsap256"]: true, decoyShapes["rsa2048"]: true}) {
		t.Fatalf("derived shapes %v, want one ecdsap256 and one rsa2048 per decoy", want)
	}
	if picked["ecdsap256"] == 0 || picked["rsa2048"] == 0 {
		t.Fatalf("decoy algorithms = %v, want both roster algorithms", picked)
	}
}

func parseCert(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("no CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// keyDescription names a public key's type and size.
func keyDescription(pub any) string {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return "ecdsa " + key.Curve.Params().Name
	case *rsa.PublicKey:
		return "rsa " + strconv.Itoa(key.N.BitLen())
	case ed25519.PublicKey:
		return "ed25519"
	default:
		return "unknown"
	}
}

// certShape is what a PIV certificate reveals besides its key, serial value,
// validity start and signature.
type certShape struct {
	version       int
	key           string
	signature     x509.SignatureAlgorithm
	subject       string
	issuer        string
	keyUsage      x509.KeyUsage
	extKeyUsage   []x509.ExtKeyUsage
	basicValid    bool
	isCA          bool
	extensions    []string
	validity      time.Duration
	serialFits128 bool
}

func shapeOfCert(t *testing.T, pemBytes []byte) certShape {
	t.Helper()
	cert := parseCert(t, pemBytes)
	s := certShape{
		version:       cert.Version,
		key:           keyDescription(cert.PublicKey),
		signature:     cert.SignatureAlgorithm,
		subject:       cert.Subject.String(),
		issuer:        cert.Issuer.String(),
		keyUsage:      cert.KeyUsage,
		extKeyUsage:   cert.ExtKeyUsage,
		basicValid:    cert.BasicConstraintsValid,
		isCA:          cert.IsCA,
		validity:      cert.NotAfter.Sub(cert.NotBefore),
		serialFits128: cert.SerialNumber.Sign() > 0 && cert.SerialNumber.BitLen() <= 128,
	}
	for _, ext := range cert.Extensions {
		s.extensions = append(s.extensions, ext.Id.String()+critical(ext.Critical))
	}
	sort.Strings(s.extensions)
	return s
}

func critical(c bool) string {
	if c {
		return "!"
	}
	return ""
}

// methodDataShape is the set of MethodData keys with their value types.
func methodDataShape(c *qrdbsdk.AuthFactorChallenge) map[string]string {
	out := make(map[string]string, len(c.MethodData))
	for k, v := range c.MethodData {
		out[k] = reflect.TypeOf(v).String()
	}
	return out
}

func TestDecoyEnrollmentIsDeterministic(t *testing.T) {
	f := New(Config{})
	like := []*qrdbsdk.AuthFactorEnrollment{enrollHolder(t, "holder-1", nil), enrollHolder(t, "holder-2", nil)}
	first := decoyFor(t, f, decoySeed, "stranger", like)
	again := decoyFor(t, f, decoySeed, "stranger", like)
	if !reflect.DeepEqual(first, again) {
		t.Fatalf("same (seed, user) derived different decoys:\n%+v\n%+v", first, again)
	}
	for name, other := range map[string]*qrdbsdk.AuthFactorEnrollment{
		"user": decoyFor(t, f, decoySeed, "someone-else", like),
		"seed": decoyFor(t, f, otherDecoySeed, "stranger", like),
	} {
		if bytes.Equal(first.PublicKey, other.PublicKey) || first.EnrollmentID == other.EnrollmentID {
			t.Errorf("a different %s derived the same certificate or id", name)
		}
	}
}

func TestDecoyChallengeMatchesRealChallengeShape(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]any
	}{
		{"default", nil},
		{"ecdsap384 in 9c", map[string]any{"algorithm": "ecdsap384", "slot": "9c"}},
		{"rsa2048", map[string]any{"algorithm": "rsa2048"}},
		{"ed25519", map[string]any{"algorithm": "ed25519"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			f := New(Config{})
			real := enrollHolder(t, "holder", tc.params)
			like := []*qrdbsdk.AuthFactorEnrollment{real, enrollHolder(t, "holder-2", tc.params)}
			fake := decoyFor(t, f, decoySeed, "stranger", like)

			if fake.UserID != "stranger" || fake.FactorName != FactorName {
				t.Errorf("decoy names user %q factor %q", fake.UserID, fake.FactorName)
			}
			if !reflect.DeepEqual(real.Metadata, fake.Metadata) {
				t.Errorf("metadata differs: real %v decoy %v", real.Metadata, fake.Metadata)
			}
			if got, want := shapeOfCert(t, fake.PublicKey), shapeOfCert(t, real.PublicKey); !reflect.DeepEqual(got, want) {
				t.Errorf("certificate shapes differ:\nreal  %+v\ndecoy %+v", want, got)
			}

			realChallenge, err := f.Challenge(ctx, real)
			if err != nil {
				t.Fatalf("Challenge real: %v", err)
			}
			fakeChallenge, err := f.Challenge(ctx, fake)
			if err != nil {
				t.Fatalf("Challenge decoy: %v", err)
			}
			if got, want := methodDataShape(fakeChallenge), methodDataShape(realChallenge); !reflect.DeepEqual(got, want) {
				t.Errorf("MethodData shapes differ: real %v decoy %v", want, got)
			}
			for _, k := range []string{"slot", "algorithm"} {
				if realChallenge.MethodData[k] != fakeChallenge.MethodData[k] {
					t.Errorf("MethodData %s: real %v decoy %v", k, realChallenge.MethodData[k], fakeChallenge.MethodData[k])
				}
			}
			if len(fakeChallenge.Nonce) != len(realChallenge.Nonce) {
				t.Errorf("nonce lengths differ")
			}
		})
	}
}

func TestDecoyEnrollmentFollowsPredominantAlgorithm(t *testing.T) {
	like := []*qrdbsdk.AuthFactorEnrollment{
		enrollHolder(t, "a", nil),
		enrollHolder(t, "b", map[string]any{"algorithm": "ed25519"}),
		enrollHolder(t, "c", map[string]any{"algorithm": "ed25519"}),
		{Metadata: map[string]string{"algorithm": "unsupported"}},
		{Metadata: map[string]string{"algorithm": "unsupported"}},
		{Metadata: map[string]string{"algorithm": "unsupported"}},
	}
	fake := decoyFor(t, New(Config{}), decoySeed, "stranger", like)
	if fake.Metadata["algorithm"] != "ed25519" || keyDescription(parseCert(t, fake.PublicKey).PublicKey) != "ed25519" {
		t.Errorf("want an ed25519 decoy, got %v", fake.Metadata)
	}
}

func TestDecoyEnrollmentEmptyLikeYieldsDefaultForm(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"zero config", Config{}},
		{"unsupported default algorithm", Config{DefaultAlgorithm: "bogus"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := decoyFor(t, New(tc.cfg), decoySeed, "stranger", nil)
			want := map[string]string{"slot": "9a", "algorithm": defaultAlgorithm, "cn": "PIV 9a", "ttl": "300"}
			if !reflect.DeepEqual(fake.Metadata, want) {
				t.Errorf("want metadata %v, got %v", want, fake.Metadata)
			}
			real, err := New(Config{}).Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{UserID: "holder", TenantID: "tenant-t"})
			if err != nil {
				t.Fatalf("Enroll: %v", err)
			}
			// With no enrollment to copy, the decoy record names no tenant
			// (decoy.Deriver.Enrollment), so its certificate carries no
			// tenant OU; every other field of the shape must match.
			got, realShape := shapeOfCert(t, fake.PublicKey), shapeOfCert(t, real.PublicKey)
			if fake.TenantID != "" || got.subject != "CN=PIV 9a" || got.issuer != "CN=PIV 9a" {
				t.Errorf("tenantless decoy: tenant %q subject %q issuer %q, want no tenant and CN=PIV 9a", fake.TenantID, got.subject, got.issuer)
			}
			got.subject, got.issuer = realShape.subject, realShape.issuer
			if !reflect.DeepEqual(got, realShape) {
				t.Errorf("certificate shapes differ:\nreal  %+v\ndecoy %+v", realShape, got)
			}
			cert := parseCert(t, fake.PublicKey)
			if from, to := decoy.NotBeforeSpan(nil); cert.NotBefore.Before(from) || cert.NotBefore.After(to) {
				t.Errorf("validity start %v outside the decoy epoch span", cert.NotBefore)
			}
		})
	}
}

func TestDecoyEnrollmentFailsVerify(t *testing.T) {
	ctx := context.Background()
	holder := New(Config{})
	if _, err := holder.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{UserID: "holder", TenantID: "tenant-t"}); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	fake := decoyFor(t, holder, decoySeed, "stranger", nil)
	challenge, err := holder.Challenge(ctx, fake)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	sig, err := holder.SignChallenge(ctx, pivcert.PIVSlotAuthentication, challenge.ChallengeID, "", challenge.Nonce)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}
	var verr *qrdbsdk.AuthFactorVerificationFailedError
	if err := holder.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: sig}); !errors.As(err, &verr) {
		t.Fatalf("want verification failure against a decoy, got %v", err)
	}
}

func TestDecoyEnrollmentRejectsBadInput(t *testing.T) {
	f := New(Config{})
	var seedErr *decoy.SeedError
	if _, err := f.DecoyEnrollment(nil, "stranger", nil); !errors.As(err, &seedErr) {
		t.Errorf("missing seed: want *decoy.SeedError, got %v", err)
	}
	var userErr *decoy.UserIDError
	if _, err := f.DecoyEnrollment(decoySeed, "", nil); !errors.As(err, &userErr) {
		t.Errorf("empty user: want *decoy.UserIDError, got %v", err)
	}
}

func TestDecoyShapesDeriveEachAlgorithm(t *testing.T) {
	want := map[string]string{
		"rsa2048":   "rsa 2048",
		"rsa4096":   "rsa 4096",
		"ecdsap256": "ecdsa P-256",
		"ecdsap384": "ecdsa P-384",
		"ed25519":   "ed25519",
	}
	if len(decoyShapes) != len(want) {
		t.Fatalf("decoyShapes covers %d algorithms, want %d", len(decoyShapes), len(want))
	}
	d, err := decoy.New(decoyLabel, decoySeed, "stranger")
	if err != nil {
		t.Fatalf("decoy.New: %v", err)
	}
	for algorithm, description := range want {
		shape, ok := decoyShapes[algorithm]
		if !ok {
			t.Fatalf("no shape for %s", algorithm)
		}
		key, err := d.Key("key", shape)
		if err != nil {
			t.Fatalf("%s: %v", algorithm, err)
		}
		if got := keyDescription(key.Public()); got != description {
			t.Errorf("%s derived %s", algorithm, got)
		}
	}
}

func TestIssueSelfSignedCertRejectsBadSerial(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := issueSelfSignedCert(key, pkix.Name{CommonName: "PIV 9a"}, big.NewInt(-1), time.Now(), 1); err == nil {
		t.Fatal("want an error for a negative serial")
	}
}
