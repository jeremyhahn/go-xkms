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
	e, err := New(Config{}).Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{UserID: user, MethodParams: params})
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
			real, err := New(Config{}).Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{UserID: "holder"})
			if err != nil {
				t.Fatalf("Enroll: %v", err)
			}
			if got, want := shapeOfCert(t, fake.PublicKey), shapeOfCert(t, real.PublicKey); !reflect.DeepEqual(got, want) {
				t.Errorf("certificate shapes differ:\nreal  %+v\ndecoy %+v", want, got)
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
	if _, err := holder.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{UserID: "holder"}); err != nil {
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
