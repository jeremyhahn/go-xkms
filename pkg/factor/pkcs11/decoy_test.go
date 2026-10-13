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

package pkcs11

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"reflect"
	"sort"
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

// enrollKey enrolls a fresh key from keyPair for user with params.
func enrollKey(t *testing.T, f *Factor, user string, keyPair func(*testing.T) (string, func([]byte) []byte), params map[string]any) *qrdbsdk.AuthFactorEnrollment {
	t.Helper()
	der, _ := keyPair(t)
	methodParams := map[string]any{"public_key_der": der}
	for k, v := range params {
		methodParams[k] = v
	}
	e, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{UserID: user, MethodParams: methodParams})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return e
}

// decoyFor derives the decoy and fails the test on error.
func decoyFor(t *testing.T, f *Factor, seed []byte, user string, like []*qrdbsdk.AuthFactorEnrollment) *qrdbsdk.AuthFactorEnrollment {
	t.Helper()
	e, err := f.DecoyEnrollment(seed, user, like)
	if err != nil {
		t.Fatalf("DecoyEnrollment: %v", err)
	}
	return e
}

// challengeShape is what a challenge reveals about its enrollment, short of
// the key bytes, the key id value and the nonce value.
type challengeShape struct {
	keys      []string
	types     map[string]string
	key       decoy.KeyShape
	mechanism string
	algorithm string
	keyIDLen  int
	nonceLen  int
}

func shapeOfChallenge(t *testing.T, c *qrdbsdk.AuthFactorChallenge) challengeShape {
	t.Helper()
	s := challengeShape{types: map[string]string{}, nonceLen: len(c.Nonce)}
	for k, v := range c.MethodData {
		s.keys = append(s.keys, k)
		s.types[k] = reflect.TypeOf(v).String()
	}
	sort.Strings(s.keys)
	enc, ok := c.MethodData[methodDataEnrolledKey].(string)
	if !ok {
		t.Fatal("challenge carries no enrolled key")
	}
	der, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("decode enrolled key: %v", err)
	}
	if s.key, ok = shapeOf(der); !ok {
		t.Fatal("enrolled key has no imitable shape")
	}
	s.mechanism, _ = c.MethodData[methodDataMechanism].(string)
	s.algorithm, _ = c.MethodData["algorithm"].(string)
	keyID, _ := c.MethodData["key_id"].(string)
	s.keyIDLen = len(keyID)
	return s
}

func TestDecoyEnrollmentIsDeterministic(t *testing.T) {
	f := New(Config{})
	like := []*qrdbsdk.AuthFactorEnrollment{
		enrollKey(t, f, "holder-1", ecKeyPair, map[string]any{"key_id": "0a1b2c3d"}),
		enrollKey(t, f, "holder-2", ecKeyPair, map[string]any{"key_id": "4e5f6071"}),
	}
	first := decoyFor(t, f, decoySeed, "stranger", like)
	again := decoyFor(t, f, decoySeed, "stranger", like)
	if !reflect.DeepEqual(first, again) {
		t.Fatalf("same (seed, user) derived different decoys:\n%+v\n%+v", first, again)
	}
	for name, other := range map[string]*qrdbsdk.AuthFactorEnrollment{
		"user": decoyFor(t, f, decoySeed, "someone-else", like),
		"seed": decoyFor(t, f, otherDecoySeed, "stranger", like),
	} {
		if bytes.Equal(first.PublicKey, other.PublicKey) || first.EnrollmentID == other.EnrollmentID ||
			first.Metadata["key_id"] == other.Metadata["key_id"] {
			t.Errorf("a different %s derived the same key, id or key id", name)
		}
	}
}

func TestDecoyChallengeMatchesRealChallengeShape(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		keyPair func(*testing.T) (string, func([]byte) []byte)
		params  map[string]any
	}{
		{"ecdsa with hex key id", Config{}, ecKeyPair, map[string]any{"key_id": "0A1B2C3D", "token_label": "quorum", "slot_id": 1}},
		{"ecdsa bare", Config{}, ecKeyPair, nil},
		{"rsa with label key id", Config{ChallengeTTLSeconds: 120}, rsaKeyPair, map[string]any{"key_id": "quorum-key"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := New(tc.cfg)
			ctx := context.Background()
			real := enrollKey(t, f, "holder", tc.keyPair, tc.params)
			like := []*qrdbsdk.AuthFactorEnrollment{real, enrollKey(t, f, "holder-2", tc.keyPair, tc.params)}
			fake := decoyFor(t, f, decoySeed, "stranger", like)

			if fake.UserID != "stranger" || fake.FactorName != FactorName {
				t.Errorf("decoy names user %q factor %q", fake.UserID, fake.FactorName)
			}
			if !sameKeys(real.Metadata, fake.Metadata) {
				t.Errorf("metadata keys differ: real %v decoy %v", real.Metadata, fake.Metadata)
			}
			for _, k := range []string{"algorithm", "mechanism", "ttl", "token_label", "slot"} {
				if real.Metadata[k] != fake.Metadata[k] {
					t.Errorf("metadata %s: real %q decoy %q", k, real.Metadata[k], fake.Metadata[k])
				}
			}

			realChallenge, err := f.Challenge(ctx, real)
			if err != nil {
				t.Fatalf("Challenge real: %v", err)
			}
			fakeChallenge, err := f.Challenge(ctx, fake)
			if err != nil {
				t.Fatalf("Challenge decoy: %v", err)
			}
			if got, want := shapeOfChallenge(t, fakeChallenge), shapeOfChallenge(t, realChallenge); !reflect.DeepEqual(got, want) {
				t.Errorf("challenge shapes differ:\nreal  %+v\ndecoy %+v", want, got)
			}
			if skew := fakeChallenge.ExpiresAt.Sub(realChallenge.ExpiresAt).Abs(); skew > 5*time.Second {
				t.Errorf("challenge lifetimes differ by %v", skew)
			}
			if id := real.Metadata["key_id"]; id != "" && id != "quorum-key" && id == fake.Metadata["key_id"] {
				t.Error("decoy copied a per-key hex key id")
			}
		})
	}
}

func TestDecoyEnrollmentFollowsPredominantKeyShape(t *testing.T) {
	f := New(Config{})
	like := []*qrdbsdk.AuthFactorEnrollment{
		enrollKey(t, f, "a", ecKeyPair, nil),
		enrollKey(t, f, "b", rsaKeyPair, nil),
		enrollKey(t, f, "c", rsaKeyPair, nil),
	}
	fake := decoyFor(t, f, decoySeed, "stranger", like)
	if s, ok := shapeOf(fake.PublicKey); !ok || s != (decoy.KeyShape{Algorithm: "rsa", Bits: 2048}) {
		t.Errorf("want an RSA-2048 decoy key, got %+v", s)
	}
	if fake.Metadata["mechanism"] != defaultRSAMechanism {
		t.Errorf("want mechanism %s, got %s", defaultRSAMechanism, fake.Metadata["mechanism"])
	}
}

func TestDecoyEnrollmentIgnoresUnimitableKeys(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	edDER, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatalf("marshal ed25519: %v", err)
	}
	odd := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 1023), E: 65537}
	oddDER, err := x509.MarshalPKIXPublicKey(odd)
	if err != nil {
		t.Fatalf("marshal rsa-1024: %v", err)
	}
	like := []*qrdbsdk.AuthFactorEnrollment{nil, {PublicKey: edDER}, {PublicKey: oddDER}, {PublicKey: []byte("junk")}}
	fake := decoyFor(t, New(Config{}), decoySeed, "stranger", like)
	if s, ok := shapeOf(fake.PublicKey); !ok || s != (decoy.KeyShape{Algorithm: "ecdsa", Curve: "P-256"}) {
		t.Errorf("want the default P-256 shape, got %+v", s)
	}
}

func TestDecoyEnrollmentEmptyLikeYieldsDefaultForm(t *testing.T) {
	cases := []struct {
		name      string
		cfg       Config
		shape     decoy.KeyShape
		mechanism string
	}{
		{"default mechanism", Config{}, decoy.KeyShape{Algorithm: "ecdsa", Curve: "P-256"}, defaultMechanism},
		{"rsa mechanism", Config{DefaultMechanism: "CKM_SHA384_RSA_PKCS"}, decoy.KeyShape{Algorithm: "rsa", Bits: 2048}, "CKM_SHA384_RSA_PKCS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := decoyFor(t, New(tc.cfg), decoySeed, "stranger", nil)
			if s, ok := shapeOf(fake.PublicKey); !ok || s != tc.shape {
				t.Errorf("want shape %+v, got %+v", tc.shape, s)
			}
			want := map[string]string{"algorithm": tc.shape.Algorithm, "mechanism": tc.mechanism, "ttl": "300"}
			if !reflect.DeepEqual(fake.Metadata, want) {
				t.Errorf("want metadata %v, got %v", want, fake.Metadata)
			}
			if fake.TenantID != "" || !fake.EnrolledAt.IsZero() {
				t.Errorf("want no tenant and zero EnrolledAt, got %q %v", fake.TenantID, fake.EnrolledAt)
			}
		})
	}
}

func TestDecoyEnrollmentFailsVerify(t *testing.T) {
	f := New(Config{})
	ctx := context.Background()
	fake := decoyFor(t, f, decoySeed, "stranger", nil)
	challenge, err := f.Challenge(ctx, fake)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	_, sign := ecKeyPair(t)
	err = f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: sign(challenge.Nonce)})
	var verr *qrdbsdk.AuthFactorVerificationFailedError
	if !errors.As(err, &verr) {
		t.Fatalf("want verification failure against a decoy, got %v", err)
	}
}

func TestDecoyEnrollmentRejectsBadInput(t *testing.T) {
	f := New(Config{})
	var seedErr *decoy.SeedError
	if _, err := f.DecoyEnrollment(decoySeed[:8], "stranger", nil); !errors.As(err, &seedErr) {
		t.Errorf("short seed: want *decoy.SeedError, got %v", err)
	}
	var userErr *decoy.UserIDError
	if _, err := f.DecoyEnrollment(decoySeed, "", nil); !errors.As(err, &userErr) {
		t.Errorf("empty user: want *decoy.UserIDError, got %v", err)
	}
}

func TestDecoyKeyID(t *testing.T) {
	d, err := decoy.New(decoyLabel, decoySeed, "stranger")
	if err != nil {
		t.Fatalf("decoy.New: %v", err)
	}
	cases := []struct {
		sample string
		check  func(string) bool
	}{
		{"0a1b2c3d", func(id string) bool { return len(id) == 8 && id != "0a1b2c3d" && id == strings.ToLower(id) }},
		{"0A1B2C3D", func(id string) bool { return len(id) == 8 && id != "0A1B2C3D" && id == strings.ToUpper(id) }},
		{"quorum-key", func(id string) bool { return id == "quorum-key" }},
		{"abc", func(id string) bool { return id == "abc" }},
	}
	for _, tc := range cases {
		id, err := decoyKeyID(d, tc.sample)
		if err != nil {
			t.Fatalf("%s: %v", tc.sample, err)
		}
		if !tc.check(id) {
			t.Errorf("sample %q: unexpected decoy key id %q", tc.sample, id)
		}
	}
}

func TestDecoyKeyIDPropagatesDerivationError(t *testing.T) {
	d, err := decoy.New(decoyLabel, decoySeed, "stranger")
	if err != nil {
		t.Fatalf("decoy.New: %v", err)
	}
	// Longer than HKDF-SHA256 can expand to.
	huge := string(bytes.Repeat([]byte("ab"), 255*32+1))
	var derr *decoy.DerivationError
	if _, err := decoyKeyID(d, huge); !errors.As(err, &derr) {
		t.Fatalf("want *decoy.DerivationError, got %v", err)
	}
}

func sameKeys(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}
