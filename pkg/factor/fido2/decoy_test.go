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

package fido2

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
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

// marshalCOSE encodes a COSE key map the way the test authenticator does.
func marshalCOSE(t *testing.T, key map[int]any) []byte {
	t.Helper()
	b, err := webauthncbor.Marshal(key)
	if err != nil {
		t.Fatalf("marshal cose: %v", err)
	}
	return b
}

// es384COSE returns a fresh ES384 credential key.
func es384COSE(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p384: %v", err)
	}
	point, err := priv.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("encode p384: %v", err)
	}
	return marshalCOSE(t, map[int]any{1: 2, 3: int(webauthncose.AlgES384), -1: 2, -2: point[1:49], -3: point[49:]})
}

// eddsaCOSE returns a fresh Ed25519 credential key.
func eddsaCOSE(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	return marshalCOSE(t, map[int]any{1: 1, 3: int(webauthncose.AlgEdDSA), -1: 6, -2: []byte(pub)})
}

// rs256COSE returns a fresh RS256 credential key.
func rs256COSE(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	return marshalCOSE(t, map[int]any{1: 3, 3: int(webauthncose.AlgRS256), -1: priv.N.Bytes(), -2: []byte{1, 0, 1}})
}

// es256COSE returns a fresh ES256 credential key.
func es256COSE(t *testing.T) []byte {
	t.Helper()
	return newAuthenticator(t, "example.com").coseKey(t)
}

// credentialID returns a fresh credential id of size bytes in enc.
func credentialID(t *testing.T, enc *base64.Encoding, size int) string {
	t.Helper()
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return enc.EncodeToString(raw)
}

// enrollCOSE enrolls cose with params on f.
func enrollCOSE(t *testing.T, f *Factor, cose []byte, params map[string]any) *qrdbsdk.AuthFactorEnrollment {
	t.Helper()
	methodParams := map[string]any{"cose_public_key": cose, "credential_id": credentialID(t, base64.RawURLEncoding, 16)}
	for k, v := range params {
		methodParams[k] = v
	}
	e, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{UserID: "holder", MethodParams: methodParams})
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

// fido2ChallengeShape is what a challenge reveals about its enrollment,
// short of the key, credential id and nonce values.
type fido2ChallengeShape struct {
	types     map[string]string
	key       coseShape
	keyLen    int
	id        credentialIDShape
	nonceLen  int
	rpID      any
	origins   any
	requireUV any
}

func shapeOfFIDO2Challenge(t *testing.T, c *qrdbsdk.AuthFactorChallenge) fido2ChallengeShape {
	t.Helper()
	s := fido2ChallengeShape{
		types:     map[string]string{},
		nonceLen:  len(c.Nonce),
		rpID:      c.MethodData[methodDataRPID],
		origins:   c.MethodData[methodDataOrigins],
		requireUV: c.MethodData[methodDataRequireUV],
	}
	for k, v := range c.MethodData {
		s.types[k] = reflect.TypeOf(v).String()
	}
	enc, ok := c.MethodData[methodDataEnrolledKey].(string)
	if !ok {
		t.Fatal("challenge carries no enrolled key")
	}
	cose, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("decode enrolled key: %v", err)
	}
	s.keyLen = len(cose)
	if s.key, ok = shapeOfCOSE(cose); !ok {
		t.Fatal("enrolled key has no imitable shape")
	}
	id, ok := c.MethodData["credential_id"].(string)
	if !ok {
		t.Fatal("challenge carries no credential id")
	}
	if s.id, ok = shapeOfCredentialID(id); !ok {
		t.Fatalf("credential id %q has no recognised encoding", id)
	}
	if b64, ok := c.MethodData["challenge_base64"].(string); ok {
		s.nonceLen = len(b64)
	}
	return s
}

func TestDecoyEnrollmentIsDeterministic(t *testing.T) {
	f := New(Config{RPID: "example.com"})
	like := []*qrdbsdk.AuthFactorEnrollment{
		enrollCOSE(t, f, es256COSE(t), nil),
		enrollCOSE(t, f, es256COSE(t), nil),
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
			first.Metadata["credential_id"] == other.Metadata["credential_id"] {
			t.Errorf("a different %s derived the same key, id or credential id", name)
		}
	}
}

func TestDecoyChallengeMatchesRealChallengeShape(t *testing.T) {
	cases := []struct {
		name   string
		cose   func(*testing.T) []byte
		params func(*testing.T) map[string]any
	}{
		{"es256", es256COSE, func(*testing.T) map[string]any { return nil }},
		{"es384 with padded std id", es384COSE, func(t *testing.T) map[string]any {
			return map[string]any{
				"credential_id":             credentialID(t, base64.StdEncoding, 64),
				"aaguid":                    "cb69481e-8ff7-4039-93ec-0a2729a154a8",
				"origins":                   []string{"https://example.com", "https://login.example.com"},
				"require_user_verification": false,
			}
		}},
		{"eddsa", eddsaCOSE, func(*testing.T) map[string]any { return nil }},
		{"rs256", rs256COSE, func(*testing.T) map[string]any { return nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			f := New(Config{RPID: "example.com"})
			real := enrollCOSE(t, f, tc.cose(t), tc.params(t))
			like := []*qrdbsdk.AuthFactorEnrollment{real, enrollCOSE(t, f, tc.cose(t), tc.params(t))}
			fake := decoyFor(t, f, decoySeed, "stranger", like)

			if fake.UserID != "stranger" || fake.FactorName != FactorName {
				t.Errorf("decoy names user %q factor %q", fake.UserID, fake.FactorName)
			}
			for _, k := range []string{"rp_id", "origins", "require_uv", "ttl", "aaguid"} {
				if real.Metadata[k] != fake.Metadata[k] {
					t.Errorf("metadata %s: real %q decoy %q", k, real.Metadata[k], fake.Metadata[k])
				}
			}
			if len(real.Metadata) != len(fake.Metadata) {
				t.Errorf("metadata keys differ: real %v decoy %v", real.Metadata, fake.Metadata)
			}

			realChallenge, err := f.Challenge(ctx, real)
			if err != nil {
				t.Fatalf("Challenge real: %v", err)
			}
			fakeChallenge, err := f.Challenge(ctx, fake)
			if err != nil {
				t.Fatalf("Challenge decoy: %v", err)
			}
			if got, want := shapeOfFIDO2Challenge(t, fakeChallenge), shapeOfFIDO2Challenge(t, realChallenge); !reflect.DeepEqual(got, want) {
				t.Errorf("challenge shapes differ:\nreal  %+v\ndecoy %+v", want, got)
			}
		})
	}
}

func TestDecoyEnrollmentPairsRPIDWithItsOrigins(t *testing.T) {
	like := []*qrdbsdk.AuthFactorEnrollment{
		{Metadata: map[string]string{"rp_id": "b.example", "origins": "https://b.example"}},
		{Metadata: map[string]string{"rp_id": "a.example", "origins": "https://a.example"}},
		{Metadata: map[string]string{"rp_id": "a.example", "origins": "https://a.example"}},
		{Metadata: map[string]string{"origins": "https://b.example"}},
		{Metadata: map[string]string{"origins": "https://b.example"}},
		nil,
	}
	fake := decoyFor(t, New(Config{}), decoySeed, "stranger", like)
	if fake.Metadata["rp_id"] != "a.example" || fake.Metadata["origins"] != "https://a.example" {
		t.Errorf("want rp a.example with its origins, got %v", fake.Metadata)
	}
}

func TestDecoyEnrollmentEmptyLikeYieldsDefaultForm(t *testing.T) {
	for _, rpID := range []string{"", "example.com"} {
		f := New(Config{RPID: rpID})
		fake := decoyFor(t, f, decoySeed, "stranger", nil)
		if s, ok := shapeOfCOSE(fake.PublicKey); !ok || s != (coseShape{kty: coseKtyEC2, alg: int64(webauthncose.AlgES256), crv: 1}) {
			t.Errorf("want an ES256 P-256 key, got %+v", s)
		}
		if s, ok := shapeOfCredentialID(fake.Metadata["credential_id"]); !ok || s != (credentialIDShape{encoding: 0, size: defaultCredentialIDSize}) {
			t.Errorf("want a %d-byte base64url credential id, got %+v", defaultCredentialIDSize, s)
		}
		want := map[string]string{
			"credential_id": fake.Metadata["credential_id"],
			"rp_id":         f.cfg.RPID,
			"ttl":           "300",
			"origins":       "https://" + f.cfg.RPID,
			"require_uv":    "true",
		}
		if !reflect.DeepEqual(fake.Metadata, want) {
			t.Errorf("want metadata %v, got %v", want, fake.Metadata)
		}
	}
}

func TestDecoyEnrollmentFailsVerify(t *testing.T) {
	ctx := context.Background()
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	fake := decoyFor(t, f, decoySeed, "stranger", []*qrdbsdk.AuthFactorEnrollment{enroll(t, f, a)})
	challenge, err := f.Challenge(ctx, fake)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	var verr *qrdbsdk.AuthFactorVerificationFailedError
	if err := f.Verify(ctx, challenge, responseFor(a, t, challenge.Nonce)); !errors.As(err, &verr) {
		t.Fatalf("want verification failure against a decoy, got %v", err)
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

func TestShapeOfCOSERejectsUnimitableKeys(t *testing.T) {
	modulus1024 := append([]byte{0x80}, make([]byte, 127)...)
	modulus2048 := append([]byte{0x80}, make([]byte, 255)...)
	cases := map[string][]byte{
		"junk":            []byte("junk"),
		"rsa-1024":        marshalCOSE(t, map[int]any{1: 3, 3: -257, -1: modulus1024, -2: []byte{1, 0, 1}}),
		"rsa exponent 3":  marshalCOSE(t, map[int]any{1: 3, 3: -257, -1: modulus2048, -2: []byte{3}}),
		"okp of 57 bytes": marshalCOSE(t, map[int]any{1: 1, 3: -8, -1: 7, -2: make([]byte, 57)}),
	}
	for name, cose := range cases {
		if s, ok := shapeOfCOSE(cose); ok {
			t.Errorf("%s: want no shape, got %+v", name, s)
		}
	}
}

func TestShapeOfCredentialID(t *testing.T) {
	cases := []struct {
		id   string
		want credentialIDShape
		ok   bool
	}{
		{"ab-_", credentialIDShape{encoding: 0, size: 3}, true},
		{"ab-_aw==", credentialIDShape{encoding: 1, size: 4}, true},
		{"ab+/aw==", credentialIDShape{encoding: 2, size: 4}, true},
		{"ab+/aw", credentialIDShape{encoding: 3, size: 4}, true},
		{"!!!", credentialIDShape{}, false},
		{"", credentialIDShape{}, false},
	}
	for _, tc := range cases {
		got, ok := shapeOfCredentialID(tc.id)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%q: want %+v %v, got %+v %v", tc.id, tc.want, tc.ok, got, ok)
		}
	}
}
