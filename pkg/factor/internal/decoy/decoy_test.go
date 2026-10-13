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

package decoy

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

const testLabel = "xkms/test-decoy/v1"

var testSeed = bytes.Repeat([]byte{0x5a}, 32)

func newDeriver(t *testing.T, seed []byte, userID string) *Deriver {
	t.Helper()
	d, err := New(testLabel, seed, userID)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func TestNewRejectsShortSeed(t *testing.T) {
	_, err := New(testLabel, make([]byte, MinSeedSize-1), "alice")
	var seedErr *SeedError
	if !errors.As(err, &seedErr) || seedErr.Size != MinSeedSize-1 {
		t.Fatalf("want *SeedError of size %d, got %v", MinSeedSize-1, err)
	}
}

func TestNewRejectsEmptyUserID(t *testing.T) {
	_, err := New(testLabel, testSeed, "")
	var userErr *UserIDError
	if !errors.As(err, &userErr) {
		t.Fatalf("want *UserIDError, got %v", err)
	}
}

func TestBytesDeterministicAndSeparated(t *testing.T) {
	a := newDeriver(t, testSeed, "alice")
	first, err := a.Bytes("purpose", 32)
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	again, err := newDeriver(t, testSeed, "alice").Bytes("purpose", 32)
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if !bytes.Equal(first, again) {
		t.Fatal("same (seed, user, purpose) derived different bytes")
	}

	otherSeed := bytes.Repeat([]byte{0xa5}, 32)
	otherLabel, err := New("xkms/other-decoy/v1", testSeed, "alice")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	variants := map[string]*Deriver{
		"user":  newDeriver(t, testSeed, "bob"),
		"seed":  newDeriver(t, otherSeed, "alice"),
		"label": otherLabel,
	}
	for name, d := range variants {
		got, err := d.Bytes("purpose", 32)
		if err != nil {
			t.Fatalf("%s: Bytes: %v", name, err)
		}
		if bytes.Equal(first, got) {
			t.Errorf("a different %s derived the same bytes", name)
		}
	}
	otherPurpose, err := a.Bytes("other", 32)
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if bytes.Equal(first, otherPurpose) {
		t.Error("a different purpose derived the same bytes")
	}
}

func TestBytesRejectsOversizedOutput(t *testing.T) {
	// HKDF-SHA256 expands to at most 255 hash blocks.
	_, err := newDeriver(t, testSeed, "alice").Bytes("purpose", 255*sha256.Size+1)
	var derr *DerivationError
	if !errors.As(err, &derr) || derr.Purpose != "purpose" {
		t.Fatalf("want *DerivationError for purpose, got %v", err)
	}
}

func TestEnrollmentIDIsDeterministicUUIDv4(t *testing.T) {
	id, err := newDeriver(t, testSeed, "alice").EnrollmentID()
	if err != nil {
		t.Fatalf("EnrollmentID: %v", err)
	}
	parsed, err := uuid.Parse(id)
	if err != nil {
		t.Fatalf("parse %q: %v", id, err)
	}
	if parsed.Version() != 4 || parsed.Variant() != uuid.RFC4122 {
		t.Errorf("want an RFC 4122 v4 UUID, got version %d variant %v", parsed.Version(), parsed.Variant())
	}
	again, err := newDeriver(t, testSeed, "alice").EnrollmentID()
	if err != nil {
		t.Fatalf("EnrollmentID: %v", err)
	}
	if id != again {
		t.Errorf("enrollment id not deterministic: %s vs %s", id, again)
	}
	other, err := newDeriver(t, testSeed, "bob").EnrollmentID()
	if err != nil {
		t.Fatalf("EnrollmentID: %v", err)
	}
	if id == other {
		t.Error("different users derived the same enrollment id")
	}
}

func TestTimeWithinRange(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(365 * 24 * time.Hour)
	d := newDeriver(t, testSeed, "alice")
	got, err := d.Time("not-before", from, to)
	if err != nil {
		t.Fatalf("Time: %v", err)
	}
	if got.Before(from) || got.After(to) || got.Nanosecond() != 0 {
		t.Errorf("time %v outside [%v, %v] or not whole seconds", got, from, to)
	}
	again, err := d.Time("not-before", from, to)
	if err != nil {
		t.Fatalf("Time: %v", err)
	}
	if !got.Equal(again) {
		t.Errorf("time not deterministic: %v vs %v", got, again)
	}
}

func TestTimeInvertedRangeYieldsFrom(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 500, time.UTC)
	got, err := newDeriver(t, testSeed, "alice").Time("t", from, from.Add(-time.Hour))
	if err != nil {
		t.Fatalf("Time: %v", err)
	}
	if want := from.Truncate(time.Second); !got.Equal(want) {
		t.Errorf("want %v, got %v", want, got)
	}
}

func TestSerialIsPositiveAndFitsSize(t *testing.T) {
	serial, err := newDeriver(t, testSeed, "alice").Serial("serial", 16)
	if err != nil {
		t.Fatalf("Serial: %v", err)
	}
	if serial.Sign() <= 0 || serial.BitLen() > 16*8-1 {
		t.Errorf("want a positive serial of at most 127 bits, got sign %d bitlen %d", serial.Sign(), serial.BitLen())
	}
	again, err := newDeriver(t, testSeed, "alice").Serial("serial", 16)
	if err != nil {
		t.Fatalf("Serial: %v", err)
	}
	if serial.Cmp(again) != 0 {
		t.Error("same inputs derived different serials")
	}
}

func TestSerialRejectsNonPositiveSize(t *testing.T) {
	_, err := newDeriver(t, testSeed, "alice").Serial("serial", 0)
	var derr *DerivationError
	if !errors.As(err, &derr) {
		t.Fatalf("want *DerivationError, got %v", err)
	}
}

func TestECDSAKeyDeterministicPerCurve(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key, err := newDeriver(t, testSeed, "alice").ECDSAKey("key", curve)
			if err != nil {
				t.Fatalf("ECDSAKey: %v", err)
			}
			if key.Curve != curve {
				t.Fatalf("want curve %s, got %s", curve.Params().Name, key.Curve.Params().Name)
			}
			again, err := newDeriver(t, testSeed, "alice").ECDSAKey("key", curve)
			if err != nil {
				t.Fatalf("ECDSAKey: %v", err)
			}
			if !key.PublicKey.Equal(&again.PublicKey) {
				t.Error("same inputs derived different keys")
			}
			other, err := newDeriver(t, testSeed, "bob").ECDSAKey("key", curve)
			if err != nil {
				t.Fatalf("ECDSAKey: %v", err)
			}
			if key.PublicKey.Equal(&other.PublicKey) {
				t.Error("different users derived the same key")
			}
		})
	}
}

func TestECDSAKeyPropagatesDerivationError(t *testing.T) {
	// A curve wider than HKDF can expand to fails in Bytes.
	params := *elliptic.P256().Params()
	params.BitSize = 255 * sha256.Size * 8 * 2
	_, err := newDeriver(t, testSeed, "alice").ECDSAKey("key", &params)
	var derr *DerivationError
	if !errors.As(err, &derr) {
		t.Fatalf("want *DerivationError, got %v", err)
	}
}

func TestEd25519KeyDeterministic(t *testing.T) {
	key, err := newDeriver(t, testSeed, "alice").Ed25519Key("key")
	if err != nil {
		t.Fatalf("Ed25519Key: %v", err)
	}
	again, err := newDeriver(t, testSeed, "alice").Ed25519Key("key")
	if err != nil {
		t.Fatalf("Ed25519Key: %v", err)
	}
	if !key.Equal(again) {
		t.Error("same inputs derived different keys")
	}
	other, err := newDeriver(t, testSeed, "bob").Ed25519Key("key")
	if err != nil {
		t.Fatalf("Ed25519Key: %v", err)
	}
	if key.Equal(other) {
		t.Error("different users derived the same key")
	}
}

func TestRSAKeyDeterministicAndExactSize(t *testing.T) {
	key, err := newDeriver(t, testSeed, "alice").RSAKey("key", 2048)
	if err != nil {
		t.Fatalf("RSAKey: %v", err)
	}
	if key.N.BitLen() != 2048 || key.E != rsaPublicExponent {
		t.Fatalf("want 2048-bit modulus with e=65537, got %d bits e=%d", key.N.BitLen(), key.E)
	}
	again, err := newDeriver(t, testSeed, "alice").RSAKey("key", 2048)
	if err != nil {
		t.Fatalf("RSAKey: %v", err)
	}
	if !key.PublicKey.Equal(&again.PublicKey) {
		t.Error("same inputs derived different keys")
	}
}

func TestRSAKeyRejectsUnsupportedSizes(t *testing.T) {
	d := newDeriver(t, testSeed, "alice")
	for _, bits := range []int{1024, 2047, 2056, 8208} {
		_, err := d.RSAKey("key", bits)
		var sizeErr *RSASizeError
		if !errors.As(err, &sizeErr) || sizeErr.Bits != bits {
			t.Errorf("%d bits: want *RSASizeError, got %v", bits, err)
		}
	}
}

func TestKeyDerivesEachShape(t *testing.T) {
	for _, s := range []KeyShape{
		{Algorithm: AlgorithmECDSA, Curve: "P-256"},
		{Algorithm: AlgorithmECDSA, Curve: "P-384"},
		{Algorithm: AlgorithmECDSA, Curve: "P-521"},
		{Algorithm: AlgorithmRSA, Bits: 2048},
		{Algorithm: AlgorithmEd25519},
	} {
		key, err := newDeriver(t, testSeed, "alice").Key("key", s)
		if err != nil {
			t.Fatalf("%+v: %v", s, err)
		}
		if got, ok := ShapeOfKey(key.Public()); !ok || got != s {
			t.Errorf("want a key of shape %+v, got %+v", s, got)
		}
	}
}

func TestKeyRejectsUnknownShapes(t *testing.T) {
	for _, s := range []KeyShape{
		{Algorithm: "dsa"},
		{Algorithm: AlgorithmECDSA, Curve: "P-224"},
		{Algorithm: AlgorithmRSA, Bits: 1024},
	} {
		if _, err := newDeriver(t, testSeed, "alice").Key("key", s); err == nil {
			t.Errorf("%+v: want an error", s)
		}
	}
}

func TestShapeOfKey(t *testing.T) {
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p224: %v", err)
	}
	modulus := func(bits int) *big.Int { return new(big.Int).Lsh(big.NewInt(1), uint(bits-1)) }
	cases := []struct {
		name string
		pub  crypto.PublicKey
		want KeyShape
		ok   bool
	}{
		{"rsa 3072", &rsa.PublicKey{N: modulus(3072), E: 65537}, KeyShape{Algorithm: AlgorithmRSA, Bits: 3072}, true},
		{"ed25519", make(ed25519.PublicKey, ed25519.PublicKeySize), KeyShape{Algorithm: AlgorithmEd25519}, true},
		{"rsa 1024", &rsa.PublicKey{N: modulus(1024), E: 65537}, KeyShape{}, false},
		{"rsa exponent 3", &rsa.PublicKey{N: modulus(2048), E: 3}, KeyShape{}, false},
		{"p-224", &p224.PublicKey, KeyShape{}, false},
		{"not a key", "junk", KeyShape{}, false},
	}
	for _, tc := range cases {
		if got, ok := ShapeOfKey(tc.pub); ok != tc.ok || got != tc.want {
			t.Errorf("%s: want %+v %v, got %+v %v", tc.name, tc.want, tc.ok, got, ok)
		}
	}
}

// certAt returns a PEM certificate whose validity starts at notBefore.
func certAt(t *testing.T, notBefore time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: notBefore, NotAfter: notBefore.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCertificatesAndNotBeforeSpan(t *testing.T) {
	early := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2026, 3, 9, 0, 0, 0, 0, time.UTC)
	like := []*qrdbsdk.AuthFactorEnrollment{
		nil,
		{PublicKey: []byte("not pem")},
		{PublicKey: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}})},
		{PublicKey: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})},
		{PublicKey: certAt(t, late)},
		{PublicKey: certAt(t, early)},
	}
	certs := Certificates(like)
	if len(certs) != 2 {
		t.Fatalf("want the 2 certificates, got %d", len(certs))
	}
	if from, to := NotBeforeSpan(certs); !from.Equal(early) || !to.Equal(late) {
		t.Errorf("want span [%v, %v], got [%v, %v]", early, late, from, to)
	}
}

func TestNotBeforeSpanWithoutCertificatesIsTheEpochYear(t *testing.T) {
	from, to := NotBeforeSpan(Certificates([]*qrdbsdk.AuthFactorEnrollment{{PublicKey: []byte("junk")}}))
	if !from.Equal(Epoch) || !to.Equal(Epoch.AddDate(1, 0, 0)) {
		t.Errorf("want the year from the epoch, got [%v, %v]", from, to)
	}
}

func TestSignerIsDeterministic(t *testing.T) {
	key, err := newDeriver(t, testSeed, "alice").ECDSAKey("key", elliptic.P256())
	if err != nil {
		t.Fatalf("ECDSAKey: %v", err)
	}
	digest := sha256.Sum256([]byte("tbs"))
	signer := Signer(key)
	first, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	second, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("signatures differ")
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], first) {
		t.Error("signature does not verify")
	}
}

func TestSignerPropagatesSignError(t *testing.T) {
	key, err := newDeriver(t, testSeed, "alice").RSAKey("key", 2048)
	if err != nil {
		t.Fatalf("RSAKey: %v", err)
	}
	// A digest whose length does not match the hash is refused.
	if _, err := Signer(key).Sign(nil, []byte("short"), crypto.SHA256); err == nil {
		t.Fatal("want an error for a mis-sized digest")
	}
}

func TestEnrollmentAssemblesDecoy(t *testing.T) {
	like := []*qrdbsdk.AuthFactorEnrollment{
		nil,
		{TenantID: "acme"},
		{TenantID: "acme"},
		{TenantID: "other"},
	}
	metadata := map[string]string{"k": "v"}
	d := newDeriver(t, testSeed, "alice")
	got, err := d.Enrollment("pkcs11", like, []byte{1, 2}, metadata)
	if err != nil {
		t.Fatalf("Enrollment: %v", err)
	}
	wantID, err := d.EnrollmentID()
	if err != nil {
		t.Fatalf("EnrollmentID: %v", err)
	}
	if got.EnrollmentID != wantID || got.UserID != "alice" || got.FactorName != "pkcs11" ||
		got.TenantID != "acme" || !bytes.Equal(got.PublicKey, []byte{1, 2}) ||
		got.Metadata["k"] != "v" || !got.EnrolledAt.IsZero() {
		t.Errorf("unexpected decoy enrollment %+v", got)
	}
}

func TestEnrollmentWithEmptyLikeHasNoTenant(t *testing.T) {
	got, err := newDeriver(t, testSeed, "alice").Enrollment("pkcs11", nil, nil, nil)
	if err != nil {
		t.Fatalf("Enrollment: %v", err)
	}
	if got.TenantID != "" {
		t.Errorf("want no tenant, got %q", got.TenantID)
	}
}

func TestMetadataValues(t *testing.T) {
	like := []*qrdbsdk.AuthFactorEnrollment{
		{Metadata: map[string]string{"slot": "1"}},
		nil,
		{Metadata: map[string]string{}},
		{},
	}
	got := MetadataValues(like, "slot")
	want := []string{"1", "", ""}
	if len(got) != len(want) {
		t.Fatalf("want %q, got %q", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("want %q, got %q", want, got)
		}
	}
	if got := MetadataValues(nil, "slot"); len(got) != 0 {
		t.Errorf("want no values for empty like, got %q", got)
	}
}

func TestNonEmpty(t *testing.T) {
	got := NonEmpty([]string{"", "a", "", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("want [a b], got %q", got)
	}
	if got := NonEmpty([]string{"", ""}); len(got) != 0 {
		t.Errorf("want no values, got %q", got)
	}
}

func TestRSASizeSupported(t *testing.T) {
	for bits, want := range map[int]bool{2048: true, 3072: true, 8192: true, 1024: false, 2047: false, 8208: false} {
		if got := RSASizeSupported(bits); got != want {
			t.Errorf("RSASizeSupported(%d) = %v, want %v", bits, got, want)
		}
	}
}

func TestPredominant(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		want   string
	}{
		{"empty yields fallback", nil, "fallback"},
		{"majority wins", []string{"a", "b", "b"}, "b"},
		{"tie goes to first seen", []string{"a", "b", "b", "a"}, "a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Predominant(tc.values, "fallback"); got != tc.want {
				t.Errorf("want %q, got %q", tc.want, got)
			}
		})
	}
}
