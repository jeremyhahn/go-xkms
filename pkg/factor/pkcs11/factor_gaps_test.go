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
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	challengemsg "github.com/jeremyhahn/go-xkms/pkg/factor/internal/challenge"
)

// ecP256 returns a freshly generated P-256 key together with its PKIX DER
// encoding, for driving the enroll/verify paths without a real token.
func ecP256(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return key, der
}

// signMessage produces the ASN.1 DER ECDSA signature over SHA-256(message)
// that the factor expects from a PKCS#11 token.
func signMessage(t *testing.T, key *ecdsa.PrivateKey, message []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	return sig
}

// TestEnroll_AcceptsRawDERBytes covers the []byte arm of the public-key
// parameter. In-process callers (the CLI and the SDK) already hold DER bytes
// and pass them directly rather than base64-encoding them; if that arm broke,
// every non-JSON enrollment would fail.
func TestEnroll_AcceptsRawDERBytes(t *testing.T) {
	_, der := ecP256(t)
	f := New(Config{})

	enrollment, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID:   "user-1",
		TenantID: "tenant-1",
		MethodParams: map[string]any{
			"public_key_der": der, // raw []byte, not base64
		},
	})
	if err != nil {
		t.Fatalf("Enroll with raw DER: %v", err)
	}
	if string(enrollment.PublicKey) != string(der) {
		t.Error("the enrolled public key is not the DER that was supplied")
	}
	if enrollment.Metadata["algorithm"] != "ecdsa" {
		t.Errorf("algorithm = %q, want ecdsa", enrollment.Metadata["algorithm"])
	}
	if enrollment.FactorName != FactorName {
		t.Errorf("FactorName = %q, want %q", enrollment.FactorName, FactorName)
	}
	if enrollment.UserID != "user-1" || enrollment.TenantID != "tenant-1" {
		t.Errorf("identity not carried onto the enrollment: %+v", enrollment)
	}
}

// TestEnroll_RejectsBadPublicKeyParameterShapes covers every rejection arm of
// the public-key extraction. Each one is a distinct operator mistake and must
// produce a typed enrollment error rather than a nil-dereference or a
// zero-length key that later "verifies" nothing.
func TestEnroll_RejectsBadPublicKeyParameterShapes(t *testing.T) {
	f := New(Config{})
	ctx := context.Background()

	cases := []struct {
		name       string
		value      any
		wantReason string
	}{
		{"missing", nil, "required"},
		{"empty string", "", "empty"},
		{"empty bytes", []byte{}, "empty"},
		{"not base64", "!!!not base64!!!", "decode public_key_der"},
		{"wrong type int", 42, "base64 string or []byte"},
		{"wrong type map", map[string]any{"der": "x"}, "base64 string or []byte"},
		{"wrong type bool", true, "base64 string or []byte"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			params := &qrdbsdk.AuthFactorEnrollParams{
				UserID:       "user-1",
				MethodParams: map[string]any{},
			}
			if tc.value != nil {
				params.MethodParams["public_key_der"] = tc.value
			}
			enrollment, err := f.Enroll(ctx, params)
			if err == nil {
				t.Fatalf("Enroll accepted %v and produced %+v", tc.value, enrollment)
			}
			if enrollment != nil {
				t.Errorf("an enrollment was returned alongside the error: %+v", enrollment)
			}
			var invalid *qrdbsdk.AuthFactorEnrollmentInvalidError
			if !errors.As(err, &invalid) {
				t.Fatalf("error type = %T, want *AuthFactorEnrollmentInvalidError", err)
			}
			if !strings.Contains(err.Error(), tc.wantReason) {
				t.Errorf("error %q does not explain the problem (want %q)", err, tc.wantReason)
			}
		})
	}
}

// TestEnroll_RejectsUnsupportedKeyAlgorithm proves a structurally valid PKIX
// key of an algorithm no PKCS#11 signing path supports is refused at
// enrollment. Accepting it would create an enrollment that can never satisfy
// a challenge — an account permanently locked out of its second factor.
func TestEnroll_RejectsUnsupportedKeyAlgorithm(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	f := New(Config{})
	enrollment, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "user-1",
		MethodParams: map[string]any{"public_key_der": der},
	})
	if err == nil {
		t.Fatalf("Enroll accepted an Ed25519 key: %+v", enrollment)
	}
	if !strings.Contains(err.Error(), "ECDSA or RSA") {
		t.Errorf("error %q does not name the supported algorithms", err)
	}

	// publicKeyAlgorithm is the classifier behind that rejection.
	if got := publicKeyAlgorithm(pub); got != "" {
		t.Errorf("publicKeyAlgorithm(ed25519) = %q, want the empty (unsupported) marker", got)
	}
	if got := publicKeyAlgorithm(nil); got != "" {
		t.Errorf("publicKeyAlgorithm(nil) = %q, want the empty marker", got)
	}
}

// TestEnroll_RecordsTokenMetadata pins the PKCS#11 locator metadata. Those
// fields are what an operator uses to find the physical token that holds the
// key, so a dropped slot or label makes a lost-token recovery impossible.
func TestEnroll_RecordsTokenMetadata(t *testing.T) {
	_, der := ecP256(t)
	f := New(Config{ChallengeTTLSeconds: 90})

	enrollment, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID: "user-1",
		MethodParams: map[string]any{
			"public_key_der": base64.StdEncoding.EncodeToString(der),
			"key_id":         "01",
			"token_label":    "custodian-token",
			"slot_id":        3,
			"mechanism":      "CKM_ECDSA",
		},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	want := map[string]string{
		"algorithm":   "ecdsa",
		"mechanism":   "CKM_ECDSA",
		"ttl":         "90",
		"key_id":      "01",
		"token_label": "custodian-token",
		"slot":        "3",
	}
	for k, v := range want {
		if enrollment.Metadata[k] != v {
			t.Errorf("metadata[%q] = %q, want %q", k, enrollment.Metadata[k], v)
		}
	}
}

// TestEnroll_OmitsAbsentAndUnusableMetadata proves optional locator fields of
// the wrong type are dropped rather than recorded as a garbage string, and
// that the configured default mechanism is used when none is supplied.
func TestEnroll_OmitsAbsentAndUnusableMetadata(t *testing.T) {
	_, der := ecP256(t)
	f := New(Config{})

	enrollment, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID: "user-1",
		MethodParams: map[string]any{
			"public_key_der": der,
			"key_id":         12345,             // not a string: dropped
			"token_label":    []string{"label"}, // not a string: dropped
			"slot_id":        struct{}{},        // not int-like: dropped
			"mechanism":      "",                // empty: falls back to the default
		},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	for _, k := range []string{"key_id", "token_label", "slot"} {
		if v, ok := enrollment.Metadata[k]; ok {
			t.Errorf("metadata[%q] = %q, want the field to be omitted for an unusable value", k, v)
		}
	}
	if enrollment.Metadata["mechanism"] != defaultMechanism {
		t.Errorf("mechanism = %q, want the package default %q", enrollment.Metadata["mechanism"], defaultMechanism)
	}
	if enrollment.Metadata["ttl"] != "300" {
		t.Errorf("ttl = %q, want the 5-minute default", enrollment.Metadata["ttl"])
	}
}

// TestIntParamString covers every numeric shape a slot id arrives in. JSON
// decoding produces float64, gRPC/CBOR produce int64, and Go callers produce
// int — all three must render the same slot number or an operator will be
// pointed at the wrong token.
func TestIntParamString(t *testing.T) {
	cases := []struct {
		name  string
		value any
		want  string
	}{
		{"int", 3, "3"},
		{"int zero", 0, "0"},
		{"int64", int64(9), "9"},
		{"float64 from JSON", float64(4), "4"},
		{"float64 truncates", float64(4.9), "4"},
		{"string passthrough", "7", "7"},
		{"nil", nil, ""},
		{"bool", true, ""},
		{"slice", []int{1}, ""},
		{"uint is not handled", uint(5), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := intParamString(tc.value); got != tc.want {
				t.Errorf("intParamString(%#v) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

// TestStringParam covers the string coercion used for the key id and token
// label: only real strings are accepted, so a numeric key id is dropped rather
// than rendered with Go syntax.
func TestStringParam(t *testing.T) {
	if got := stringParam("abc"); got != "abc" {
		t.Errorf("stringParam(%q) = %q", "abc", got)
	}
	for _, v := range []any{nil, 1, 1.5, true, []byte("abc"), []string{"abc"}} {
		if got := stringParam(v); got != "" {
			t.Errorf("stringParam(%#v) = %q, want the empty string", v, got)
		}
	}
}

// TestVerify_RejectsBadEnrolledKeyMaterial covers each way the challenge's
// enrolled key can be absent or unusable. Every one must fail closed with a
// verification error, and none may fall back to key material in the response.
func TestVerify_RejectsBadEnrolledKeyMaterial(t *testing.T) {
	key, der := ecP256(t)
	f := New(Config{})
	ctx := context.Background()

	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "user-1",
		MethodParams: map[string]any{"public_key_der": der},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	cases := []struct {
		name       string
		enrolled   any
		wantReason string
	}{
		{"absent", nil, "missing from challenge MethodData"},
		{"not a string", der, "missing from challenge MethodData"},
		{"empty", "", "missing from challenge MethodData"},
		{"not base64", "%%%", "decode " + methodDataEnrolledKey},
		{"not PKIX", base64.StdEncoding.EncodeToString([]byte("nope")), "parse public key"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			challenge, err := f.Challenge(ctx, enrollment)
			if err != nil {
				t.Fatalf("Challenge: %v", err)
			}
			delete(challenge.MethodData, methodDataEnrolledKey)
			if tc.enrolled != nil {
				challenge.MethodData[methodDataEnrolledKey] = tc.enrolled
			}

			// The response offers the genuine key; it must not be consulted.
			err = f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{
				Value:    signMessage(t, key, challengemsg.Message(challenge)),
				Metadata: map[string]string{"public_key_der": base64.StdEncoding.EncodeToString(der)},
			})
			if err == nil {
				t.Fatal("Verify accepted an unusable enrolled key")
			}
			var failed *qrdbsdk.AuthFactorVerificationFailedError
			if !errors.As(err, &failed) {
				t.Fatalf("error type = %T, want *AuthFactorVerificationFailedError", err)
			}
			if failed.FactorName != FactorName {
				t.Errorf("FactorName = %q, want %q", failed.FactorName, FactorName)
			}
			if !strings.Contains(err.Error(), tc.wantReason) {
				t.Errorf("error %q does not explain the problem (want %q)", err, tc.wantReason)
			}
		})
	}
}

// TestVerify_RejectsUnsupportedKeyType covers the type switch's default arm.
// An Ed25519 key cannot reach this path through Enroll (it is rejected there),
// but Verify parses whatever the challenge carries, so it must refuse an
// unsupported key independently rather than falling through to "verified".
func TestVerify_RejectsUnsupportedKeyType(t *testing.T) {
	key, der := ecP256(t)
	f := New(Config{})
	ctx := context.Background()

	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "user-1",
		MethodParams: map[string]any{"public_key_der": der},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}

	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	edDER, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	challenge.MethodData[methodDataEnrolledKey] = base64.StdEncoding.EncodeToString(edDER)

	err = f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{
		Value: signMessage(t, key, challengemsg.Message(challenge)),
	})
	if err == nil {
		t.Fatal("Verify accepted an Ed25519 public key")
	}
	if !strings.Contains(err.Error(), "unsupported public key type") {
		t.Errorf("error %q does not name the unsupported key type", err)
	}
}

// TestVerifyECDSA_RejectsDegenerateSignatures covers the signature sanity
// checks directly. A signature whose r or s is zero or negative is a classic
// forgery attempt: some verifiers accept (0,0) against any key, so the
// explicit positivity check must reject it before ecdsa.Verify is reached.
func TestVerifyECDSA_RejectsDegenerateSignatures(t *testing.T) {
	key, _ := ecP256(t)
	digest := sha256.Sum256([]byte("nonce"))

	encode := func(t *testing.T, r, s *big.Int) []byte {
		t.Helper()
		der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		if err != nil {
			t.Fatalf("asn1.Marshal: %v", err)
		}
		return der
	}

	cases := []struct {
		name string
		sig  []byte
	}{
		{"zero r and s", encode(t, big.NewInt(0), big.NewInt(0))},
		{"zero r", encode(t, big.NewInt(0), big.NewInt(1))},
		{"zero s", encode(t, big.NewInt(1), big.NewInt(0))},
		{"negative r", encode(t, big.NewInt(-1), big.NewInt(1))},
		{"negative s", encode(t, big.NewInt(1), big.NewInt(-1))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyECDSA(&key.PublicKey, digest[:], tc.sig)
			if err == nil {
				t.Fatal("a degenerate signature was accepted")
			}
			if !strings.Contains(err.Error(), "non-positive component") {
				t.Errorf("error %q does not identify the degenerate component", err)
			}
		})
	}

	t.Run("not ASN.1 at all", func(t *testing.T) {
		err := verifyECDSA(&key.PublicKey, digest[:], []byte{0xFF, 0x00, 0x01})
		if err == nil {
			t.Fatal("a non-ASN.1 signature was accepted")
		}
		if !strings.Contains(err.Error(), "unmarshal signature") {
			t.Errorf("error %q does not identify the decode failure", err)
		}
	})

	t.Run("valid signature is accepted", func(t *testing.T) {
		sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatalf("SignASN1: %v", err)
		}
		if err := verifyECDSA(&key.PublicKey, digest[:], sig); err != nil {
			t.Fatalf("a genuine signature was rejected: %v", err)
		}
	})
}

// TestChallenge_HonorsEnrolledTTL proves the per-enrollment ttl metadata wins
// over the factor default and that an unparsable or non-positive value falls
// back to the default rather than producing an already-expired challenge.
func TestChallenge_HonorsEnrolledTTL(t *testing.T) {
	f := New(Config{ChallengeTTLSeconds: 300})
	ctx := context.Background()

	cases := []struct {
		name       string
		ttl        string
		wantAtMost time.Duration
		wantAtMin  time.Duration
	}{
		{"enrolled ttl wins", "60", 65 * time.Second, 55 * time.Second},
		{"unparsable falls back", "not-a-number", 305 * time.Second, 295 * time.Second},
		{"zero falls back", "0", 305 * time.Second, 295 * time.Second},
		{"negative falls back", "-30", 305 * time.Second, 295 * time.Second},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			challenge, err := f.Challenge(ctx, &qrdbsdk.AuthFactorEnrollment{
				EnrollmentID: "enr-1",
				Metadata:     map[string]string{"ttl": tc.ttl},
			})
			if err != nil {
				t.Fatalf("Challenge: %v", err)
			}
			ttl := time.Until(challenge.ExpiresAt)
			if ttl > tc.wantAtMost || ttl < tc.wantAtMin {
				t.Errorf("challenge ttl = %v, want between %v and %v", ttl, tc.wantAtMin, tc.wantAtMost)
			}
			if len(challenge.Nonce) != nonceLength {
				t.Errorf("nonce length = %d, want %d", len(challenge.Nonce), nonceLength)
			}
			if challenge.EnrollmentID != "enr-1" {
				t.Errorf("EnrollmentID = %q, want enr-1", challenge.EnrollmentID)
			}
		})
	}
}

// TestChallenge_NoncesAreUnique guards the replay property: two challenges for
// the same enrollment must never share a nonce, otherwise a captured signature
// could be replayed against a later challenge.
func TestChallenge_NoncesAreUnique(t *testing.T) {
	f := New(Config{})
	ctx := context.Background()
	enrollment := &qrdbsdk.AuthFactorEnrollment{EnrollmentID: "enr-1", Metadata: map[string]string{}}

	seen := make(map[string]struct{}, 32)
	for i := 0; i < 32; i++ {
		challenge, err := f.Challenge(ctx, enrollment)
		if err != nil {
			t.Fatalf("Challenge #%d: %v", i, err)
		}
		key := string(challenge.Nonce)
		if _, dup := seen[key]; dup {
			t.Fatalf("challenge #%d repeated a nonce", i)
		}
		seen[key] = struct{}{}
		if challenge.ChallengeID == "" {
			t.Fatalf("challenge #%d has no ChallengeID", i)
		}
	}
}

// TestDerDecodeError_Message keeps the typed DER error's message meaningful:
// it is the text an operator sees when an enrollment payload is malformed.
func TestDerDecodeError_Message(t *testing.T) {
	err := &derDecodeError{reason: "public_key_der is required"}
	if err.Error() != "public_key_der is required" {
		t.Errorf("Error() = %q, want the reason verbatim", err.Error())
	}
	if (&derDecodeError{}).Error() != "" {
		t.Error("an empty reason should render as an empty message, not a placeholder")
	}
}

// TestMechanismFamily pins the mechanism classifier that both Enroll and
// Verify rely on to decide whether a mechanism is consistent with a key's
// algorithm.
func TestMechanismFamily(t *testing.T) {
	cases := []struct {
		mechanism string
		want      string
	}{
		{"CKM_ECDSA", "ecdsa"},
		{"CKM_ECDSA_SHA256", "ecdsa"},
		{"CKM_ECDSA_SHA384", "ecdsa"},
		{"CKM_RSA_PKCS", "rsa"},
		{"CKM_SHA256_RSA_PKCS", "rsa"},
		{"CKM_RSA_PKCS_PSS", "rsa"},
		{"CKM_AES_CBC", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := mechanismFamily(tc.mechanism); got != tc.want {
			t.Errorf("mechanismFamily(%q) = %q, want %q", tc.mechanism, got, tc.want)
		}
	}
}

// TestEnroll_RejectsMechanismInconsistentWithKeyType proves the enrollment
// record can never carry a mechanism that names the wrong key algorithm — an
// EC key with an RSA mechanism, or vice versa — because a record like that
// can never be satisfied by a genuine signature from the enrolled key.
func TestEnroll_RejectsMechanismInconsistentWithKeyType(t *testing.T) {
	f := New(Config{})
	ctx := context.Background()

	t.Run("ecdsa key with rsa mechanism", func(t *testing.T) {
		_, der := ecP256(t)
		_, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
			UserID: "user-1",
			MethodParams: map[string]any{
				"public_key_der": der,
				"mechanism":      "CKM_RSA_PKCS",
			},
		})
		var invalid *qrdbsdk.AuthFactorEnrollmentInvalidError
		if !errors.As(err, &invalid) {
			t.Fatalf("error type = %T, want *AuthFactorEnrollmentInvalidError", err)
		}
		if !strings.Contains(err.Error(), "inconsistent") {
			t.Errorf("error %q does not explain the inconsistency", err)
		}
	})

	t.Run("rsa key with ecdsa mechanism", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey: %v", err)
		}
		der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey: %v", err)
		}
		_, err = f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
			UserID: "user-1",
			MethodParams: map[string]any{
				"public_key_der": der,
				"mechanism":      "CKM_ECDSA_SHA256",
			},
		})
		var invalid *qrdbsdk.AuthFactorEnrollmentInvalidError
		if !errors.As(err, &invalid) {
			t.Fatalf("error type = %T, want *AuthFactorEnrollmentInvalidError", err)
		}
		if !strings.Contains(err.Error(), "inconsistent") {
			t.Errorf("error %q does not explain the inconsistency", err)
		}
	})
}

// TestEnroll_RSADefaultsToAnRSAMechanism is the regression for a latent bug:
// f.cfg.DefaultMechanism is CKM_ECDSA_SHA256, so an RSA enrollment that omits
// "mechanism" previously recorded an ECDSA mechanism against an RSA key — an
// enrollment the mechanism/key-type consistency check would then always
// refuse to verify. An RSA key enrolled without an explicit mechanism must
// get an RSA-family default instead.
func TestEnroll_RSADefaultsToAnRSAMechanism(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	f := New(Config{})
	enrollment, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "user-1",
		MethodParams: map[string]any{"public_key_der": der},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if got := mechanismFamily(enrollment.Metadata["mechanism"]); got != "rsa" {
		t.Fatalf("mechanism = %q (family %q), want an RSA mechanism", enrollment.Metadata["mechanism"], got)
	}
}

// TestVerify_RejectsResponseNamingADifferentMechanism is the mechanism
// analogue of TestPKCS11Factor_Verify_RejectsAttackerKeyInResponse: a
// response whose declared mechanism differs from the one recorded at
// enrollment must be refused, even when the signature itself is genuine and
// otherwise valid.
func TestVerify_RejectsResponseNamingADifferentMechanism(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	key, der := ecP256(t)

	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "user-1",
		MethodParams: map[string]any{"public_key_der": der},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if got := challenge.MethodData[methodDataMechanism]; got != defaultMechanism {
		t.Fatalf("challenge MethodData[%q] = %v, want %q", methodDataMechanism, got, defaultMechanism)
	}

	err = f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{
		Value:    signMessage(t, key, challengemsg.Message(challenge)),
		Metadata: map[string]string{responseMechanism: "CKM_RSA_PKCS"},
	})
	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if !errors.As(err, &failed) {
		t.Fatalf("Verify(mismatched mechanism) err = %v, want VerificationFailedError", err)
	}
	if !strings.Contains(err.Error(), "response named mechanism") {
		t.Errorf("error %q does not explain the mechanism mismatch", err)
	}
}

// TestVerify_AcceptsResponseNamingTheEnrolledMechanism proves a response that
// echoes back the enrolled mechanism (as a well-behaved custodian client
// would) is not penalized by the new check — only a genuine mismatch is
// refused.
func TestVerify_AcceptsResponseNamingTheEnrolledMechanism(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	key, der := ecP256(t)

	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "user-1",
		MethodParams: map[string]any{"public_key_der": der},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}

	err = f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{
		Value:    signMessage(t, key, challengemsg.Message(challenge)),
		Metadata: map[string]string{responseMechanism: defaultMechanism},
	})
	if err != nil {
		t.Fatalf("Verify(matching mechanism) failed: %v", err)
	}
}

// TestVerify_RejectsChallengeWithoutMechanism proves Verify fails closed when
// the enrolled mechanism is missing from the challenge — the same treatment
// the enrolled key already gets — rather than silently skipping the check.
func TestVerify_RejectsChallengeWithoutMechanism(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	key, der := ecP256(t)

	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "user-1",
		MethodParams: map[string]any{"public_key_der": der},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	delete(challenge.MethodData, methodDataMechanism)

	err = f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{
		Value: signMessage(t, key, challengemsg.Message(challenge)),
	})
	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if !errors.As(err, &failed) {
		t.Fatalf("Verify(no mechanism) err = %v, want VerificationFailedError", err)
	}
	if !strings.Contains(err.Error(), "mechanism missing from challenge MethodData") {
		t.Errorf("error %q does not explain the missing mechanism", err)
	}
}

// TestVerify_RejectsChallengeWithInconsistentMechanism covers a
// hand-tampered or corrupted challenge whose mechanism no longer matches the
// enrolled key's algorithm — the key parses as ECDSA, but the mechanism
// string names an RSA operation. Verify must refuse rather than silently
// falling back to the key-type switch alone.
func TestVerify_RejectsChallengeWithInconsistentMechanism(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	key, der := ecP256(t)

	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "user-1",
		MethodParams: map[string]any{"public_key_der": der},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	challenge.MethodData[methodDataMechanism] = "CKM_RSA_PKCS"

	err = f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{
		Value: signMessage(t, key, challengemsg.Message(challenge)),
	})
	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if !errors.As(err, &failed) {
		t.Fatalf("Verify(inconsistent mechanism) err = %v, want VerificationFailedError", err)
	}
	if !strings.Contains(err.Error(), "inconsistent with the enrolled ecdsa key") {
		t.Errorf("error %q does not explain the inconsistency", err)
	}
}
