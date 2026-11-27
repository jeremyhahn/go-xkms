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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// authenticator is a minimal in-test WebAuthn authenticator producing the same
// COSE key, authenticatorData and assertion signature that a real FIDO2 device
// (and the go-xkms MockAuthenticator) produces. It exercises the real
// webauthncose verification path in Factor.Verify.
type authenticator struct {
	priv    *ecdsa.PrivateKey
	rpID    string
	rpIDHsh []byte

	// flags is the authenticatorData flags byte; ceremonyType is the
	// clientDataJSON "type"; origin is the clientDataJSON "origin". Tests
	// alter them to model a misbehaving or hostile client.
	flags        byte
	ceremonyType string
	origin       string
}

func newAuthenticator(t *testing.T, rpID string) *authenticator {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	h := sha256.Sum256([]byte(rpID))
	return &authenticator{
		priv:         priv,
		rpID:         rpID,
		rpIDHsh:      h[:],
		flags:        0x05, // UP + UV
		ceremonyType: "webauthn.get",
		origin:       "https://" + rpID,
	}
}

// coseKey returns the credential public key in COSE_Key (ES256) form.
func (a *authenticator) coseKey(t *testing.T) []byte {
	t.Helper()
	// Derive the uncompressed point (0x04 || X || Y) via crypto/ecdh rather than
	// the deprecated ecdsa.PublicKey.X/.Y big.Int coordinate fields.
	ecdhPub, err := a.priv.PublicKey.ECDH()
	if err != nil {
		t.Fatalf("convert public key to ecdh: %v", err)
	}
	point := ecdhPub.Bytes()
	x := point[1:33]
	y := point[33:65]
	coseKey := map[int]interface{}{
		1:  2,                          // kty: EC2
		3:  int(webauthncose.AlgES256), // alg: ES256
		-1: 1,                          // crv: P-256
		-2: x,
		-3: y,
	}
	b, err := webauthncbor.Marshal(coseKey)
	if err != nil {
		t.Fatalf("marshal cose: %v", err)
	}
	return b
}

// authData builds authenticatorData (rpIdHash || flags || signCount).
func (a *authenticator) authData() []byte {
	out := make([]byte, 0, 37)
	out = append(out, a.rpIDHsh...)
	out = append(out, a.flags)
	count := make([]byte, 4)
	binary.BigEndian.PutUint32(count, 1)
	out = append(out, count...)
	return out
}

// clientDataJSON builds a WebAuthn CollectedClientData for an assertion.
func (a *authenticator) clientDataJSON(challenge []byte) []byte {
	cd := struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}{
		Type:      a.ceremonyType,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Origin:    a.origin,
	}
	b, _ := json.Marshal(cd)
	return b
}

// assert produces an assertion (authData, clientData, signature) over the
// supplied challenge, signing authData || SHA-256(clientData) with ECDSA.
func (a *authenticator) assert(t *testing.T, challenge []byte) (authData, clientData, sig []byte) {
	t.Helper()
	authData = a.authData()
	clientData = a.clientDataJSON(challenge)
	clientDataHash := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	r, s, err := ecdsa.Sign(rand.Reader, a.priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig, err = marshalASN1(r, s)
	if err != nil {
		t.Fatalf("marshal sig: %v", err)
	}
	return authData, clientData, sig
}

// marshalASN1 encodes (r,s) as an ASN.1 DER ECDSA signature.
func marshalASN1(r, s *big.Int) ([]byte, error) {
	rb := r.Bytes()
	sb := s.Bytes()
	if len(rb) > 0 && rb[0] >= 0x80 {
		rb = append([]byte{0x00}, rb...)
	}
	if len(sb) > 0 && sb[0] >= 0x80 {
		sb = append([]byte{0x00}, sb...)
	}
	body := make([]byte, 0, 6+len(rb)+len(sb))
	body = append(body, 0x02, byte(len(rb)))
	body = append(body, rb...)
	body = append(body, 0x02, byte(len(sb)))
	body = append(body, sb...)
	out := make([]byte, 0, 2+len(body))
	out = append(out, 0x30, byte(len(body)))
	out = append(out, body...)
	return out, nil
}

func enroll(t *testing.T, f *Factor, a *authenticator) *qrdbsdk.AuthFactorEnrollment {
	t.Helper()
	return enrollWithParams(t, f, a, nil)
}

// enrollWithParams enrolls a's credential, overlaying extra onto the base
// MethodParams so tests can exercise "origins" and
// "require_user_verification" without duplicating the whole call.
func enrollWithParams(t *testing.T, f *Factor, a *authenticator, extra map[string]any) *qrdbsdk.AuthFactorEnrollment {
	t.Helper()
	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("rand credID: %v", err)
	}
	params := map[string]any{
		"cose_public_key": base64.StdEncoding.EncodeToString(a.coseKey(t)),
		"credential_id":   base64.RawURLEncoding.EncodeToString(credID),
		"rp_id":           a.rpID,
	}
	for k, v := range extra {
		params[k] = v
	}
	enrollment, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "custodian-1",
		MethodParams: params,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return enrollment
}

// responseFor produces the wire response for an assertion over nonce: the
// signature plus authenticatorData and clientDataJSON. It carries no key.
func responseFor(a *authenticator, t *testing.T, nonce []byte) *qrdbsdk.AuthFactorResponse {
	authData, clientData, sig := a.assert(t, nonce)
	return &qrdbsdk.AuthFactorResponse{
		Value: sig,
		Metadata: map[string]string{
			"authenticator_data": base64.StdEncoding.EncodeToString(authData),
			"client_data":        base64.StdEncoding.EncodeToString(clientData),
		},
	}
}

// issue enrolls a's credential with f and issues a challenge for it.
func issue(t *testing.T, f *Factor, a *authenticator) (*qrdbsdk.AuthFactorEnrollment, *qrdbsdk.AuthFactorChallenge) {
	t.Helper()
	return issueWithParams(t, f, a, nil)
}

// issueWithParams enrolls a's credential with extra MethodParams overlaid and
// issues a challenge for it.
func issueWithParams(t *testing.T, f *Factor, a *authenticator, extra map[string]any) (*qrdbsdk.AuthFactorEnrollment, *qrdbsdk.AuthFactorChallenge) {
	t.Helper()
	enrollment := enrollWithParams(t, f, a, extra)
	challenge, err := f.Challenge(context.Background(), enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	return enrollment, challenge
}

// requireVerificationFailed asserts err is the factor's verification refusal.
func requireVerificationFailed(t *testing.T, err error) {
	t.Helper()
	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if !errors.As(err, &failed) {
		t.Fatalf("Verify err = %v, want VerificationFailedError", err)
	}
}

func TestFIDO2Factor_NewDefaults(t *testing.T) {
	f := New(Config{})
	if f.cfg.RPID != defaultRPID {
		t.Fatalf("RPID = %q, want %q", f.cfg.RPID, defaultRPID)
	}
	if f.cfg.ChallengeTTLSeconds != defaultChallengeTTLSeconds {
		t.Fatalf("ChallengeTTLSeconds = %d, want %d", f.cfg.ChallengeTTLSeconds, defaultChallengeTTLSeconds)
	}
}

func TestFIDO2Factor_RoundTrip(t *testing.T) {
	ctx := context.Background()
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")

	enrollment := enroll(t, f, a)
	if enrollment.FactorName != FactorName {
		t.Fatalf("FactorName = %q, want %q", enrollment.FactorName, FactorName)
	}
	if enrollment.Metadata["rp_id"] != "example.com" {
		t.Fatalf("rp_id = %q, want example.com", enrollment.Metadata["rp_id"])
	}
	if len(enrollment.PublicKey) == 0 {
		t.Fatal("PublicKey is empty")
	}

	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if len(challenge.Nonce) != challengeLength {
		t.Fatalf("nonce length = %d, want %d", len(challenge.Nonce), challengeLength)
	}

	if got := challenge.MethodData[methodDataEnrolledKey]; got != base64.StdEncoding.EncodeToString(enrollment.PublicKey) {
		t.Fatalf("challenge MethodData[%q] = %v, want the enrolled COSE key", methodDataEnrolledKey, got)
	}
	if got := challenge.MethodData[methodDataRPID]; got != "example.com" {
		t.Fatalf("challenge MethodData[%q] = %v, want example.com", methodDataRPID, got)
	}

	if err := f.Verify(ctx, challenge, responseFor(a, t, challenge.Nonce)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestFIDO2Factor_Enroll_RejectsNilParams(t *testing.T) {
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	if _, err := New(Config{}).Enroll(context.Background(), nil); !errors.As(err, &inv) {
		t.Fatalf("Enroll(nil) err = %v, want EnrollmentInvalidError", err)
	}
}

func TestFIDO2Factor_Enroll_RejectsMissingCOSE(t *testing.T) {
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	_, err := New(Config{}).Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "u1",
		MethodParams: map[string]any{"credential_id": "abc"},
	})
	if !errors.As(err, &inv) {
		t.Fatalf("Enroll(no cose) err = %v, want EnrollmentInvalidError", err)
	}
}

func TestFIDO2Factor_Enroll_RejectsMissingCredentialID(t *testing.T) {
	a := newAuthenticator(t, "example.com")
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	_, err := New(Config{}).Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID: "u1",
		MethodParams: map[string]any{
			"cose_public_key": base64.StdEncoding.EncodeToString(a.coseKey(t)),
		},
	})
	if !errors.As(err, &inv) {
		t.Fatalf("Enroll(no cred id) err = %v, want EnrollmentInvalidError", err)
	}
}

func TestFIDO2Factor_Enroll_RejectsMalformedCOSE(t *testing.T) {
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	_, err := New(Config{}).Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID: "u1",
		MethodParams: map[string]any{
			"cose_public_key": base64.StdEncoding.EncodeToString([]byte("not-cose")),
			"credential_id":   "abc",
		},
	})
	if !errors.As(err, &inv) {
		t.Fatalf("Enroll(bad cose) err = %v, want EnrollmentInvalidError", err)
	}
}

func TestFIDO2Factor_Verify_RejectsExpiredChallenge(t *testing.T) {
	ctx := context.Background()
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	_, challenge := issue(t, f, a)
	resp := responseFor(a, t, challenge.Nonce)
	challenge.ExpiresAt = challenge.ExpiresAt.Add(-time.Hour)

	var expired *qrdbsdk.AuthFactorChallengeExpiredError
	if err := f.Verify(ctx, challenge, resp); !errors.As(err, &expired) {
		t.Fatalf("Verify(expired) err = %v, want ChallengeExpiredError", err)
	}
}

func TestFIDO2Factor_Verify_RejectsTamperedSignature(t *testing.T) {
	ctx := context.Background()
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	_, challenge := issue(t, f, a)
	resp := responseFor(a, t, challenge.Nonce)
	resp.Value[len(resp.Value)-1] ^= 0xFF

	requireVerificationFailed(t, f.Verify(ctx, challenge, resp))
}

func TestFIDO2Factor_Verify_RejectsWrongChallengeBinding(t *testing.T) {
	ctx := context.Background()
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	_, challenge := issue(t, f, a)

	// Build an assertion bound to a DIFFERENT challenge nonce; signature is
	// valid but does not bind the issued challenge.
	otherNonce := make([]byte, challengeLength)
	if _, err := rand.Read(otherNonce); err != nil {
		t.Fatalf("rand: %v", err)
	}
	requireVerificationFailed(t, f.Verify(ctx, challenge, responseFor(a, t, otherNonce)))
}

// TestFIDO2Factor_Verify_RejectsAttackerKeyInResponse is the #1282
// regression: an assertion from a credential the attacker controls, carrying
// that credential's COSE key in the response metadata, must not verify
// against the enrollment.
func TestFIDO2Factor_Verify_RejectsAttackerKeyInResponse(t *testing.T) {
	ctx := context.Background()
	f := New(Config{RPID: "example.com"})
	victim := newAuthenticator(t, "example.com")
	attacker := newAuthenticator(t, "example.com")
	_, challenge := issue(t, f, victim)

	resp := responseFor(attacker, t, challenge.Nonce)
	resp.Metadata["cose_public_key"] = base64.StdEncoding.EncodeToString(attacker.coseKey(t))

	requireVerificationFailed(t, f.Verify(ctx, challenge, resp))
}

// TestFIDO2Factor_Verify_RejectsChallengeWithoutEnrolledKey proves Verify has
// no second source for the key: with the enrolled key absent from, or unusable
// in, the challenge it refuses — even when the response carries the genuine
// key.
func TestFIDO2Factor_Verify_RejectsChallengeWithoutEnrolledKey(t *testing.T) {
	cases := []struct {
		name     string
		enrolled any
	}{
		{"absent", nil},
		{"not a string", []byte("cose")},
		{"empty", ""},
		{"not base64", "%%%"},
		{"not COSE", base64.StdEncoding.EncodeToString([]byte("not-cose"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := New(Config{RPID: "example.com"})
			a := newAuthenticator(t, "example.com")
			enrollment, challenge := issue(t, f, a)
			delete(challenge.MethodData, methodDataEnrolledKey)
			if tc.enrolled != nil {
				challenge.MethodData[methodDataEnrolledKey] = tc.enrolled
			}

			resp := responseFor(a, t, challenge.Nonce)
			resp.Metadata["cose_public_key"] = base64.StdEncoding.EncodeToString(enrollment.PublicKey)

			requireVerificationFailed(t, f.Verify(context.Background(), challenge, resp))
		})
	}
}

func TestFIDO2Factor_Verify_RejectsChallengeWithoutRPID(t *testing.T) {
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	_, challenge := issue(t, f, a)
	delete(challenge.MethodData, methodDataRPID)

	requireVerificationFailed(t, f.Verify(context.Background(), challenge, responseFor(a, t, challenge.Nonce)))
}

// TestFIDO2Factor_Verify_RejectsWrongRPIDHash covers an assertion the enrolled
// credential genuinely signed, but for a different relying party.
func TestFIDO2Factor_Verify_RejectsWrongRPIDHash(t *testing.T) {
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	_, challenge := issue(t, f, a)

	other := sha256.Sum256([]byte("evil.example.net"))
	a.rpIDHsh = other[:]

	err := f.Verify(context.Background(), challenge, responseFor(a, t, challenge.Nonce))
	requireVerificationFailed(t, err)
	if !strings.Contains(err.Error(), "rpIdHash") {
		t.Errorf("error %q does not name the rpIdHash mismatch", err)
	}
}

func TestFIDO2Factor_Verify_RejectsMissingUserPresence(t *testing.T) {
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	_, challenge := issue(t, f, a)
	a.flags = 0x04 // UV without UP

	err := f.Verify(context.Background(), challenge, responseFor(a, t, challenge.Nonce))
	requireVerificationFailed(t, err)
	if !strings.Contains(err.Error(), "user-present") {
		t.Errorf("error %q does not name the missing user-present flag", err)
	}
}

// TestFIDO2Factor_Verify_RejectsUserPresenceWithoutVerification pins the
// WebAuthn/CTAP2 best-practice default for a factor used to unseal or
// authenticate: every enrollment requires user verification unless it
// explicitly opts out, so UP alone is refused.
func TestFIDO2Factor_Verify_RejectsUserPresenceWithoutVerification(t *testing.T) {
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	_, challenge := issue(t, f, a)
	a.flags = 0x01 // UP only, no UV

	err := f.Verify(context.Background(), challenge, responseFor(a, t, challenge.Nonce))
	requireVerificationFailed(t, err)
	if !strings.Contains(err.Error(), "user-verified") {
		t.Errorf("error %q does not name the missing user-verified flag", err)
	}
}

// TestFIDO2Factor_Verify_AcceptsUserPresenceWhenVerificationNotRequired pins
// the explicit opt-out: an enrollment that sets
// "require_user_verification": false accepts UP alone.
func TestFIDO2Factor_Verify_AcceptsUserPresenceWhenVerificationNotRequired(t *testing.T) {
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	_, challenge := issueWithParams(t, f, a, map[string]any{"require_user_verification": false})
	a.flags = 0x01 // UP only, no UV

	if err := f.Verify(context.Background(), challenge, responseFor(a, t, challenge.Nonce)); err != nil {
		t.Fatalf("Verify(UP only, UV not required): %v", err)
	}
}

// TestFIDO2Factor_Verify_RejectsChallengeWithoutRequireUV proves Verify has
// no implicit default when the enrollment carries no user-verification
// requirement at all (e.g. a pre-existing enrollment predating this field):
// it refuses rather than silently defaulting to permissive.
func TestFIDO2Factor_Verify_RejectsChallengeWithoutRequireUV(t *testing.T) {
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	_, challenge := issue(t, f, a)
	delete(challenge.MethodData, methodDataRequireUV)

	err := f.Verify(context.Background(), challenge, responseFor(a, t, challenge.Nonce))
	requireVerificationFailed(t, err)
	if !strings.Contains(err.Error(), methodDataRequireUV) {
		t.Errorf("error %q does not name the missing %s", err, methodDataRequireUV)
	}
}

// TestFIDO2Factor_Verify_RejectsWrongOrigin covers a clientDataJSON whose
// origin does not match any origin the enrollment recorded, per WebAuthn
// L2/L3 §7.2 step 9.
func TestFIDO2Factor_Verify_RejectsWrongOrigin(t *testing.T) {
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	_, challenge := issue(t, f, a)
	a.origin = "https://evil.example.net"

	err := f.Verify(context.Background(), challenge, responseFor(a, t, challenge.Nonce))
	requireVerificationFailed(t, err)
	if !strings.Contains(err.Error(), "origin") {
		t.Errorf("error %q does not name the origin mismatch", err)
	}
}

// TestFIDO2Factor_Verify_AcceptsAnyEnrolledOrigin covers an enrollment that
// records several accepted origins (e.g. an apex domain and a www subdomain):
// an assertion from any one of them verifies.
func TestFIDO2Factor_Verify_AcceptsAnyEnrolledOrigin(t *testing.T) {
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	_, challenge := issueWithParams(t, f, a, map[string]any{
		"origins": []string{"https://example.com", "https://www.example.com"},
	})
	a.origin = "https://www.example.com"

	if err := f.Verify(context.Background(), challenge, responseFor(a, t, challenge.Nonce)); err != nil {
		t.Fatalf("Verify(second enrolled origin): %v", err)
	}
}

func TestFIDO2Factor_Verify_RejectsChallengeWithoutOrigins(t *testing.T) {
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	_, challenge := issue(t, f, a)
	delete(challenge.MethodData, methodDataOrigins)

	err := f.Verify(context.Background(), challenge, responseFor(a, t, challenge.Nonce))
	requireVerificationFailed(t, err)
	if !strings.Contains(err.Error(), methodDataOrigins) {
		t.Errorf("error %q does not name the missing %s", err, methodDataOrigins)
	}
}

// TestFIDO2Factor_Enroll_RecordsOriginAndUVRequirement pins that Enroll
// records both fields even with no explicit MethodParams: the default
// origin "https://" + rp_id and the secure require_user_verification default
// of true, and that Challenge carries both into MethodData for Verify to
// read.
func TestFIDO2Factor_Enroll_RecordsOriginAndUVRequirement(t *testing.T) {
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")

	enrollment := enroll(t, f, a)
	if got, want := enrollment.Metadata["origins"], "https://example.com"; got != want {
		t.Errorf("enrollment Metadata[origins] = %q, want %q", got, want)
	}
	if got, want := enrollment.Metadata["require_uv"], "true"; got != want {
		t.Errorf("enrollment Metadata[require_uv] = %q, want %q", got, want)
	}

	challenge, err := f.Challenge(context.Background(), enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	origins, ok := challenge.MethodData[methodDataOrigins].([]string)
	if !ok || len(origins) != 1 || origins[0] != "https://example.com" {
		t.Errorf("challenge MethodData[%q] = %v, want [https://example.com]", methodDataOrigins, challenge.MethodData[methodDataOrigins])
	}
	if requireUV, ok := challenge.MethodData[methodDataRequireUV].(bool); !ok || !requireUV {
		t.Errorf("challenge MethodData[%q] = %v, want true", methodDataRequireUV, challenge.MethodData[methodDataRequireUV])
	}
}

// TestFIDO2Factor_Enroll_RecordsExplicitOriginsAndUVOverride pins that
// explicit MethodParams values for "origins" and
// "require_user_verification" are recorded verbatim rather than the
// defaults.
func TestFIDO2Factor_Enroll_RecordsExplicitOriginsAndUVOverride(t *testing.T) {
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")

	enrollment := enrollWithParams(t, f, a, map[string]any{
		"origins":                   []string{"https://example.com", "https://www.example.com"},
		"require_user_verification": false,
	})
	if got, want := enrollment.Metadata["origins"], "https://example.com,https://www.example.com"; got != want {
		t.Errorf("enrollment Metadata[origins] = %q, want %q", got, want)
	}
	if got, want := enrollment.Metadata["require_uv"], "false"; got != want {
		t.Errorf("enrollment Metadata[require_uv] = %q, want %q", got, want)
	}
}

func TestFIDO2Factor_Enroll_RejectsEmptyOrigins(t *testing.T) {
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	_, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID: "custodian-1",
		MethodParams: map[string]any{
			"cose_public_key": base64.StdEncoding.EncodeToString(a.coseKey(t)),
			"credential_id":   base64.RawURLEncoding.EncodeToString([]byte("credential-id-1")),
			"rp_id":           a.rpID,
			"origins":         []string{},
		},
	})
	if !errors.As(err, &inv) {
		t.Fatalf("Enroll(empty origins) err = %v, want EnrollmentInvalidError", err)
	}
}

func TestFIDO2Factor_Enroll_RejectsMalformedRequireUserVerification(t *testing.T) {
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	_, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID: "custodian-1",
		MethodParams: map[string]any{
			"cose_public_key":           base64.StdEncoding.EncodeToString(a.coseKey(t)),
			"credential_id":             base64.RawURLEncoding.EncodeToString([]byte("credential-id-1")),
			"rp_id":                     a.rpID,
			"require_user_verification": 42,
		},
	})
	if !errors.As(err, &inv) {
		t.Fatalf("Enroll(bad require_user_verification) err = %v, want EnrollmentInvalidError", err)
	}
}

func TestFIDO2Factor_Verify_RejectsMalformedAuthenticatorData(t *testing.T) {
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	_, challenge := issue(t, f, a)
	resp := responseFor(a, t, challenge.Nonce)
	resp.Metadata["authenticator_data"] = base64.StdEncoding.EncodeToString([]byte("short"))

	requireVerificationFailed(t, f.Verify(context.Background(), challenge, resp))
}

// TestFIDO2Factor_Verify_RejectsRegistrationCeremony covers a clientDataJSON
// whose type is not "webauthn.get", so a registration signature cannot stand
// in for an assertion.
func TestFIDO2Factor_Verify_RejectsRegistrationCeremony(t *testing.T) {
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	_, challenge := issue(t, f, a)
	a.ceremonyType = "webauthn.create"

	err := f.Verify(context.Background(), challenge, responseFor(a, t, challenge.Nonce))
	requireVerificationFailed(t, err)
	if !strings.Contains(err.Error(), "webauthn.get") {
		t.Errorf("error %q does not name the expected ceremony type", err)
	}
}

func TestFIDO2Factor_Verify_RejectsMalformedClientData(t *testing.T) {
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	_, challenge := issue(t, f, a)
	resp := responseFor(a, t, challenge.Nonce)
	resp.Metadata["client_data"] = base64.StdEncoding.EncodeToString([]byte("not json"))

	requireVerificationFailed(t, f.Verify(context.Background(), challenge, resp))
}

func TestFIDO2Factor_Verify_RejectsMissingMetadata(t *testing.T) {
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	_, challenge := issue(t, f, a)

	requireVerificationFailed(t, f.Verify(context.Background(), challenge, &qrdbsdk.AuthFactorResponse{Metadata: map[string]string{}}))

	// authenticator_data present, client_data absent.
	resp := responseFor(a, t, challenge.Nonce)
	delete(resp.Metadata, "client_data")
	requireVerificationFailed(t, f.Verify(context.Background(), challenge, resp))
}

func TestFIDO2Factor_Verify_RejectsNilArgs(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	if err := f.Verify(ctx, nil, &qrdbsdk.AuthFactorResponse{}); !errors.As(err, &inv) {
		t.Fatalf("Verify(nil challenge) err = %v, want EnrollmentInvalidError", err)
	}
	if err := f.Verify(ctx, &qrdbsdk.AuthFactorChallenge{}, nil); !errors.As(err, &inv) {
		t.Fatalf("Verify(nil response) err = %v, want EnrollmentInvalidError", err)
	}
}

func TestFIDO2Factor_Challenge_RejectsNilEnrollment(t *testing.T) {
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	if _, err := New(Config{}).Challenge(context.Background(), nil); !errors.As(err, &inv) {
		t.Fatalf("Challenge(nil) err = %v, want EnrollmentInvalidError", err)
	}
}
