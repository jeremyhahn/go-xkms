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
}

func newAuthenticator(t *testing.T, rpID string) *authenticator {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	h := sha256.Sum256([]byte(rpID))
	return &authenticator{priv: priv, rpID: rpID, rpIDHsh: h[:]}
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
	out = append(out, 0x05) // UP + UV
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
		Type:      "webauthn.get",
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Origin:    "https://" + a.rpID,
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
	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("rand credID: %v", err)
	}
	enrollment, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID: "custodian-1",
		MethodParams: map[string]any{
			"cose_public_key": base64.StdEncoding.EncodeToString(a.coseKey(t)),
			"credential_id":   base64.RawURLEncoding.EncodeToString(credID),
			"rp_id":           a.rpID,
		},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return enrollment
}

func responseFor(a *authenticator, t *testing.T, enrollment *qrdbsdk.AuthFactorEnrollment, challenge *qrdbsdk.AuthFactorChallenge) *qrdbsdk.AuthFactorResponse {
	authData, clientData, sig := a.assert(t, challenge.Nonce)
	return &qrdbsdk.AuthFactorResponse{
		Value: sig,
		Metadata: map[string]string{
			"authenticator_data": base64.StdEncoding.EncodeToString(authData),
			"client_data":        base64.StdEncoding.EncodeToString(clientData),
			"cose_public_key":    base64.StdEncoding.EncodeToString(enrollment.PublicKey),
		},
	}
}

func TestFIDO2Factor_Name(t *testing.T) {
	if got := New(Config{}).Name(); got != FactorName {
		t.Fatalf("Name() = %q, want %q", got, FactorName)
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
	if enrollment.Metadata["public_key_hash"] == "" {
		t.Fatal("public_key_hash missing")
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

	if err := f.Verify(ctx, challenge, responseFor(a, t, enrollment, challenge)); err != nil {
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
	enrollment := enroll(t, f, a)
	challenge, _ := f.Challenge(ctx, enrollment)
	resp := responseFor(a, t, enrollment, challenge)
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
	enrollment := enroll(t, f, a)
	challenge, _ := f.Challenge(ctx, enrollment)
	resp := responseFor(a, t, enrollment, challenge)
	resp.Value[len(resp.Value)-1] ^= 0xFF

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if err := f.Verify(ctx, challenge, resp); !errors.As(err, &failed) {
		t.Fatalf("Verify(tampered sig) err = %v, want VerificationFailedError", err)
	}
}

func TestFIDO2Factor_Verify_RejectsWrongChallengeBinding(t *testing.T) {
	ctx := context.Background()
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	enrollment := enroll(t, f, a)
	challenge, _ := f.Challenge(ctx, enrollment)

	// Build an assertion bound to a DIFFERENT challenge nonce; signature is
	// valid but does not bind the issued challenge.
	otherNonce := make([]byte, challengeLength)
	if _, err := rand.Read(otherNonce); err != nil {
		t.Fatalf("rand: %v", err)
	}
	authData, clientData, sig := a.assert(t, otherNonce)
	resp := &qrdbsdk.AuthFactorResponse{
		Value: sig,
		Metadata: map[string]string{
			"authenticator_data": base64.StdEncoding.EncodeToString(authData),
			"client_data":        base64.StdEncoding.EncodeToString(clientData),
			"cose_public_key":    base64.StdEncoding.EncodeToString(enrollment.PublicKey),
		},
	}

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if err := f.Verify(ctx, challenge, resp); !errors.As(err, &failed) {
		t.Fatalf("Verify(wrong challenge) err = %v, want VerificationFailedError", err)
	}
}

func TestFIDO2Factor_Verify_RejectsWrongKey(t *testing.T) {
	ctx := context.Background()
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	other := newAuthenticator(t, "example.com")
	enrollment := enroll(t, f, a)
	challenge, _ := f.Challenge(ctx, enrollment)

	// Assertion signed by a different key than the enrolled one.
	authData, clientData, sig := other.assert(t, challenge.Nonce)
	resp := &qrdbsdk.AuthFactorResponse{
		Value: sig,
		Metadata: map[string]string{
			"authenticator_data": base64.StdEncoding.EncodeToString(authData),
			"client_data":        base64.StdEncoding.EncodeToString(clientData),
			"cose_public_key":    base64.StdEncoding.EncodeToString(enrollment.PublicKey),
		},
	}

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if err := f.Verify(ctx, challenge, resp); !errors.As(err, &failed) {
		t.Fatalf("Verify(wrong key) err = %v, want VerificationFailedError", err)
	}
}

func TestFIDO2Factor_Verify_RejectsMissingMetadata(t *testing.T) {
	ctx := context.Background()
	f := New(Config{RPID: "example.com"})
	a := newAuthenticator(t, "example.com")
	enrollment := enroll(t, f, a)
	challenge, _ := f.Challenge(ctx, enrollment)

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Metadata: map[string]string{}}); !errors.As(err, &failed) {
		t.Fatalf("Verify(no metadata) err = %v, want VerificationFailedError", err)
	}
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
