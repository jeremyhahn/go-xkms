// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
)

// buildCOSEES256Key builds a CBOR-encoded COSE_Key for an ES256 (P-256) public
// key using the canonical COSE label layout the WebAuthn parser expects:
//
//	1 (kty)  = 2 (EC2)
//	3 (alg)  = -7 (ES256)
//	-1 (crv) = 1 (P-256)
//	-2 (x)   = 32-byte X coordinate
//	-3 (y)   = 32-byte Y coordinate
func buildCOSEES256Key(t *testing.T) []byte {
	t.Helper()

	// Generate a real P-256 point so X/Y are valid curve coordinates. Derive the
	// uncompressed point via crypto/ecdh rather than the deprecated
	// elliptic.GenerateKey / ecdsa coordinate big.Int fields.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	ecdhPub, err := priv.PublicKey.ECDH()
	if err != nil {
		t.Fatalf("convert public key to ecdh: %v", err)
	}
	point := ecdhPub.Bytes() // 0x04 || X(32) || Y(32)
	xb := point[1:33]
	yb := point[33:65]

	coseKey := map[int]interface{}{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: xb, // x
		-3: yb, // y
	}

	encMode, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatalf("cbor enc mode: %v", err)
	}
	encoded, err := encMode.Marshal(coseKey)
	if err != nil {
		t.Fatalf("marshal COSE key: %v", err)
	}
	return encoded
}

// buildSyntheticAuthData hand-builds WebAuthn authenticator data containing
// attested credential data with the given credential id and COSE public key.
//
//	rpIdHash[32] | flags[1] | signCount[4] | aaguid[16] | credIdLen[2] | credId | coseKey
func buildSyntheticAuthData(t *testing.T, credID, coseKey []byte) []byte {
	t.Helper()

	authData := make([]byte, 0, 37+16+2+len(credID)+len(coseKey))

	// rpIdHash: 32 bytes (arbitrary but fixed).
	rpIDHash := make([]byte, 32)
	for i := range rpIDHash {
		rpIDHash[i] = byte(i)
	}
	authData = append(authData, rpIDHash...)

	// flags: UP (0x01) + UV (0x04) + AT (0x40) set.
	authData = append(authData, 0x01|0x04|0x40)

	// signCount: 4 bytes.
	signCount := make([]byte, 4)
	binary.BigEndian.PutUint32(signCount, 1)
	authData = append(authData, signCount...)

	// aaguid: 16 bytes (all zero — valid for fmt "none").
	authData = append(authData, make([]byte, 16)...)

	// credIdLen: 2 bytes big-endian.
	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(credID)))
	authData = append(authData, credIDLen...)

	// credId.
	authData = append(authData, credID...)

	// credentialPublicKey (CBOR COSE_Key).
	authData = append(authData, coseKey...)

	return authData
}

// syntheticMakeCredentialResponse returns a well-formed "none"-format
// MakeCredentialResponse with the supplied credential id.
func syntheticMakeCredentialResponse(t *testing.T, credID []byte) *MakeCredentialResponse {
	t.Helper()
	coseKey := buildCOSEES256Key(t)
	return &MakeCredentialResponse{
		Fmt:      "none",
		AuthData: buildSyntheticAuthData(t, credID, coseKey),
		AttStmt:  map[string]interface{}{},
	}
}

// TestBuildWebAuthnAttestationParsesViaServerParser proves the generated
// PublicKeyCredential JSON is server-acceptable: it parses with no error via
// protocol.ParseCredentialCreationResponseBody (the exact parser
// XKMSService.FinishRegistration uses) and the parsed RawID matches the input
// credential id.
func TestBuildWebAuthnAttestationParsesViaServerParser(t *testing.T) {
	credID := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	challenge := make([]byte, 32)
	for i := range challenge {
		challenge[i] = byte(0x80 + i)
	}
	origin := "https://login.example.com"

	resp := syntheticMakeCredentialResponse(t, credID)

	att, err := buildWebAuthnAttestation(resp, challenge, origin)
	if err != nil {
		t.Fatalf("buildWebAuthnAttestation: %v", err)
	}

	if !bytes.Equal(att.CredentialID, credID) {
		t.Fatalf("extracted credential id mismatch: got %x want %x", att.CredentialID, credID)
	}

	// The decisive assertion: the server's parser must accept the JSON.
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(att.PublicKeyCredentialJSON))
	if err != nil {
		t.Fatalf("ParseCredentialCreationResponseBody rejected attestation: %v", err)
	}

	// RawID in the parsed credential must equal our input credential id.
	if !bytes.Equal(parsed.RawID, credID) {
		t.Fatalf("parsed RawID mismatch: got %x want %x", []byte(parsed.RawID), credID)
	}

	// The parsed attestation format must round-trip as "none".
	if parsed.Response.AttestationObject.Format != "none" {
		t.Fatalf("parsed attestation format: got %q want %q",
			parsed.Response.AttestationObject.Format, "none")
	}

	// The parsed credential id (base64url) must equal our encoding.
	wantID := base64.RawURLEncoding.EncodeToString(credID)
	if parsed.ID != wantID {
		t.Fatalf("parsed credential ID mismatch: got %q want %q", parsed.ID, wantID)
	}
}

// TestBuildClientDataJSONShape verifies the clientDataJSON has the correct
// WebAuthn registration shape: type "webauthn.create", base64url(challenge)
// with no padding, and the supplied origin.
func TestBuildClientDataJSONShape(t *testing.T) {
	challenge := []byte("a-non-multiple-of-3-challenge!!")
	origin := "https://rp.example.org"

	raw, err := buildClientDataJSON(challenge, origin)
	if err != nil {
		t.Fatalf("buildClientDataJSON: %v", err)
	}

	var cd collectedClientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		t.Fatalf("unmarshal clientDataJSON: %v", err)
	}

	if cd.Type != "webauthn.create" {
		t.Errorf("type: got %q want %q", cd.Type, "webauthn.create")
	}
	if cd.Origin != origin {
		t.Errorf("origin: got %q want %q", cd.Origin, origin)
	}

	wantChallenge := base64.RawURLEncoding.EncodeToString(challenge)
	if cd.Challenge != wantChallenge {
		t.Errorf("challenge: got %q want %q", cd.Challenge, wantChallenge)
	}

	// Decoding the challenge field must reproduce the original bytes.
	decoded, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	if !bytes.Equal(decoded, challenge) {
		t.Errorf("decoded challenge mismatch: got %x want %x", decoded, challenge)
	}
}

// TestExtractCredentialID verifies credential id extraction against the
// authData layout, including a multi-byte length and offset arithmetic.
func TestExtractCredentialID(t *testing.T) {
	credID := bytes.Repeat([]byte{0xAB}, 64) // forces credIdLen high byte = 0x00, low = 0x40
	coseKey := buildCOSEES256Key(t)
	authData := buildSyntheticAuthData(t, credID, coseKey)

	got, err := extractCredentialID(authData)
	if err != nil {
		t.Fatalf("extractCredentialID: %v", err)
	}
	if !bytes.Equal(got, credID) {
		t.Fatalf("credential id mismatch: got %x want %x", got, credID)
	}
}

// TestExtractCredentialIDErrors verifies error handling for malformed authData:
// too-short buffers, a missing AT flag, and a truncated credential id.
func TestExtractCredentialIDErrors(t *testing.T) {
	// Too short (< 37 bytes).
	if _, err := extractCredentialID(make([]byte, 10)); err == nil {
		t.Error("expected error for too-short authData")
	}

	// AT flag unset: 37-byte header with flags=0.
	noAT := make([]byte, 37)
	noAT[32] = 0x01 // UP only, no AT
	if _, err := extractCredentialID(noAT); err == nil {
		t.Error("expected error when AT flag unset")
	}

	// AT flag set but credential id length exceeds buffer.
	truncated := make([]byte, 37+16+2)
	truncated[32] = 0x40                                  // AT flag set
	binary.BigEndian.PutUint16(truncated[37+16:], 0x00FF) // claims 255 bytes
	if _, err := extractCredentialID(truncated); err == nil {
		t.Error("expected error for truncated credential id")
	}
}

// TestEncodeAttestationObjectErrors verifies error handling for nil and
// empty-authData responses.
func TestEncodeAttestationObjectErrors(t *testing.T) {
	if _, err := encodeAttestationObject(nil); err == nil {
		t.Error("expected error for nil response")
	}
	if _, err := encodeAttestationObject(&MakeCredentialResponse{Fmt: "none"}); err == nil {
		t.Error("expected error for empty authData")
	}
}

// TestEncodeAttestationObjectRoundTrip verifies the encoded attestationObject is
// a CBOR map carrying the three WebAuthn fields with their original values.
func TestEncodeAttestationObjectRoundTrip(t *testing.T) {
	credID := []byte{0x01, 0x02, 0x03, 0x04}
	resp := syntheticMakeCredentialResponse(t, credID)

	encoded, err := encodeAttestationObject(resp)
	if err != nil {
		t.Fatalf("encodeAttestationObject: %v", err)
	}

	var decoded struct {
		Fmt      string                 `cbor:"fmt"`
		AttStmt  map[string]interface{} `cbor:"attStmt"`
		AuthData []byte                 `cbor:"authData"`
	}
	if err := cbor.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("cbor unmarshal attestationObject: %v", err)
	}

	if decoded.Fmt != "none" {
		t.Errorf("fmt: got %q want %q", decoded.Fmt, "none")
	}
	if !bytes.Equal(decoded.AuthData, resp.AuthData) {
		t.Errorf("authData round-trip mismatch")
	}
}

// newPINProtectedHandler builds a handler over a single mock authenticator
// whose simulator enforces pin, mirroring a security key with a PIN set. Both
// ceremonies use it: the simulator enforces the PIN on MakeCredential and on
// GetAssertion alike, exactly as a real key does.
func newPINProtectedHandler(t *testing.T, pin string) *FIDO2Handler {
	t.Helper()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	mockDev.sim.pin = pin

	enum := NewMockHIDDeviceEnumerator()
	enum.AddDevice(mockDev)

	config := DefaultConfig
	handler, err := NewHandler(&config, enum)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return handler
}

// pinRegistrationOptions is a minimal registration ceremony for a
// PIN-protected authenticator.
func pinRegistrationOptions(t *testing.T, pin string) WebAuthnRegistrationOptions {
	t.Helper()

	return WebAuthnRegistrationOptions{
		Challenge:       []byte("registration-challenge"),
		Origin:          "https://xkms.example.com",
		RPID:            "xkms.example.com",
		RPName:          "xkms",
		UserID:          []byte("user-handle"),
		UserName:        "administrator",
		UserDisplayName: "administrator",
		// A PIN-protected key has no built-in user verification method, so
		// this must NOT reach the wire as the "uv" option once a PIN is
		// supplied — the simulator rejects that combination outright.
		RequireUserVerification: true,
		PIN:                     testSecret(t, pin),
	}
}

func TestRegisterWebAuthnWithPIN(t *testing.T) {
	handler := newPINProtectedHandler(t, "123456")

	attestation, err := handler.RegisterWebAuthn(pinRegistrationOptions(t, "123456"))
	if err != nil {
		t.Fatalf("RegisterWebAuthn with PIN: %v", err)
	}
	if len(attestation.CredentialID) == 0 {
		t.Fatal("attestation carries no credential id")
	}

	// The credential must survive the same parser the browser path uses.
	if _, err := protocol.ParseCredentialCreationResponseBody(
		bytes.NewReader(attestation.PublicKeyCredentialJSON),
	); err != nil {
		t.Fatalf("server-side parse of the enrolled credential: %v", err)
	}
}

func TestRegisterWebAuthnPINErrors(t *testing.T) {
	t.Run("PIN-protected key refuses an unauthorized request", func(t *testing.T) {
		handler := newPINProtectedHandler(t, "123456")

		// No PIN supplied: this is the failure the init ceremony hit before the
		// PIN was threaded through, and it must stay legible. The "uv" option
		// is off here so the refusal is unambiguously about the missing
		// pinUvAuthParam rather than about asking a PIN-only key for built-in
		// user verification.
		opts := pinRegistrationOptions(t, "")
		opts.RequireUserVerification = false

		attestation, err := handler.RegisterWebAuthn(opts)
		if attestation != nil {
			t.Fatal("an unauthorized request must not yield a credential")
		}
		if !errors.Is(err, ErrPINRequired) {
			t.Fatalf("want ErrPINRequired, got %v", err)
		}
	})

	t.Run("wrong PIN is not reported as a refusal", func(t *testing.T) {
		handler := newPINProtectedHandler(t, "123456")

		attestation, err := handler.RegisterWebAuthn(pinRegistrationOptions(t, "999999"))
		if attestation != nil {
			t.Fatal("a wrong PIN must not yield a credential")
		}
		if !errors.Is(err, ErrInvalidPIN) {
			t.Fatalf("want ErrInvalidPIN, got %v", err)
		}
	})

	t.Run("a key with no PIN ignores a supplied one", func(t *testing.T) {
		handler := newPINProtectedHandler(t, "")

		// GetPINToken against a key with no PIN set is an error rather than a
		// silent success, so the operator learns the PIN was pointless instead
		// of enrolling a credential that verification will not match.
		attestation, err := handler.RegisterWebAuthn(pinRegistrationOptions(t, "123456"))
		if attestation != nil {
			t.Fatal("expected no credential")
		}
		if !errors.Is(err, ErrPINNotSet) {
			t.Fatalf("want ErrPINNotSet, got %v", err)
		}
	})
}
