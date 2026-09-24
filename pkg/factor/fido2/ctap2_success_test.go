// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package fido2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"

	pkgfido2 "github.com/jeremyhahn/go-xkms/pkg/fido2"
)

// buildTestCOSEKey builds a CBOR-encoded ES256 COSE_Key over a fresh P-256
// key, using the canonical COSE label layout the WebAuthn parser expects.
func buildTestCOSEKey(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	ecdhPub, err := priv.PublicKey.ECDH()
	if err != nil {
		t.Fatalf("convert public key to ecdh: %v", err)
	}
	point := ecdhPub.Bytes() // 0x04 || X(32) || Y(32)
	coseKey := map[int]interface{}{
		1:  2,            // kty: EC2
		3:  -7,           // alg: ES256
		-1: 1,            // crv: P-256
		-2: point[1:33],  // x
		-3: point[33:65], // y
	}
	encoded, err := webauthncbor.Marshal(coseKey)
	if err != nil {
		t.Fatalf("marshal COSE key: %v", err)
	}
	return encoded
}

// buildTestAuthData hand-builds WebAuthn authenticator data carrying
// attested credential data, matching the layout
// pkg/fido2's buildSyntheticAuthData exercises against the real server
// parser: rpIdHash[32] | flags[1] | signCount[4] | aaguid[16] | credIdLen[2]
// | credId | coseKey.
func buildTestAuthData(credID, coseKey []byte) []byte {
	authData := make([]byte, 0, 37+16+2+len(credID)+len(coseKey))
	authData = append(authData, make([]byte, 32)...) // rpIdHash (arbitrary)
	authData = append(authData, 0x01|0x04|0x40)      // UP | UV | AT
	signCount := make([]byte, 4)
	binary.BigEndian.PutUint32(signCount, 1)
	authData = append(authData, signCount...)
	authData = append(authData, make([]byte, 16)...) // aaguid (zero)
	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(credID)))
	authData = append(authData, credIDLen...)
	authData = append(authData, credID...)
	authData = append(authData, coseKey...)
	return authData
}

// buildTestAttestation assembles a real, server-parseable
// *pkgfido2.WebAuthnAttestation — the same document shape
// protocol.ParseCredentialCreationResponseBody (credentialFromAttestation's
// parser) accepts from a browser — so LocalCeremony.Enroll's success path
// can be exercised without an attached authenticator or a stubbed failure.
func buildTestAttestation(t *testing.T, credID []byte, challenge []byte, origin string) *pkgfido2.WebAuthnAttestation {
	t.Helper()
	coseKey := buildTestCOSEKey(t)
	authData := buildTestAuthData(credID, coseKey)

	attObj := map[string]interface{}{
		"fmt":      "none",
		"attStmt":  map[string]interface{}{},
		"authData": authData,
	}
	attObjBytes, err := webauthncbor.Marshal(attObj)
	if err != nil {
		t.Fatalf("marshal attestation object: %v", err)
	}

	clientData, err := json.Marshal(map[string]string{
		"type":      "webauthn.create",
		"challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"origin":    origin,
	})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}

	credIDB64 := base64.RawURLEncoding.EncodeToString(credID)
	doc, err := json.Marshal(map[string]interface{}{
		"id":    credIDB64,
		"rawId": credIDB64,
		"type":  "public-key",
		"response": map[string]string{
			"attestationObject": base64.RawURLEncoding.EncodeToString(attObjBytes),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
		},
	})
	if err != nil {
		t.Fatalf("marshal PublicKeyCredential JSON: %v", err)
	}

	return &pkgfido2.WebAuthnAttestation{CredentialID: credID, PublicKeyCredentialJSON: doc}
}

// TestLocalCeremony_Enroll_Success drives the full happy path: a real,
// parseable attestation is returned by the (fake) authenticator ceremony,
// so credentialFromAttestation succeeds and Enroll assembles the
// MethodParams a real init-time passkey enrollment would produce.
func TestLocalCeremony_Enroll_Success(t *testing.T) {
	credID := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	req := localRequest()
	att := buildTestAttestation(t, credID, req.Challenge, "https://"+req.RPID)
	ceremony := &fakeCeremony{}
	ceremony.attestation = att

	c := newLocalCeremony(&fakeDevices{devices: []pkgfido2.Device{yubi("1")}}, ceremony, 0)

	result, err := c.Enroll(context.Background(), req)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if string(result.CredentialID) != string(credID) {
		t.Fatalf("CredentialID = %v, want %v", result.CredentialID, credID)
	}
	if result.Device == "" {
		t.Error("Device must describe the authenticator used")
	}
	if result.MethodParams["rp_id"] != req.RPID {
		t.Errorf("rp_id = %v, want %v", result.MethodParams["rp_id"], req.RPID)
	}
	wantCredID := base64.RawURLEncoding.EncodeToString(credID)
	if result.MethodParams["credential_id"] != wantCredID {
		t.Errorf("credential_id = %v, want %v", result.MethodParams["credential_id"], wantCredID)
	}
	if _, ok := result.MethodParams["cose_public_key"]; !ok {
		t.Error("MethodParams missing cose_public_key")
	}
	// The attested credential data always carries a 16-byte AAGUID slot (even
	// when it is all-zero, as here), so Enroll's len(aaguid) > 0 guard must
	// include it rather than omit it.
	wantAAGUID := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	if result.MethodParams["aaguid"] != wantAAGUID {
		t.Errorf("aaguid = %v, want %v", result.MethodParams["aaguid"], wantAAGUID)
	}
}
