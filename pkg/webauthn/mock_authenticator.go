// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// MockAuthenticator simulates a WebAuthn authenticator for testing purposes.
// It generates valid attestation and assertion responses that can be validated
// by the WebAuthn service.
type MockAuthenticator struct {
	// AAGUID is the authenticator's unique identifier (16 bytes).
	AAGUID []byte

	// privateKey is the authenticator's signing key.
	privateKey *ecdsa.PrivateKey

	// CredentialID is the credential identifier.
	CredentialID []byte

	// SignCount is the current signature counter for clone detection.
	SignCount uint32

	// UserPresent indicates whether UP flag should be set.
	UserPresent bool

	// UserVerified indicates whether UV flag should be set.
	UserVerified bool

	// ResidentKey indicates if this is a resident/discoverable credential.
	ResidentKey bool

	// rpID is the Relying Party ID (usually the domain).
	rpID string

	// rpIDHash is the SHA-256 hash of the RP ID.
	rpIDHash []byte
}

// MockAuthenticatorOption is a functional option for configuring a MockAuthenticator.
type MockAuthenticatorOption func(*MockAuthenticator)

// WithAAGUID sets a custom AAGUID.
func WithAAGUID(aaguid []byte) MockAuthenticatorOption {
	return func(m *MockAuthenticator) {
		m.AAGUID = aaguid
	}
}

// WithCredentialID sets a custom credential ID.
func WithCredentialID(credID []byte) MockAuthenticatorOption {
	return func(m *MockAuthenticator) {
		m.CredentialID = credID
	}
}

// WithSignCount sets the initial sign count.
func WithSignCount(count uint32) MockAuthenticatorOption {
	return func(m *MockAuthenticator) {
		m.SignCount = count
	}
}

// WithUserPresent sets the UP flag.
func WithUserPresent(up bool) MockAuthenticatorOption {
	return func(m *MockAuthenticator) {
		m.UserPresent = up
	}
}

// WithUserVerified sets the UV flag.
func WithUserVerified(uv bool) MockAuthenticatorOption {
	return func(m *MockAuthenticator) {
		m.UserVerified = uv
	}
}

// WithResidentKey enables resident key mode.
func WithResidentKey(rk bool) MockAuthenticatorOption {
	return func(m *MockAuthenticator) {
		m.ResidentKey = rk
	}
}

// NewMockAuthenticator creates a new mock authenticator for testing.
func NewMockAuthenticator(rpID string, opts ...MockAuthenticatorOption) (*MockAuthenticator, error) {
	// Generate a new ECDSA key pair (P-256)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Generate random AAGUID (16 bytes)
	aaguid := make([]byte, 16)
	if _, err := rand.Read(aaguid); err != nil {
		return nil, err
	}

	// Generate random credential ID
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		return nil, err
	}

	// Compute RP ID hash
	rpIDHash := sha256.Sum256([]byte(rpID))

	m := &MockAuthenticator{
		AAGUID:       aaguid,
		privateKey:   privateKey,
		CredentialID: credID,
		SignCount:    0,
		UserPresent:  true,
		UserVerified: true,
		ResidentKey:  false,
		rpID:         rpID,
		rpIDHash:     rpIDHash[:],
	}

	for _, opt := range opts {
		opt(m)
	}

	return m, nil
}

// PublicKey returns the authenticator's public key.
func (m *MockAuthenticator) PublicKey() crypto.PublicKey {
	return m.privateKey.Public()
}

// PublicKeyBytes returns the public key in COSE format.
func (m *MockAuthenticator) PublicKeyBytes() ([]byte, error) {
	pubKey := m.privateKey.Public().(*ecdsa.PublicKey)

	// Create COSE key representation for ES256
	coseKey := map[int]interface{}{
		1:  2,                          // kty: EC2
		3:  int(webauthncose.AlgES256), // alg: ES256
		-1: 1,                          // crv: P-256
		-2: pubKey.X.Bytes(),           // x coordinate
		-3: pubKey.Y.Bytes(),           // y coordinate
	}

	return webauthncbor.Marshal(coseKey)
}

// IncrementSignCount increments and returns the new sign count.
func (m *MockAuthenticator) IncrementSignCount() uint32 {
	m.SignCount++
	return m.SignCount
}

// SetSignCount sets the sign count to a specific value (useful for testing clone detection).
func (m *MockAuthenticator) SetSignCount(count uint32) {
	m.SignCount = count
}

// CreateAttestationObject creates a valid attestation object for registration.
// This simulates what a real authenticator would return.
func (m *MockAuthenticator) CreateAttestationObject(
	challenge []byte,
	userID []byte,
	origin string,
) (*protocol.ParsedCredentialCreationData, error) {
	// Build authenticator data
	authData, err := m.buildAuthenticatorData(true, userID)
	if err != nil {
		return nil, err
	}

	// Compute client data JSON (for the response)
	clientDataJSON := m.buildClientDataJSON(challenge, origin, "webauthn.create")

	// For "none" attestation format, we don't include a signature.
	// The signature is only needed for attestation types like "packed" or "fido-u2f".

	// Build attestation object with "none" attestation (most common)
	attestationObject := map[string]interface{}{
		"authData": authData,
		"fmt":      "none",
		"attStmt":  map[string]interface{}{},
	}

	attestationObjectBytes, err := webauthncbor.Marshal(attestationObject)
	if err != nil {
		return nil, err
	}

	// Get public key in COSE format
	pubKeyBytes, err := m.PublicKeyBytes()
	if err != nil {
		return nil, err
	}

	// Parse the attestation object to get AuthData
	parsedAttObj := protocol.AttestationObject{
		Format:       "none",
		AttStatement: map[string]interface{}{},
	}

	// Build the parsed authenticator data
	parsedAuthData := protocol.AuthenticatorData{
		RPIDHash: m.rpIDHash,
		Flags:    m.buildFlags(true),
		Counter:  m.SignCount,
		AttData: protocol.AttestedCredentialData{
			AAGUID:              m.AAGUID,
			CredentialID:        m.CredentialID,
			CredentialPublicKey: pubKeyBytes,
		},
	}
	parsedAttObj.AuthData = parsedAuthData

	// Build parsed credential creation data
	credentialIDBase64 := base64.RawURLEncoding.EncodeToString(m.CredentialID)

	return &protocol.ParsedCredentialCreationData{
		ParsedPublicKeyCredential: protocol.ParsedPublicKeyCredential{
			ParsedCredential: protocol.ParsedCredential{
				ID:   credentialIDBase64,
				Type: "public-key",
			},
			RawID:                  m.CredentialID,
			ClientExtensionResults: protocol.AuthenticationExtensionsClientOutputs{},
		},
		Response: protocol.ParsedAttestationResponse{
			CollectedClientData: protocol.CollectedClientData{
				Type:      "webauthn.create",
				Challenge: base64.RawURLEncoding.EncodeToString(challenge),
				Origin:    origin,
			},
			AttestationObject: parsedAttObj,
			Transports:        []protocol.AuthenticatorTransport{protocol.USB},
		},
		Raw: protocol.CredentialCreationResponse{
			PublicKeyCredential: protocol.PublicKeyCredential{
				Credential: protocol.Credential{
					ID:   credentialIDBase64,
					Type: "public-key",
				},
				RawID:                  m.CredentialID,
				ClientExtensionResults: protocol.AuthenticationExtensionsClientOutputs{},
			},
			AttestationResponse: protocol.AuthenticatorAttestationResponse{
				AuthenticatorResponse: protocol.AuthenticatorResponse{
					ClientDataJSON: clientDataJSON,
				},
				AttestationObject: attestationObjectBytes,
				Transports:        []string{"usb"},
			},
		},
	}, nil
}

// CreateAssertionResponse creates a valid assertion response for authentication.
func (m *MockAuthenticator) CreateAssertionResponse(
	challenge []byte,
	userHandle []byte,
	origin string,
) (*protocol.ParsedCredentialAssertionData, error) {
	// Increment sign count for each authentication
	m.IncrementSignCount()

	// Build authenticator data (without attested credential data)
	authData, err := m.buildAuthenticatorData(false, nil)
	if err != nil {
		return nil, err
	}

	// Compute client data hash
	clientDataJSON := m.buildClientDataJSON(challenge, origin, "webauthn.get")
	clientDataHash := sha256.Sum256(clientDataJSON)

	// Create signature over authData || clientDataHash
	signedData := append(authData, clientDataHash[:]...)
	signature, err := m.sign(signedData)
	if err != nil {
		return nil, err
	}

	// Build parsed authenticator data
	parsedAuthData := protocol.AuthenticatorData{
		RPIDHash: m.rpIDHash,
		Flags:    m.buildFlags(false),
		Counter:  m.SignCount,
	}

	credentialIDBase64 := base64.RawURLEncoding.EncodeToString(m.CredentialID)

	return &protocol.ParsedCredentialAssertionData{
		ParsedPublicKeyCredential: protocol.ParsedPublicKeyCredential{
			ParsedCredential: protocol.ParsedCredential{
				ID:   credentialIDBase64,
				Type: "public-key",
			},
			RawID:                  m.CredentialID,
			ClientExtensionResults: protocol.AuthenticationExtensionsClientOutputs{},
		},
		Response: protocol.ParsedAssertionResponse{
			CollectedClientData: protocol.CollectedClientData{
				Type:      "webauthn.get",
				Challenge: base64.RawURLEncoding.EncodeToString(challenge),
				Origin:    origin,
			},
			AuthenticatorData: parsedAuthData,
			Signature:         signature,
			UserHandle:        userHandle,
		},
		Raw: protocol.CredentialAssertionResponse{
			PublicKeyCredential: protocol.PublicKeyCredential{
				Credential: protocol.Credential{
					ID:   credentialIDBase64,
					Type: "public-key",
				},
				RawID:                  m.CredentialID,
				ClientExtensionResults: protocol.AuthenticationExtensionsClientOutputs{},
			},
			AssertionResponse: protocol.AuthenticatorAssertionResponse{
				AuthenticatorResponse: protocol.AuthenticatorResponse{
					ClientDataJSON: clientDataJSON,
				},
				AuthenticatorData: authData,
				Signature:         signature,
				UserHandle:        userHandle,
			},
		},
	}, nil
}

// buildFlags builds the authenticator flags byte.
func (m *MockAuthenticator) buildFlags(includeCredential bool) protocol.AuthenticatorFlags {
	var flags byte
	if m.UserPresent {
		flags |= 0x01 // UP
	}
	if m.UserVerified {
		flags |= 0x04 // UV
	}
	if includeCredential {
		flags |= 0x40 // AT (attested credential data present)
	}
	return protocol.AuthenticatorFlags(flags)
}

// buildAuthenticatorData builds the authenticator data structure.
// If includeCredential is true, includes attested credential data (for registration).
func (m *MockAuthenticator) buildAuthenticatorData(includeCredential bool, userID []byte) ([]byte, error) {
	var buf bytes.Buffer

	// rpIdHash (32 bytes)
	buf.Write(m.rpIDHash)

	// flags (1 byte)
	buf.WriteByte(byte(m.buildFlags(includeCredential)))

	// signCount (4 bytes, big-endian)
	signCountBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(signCountBytes, m.SignCount)
	buf.Write(signCountBytes)

	// Attested credential data (only for registration)
	if includeCredential {
		// AAGUID (16 bytes)
		buf.Write(m.AAGUID)

		// Credential ID length (2 bytes, big-endian)
		credIDLen := make([]byte, 2)
		binary.BigEndian.PutUint16(credIDLen, uint16(len(m.CredentialID)))
		buf.Write(credIDLen)

		// Credential ID
		buf.Write(m.CredentialID)

		// Credential public key (COSE format)
		pubKeyBytes, err := m.PublicKeyBytes()
		if err != nil {
			return nil, err
		}
		buf.Write(pubKeyBytes)
	}

	return buf.Bytes(), nil
}

// buildClientDataJSON builds the client data JSON structure.
func (m *MockAuthenticator) buildClientDataJSON(challenge []byte, origin, credType string) []byte {
	clientData := struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}{
		Type:      credType,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Origin:    origin,
	}

	jsonBytes, _ := json.Marshal(clientData)
	return jsonBytes
}

// sign creates an ECDSA signature over the data.
func (m *MockAuthenticator) sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, m.privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	// Encode as ASN.1 DER signature (required by WebAuthn)
	return asn1MarshalSignature(r, s)
}

// asn1MarshalSignature encodes r and s as an ASN.1 DER signature.
func asn1MarshalSignature(r, s *big.Int) ([]byte, error) {
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Ensure leading zero for negative-looking values
	if len(rBytes) > 0 && rBytes[0] >= 0x80 {
		rBytes = append([]byte{0x00}, rBytes...)
	}
	if len(sBytes) > 0 && sBytes[0] >= 0x80 {
		sBytes = append([]byte{0x00}, sBytes...)
	}

	// ASN.1 SEQUENCE containing two INTEGERs
	rLen := len(rBytes)
	sLen := len(sBytes)
	seqLen := 2 + rLen + 2 + sLen

	sig := make([]byte, 0, 2+seqLen)
	sig = append(sig, 0x30)         // SEQUENCE tag
	sig = append(sig, byte(seqLen)) // SEQUENCE length
	sig = append(sig, 0x02)         // INTEGER tag (r)
	sig = append(sig, byte(rLen))   // r length
	sig = append(sig, rBytes...)    // r value
	sig = append(sig, 0x02)         // INTEGER tag (s)
	sig = append(sig, byte(sLen))   // s length
	sig = append(sig, sBytes...)    // s value

	return sig, nil
}
