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

package authenticator

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// AuthenticatorData layout constants
const (
	rpIDHashLen       = 32 // SHA-256 hash length
	flagsLen          = 1
	signCountLen      = 4
	aaguidLen         = 16
	credIDLenFieldLen = 2

	// Minimum authenticator data length (rpIdHash + flags + signCount)
	minAuthDataLen = rpIDHashLen + flagsLen + signCountLen
)

// Typed errors for authenticator data operations
var (
	ErrAuthDataTooShort       = errors.New("authenticator: data too short")
	ErrAuthDataInvalidRPID    = errors.New("authenticator: invalid RP ID")
	ErrAuthDataInvalidAAGUID  = errors.New("authenticator: invalid AAGUID length")
	ErrAuthDataCredIDTooLong  = errors.New("authenticator: credential ID exceeds maximum length")
	ErrAuthDataInvalidCredLen = errors.New("authenticator: invalid credential ID length")
	ErrAuthDataNoPublicKey    = errors.New("authenticator: missing public key")
	ErrAuthDataCBORDecode     = errors.New("authenticator: failed to decode CBOR")
	ErrAuthDataCBOREncode     = errors.New("authenticator: failed to encode CBOR")
	ErrAuthDataTruncated      = errors.New("authenticator: data truncated")
)

// AuthDataFlags represents authenticator data flags per CTAP2/WebAuthn spec.
type AuthDataFlags uint8

const (
	// FlagUP indicates User Present (bit 0).
	FlagUP AuthDataFlags = 0x01

	// FlagUV indicates User Verified (bit 2).
	FlagUV AuthDataFlags = 0x04

	// FlagBE indicates Backup Eligible (bit 3).
	FlagBE AuthDataFlags = 0x08

	// FlagBS indicates Backup State (bit 4).
	FlagBS AuthDataFlags = 0x10

	// FlagAT indicates Attested Credential Data included (bit 6).
	FlagAT AuthDataFlags = 0x40

	// FlagED indicates Extension Data included (bit 7).
	FlagED AuthDataFlags = 0x80
)

// Has returns true if the flag is set.
func (f AuthDataFlags) Has(flag AuthDataFlags) bool {
	return f&flag != 0
}

// String returns a human-readable representation of the flags.
func (f AuthDataFlags) String() string {
	var buf bytes.Buffer
	buf.WriteString("AuthDataFlags{")
	first := true
	writeFlag := func(name string) {
		if !first {
			buf.WriteString(", ")
		}
		buf.WriteString(name)
		first = false
	}
	if f.Has(FlagUP) {
		writeFlag("UP")
	}
	if f.Has(FlagUV) {
		writeFlag("UV")
	}
	if f.Has(FlagBE) {
		writeFlag("BE")
	}
	if f.Has(FlagBS) {
		writeFlag("BS")
	}
	if f.Has(FlagAT) {
		writeFlag("AT")
	}
	if f.Has(FlagED) {
		writeFlag("ED")
	}
	buf.WriteString("}")
	return buf.String()
}

// AuthenticatorData represents parsed authenticator data per CTAP2/WebAuthn spec.
type AuthenticatorData struct {
	// RPIDHash is the SHA-256 hash of the RP ID (32 bytes).
	RPIDHash []byte

	// Flags contains the authenticator data flags.
	Flags AuthDataFlags

	// SignCount is the signature counter.
	SignCount uint32

	// AAGUID is the authenticator attestation GUID (16 bytes).
	// Present only if AT flag is set.
	AAGUID []byte

	// CredentialID is the credential identifier.
	// Present only if AT flag is set.
	CredentialID []byte

	// PublicKey is the COSE-encoded credential public key.
	// Present only if AT flag is set.
	PublicKey []byte

	// Extensions contains the extension data.
	// Present only if ED flag is set.
	Extensions map[string]interface{}
}

// HasAttestedCredentialData returns true if attested credential data is present.
func (a *AuthenticatorData) HasAttestedCredentialData() bool {
	return a.Flags.Has(FlagAT)
}

// HasExtensions returns true if extension data is present.
func (a *AuthenticatorData) HasExtensions() bool {
	return a.Flags.Has(FlagED)
}

// UserPresent returns true if user presence was verified.
func (a *AuthenticatorData) UserPresent() bool {
	return a.Flags.Has(FlagUP)
}

// UserVerified returns true if user verification was performed.
func (a *AuthenticatorData) UserVerified() bool {
	return a.Flags.Has(FlagUV)
}

// BackupEligible returns true if the credential is backup eligible.
func (a *AuthenticatorData) BackupEligible() bool {
	return a.Flags.Has(FlagBE)
}

// BackupState returns true if the credential is currently backed up.
func (a *AuthenticatorData) BackupState() bool {
	return a.Flags.Has(FlagBS)
}

// AuthDataBuilder builds authenticator data according to CTAP2/WebAuthn spec.
type AuthDataBuilder struct {
	rpID         string
	flags        AuthDataFlags
	signCount    uint32
	aaguid       [16]byte
	credentialID []byte
	publicKey    []byte
	extensions   map[string]interface{}
	hasAttested  bool
}

// NewAuthDataBuilder creates a new authenticator data builder for the given RP ID.
func NewAuthDataBuilder(rpID string) *AuthDataBuilder {
	return &AuthDataBuilder{
		rpID:       rpID,
		extensions: make(map[string]interface{}),
	}
}

// WithFlags sets the authenticator data flags.
// Note: AT and ED flags are set automatically based on attested credential data
// and extensions being present.
func (b *AuthDataBuilder) WithFlags(flags AuthDataFlags) *AuthDataBuilder {
	b.flags = flags
	return b
}

// WithSignCount sets the signature counter value.
func (b *AuthDataBuilder) WithSignCount(count uint32) *AuthDataBuilder {
	b.signCount = count
	return b
}

// WithAttestedCredentialData adds attested credential data to the authenticator data.
// This automatically sets the AT flag.
func (b *AuthDataBuilder) WithAttestedCredentialData(
	aaguid [16]byte,
	credentialID []byte,
	publicKeyCOSE []byte,
) *AuthDataBuilder {
	b.aaguid = aaguid
	b.credentialID = credentialID
	b.publicKey = publicKeyCOSE
	b.hasAttested = true
	return b
}

// WithExtension adds an extension to the authenticator data.
// This automatically sets the ED flag when extensions are present.
func (b *AuthDataBuilder) WithExtension(name string, value interface{}) *AuthDataBuilder {
	if b.extensions == nil {
		b.extensions = make(map[string]interface{})
	}
	b.extensions[name] = value
	return b
}

// WithExtensions sets multiple extensions at once.
func (b *AuthDataBuilder) WithExtensions(extensions map[string]interface{}) *AuthDataBuilder {
	for name, value := range extensions {
		b.WithExtension(name, value)
	}
	return b
}

// Build constructs the binary authenticator data according to CTAP2/WebAuthn spec.
//
// Layout:
//
//	[0:32]   - rpIdHash: SHA-256 of RP ID (32 bytes)
//	[32]     - flags (1 byte)
//	[33:37]  - signCount: big-endian uint32 (4 bytes)
//	[37:]    - attestedCredentialData (if AT flag set)
//	[...]    - extensions (if ED flag set): CBOR-encoded map
func (b *AuthDataBuilder) Build() ([]byte, error) {
	if b.rpID == "" {
		return nil, ErrAuthDataInvalidRPID
	}

	if b.hasAttested && len(b.publicKey) == 0 {
		return nil, ErrAuthDataNoPublicKey
	}

	// Calculate credential ID length for validation
	if b.hasAttested && len(b.credentialID) > 65535 {
		return nil, ErrAuthDataCredIDTooLong
	}

	// Estimate buffer size
	estimatedSize := minAuthDataLen
	if b.hasAttested {
		estimatedSize += aaguidLen + credIDLenFieldLen + len(b.credentialID) + len(b.publicKey)
	}
	if len(b.extensions) > 0 {
		estimatedSize += 256 // Rough estimate for extensions
	}

	var buf bytes.Buffer
	buf.Grow(estimatedSize)

	// rpIdHash: SHA-256 of RP ID (32 bytes)
	rpIDHash := sha256.Sum256([]byte(b.rpID))
	buf.Write(rpIDHash[:])

	// flags: Compute final flags based on content
	flags := b.flags
	if b.hasAttested {
		flags |= FlagAT
	}
	if len(b.extensions) > 0 {
		flags |= FlagED
	}
	buf.WriteByte(byte(flags))

	// signCount: big-endian uint32 (4 bytes)
	signCountBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(signCountBytes, b.signCount)
	buf.Write(signCountBytes)

	// attestedCredentialData (if AT flag set)
	if b.hasAttested {
		// aaguid (16 bytes)
		buf.Write(b.aaguid[:])

		// credentialIdLength (big-endian uint16)
		credIDLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(credIDLenBytes, uint16(len(b.credentialID)))
		buf.Write(credIDLenBytes)

		// credentialId
		buf.Write(b.credentialID)

		// credentialPublicKey (CBOR-encoded COSE_Key)
		buf.Write(b.publicKey)
	}

	// extensions (if ED flag set): CBOR-encoded map
	if len(b.extensions) > 0 {
		extBytes, err := cbor.Marshal(b.extensions)
		if err != nil {
			return nil, ErrAuthDataCBOREncode
		}
		buf.Write(extBytes)
	}

	return buf.Bytes(), nil
}

// ParseAuthData parses binary authenticator data into an AuthenticatorData structure.
func ParseAuthData(data []byte) (*AuthenticatorData, error) {
	if len(data) < minAuthDataLen {
		return nil, ErrAuthDataTooShort
	}

	authData := &AuthenticatorData{}
	offset := 0

	// rpIdHash (32 bytes)
	authData.RPIDHash = make([]byte, rpIDHashLen)
	copy(authData.RPIDHash, data[offset:offset+rpIDHashLen])
	offset += rpIDHashLen

	// flags (1 byte)
	authData.Flags = AuthDataFlags(data[offset])
	offset += flagsLen

	// signCount (4 bytes, big-endian)
	authData.SignCount = binary.BigEndian.Uint32(data[offset : offset+signCountLen])
	offset += signCountLen

	// attestedCredentialData (if AT flag set)
	if authData.Flags.Has(FlagAT) {
		// aaguid (16 bytes)
		if len(data) < offset+aaguidLen {
			return nil, ErrAuthDataTruncated
		}
		authData.AAGUID = make([]byte, aaguidLen)
		copy(authData.AAGUID, data[offset:offset+aaguidLen])
		offset += aaguidLen

		// credentialIdLength (2 bytes, big-endian)
		if len(data) < offset+credIDLenFieldLen {
			return nil, ErrAuthDataTruncated
		}
		credIDLen := binary.BigEndian.Uint16(data[offset : offset+credIDLenFieldLen])
		offset += credIDLenFieldLen

		// credentialId
		if len(data) < offset+int(credIDLen) {
			return nil, ErrAuthDataTruncated
		}
		authData.CredentialID = make([]byte, credIDLen)
		copy(authData.CredentialID, data[offset:offset+int(credIDLen)])
		offset += int(credIDLen)

		// credentialPublicKey (CBOR-encoded COSE_Key)
		// Calculate the length of the CBOR-encoded public key
		cborLen, err := calcCBORLength(data[offset:])
		if err != nil {
			return nil, ErrAuthDataCBORDecode
		}
		if len(data) < offset+cborLen {
			return nil, ErrAuthDataTruncated
		}
		authData.PublicKey = make([]byte, cborLen)
		copy(authData.PublicKey, data[offset:offset+cborLen])
		offset += cborLen
	}

	// extensions (if ED flag set): CBOR-encoded map
	if authData.Flags.Has(FlagED) {
		if offset >= len(data) {
			return nil, ErrAuthDataTruncated
		}
		authData.Extensions = make(map[string]interface{})
		if err := cbor.Unmarshal(data[offset:], &authData.Extensions); err != nil {
			return nil, ErrAuthDataCBORDecode
		}
	}

	return authData, nil
}

// calcCBORLength calculates the byte length of a CBOR-encoded value.
// This uses a streaming decoder to read a single value, then re-encodes it
// to determine its canonical length.
func calcCBORLength(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, ErrAuthDataTruncated
	}

	// Use a decoder to read just the first CBOR value from the data.
	// This handles cases where there might be additional data after the value.
	reader := bytes.NewReader(data)
	decoder := cbor.NewDecoder(reader)

	var value interface{}
	if err := decoder.Decode(&value); err != nil {
		return 0, err
	}

	// Re-encode the value to get its canonical length.
	// This works because CBOR encoding is deterministic for the same semantic value.
	encoded, err := cbor.Marshal(value)
	if err != nil {
		return 0, err
	}

	return len(encoded), nil
}

// VerifyRPIDHash verifies that the rpIdHash matches the expected RP ID.
func VerifyRPIDHash(authData *AuthenticatorData, expectedRPID string) bool {
	expectedHash := sha256.Sum256([]byte(expectedRPID))
	return bytes.Equal(authData.RPIDHash, expectedHash[:])
}
