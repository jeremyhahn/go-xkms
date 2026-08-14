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
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacyGoldenSecret pins the value the pre-fix derivation produced for
// legacyGoldenCredentialID and legacyGoldenSalt: SHA-256(credentialID ||
// salt). A volume enrolled against the broken derivation is keyed with it,
// so migration only works while this vector reproduces exactly.
const legacyGoldenSecret = "e5c6e21ed7852c0b4a9193fcd56fb279cdfe6b43e97184be464c06dfac359b92"

// legacyGoldenCredentialID and legacyGoldenSalt are the inputs behind
// legacyGoldenSecret. Both are public values: the credential ID is handed
// out by the authenticator and the salt is stored beside the volume.
var (
	legacyGoldenCredentialID = func() []byte {
		id := make([]byte, 32)
		for i := range id {
			id[i] = byte(i)
		}
		return id
	}()

	legacyGoldenSalt = bytes.Repeat([]byte{0xA5}, 32)
)

// newSimulatedExtension wires an HMACSecretExtension to a mock device
// backed by the authenticator simulator.
func newSimulatedExtension(t *testing.T) (*HMACSecretExtension, *MockHIDDevice) {
	t.Helper()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctapDev.Close() })

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	return hmacExt, mockDev
}

// TestDeriveSecret_IgnoresPublicBytesAtFixedOffset is the regression test
// for the derivation defect: the platform must not read the authenticator
// data at a fixed offset, and must never fabricate a secret from the
// credential ID and salt.
//
// The simulator sets the AT flag, so the 32 bytes at offset 37 are the
// aaguid followed by the credential ID — values an attacker holding the
// encrypted volume already knows. A derived secret equal to those bytes, or
// to SHA-256(credentialID || salt), is a key that can be recomputed without
// the authenticator.
func TestDeriveSecret_IgnoresPublicBytesAtFixedOffset(t *testing.T) {
	hmacExt, mockDev := newSimulatedExtension(t)
	mockDev.sim.attestedCredentialData = true
	mockDev.sim.credentialID = legacyGoldenCredentialID

	config := &AuthenticationConfig{
		RelyingPartyID: "example.com",
		CredentialID:   legacyGoldenCredentialID,
		Salt:           legacyGoldenSalt,
	}

	result, err := hmacExt.DeriveSecret(config)
	require.NoError(t, err)
	require.NotNil(t, result)

	// The bytes an offset-37 reader would have returned are public.
	publicBytes := result.AuthData[authDataHeaderLen : authDataHeaderLen+hmacSecretSaltLen]
	require.Equal(t, mockDev.sim.aaguid, publicBytes[:aaguidLen],
		"the simulator must place attested credential data at offset 37 for this test to prove anything")

	assert.NotEqual(t, publicBytes, result.HMACSecret,
		"derived secret must not be the public bytes at the fixed offset")

	fabricated := sha256.Sum256(append(append([]byte{}, config.CredentialID...), config.Salt...))
	assert.NotEqual(t, fabricated[:], result.HMACSecret,
		"derived secret must not be SHA-256(credentialID || salt)")

	golden, err := hex.DecodeString(legacyGoldenSecret)
	require.NoError(t, err)
	assert.NotEqual(t, golden, result.HMACSecret,
		"derived secret must not be the legacy fabricated value")

	// It must instead be the authenticator's genuine output, which is keyed
	// with a secret that never left the simulator.
	assert.Equal(t, mockDev.sim.hmacOutput(config.Salt), result.HMACSecret)
}

// TestDeriveSecret_MatchesAuthenticatorOutput covers the ordinary case,
// where the extension map terminates authenticator data that carries no
// attested credential data.
func TestDeriveSecret_MatchesAuthenticatorOutput(t *testing.T) {
	hmacExt, mockDev := newSimulatedExtension(t)

	config := &AuthenticationConfig{
		RelyingPartyID: "example.com",
		CredentialID:   legacyGoldenCredentialID,
		Salt:           legacyGoldenSalt,
	}

	result, err := hmacExt.DeriveSecret(config)
	require.NoError(t, err)

	assert.Equal(t, mockDev.sim.hmacOutput(config.Salt), result.HMACSecret)
	assert.Len(t, result.HMACSecret, hmacSecretSaltLen)
	assert.Nil(t, result.HMACSecret2, "a single salt yields a single output")
	assert.True(t, result.UserPresent)
}

// TestDeriveSecret_TwoSalts covers the 64-byte extension output CTAP 2.1
// 12.5 defines for a two-salt request.
func TestDeriveSecret_TwoSalts(t *testing.T) {
	hmacExt, mockDev := newSimulatedExtension(t)

	config := &AuthenticationConfig{
		RelyingPartyID: "example.com",
		CredentialID:   legacyGoldenCredentialID,
		Salt:           legacyGoldenSalt,
		Salt2:          bytes.Repeat([]byte{0x5A}, 32),
	}

	result, err := hmacExt.DeriveSecret(config)
	require.NoError(t, err)

	assert.Equal(t, mockDev.sim.hmacOutput(config.Salt), result.HMACSecret)
	assert.Equal(t, mockDev.sim.hmacOutput(config.Salt2), result.HMACSecret2)
	assert.NotEqual(t, result.HMACSecret, result.HMACSecret2)
}

// TestDeriveSecret_ProtocolOne exercises PIN/UV auth protocol one, which an
// authenticator that advertises no newer protocol negotiates.
func TestDeriveSecret_ProtocolOne(t *testing.T) {
	hmacExt, mockDev := newSimulatedExtension(t)
	hmacExt.auth.info.PINProtocols = []uint64{PINUVAuthProtocolV1}

	require.Equal(t, PINUVAuthProtocolV1, hmacExt.auth.PINUVAuthProtocolVersion())

	config := &AuthenticationConfig{
		RelyingPartyID: "example.com",
		CredentialID:   legacyGoldenCredentialID,
		Salt:           legacyGoldenSalt,
	}

	result, err := hmacExt.DeriveSecret(config)
	require.NoError(t, err)
	assert.Equal(t, mockDev.sim.hmacOutput(config.Salt), result.HMACSecret)
}

// TestDeriveSecret_ProtocolTwo exercises PIN/UV auth protocol two, which is
// preferred whenever the authenticator advertises it.
func TestDeriveSecret_ProtocolTwo(t *testing.T) {
	hmacExt, mockDev := newSimulatedExtension(t)
	require.Equal(t, PINUVAuthProtocolV2, hmacExt.auth.PINUVAuthProtocolVersion())

	config := &AuthenticationConfig{
		RelyingPartyID: "example.com",
		CredentialID:   legacyGoldenCredentialID,
		Salt:           legacyGoldenSalt,
	}

	result, err := hmacExt.DeriveSecret(config)
	require.NoError(t, err)
	assert.Equal(t, mockDev.sim.hmacOutput(config.Salt), result.HMACSecret)
}

// TestDeriveSecret_DistinctSaltsProduceDistinctSecrets guards against a
// derivation that ignores the salt.
func TestDeriveSecret_DistinctSaltsProduceDistinctSecrets(t *testing.T) {
	hmacExt, _ := newSimulatedExtension(t)

	first, err := hmacExt.DeriveSecret(&AuthenticationConfig{
		RelyingPartyID: "example.com",
		CredentialID:   legacyGoldenCredentialID,
		Salt:           legacyGoldenSalt,
	})
	require.NoError(t, err)

	second, err := hmacExt.DeriveSecret(&AuthenticationConfig{
		RelyingPartyID: "example.com",
		CredentialID:   legacyGoldenCredentialID,
		Salt:           bytes.Repeat([]byte{0x11}, 32),
	})
	require.NoError(t, err)

	assert.NotEqual(t, first.HMACSecret, second.HMACSecret)
}

// TestDeriveSecret_InvalidInput rejects malformed configurations before any
// command reaches the authenticator.
func TestDeriveSecret_InvalidInput(t *testing.T) {
	hmacExt, _ := newSimulatedExtension(t)

	tests := []struct {
		name     string
		config   *AuthenticationConfig
		expected error
	}{
		{
			name:     "nil configuration",
			config:   nil,
			expected: ErrAuthenticationConfigNil,
		},
		{
			name: "missing credential ID",
			config: &AuthenticationConfig{
				RelyingPartyID: "example.com",
				Salt:           legacyGoldenSalt,
			},
			expected: ErrInvalidCredentialID,
		},
		{
			name: "short salt",
			config: &AuthenticationConfig{
				RelyingPartyID: "example.com",
				CredentialID:   legacyGoldenCredentialID,
				Salt:           make([]byte, 16),
			},
			expected: ErrInvalidSalt,
		},
		{
			name: "short second salt",
			config: &AuthenticationConfig{
				RelyingPartyID: "example.com",
				CredentialID:   legacyGoldenCredentialID,
				Salt:           legacyGoldenSalt,
				Salt2:          make([]byte, 8),
			},
			expected: ErrInvalidSalt,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := hmacExt.DeriveSecret(tt.config)
			assert.ErrorIs(t, err, tt.expected)
			assert.Nil(t, result, "no key may be returned when the input is rejected")
		})
	}
}

// TestHMACSecretOutput_Rejected proves that every malformed extension
// output is terminal: the fabrication path is gone, so nothing is returned.
func TestHMACSecretOutput_Rejected(t *testing.T) {
	session, _, err := newTestSession(PINUVAuthProtocolV2)
	require.NoError(t, err)

	ciphertext, err := session.Encrypt(make([]byte, hmacSecretSaltLen))
	require.NoError(t, err)

	tests := []struct {
		name     string
		authData []byte
		saltsLen int
		expected error
	}{
		{
			name:     "no extension data flag",
			authData: simAuthData(t, FlagUserPresent, nil),
			saltsLen: hmacSecretSaltLen,
			expected: ErrHMACSecretMissing,
		},
		{
			name: "extension map without hmac-secret",
			authData: simAuthData(t, FlagUserPresent|FlagExtensionData,
				mustCBOR(t, map[string]interface{}{ExtensionCredBlob: []byte{0x01}})),
			saltsLen: hmacSecretSaltLen,
			expected: ErrHMACSecretMissing,
		},
		{
			name: "hmac-secret is not a byte string",
			authData: simAuthData(t, FlagUserPresent|FlagExtensionData,
				mustCBOR(t, map[string]interface{}{ExtensionHMACSecret: true})),
			saltsLen: hmacSecretSaltLen,
			expected: ErrHMACSecretOutputInvalid,
		},
		{
			name: "hmac-secret is not a whole number of AES blocks",
			authData: simAuthData(t, FlagUserPresent|FlagExtensionData,
				mustCBOR(t, map[string]interface{}{ExtensionHMACSecret: make([]byte, 20)})),
			saltsLen: hmacSecretSaltLen,
			expected: ErrHMACSecretOutputInvalid,
		},
		{
			name: "hmac-secret decrypts to the wrong length",
			authData: simAuthData(t, FlagUserPresent|FlagExtensionData,
				mustCBOR(t, map[string]interface{}{ExtensionHMACSecret: ciphertext})),
			saltsLen: 2 * hmacSecretSaltLen,
			expected: ErrHMACSecretOutputInvalid,
		},
		{
			name:     "extension map is truncated",
			authData: simAuthData(t, FlagUserPresent|FlagExtensionData, []byte{0xA1, 0x6B}),
			saltsLen: hmacSecretSaltLen,
			expected: ErrInvalidExtensions,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := hmacSecretOutput(tt.authData, session, tt.saltsLen)
			assert.ErrorIs(t, err, tt.expected)
			assert.Nil(t, output, "no secret may be returned for a malformed output")
		})
	}
}

// TestHMACSecretOutput_Accepted covers the lengths CTAP 2.1 12.5 defines.
func TestHMACSecretOutput_Accepted(t *testing.T) {
	for _, version := range []uint64{PINUVAuthProtocolV1, PINUVAuthProtocolV2} {
		session, _, err := newTestSession(version)
		require.NoError(t, err)

		for _, saltCount := range []int{1, 2} {
			expected := make([]byte, saltCount*hmacSecretSaltLen)
			_, err := rand.Read(expected)
			require.NoError(t, err)

			ciphertext, err := session.Encrypt(expected)
			require.NoError(t, err)

			authData := simAuthData(t, FlagUserPresent|FlagExtensionData,
				mustCBOR(t, map[string]interface{}{ExtensionHMACSecret: ciphertext}))

			output, err := hmacSecretOutput(authData, session, len(expected))
			require.NoError(t, err)
			assert.Equal(t, expected, output)
		}
	}
}

// TestDerivationModeLegacy_ReproducesGoldenValue proves the migration
// escape hatch still unlocks a volume keyed with the broken derivation.
func TestDerivationModeLegacy_ReproducesGoldenValue(t *testing.T) {
	hmacExt, _ := newSimulatedExtension(t)

	warnings := captureWarnings(t)

	config := &AuthenticationConfig{
		RelyingPartyID: "example.com",
		CredentialID:   legacyGoldenCredentialID,
		Salt:           legacyGoldenSalt,
		DerivationMode: DerivationModeLegacyInsecure,
	}

	result, err := hmacExt.DeriveSecret(config)
	require.NoError(t, err)

	golden, err := hex.DecodeString(legacyGoldenSecret)
	require.NoError(t, err)
	assert.Equal(t, golden, result.HMACSecret,
		"legacy mode must reproduce the pre-fix value byte for byte")

	assert.Contains(t, warnings.String(), "NOT bound to the authenticator",
		"legacy mode must warn that the key is not hardware-bound")
	assert.Contains(t, warnings.String(), "re-enroll")
}

// TestDerivationModeLegacy_IsNotReachableByDefault proves the fabrication
// cannot be reached without the explicit opt-in.
func TestDerivationModeLegacy_IsNotReachableByDefault(t *testing.T) {
	// The zero value of the mode is the CTAP2 derivation, so a caller that
	// never mentions DerivationMode gets the secure path.
	assert.Equal(t, DerivationModeCTAP2, DerivationMode(0))
	assert.Equal(t, DerivationModeCTAP2, (&AuthenticationConfig{}).DerivationMode)
	assert.Equal(t, DerivationModeCTAP2, DefaultAuthenticationConfig(nil, nil).DerivationMode)

	// The field is excluded from every serialization format, so no
	// configuration file can select the insecure mode.
	field, ok := reflect.TypeOf(AuthenticationConfig{}).FieldByName("DerivationMode")
	require.True(t, ok)
	for _, tag := range []string{"yaml", "json", "mapstructure"} {
		assert.Equal(t, "-", field.Tag.Get(tag), "DerivationMode must be excluded from %s", tag)
	}

	// And with the default mode, an authenticator that returns no output
	// yields an error rather than the fabricated value.
	hmacExt, mockDev := newSimulatedExtension(t)
	mockDev.sim.suppressExtensionOutput = true

	warnings := captureWarnings(t)

	result, err := hmacExt.DeriveSecret(&AuthenticationConfig{
		RelyingPartyID: "example.com",
		CredentialID:   legacyGoldenCredentialID,
		Salt:           legacyGoldenSalt,
	})
	assert.ErrorIs(t, err, ErrHMACSecretMissing)
	assert.Nil(t, result)
	assert.Empty(t, warnings.String(), "the default path must not emit the legacy warning")
}

// TestLegacyHMACSecret_FixedOffsetBranch covers the other half of the
// pre-fix extraction: raw bytes read from offset 37 regardless of what the
// AT flag says lives there.
func TestLegacyHMACSecret_FixedOffsetBranch(t *testing.T) {
	config := &AuthenticationConfig{
		CredentialID: legacyGoldenCredentialID,
		Salt:         legacyGoldenSalt,
	}

	raw := bytes.Repeat([]byte{0x77}, hmacSecretSaltLen)
	authData := simAuthData(t, FlagUserPresent|FlagExtensionData, raw)
	assert.Equal(t, raw, legacyHMACSecret(authData, config))

	// Without the ED flag the extraction falls back to public material.
	golden, err := hex.DecodeString(legacyGoldenSecret)
	require.NoError(t, err)
	assert.Equal(t, golden, legacyHMACSecret(simAuthData(t, FlagUserPresent, nil), config))

	// So does an ED flag over fewer than 32 trailing bytes.
	assert.Equal(t, golden, legacyHMACSecret(
		simAuthData(t, FlagUserPresent|FlagExtensionData, make([]byte, 4)), config))
}

// captureWarnings redirects the default slog logger to a buffer for the
// duration of the test.
func captureWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()

	buf := &bytes.Buffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	return buf
}

// simAuthData builds authenticator data with the given flags and trailing
// bytes.
func simAuthData(t *testing.T, flags byte, trailing []byte) []byte {
	t.Helper()

	authData := make([]byte, authDataHeaderLen)
	authData[authDataRPIDHashLen] = flags
	binary.BigEndian.PutUint32(authData[authDataRPIDHashLen+1:authDataHeaderLen], 7)

	if flags&FlagAttestedCredentialData != 0 {
		attested := append([]byte{}, bytes.Repeat([]byte{0xAB}, aaguidLen)...)
		attested = binary.BigEndian.AppendUint16(attested, uint16(len(legacyGoldenCredentialID)))
		attested = append(attested, legacyGoldenCredentialID...)
		authData = append(authData, attested...)
	}

	return append(authData, trailing...)
}

// mustCBOR encodes a value or fails the test.
func mustCBOR(t *testing.T, value interface{}) []byte {
	t.Helper()

	encoded, err := cbor.Marshal(value)
	require.NoError(t, err)
	return encoded
}

// newTestSession derives a session from a fresh key pair on both sides,
// returning the platform session and the peer's private key so a test can
// build the matching authenticator-side session.
func newTestSession(version uint64) (*PINUVAuthSession, *ecdh.PrivateKey, error) {
	peer, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	peerKey, err := NewCOSEKeyEC2(peer.PublicKey())
	if err != nil {
		return nil, nil, err
	}

	session, err := NewPINUVAuthSession(version, peerKey)
	if err != nil {
		return nil, nil, err
	}

	return session, peer, nil
}
