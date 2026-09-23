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
	"crypto/aes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// testSecret seals a test PIN string into protected memory. An empty s
// returns nil, mirroring what an authenticator with no PIN configured
// receives.
func testSecret(t *testing.T, s string) *secure.Secret {
	t.Helper()

	if s == "" {
		return nil
	}
	secret, err := secure.NewSecret([]byte(s))
	require.NoError(t, err)
	return secret
}

// newTestKeyPair generates a P-256 key pair and its COSE_Key rendering.
func newTestKeyPair(t *testing.T) (*ecdh.PrivateKey, *COSEKeyEC2) {
	t.Helper()

	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	key, err := NewCOSEKeyEC2(priv.PublicKey())
	require.NoError(t, err)

	return priv, key
}

func TestNewCOSEKeyEC2(t *testing.T) {
	priv, key := newTestKeyPair(t)

	assert.Equal(t, COSEAlgECDHESHKDF256, key.Algorithm)
	assert.Equal(t, coseCrvP256, key.Curve)
	assert.Len(t, key.X, coseP256CoordinateLen)
	assert.Len(t, key.Y, coseP256CoordinateLen)

	point := priv.PublicKey().Bytes()
	assert.Equal(t, point[1:1+coseP256CoordinateLen], key.X)
	assert.Equal(t, point[1+coseP256CoordinateLen:], key.Y)
}

func TestNewCOSEKeyEC2_NilKey(t *testing.T) {
	key, err := NewCOSEKeyEC2(nil)
	assert.ErrorIs(t, err, ErrInvalidCOSEKeyAgreement)
	assert.Nil(t, key)
}

func TestCOSEKeyEC2_Map(t *testing.T) {
	_, key := newTestKeyPair(t)

	m := key.Map()
	assert.Equal(t, coseKtyEC2, m[coseLabelKty])
	assert.Equal(t, key.Algorithm, m[coseLabelAlg])
	assert.Equal(t, coseCrvP256, m[coseLabelCrv])
	assert.Equal(t, key.X, m[coseLabelX])
	assert.Equal(t, key.Y, m[coseLabelY])
}

func TestCOSEKeyEC2_ECDHPublicKey(t *testing.T) {
	priv, key := newTestKeyPair(t)

	pub, err := key.ECDHPublicKey()
	require.NoError(t, err)
	assert.True(t, priv.PublicKey().Equal(pub))
}

func TestCOSEKeyEC2_ECDHPublicKey_Invalid(t *testing.T) {
	_, valid := newTestKeyPair(t)

	tests := []struct {
		name string
		key  *COSEKeyEC2
	}{
		{
			name: "unsupported curve",
			key:  &COSEKeyEC2{Curve: 2, X: valid.X, Y: valid.Y},
		},
		{
			name: "short x coordinate",
			key:  &COSEKeyEC2{Curve: coseCrvP256, X: valid.X[:16], Y: valid.Y},
		},
		{
			name: "short y coordinate",
			key:  &COSEKeyEC2{Curve: coseCrvP256, X: valid.X, Y: valid.Y[:1]},
		},
		{
			name: "point not on the curve",
			key: &COSEKeyEC2{
				Curve: coseCrvP256,
				X:     bytes.Repeat([]byte{0x01}, coseP256CoordinateLen),
				Y:     bytes.Repeat([]byte{0x02}, coseP256CoordinateLen),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := tt.key.ECDHPublicKey()
			assert.ErrorIs(t, err, ErrInvalidCOSEKeyAgreement)
			assert.Nil(t, pub)
		})
	}
}

func TestParseCOSEKeyEC2(t *testing.T) {
	_, key := newTestKeyPair(t)

	t.Run("interface-keyed map", func(t *testing.T) {
		decoded, err := ParseCOSEKeyEC2(map[interface{}]interface{}{
			int64(coseLabelKty): int64(coseKtyEC2),
			int64(coseLabelAlg): int64(COSEAlgECDHESHKDF256),
			int64(coseLabelCrv): int64(coseCrvP256),
			int64(coseLabelX):   key.X,
			int64(coseLabelY):   key.Y,
		})
		require.NoError(t, err)
		assert.Equal(t, key, decoded)
	})

	t.Run("integer-keyed map", func(t *testing.T) {
		decoded, err := ParseCOSEKeyEC2(key.Map())
		require.NoError(t, err)
		assert.Equal(t, key, decoded)
	})

	t.Run("int64-keyed map", func(t *testing.T) {
		decoded, err := ParseCOSEKeyEC2(map[int64]interface{}{
			coseLabelKty: coseKtyEC2,
			coseLabelCrv: coseCrvP256,
			coseLabelX:   key.X,
			coseLabelY:   key.Y,
		})
		require.NoError(t, err)
		// The algorithm label is optional and defaults to the key
		// agreement algorithm.
		assert.Equal(t, COSEAlgECDHESHKDF256, decoded.Algorithm)
	})
}

func TestParseCOSEKeyEC2_Invalid(t *testing.T) {
	_, key := newTestKeyPair(t)

	tests := []struct {
		name  string
		value interface{}
	}{
		{name: "absent", value: nil},
		{name: "not a map", value: []byte{0x01}},
		{
			name:  "non-integer label",
			value: map[interface{}]interface{}{"kty": int64(2)},
		},
		{
			name:  "missing key type",
			value: map[int]interface{}{coseLabelCrv: coseCrvP256},
		},
		{
			name:  "wrong key type",
			value: map[int]interface{}{coseLabelKty: 1},
		},
		{
			name:  "non-integer key type",
			value: map[int]interface{}{coseLabelKty: "EC2"},
		},
		{
			name:  "missing curve",
			value: map[int]interface{}{coseLabelKty: coseKtyEC2},
		},
		{
			name: "missing x",
			value: map[int]interface{}{
				coseLabelKty: coseKtyEC2,
				coseLabelCrv: coseCrvP256,
			},
		},
		{
			name: "x is not a byte string",
			value: map[int]interface{}{
				coseLabelKty: coseKtyEC2,
				coseLabelCrv: coseCrvP256,
				coseLabelX:   "not bytes",
			},
		},
		{
			name: "missing y",
			value: map[int]interface{}{
				coseLabelKty: coseKtyEC2,
				coseLabelCrv: coseCrvP256,
				coseLabelX:   key.X,
			},
		},
		{
			name: "non-integer algorithm",
			value: map[int]interface{}{
				coseLabelKty: coseKtyEC2,
				coseLabelCrv: coseCrvP256,
				coseLabelX:   key.X,
				coseLabelY:   key.Y,
				coseLabelAlg: []byte{0x01},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoded, err := ParseCOSEKeyEC2(tt.value)
			assert.ErrorIs(t, err, ErrInvalidCOSEKeyAgreement)
			assert.Nil(t, decoded)
		})
	}
}

func TestParseCOSEKeyEC2_UnsignedLabels(t *testing.T) {
	_, key := newTestKeyPair(t)

	decoded, err := ParseCOSEKeyEC2(map[interface{}]interface{}{
		uint64(coseLabelKty): uint64(coseKtyEC2),
		int(coseLabelCrv):    int(coseCrvP256),
		int64(coseLabelX):    key.X,
		int64(coseLabelY):    key.Y,
	})
	require.NoError(t, err)
	assert.Equal(t, key.X, decoded.X)
}

// TestPINUVAuthSession_SharedSecretMatchesSpec checks the derivations
// CTAP 2.1 6.5.6 and 6.5.7 define, independently of the implementation.
func TestPINUVAuthSession_SharedSecretMatchesSpec(t *testing.T) {
	platform, _ := newTestKeyPair(t)
	authenticator, authenticatorKey := newTestKeyPair(t)

	peer, err := authenticatorKey.ECDHPublicKey()
	require.NoError(t, err)

	point, err := platform.ECDH(peer)
	require.NoError(t, err)

	t.Run("protocol one is SHA-256 of the ECDH point", func(t *testing.T) {
		session, err := newPINUVAuthSession(PINUVAuthProtocolV1, platform, peer)
		require.NoError(t, err)

		expected := sha256.Sum256(point)
		assert.Equal(t, expected[:], session.sharedSecret)
		assert.Equal(t, expected[:], session.hmacKey())
		assert.Equal(t, expected[:], session.aesKey())
	})

	t.Run("protocol two splits an HKDF expansion", func(t *testing.T) {
		session, err := newPINUVAuthSession(PINUVAuthProtocolV2, platform, peer)
		require.NoError(t, err)

		hmacKey, err := hkdf.Key(sha256.New, point, make([]byte, 32), "CTAP2 HMAC key", 32)
		require.NoError(t, err)
		aesKey, err := hkdf.Key(sha256.New, point, make([]byte, 32), "CTAP2 AES key", 32)
		require.NoError(t, err)

		assert.Len(t, session.sharedSecret, 64)
		assert.Equal(t, hmacKey, session.hmacKey())
		assert.Equal(t, aesKey, session.aesKey())
		assert.NotEqual(t, session.hmacKey(), session.aesKey())
	})

	t.Run("both sides derive the same secret", func(t *testing.T) {
		platformPub, err := NewCOSEKeyEC2(platform.PublicKey())
		require.NoError(t, err)
		platformPeer, err := platformPub.ECDHPublicKey()
		require.NoError(t, err)

		platformSide, err := newPINUVAuthSession(PINUVAuthProtocolV2, platform, peer)
		require.NoError(t, err)
		authenticatorSide, err := newPINUVAuthSession(PINUVAuthProtocolV2, authenticator, platformPeer)
		require.NoError(t, err)

		assert.Equal(t, platformSide.sharedSecret, authenticatorSide.sharedSecret)
	})
}

func TestNewPINUVAuthSession(t *testing.T) {
	_, authenticatorKey := newTestKeyPair(t)

	for _, version := range []uint64{PINUVAuthProtocolV1, PINUVAuthProtocolV2} {
		session, err := NewPINUVAuthSession(version, authenticatorKey)
		require.NoError(t, err)

		assert.Equal(t, version, session.Version())
		require.NotNil(t, session.PlatformKeyAgreement())
		assert.Len(t, session.PlatformKeyAgreement().X, coseP256CoordinateLen)

		// The platform key is ephemeral: a second session must not reuse it.
		other, err := NewPINUVAuthSession(version, authenticatorKey)
		require.NoError(t, err)
		assert.NotEqual(t, session.PlatformKeyAgreement().X, other.PlatformKeyAgreement().X)
		assert.NotEqual(t, session.sharedSecret, other.sharedSecret)
	}
}

func TestNewPINUVAuthSession_Invalid(t *testing.T) {
	_, authenticatorKey := newTestKeyPair(t)

	t.Run("unsupported protocol version", func(t *testing.T) {
		session, err := NewPINUVAuthSession(3, authenticatorKey)
		assert.ErrorIs(t, err, ErrUnsupportedPINUVAuthProtocol)
		assert.Nil(t, session)
	})

	t.Run("nil key agreement key", func(t *testing.T) {
		session, err := NewPINUVAuthSession(PINUVAuthProtocolV1, nil)
		assert.ErrorIs(t, err, ErrInvalidCOSEKeyAgreement)
		assert.Nil(t, session)
	})

	t.Run("malformed key agreement key", func(t *testing.T) {
		session, err := NewPINUVAuthSession(PINUVAuthProtocolV1, &COSEKeyEC2{Curve: coseCrvP256})
		assert.ErrorIs(t, err, ErrInvalidCOSEKeyAgreement)
		assert.Nil(t, session)
	})
}

func TestNewPINUVAuthSession_UnsupportedVersionInDerivation(t *testing.T) {
	platform, _ := newTestKeyPair(t)
	_, authenticatorKey := newTestKeyPair(t)

	peer, err := authenticatorKey.ECDHPublicKey()
	require.NoError(t, err)

	session, err := newPINUVAuthSession(99, platform, peer)
	assert.ErrorIs(t, err, ErrUnsupportedPINUVAuthProtocol)
	assert.Nil(t, session)
}

func TestPINUVAuthSession_EncryptDecrypt(t *testing.T) {
	_, authenticatorKey := newTestKeyPair(t)

	for _, version := range []uint64{PINUVAuthProtocolV1, PINUVAuthProtocolV2} {
		session, err := NewPINUVAuthSession(version, authenticatorKey)
		require.NoError(t, err)

		for _, size := range []int{aes.BlockSize, hmacSecretSaltLen, 2 * hmacSecretSaltLen} {
			plaintext := make([]byte, size)
			_, err := rand.Read(plaintext)
			require.NoError(t, err)

			ciphertext, err := session.Encrypt(plaintext)
			require.NoError(t, err)
			assert.NotEqual(t, plaintext, ciphertext)

			if version == PINUVAuthProtocolV2 {
				// Protocol two prefixes a random IV.
				assert.Len(t, ciphertext, aes.BlockSize+size)
			} else {
				assert.Len(t, ciphertext, size)
			}

			decrypted, err := session.Decrypt(ciphertext)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)
		}
	}
}

func TestPINUVAuthSession_EncryptIVBehavior(t *testing.T) {
	_, authenticatorKey := newTestKeyPair(t)
	plaintext := bytes.Repeat([]byte{0x42}, hmacSecretSaltLen)

	t.Run("protocol one is deterministic", func(t *testing.T) {
		session, err := NewPINUVAuthSession(PINUVAuthProtocolV1, authenticatorKey)
		require.NoError(t, err)

		first, err := session.Encrypt(plaintext)
		require.NoError(t, err)
		second, err := session.Encrypt(plaintext)
		require.NoError(t, err)

		assert.Equal(t, first, second, "protocol one uses an all-zero IV")
	})

	t.Run("protocol two randomizes the IV", func(t *testing.T) {
		session, err := NewPINUVAuthSession(PINUVAuthProtocolV2, authenticatorKey)
		require.NoError(t, err)

		first, err := session.Encrypt(plaintext)
		require.NoError(t, err)
		second, err := session.Encrypt(plaintext)
		require.NoError(t, err)

		assert.NotEqual(t, first, second, "protocol two prefixes a random IV")
	})
}

func TestPINUVAuthSession_EncryptInvalid(t *testing.T) {
	_, authenticatorKey := newTestKeyPair(t)
	session, err := NewPINUVAuthSession(PINUVAuthProtocolV1, authenticatorKey)
	require.NoError(t, err)

	for _, plaintext := range [][]byte{nil, {}, make([]byte, 31)} {
		ciphertext, err := session.Encrypt(plaintext)
		assert.ErrorIs(t, err, ErrInvalidPINUVAuthPlaintext)
		assert.Nil(t, ciphertext)
	}
}

func TestPINUVAuthSession_DecryptInvalid(t *testing.T) {
	_, authenticatorKey := newTestKeyPair(t)

	t.Run("protocol one", func(t *testing.T) {
		session, err := NewPINUVAuthSession(PINUVAuthProtocolV1, authenticatorKey)
		require.NoError(t, err)

		for _, ciphertext := range [][]byte{nil, {}, make([]byte, 20)} {
			plaintext, err := session.Decrypt(ciphertext)
			assert.ErrorIs(t, err, ErrInvalidPINUVAuthCiphertext)
			assert.Nil(t, plaintext)
		}
	})

	t.Run("protocol two", func(t *testing.T) {
		session, err := NewPINUVAuthSession(PINUVAuthProtocolV2, authenticatorKey)
		require.NoError(t, err)

		// Too short to carry both an IV and a ciphertext.
		for _, ciphertext := range [][]byte{nil, make([]byte, aes.BlockSize)} {
			plaintext, err := session.Decrypt(ciphertext)
			assert.ErrorIs(t, err, ErrInvalidPINUVAuthCiphertext)
			assert.Nil(t, plaintext)
		}

		// IV present but the body is not a whole number of blocks.
		plaintext, err := session.Decrypt(make([]byte, aes.BlockSize+5))
		assert.ErrorIs(t, err, ErrInvalidPINUVAuthCiphertext)
		assert.Nil(t, plaintext)
	})
}

func TestPINUVAuthSession_Authenticate(t *testing.T) {
	_, authenticatorKey := newTestKeyPair(t)
	message := []byte("saltEnc")

	v1, err := NewPINUVAuthSession(PINUVAuthProtocolV1, authenticatorKey)
	require.NoError(t, err)
	v2, err := NewPINUVAuthSession(PINUVAuthProtocolV2, authenticatorKey)
	require.NoError(t, err)

	assert.Len(t, v1.Authenticate(message), 16, "protocol one truncates the tag")
	assert.Len(t, v2.Authenticate(message), sha256.Size, "protocol two uses the full tag")

	assert.Equal(t, v1.Authenticate(message), v1.Authenticate(message))
	assert.NotEqual(t, v1.Authenticate(message), v1.Authenticate([]byte("other")))
}

func TestPINUVAuthSession_AuthenticateWithToken(t *testing.T) {
	_, authenticatorKey := newTestKeyPair(t)
	message := []byte("clientDataHash")
	token := bytes.Repeat([]byte{0x5A}, sha256.Size)

	v1, err := NewPINUVAuthSession(PINUVAuthProtocolV1, authenticatorKey)
	require.NoError(t, err)
	v2, err := NewPINUVAuthSession(PINUVAuthProtocolV2, authenticatorKey)
	require.NoError(t, err)

	assert.Len(t, v1.AuthenticateWithToken(token, message), 16, "protocol one truncates the tag")
	assert.Len(t, v2.AuthenticateWithToken(token, message), sha256.Size, "protocol two uses the full tag")

	// The token, not the shared secret, keys a pinUvAuthParam. Keying it with
	// the shared secret produces a tag every authenticator rejects.
	assert.NotEqual(t, v2.Authenticate(message), v2.AuthenticateWithToken(token, message))

	assert.NotEqual(t,
		v2.AuthenticateWithToken(token, message),
		v2.AuthenticateWithToken(bytes.Repeat([]byte{0x5B}, sha256.Size), message),
		"a different token must produce a different tag")
}

// newPINAuthenticator builds a platform-side Authenticator over a simulator
// with pin configured, mirroring a security key that has a PIN set.
func newPINAuthenticator(t *testing.T, pin string) (*Authenticator, *authenticatorSim) {
	t.Helper()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	mockDev.sim.pin = pin
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctapDev.Close() })

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	return auth, mockDev.sim
}

func TestAuthenticator_GetPINToken(t *testing.T) {
	auth, sim := newPINAuthenticator(t, "123456")

	session, err := auth.EstablishPINUVAuthSession()
	require.NoError(t, err)

	token, err := auth.GetPINToken(session, testSecret(t, "123456"))
	require.NoError(t, err)

	// The platform must recover the exact token the authenticator minted; a
	// token that merely decrypts to the right length authenticates nothing.
	assert.Equal(t, sim.pinToken, token)
	assert.Len(t, token, sha256.Size)
}

func TestAuthenticator_GetPINToken_Errors(t *testing.T) {
	t.Run("wrong PIN is distinguishable from a refusal", func(t *testing.T) {
		auth, _ := newPINAuthenticator(t, "123456")

		session, err := auth.EstablishPINUVAuthSession()
		require.NoError(t, err)

		token, err := auth.GetPINToken(session, testSecret(t, "999999"))
		assert.Nil(t, token)
		assert.ErrorIs(t, err, ErrPINTokenFailed)
		assert.ErrorIs(t, err, ErrInvalidPIN, "an operator who mistyped must not read 'denied'")
	})

	t.Run("authenticator with no PIN set", func(t *testing.T) {
		auth, _ := newPINAuthenticator(t, "")

		session, err := auth.EstablishPINUVAuthSession()
		require.NoError(t, err)

		token, err := auth.GetPINToken(session, testSecret(t, "123456"))
		assert.Nil(t, token)
		assert.ErrorIs(t, err, ErrPINNotSet)
	})

	t.Run("nil session", func(t *testing.T) {
		auth, _ := newPINAuthenticator(t, "123456")

		token, err := auth.GetPINToken(nil, testSecret(t, "123456"))
		assert.Nil(t, token)
		assert.ErrorIs(t, err, ErrPINTokenFailed)
	})

	t.Run("nil PIN never reaches the wire", func(t *testing.T) {
		auth, sim := newPINAuthenticator(t, "123456")

		session, err := auth.EstablishPINUVAuthSession()
		require.NoError(t, err)

		token, err := auth.GetPINToken(session, nil)
		assert.Nil(t, token)
		assert.ErrorIs(t, err, ErrPINTokenFailed)
		assert.Nil(t, sim.pinToken, "no token may be minted for a nil PIN")
	})
}

func TestAuthenticator_AuthorizeWithPIN(t *testing.T) {
	auth, sim := newPINAuthenticator(t, "123456")
	clientDataHash := sha256.Sum256([]byte("clientDataJSON"))

	param, protocol, err := auth.AuthorizeWithPIN(testSecret(t, "123456"), clientDataHash[:])
	require.NoError(t, err)

	assert.Equal(t, PINUVAuthProtocolV2, protocol, "protocol two is preferred when advertised")
	assert.Equal(t,
		pinUVAuthenticate(protocol, sim.pinToken, clientDataHash[:]),
		param,
		"pinUvAuthParam must authenticate the clientDataHash under the issued token")
}

func TestAuthenticator_AuthorizeWithPIN_WrongPIN(t *testing.T) {
	auth, _ := newPINAuthenticator(t, "123456")
	clientDataHash := sha256.Sum256([]byte("clientDataJSON"))

	param, protocol, err := auth.AuthorizeWithPIN(testSecret(t, "000000"), clientDataHash[:])
	assert.Nil(t, param)
	assert.Zero(t, protocol)
	assert.ErrorIs(t, err, ErrInvalidPIN)
}

func TestAuthenticator_KeyAgreement(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	key, err := auth.KeyAgreement(PINUVAuthProtocolV2)
	require.NoError(t, err)

	expected, err := NewCOSEKeyEC2(mockDev.sim.privateKey.PublicKey())
	require.NoError(t, err)
	assert.Equal(t, expected.X, key.X)
	assert.Equal(t, expected.Y, key.Y)
}

func TestAuthenticator_KeyAgreement_UnsupportedVersion(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	key, err := auth.KeyAgreement(7)
	assert.ErrorIs(t, err, ErrUnsupportedPINUVAuthProtocol)
	assert.Nil(t, key)
}

func TestAuthenticator_KeyAgreement_DeviceError(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	// A device that answers ClientPIN with an error status must not yield a
	// session.
	mockDev.sim.failClientPIN = true

	key, err := auth.KeyAgreement(PINUVAuthProtocolV1)
	assert.ErrorIs(t, err, ErrKeyAgreementFailed)
	assert.Nil(t, key)

	session, err := auth.EstablishPINUVAuthSession()
	assert.ErrorIs(t, err, ErrKeyAgreementFailed)
	assert.Nil(t, session)
}

func TestAuthenticator_PINUVAuthProtocolVersion(t *testing.T) {
	tests := []struct {
		name     string
		info     *DeviceInfo
		expected uint64
	}{
		{
			name:     "no device info defaults to protocol one",
			info:     nil,
			expected: PINUVAuthProtocolV1,
		},
		{
			name:     "no advertised protocols defaults to protocol one",
			info:     &DeviceInfo{},
			expected: PINUVAuthProtocolV1,
		},
		{
			name:     "protocol one only",
			info:     &DeviceInfo{PINProtocols: []uint64{1}},
			expected: PINUVAuthProtocolV1,
		},
		{
			name:     "protocol two is preferred",
			info:     &DeviceInfo{PINProtocols: []uint64{1, 2}},
			expected: PINUVAuthProtocolV2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &Authenticator{info: tt.info}
			assert.Equal(t, tt.expected, auth.PINUVAuthProtocolVersion())
		})
	}
}

func TestAuthenticator_EstablishPINUVAuthSession(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	session, err := auth.EstablishPINUVAuthSession()
	require.NoError(t, err)
	assert.Equal(t, PINUVAuthProtocolV2, session.Version())

	// The authenticator must be able to reproduce the same secret from the
	// platform key the session carries.
	platformPeer, err := session.PlatformKeyAgreement().ECDHPublicKey()
	require.NoError(t, err)

	authenticatorSide, err := newPINUVAuthSession(session.Version(), mockDev.sim.privateKey, platformPeer)
	require.NoError(t, err)
	assert.Equal(t, session.sharedSecret, authenticatorSide.sharedSecret)
}
