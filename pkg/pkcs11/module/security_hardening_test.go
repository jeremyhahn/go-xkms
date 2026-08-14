package module

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateECDHPeerPoint closes the invalid-curve attack at the one place
// every backend passes through.
//
// CK_ECDH1_DERIVE_PARAMS.pPublicData is the other party's point and is entirely
// attacker-supplied. A point on a low-order twist puts the shared secret in a
// small subgroup, so each derivation leaks residues of the static private scalar
// and enough derivations recover it by CRT. NIST SP 800-56A Rev. 3 §5.6.2.3.2
// makes full public-key validation mandatory for static-key ECDH for this
// reason. Validating in the mechanism layer rather than per backend is what
// makes it a property of the token instead of a property of whichever backend
// happens to serve the request.
func TestValidateECDHPeerPoint(t *testing.T) {
	t.Run("accepts a genuine point on each supported curve", func(t *testing.T) {
		for name, curve := range map[string]ecdh.Curve{
			"P-256": ecdh.P256(),
			"P-384": ecdh.P384(),
			"P-521": ecdh.P521(),
		} {
			t.Run(name, func(t *testing.T) {
				key, err := curve.GenerateKey(rand.Reader)
				require.NoError(t, err)

				assert.NoError(t, ValidateECDHPeerPoint(key.PublicKey().Bytes()),
					"a real point must be accepted, or the check has made ECDH unusable")
			})
		}
	})

	t.Run("refuses a point that is not on the curve", func(t *testing.T) {
		// Correct length and correct 0x04 prefix, but the coordinates do not
		// satisfy the curve equation. This is the shape an invalid-curve attack
		// takes, and the only thing that rejects it is the on-curve test.
		offCurve := make([]byte, 65)
		offCurve[0] = 0x04
		offCurve[64] = 0x01

		require.False(t, elliptic.P256().IsOnCurve( //nolint:staticcheck // the deprecated API states the premise
			new(big.Int).SetBytes(offCurve[1:33]),
			new(big.Int).SetBytes(offCurve[33:])),
			"precondition: the fixture point must genuinely be off the curve")

		assert.Error(t, ValidateECDHPeerPoint(offCurve))
	})

	t.Run("refuses the all-zero point", func(t *testing.T) {
		zero := make([]byte, 65)
		zero[0] = 0x04

		assert.Error(t, ValidateECDHPeerPoint(zero),
			"the point at infinity encoded as zeroes is not a valid peer key")
	})

	t.Run("refuses a compressed point", func(t *testing.T) {
		key, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)

		compressed := make([]byte, 33)
		compressed[0] = 0x02
		copy(compressed[1:], key.PublicKey().Bytes()[1:33])

		assert.Error(t, ValidateECDHPeerPoint(compressed),
			"PKCS#11 v3.2 §6.3.3 gives the uncompressed form; a length no curve uses must be refused")
	})

	t.Run("refuses an empty or truncated point", func(t *testing.T) {
		assert.Error(t, ValidateECDHPeerPoint(nil))
		assert.Error(t, ValidateECDHPeerPoint([]byte{0x04}))
		assert.Error(t, ValidateECDHPeerPoint(make([]byte, 64)))
	})

	t.Run("refuses a correctly sized point with a bad prefix", func(t *testing.T) {
		key, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)

		wrongPrefix := append([]byte(nil), key.PublicKey().Bytes()...)
		wrongPrefix[0] = 0x03

		assert.Error(t, ValidateECDHPeerPoint(wrongPrefix))
	})
}

// TestAuthWrapRefusesWeakerWrappingKey pins NIST SP 800-57 Part 1 Rev. 5 §5.6.2:
// a key shall not be protected by a key of lesser strength.
//
// A wrapped key is only as confidential as the key encryption key, so an
// AES-128 KEK over an AES-256 key exports that key at 128-bit strength while the
// application still believes it holds a 256-bit secret -- and the token said
// CKR_OK.
func TestAuthWrapRefusesWeakerWrappingKey(t *testing.T) {
	newAESKey := func(t *testing.T, size int) []byte {
		t.Helper()
		value := make([]byte, size)
		_, err := rand.Read(value)
		require.NoError(t, err)
		return value
	}

	createKey := func(t *testing.T, m *Module, session SessionHandle, value []byte, extra ...Attribute) ObjectHandle {
		t.Helper()
		handle, rv := m.CreateObject(session, append([]Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewAttribute(CKA_VALUE, value),
		}, extra...))
		require.Equal(t, CKR_OK, rv)
		return handle
	}

	cases := []struct {
		name       string
		kekSize    int
		targetSize int
		wantErr    bool
	}{
		{name: "AES-128 KEK over an AES-256 key is refused", kekSize: 16, targetSize: 32, wantErr: true},
		{name: "AES-192 KEK over an AES-256 key is refused", kekSize: 24, targetSize: 32, wantErr: true},
		{name: "AES-128 KEK over an AES-192 key is refused", kekSize: 16, targetSize: 24, wantErr: true},
		{name: "an equal-strength KEK is accepted", kekSize: 32, targetSize: 32, wantErr: false},
		{name: "a stronger KEK is accepted", kekSize: 32, targetSize: 16, wantErr: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := initializeTestModule(t)
			defer m.Finalize()

			session := loginAsNormalUser(t, m)

			wrappingKey := createKey(t, m, session, newAESKey(t, tc.kekSize),
				NewBoolAttribute(CKA_WRAP, true))
			targetKey := createKey(t, m, session, newAESKey(t, tc.targetSize),
				NewBoolAttribute(CKA_EXTRACTABLE, true))

			mechanism := NewMechanism(CKM_AES_GCM)

			_, err := m.WrapKeyAuthenticated(session, mechanism, wrappingKey, targetKey, nil)
			_, sizeErr := m.WrapKeyAuthenticatedSize(session, mechanism, wrappingKey, targetKey)

			if !tc.wantErr {
				require.NoError(t, err)
				require.NoError(t, sizeErr)
				return
			}

			require.Error(t, err)
			var pkcsErr *PKCS11Error
			require.ErrorAs(t, err, &pkcsErr)
			assert.Equal(t, CKR_WRAPPING_KEY_SIZE_RANGE, pkcsErr.Code)

			// The size query must refuse identically, or an application sizes a
			// buffer for a call that can only fail.
			require.Error(t, sizeErr, "the size query must answer as the wrap does")
			require.ErrorAs(t, sizeErr, &pkcsErr)
			assert.Equal(t, CKR_WRAPPING_KEY_SIZE_RANGE, pkcsErr.Code)
		})
	}
}
