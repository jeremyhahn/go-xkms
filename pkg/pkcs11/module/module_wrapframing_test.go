// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package module

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The wire format C_WrapKey emits and C_UnwrapKey consumes, restated here as
// the constants the oracle below frames with. They are the service's, not this
// module's: pkg/xkms/servicer_wrapkey.go produces exactly this shape and
// pkg/xkms/servicer_wrapkey_params_test.go checks it against crypto/cipher.
const (
	oracleGCMNonceSize = 12
	oracleGCMTagSize   = 16
	oracleCBCIVSize    = 16
)

// wrapOracleTransport is a stand-in for the xkms service that performs real
// cryptography with the Go standard library.
//
// It exists because the ordinary mockClient answers WrapKeyByID with a fixed
// string, which made every wrap assertion in this package vacuous: "CKR_OK and
// a non-empty slice" holds for any bytes at all, including a blob nothing can
// unwrap. Wrapping here with crypto/cipher and crypto/rsa, in the framing the
// service uses, is what lets a test recover the original key bytes and say so.
//
// It performs no operation the module also performs: the module's job is to
// carry material and CK_MECHANISM parameters faithfully, and that is what these
// tests measure.
type wrapOracleTransport struct {
	*mockClient

	// kek is the AES key-encryption key every symmetric mechanism wraps under.
	kek []byte

	// rsaKey is the RSA key pair the asymmetric mechanisms wrap under.
	rsaKey *rsa.PrivateKey

	// material maps a backend key id onto the plaintext a wrap of that key
	// must produce, standing in for the service's ExportKeyMaterial.
	material map[string][]byte

	lastWrapReq   *transport.WrapKeyByIDRequest
	lastUnwrapReq *transport.UnwrapKeyByIDRequest

	// unwrapped is the plaintext the last UnwrapKeyByID recovered.
	unwrapped []byte
}

// Compile-time check: wrapOracleTransport satisfies PKCS11Transport.
//
// Every test double in this package carries this assertion so that adding a
// method to the interface fails here, at the definition, rather than at each
// place the double is passed to WithClient or NewCryptoManager.
var _ PKCS11Transport = (*wrapOracleTransport)(nil)

func newWrapOracleTransport(t *testing.T) *wrapOracleTransport {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return &wrapOracleTransport{
		mockClient: newMockClient(),
		kek:        []byte("0123456789ABCDEF0123456789ABCDEF"),
		rsaKey:     rsaKey,
		material:   make(map[string][]byte),
	}
}

func (o *wrapOracleTransport) gcmTagSize(tagBits int) int {
	if tagBits == 0 {
		return oracleGCMTagSize
	}
	return tagBits / 8
}

// ImportKey completes the ceremony the embedded mockClient runs and then
// records the recovered plaintext under the new key id.
//
// C_CreateObject imports a secret key's material, so a key an application
// created that way is afterwards a key this oracle holds -- which is the whole
// point of the change these tests cover. Recording it here is what lets the
// same key be named as a wrapping key or resolved as a wrap target by id,
// exactly as the service resolves it.
func (o *wrapOracleTransport) ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	resp, err := o.mockClient.ImportKey(ctx, req)
	if err != nil {
		return nil, err
	}
	o.material[req.KeyID] = o.mockClient.importedMaterial[req.KeyID]
	return resp, nil
}

// symmetricKEK resolves the key-encryption key a request names.
//
// The oracle used to wrap under its own fixed o.kek whatever key the request
// named, which made every symmetric assertion independent of the key id the
// module sent -- so a module that named the wrong key, or no key at all, still
// round-tripped here. Resolving the id against the material this oracle holds
// is what the service does, and it is what makes "the KEK must be resolvable
// server-side" a property these tests can actually observe. The fallback
// covers the fixtures that never import a KEK at all.
func (o *wrapOracleTransport) symmetricKEK(keyID string) []byte {
	if material, ok := o.material[keyID]; ok && len(material) > 0 {
		return material
	}
	return o.kek
}

func (o *wrapOracleTransport) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	o.lastWrapReq = req

	material := req.TargetKeyMaterial
	if len(material) == 0 {
		material = o.material[req.TargetKeyID]
	}
	if len(material) == 0 {
		return nil, NewPKCS11ErrorWithMessage(CKR_KEY_HANDLE_INVALID, "oracle has no material for the target key")
	}

	wrapped, err := o.wrap(req, material)
	if err != nil {
		return nil, err
	}
	return &transport.WrapKeyByIDResponse{WrappedKey: wrapped, Algorithm: req.Algorithm}, nil
}

func (o *wrapOracleTransport) wrap(req *transport.WrapKeyByIDRequest, material []byte) ([]byte, error) {
	kek := o.symmetricKEK(req.WrappingKeyID)

	switch types.KeyWrapAlgorithm(req.Algorithm) {
	case types.WrapAESKW:
		return wrapping.WrapAESKW(material, kek)

	case types.WrapAESKWP:
		return wrapping.WrapAESKWP(material, kek)

	case types.WrapAESGCM:
		block, err := aes.NewCipher(kek)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCMWithTagSize(block, o.gcmTagSize(req.TagBits))
		if err != nil {
			return nil, err
		}
		nonce := req.IV
		if len(nonce) == 0 {
			nonce = make([]byte, oracleGCMNonceSize)
			if _, err := rand.Read(nonce); err != nil {
				return nil, err
			}
		}
		return append(append([]byte{}, nonce...), gcm.Seal(nil, nonce, material, req.AAD)...), nil

	case types.WrapAESCBC, types.WrapAESCBCPad:
		block, err := aes.NewCipher(kek)
		if err != nil {
			return nil, err
		}
		plaintext := material
		if types.KeyWrapAlgorithm(req.Algorithm) == types.WrapAESCBCPad {
			pad := aes.BlockSize - len(plaintext)%aes.BlockSize
			plaintext = append(append([]byte{}, plaintext...), bytes.Repeat([]byte{byte(pad)}, pad)...)
		}
		if len(plaintext)%aes.BlockSize != 0 {
			return nil, NewPKCS11ErrorWithMessage(CKR_DATA_LEN_RANGE, "cbc input is not block aligned")
		}
		iv := req.IV
		if len(iv) == 0 {
			iv = make([]byte, oracleCBCIVSize)
			if _, err := rand.Read(iv); err != nil {
				return nil, err
			}
		}
		out := make([]byte, len(plaintext))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
		return append(append([]byte{}, iv...), out...), nil

	case types.WrapRSAOAEPSHA256:
		return rsa.EncryptOAEP(sha256.New(), rand.Reader, &o.rsaKey.PublicKey, material, req.OAEPLabel)

	case types.WrapRSAPKCS1v15:
		return rsa.EncryptPKCS1v15(rand.Reader, &o.rsaKey.PublicKey, material)
	}

	return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID, "oracle does not implement "+req.Algorithm)
}

func (o *wrapOracleTransport) UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	o.lastUnwrapReq = req

	plaintext, err := o.unwrap(req)
	if err != nil {
		return nil, err
	}
	o.unwrapped = plaintext
	o.material[req.TargetKeyID] = plaintext

	return &transport.UnwrapKeyByIDResponse{
		KeyID:   req.TargetKeyID,
		Backend: req.TargetKeyBackend,
		Success: true,
	}, nil
}

func (o *wrapOracleTransport) unwrap(req *transport.UnwrapKeyByIDRequest) ([]byte, error) {
	kek := o.symmetricKEK(req.UnwrappingKeyID)

	switch types.KeyWrapAlgorithm(req.Algorithm) {
	case types.WrapAESKW:
		return wrapping.UnwrapAESKW(req.WrappedKey, kek)

	case types.WrapAESKWP:
		return wrapping.UnwrapAESKWP(req.WrappedKey, kek)

	case types.WrapAESGCM:
		tagSize := o.gcmTagSize(req.TagBits)
		if len(req.WrappedKey) < oracleGCMNonceSize+tagSize {
			return nil, NewPKCS11ErrorWithMessage(CKR_WRAPPED_KEY_LEN_RANGE, "gcm blob is too short")
		}
		block, err := aes.NewCipher(kek)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCMWithTagSize(block, tagSize)
		if err != nil {
			return nil, err
		}
		return gcm.Open(nil, req.WrappedKey[:oracleGCMNonceSize], req.WrappedKey[oracleGCMNonceSize:], req.AAD)

	case types.WrapAESCBC, types.WrapAESCBCPad:
		if len(req.WrappedKey) <= oracleCBCIVSize {
			return nil, NewPKCS11ErrorWithMessage(CKR_WRAPPED_KEY_LEN_RANGE, "cbc blob is too short")
		}
		block, err := aes.NewCipher(kek)
		if err != nil {
			return nil, err
		}
		ciphertext := req.WrappedKey[oracleCBCIVSize:]
		if len(ciphertext)%aes.BlockSize != 0 {
			return nil, NewPKCS11ErrorWithMessage(CKR_WRAPPED_KEY_LEN_RANGE, "cbc ciphertext is not block aligned")
		}
		out := make([]byte, len(ciphertext))
		cipher.NewCBCDecrypter(block, req.WrappedKey[:oracleCBCIVSize]).CryptBlocks(out, ciphertext)
		if types.KeyWrapAlgorithm(req.Algorithm) == types.WrapAESCBCPad {
			pad := int(out[len(out)-1])
			if pad == 0 || pad > aes.BlockSize || pad > len(out) {
				return nil, NewPKCS11ErrorWithMessage(CKR_WRAPPED_KEY_INVALID, "bad pkcs#7 padding")
			}
			out = out[:len(out)-pad]
		}
		return out, nil

	case types.WrapRSAOAEPSHA256:
		return rsa.DecryptOAEP(sha256.New(), rand.Reader, o.rsaKey, req.WrappedKey, req.OAEPLabel)

	case types.WrapRSAPKCS1v15:
		return rsa.DecryptPKCS1v15(rand.Reader, o.rsaKey, req.WrappedKey)
	}

	return nil, NewPKCS11ErrorWithMessage(CKR_MECHANISM_INVALID, "oracle does not implement "+req.Algorithm)
}

// newWrapRoundTripModule returns a module whose transport is the crypto oracle,
// along with a logged-in session, a wrapping key and a target key created the
// way an application imports one: C_CreateObject with CKA_VALUE, which is the
// case that produced an unrecoverable blob.
//
// Neither key is bound to a backend by the test. C_CreateObject imports a
// secret key's material itself now, so both come back already naming a key the
// oracle holds -- which is what makes the KEK usable here at all. A fixture
// that assigned the id by hand would prove nothing about the code path an
// application actually takes.
func newWrapRoundTripModule(t *testing.T, targetValue []byte) (*Module, *wrapOracleTransport, SessionHandle, ObjectHandle, ObjectHandle) {
	t.Helper()

	m := initializeTestModule(t)
	oracle := newWrapOracleTransport(t)
	m.cryptoManager.client = oracle

	session := loginAsNormalUser(t, m)

	wrappingKey, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "round-trip-kek"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_WRAP, true),
		NewBoolAttribute(CKA_UNWRAP, true),
		NewAttribute(CKA_VALUE, []byte("0123456789ABCDEF")),
	})
	require.Equal(t, CKR_OK, rv)
	requireBoundToBackend(t, m, wrappingKey)

	targetKey, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, "round-trip-target"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewAttribute(CKA_VALUE, targetValue),
	})
	require.Equal(t, CKR_OK, rv)

	return m, oracle, session, wrappingKey, targetKey
}

// unwrapTemplate is the C_UnwrapKey template for an AES secret key.
func unwrapTemplate() []Attribute {
	return []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
	}
}

// TestWrapUnwrapRoundTripRecoversOriginalKeyBytes is the round trip C_WrapKey
// never had: for every mechanism this token wraps with, a key imported by
// C_CreateObject is wrapped, and the blob is unwrapped back to the original
// bytes.
//
// Each mechanism used to fail differently and silently. AES-GCM emitted
// ciphertext||tag and discarded the token-generated nonce, so the blob was
// unrecoverable by anyone including this module. AES-CBC emitted no IV where
// C_UnwrapKey expects one at the front. The AES key-wrap mechanisms could not
// be reached at all, because C_EncryptInit refuses a mechanism without
// CKF_ENCRYPT. Every one of them returned CKR_OK.
//
// The mechanism list is not a sample: it is every mechanism C_WrapKey and
// C_UnwrapKey both accept, which is what makes this an N-of-N check rather
// than an N-1-of-N one. TestWrapMechanismsAllRoundTrip below asserts the list
// stays complete.
func TestWrapUnwrapRoundTripRecoversOriginalKeyBytes(t *testing.T) {
	for _, tc := range wrapRoundTripCases() {
		t.Run(GetMechanismName(tc.mechType), func(t *testing.T) {
			m, oracle, session, wrappingKey, targetKey := newWrapRoundTripModule(t, tc.value)
			defer m.Finalize()

			wrapped, rv := m.WrapKey(session, tc.mechanism(), wrappingKey, targetKey)
			require.Equal(t, CKR_OK, rv)
			require.NotEmpty(t, wrapped)

			// The blob must not be the plaintext, which is the one thing
			// "CKR_OK and non-empty" never ruled out.
			assert.NotEqual(t, tc.value, wrapped)

			handle, rv := m.UnwrapKey(session, tc.mechanism(), wrappingKey, wrapped, unwrapTemplate())
			require.Equal(t, CKR_OK, rv, "the blob C_WrapKey produced must be one C_UnwrapKey can consume")
			require.NotEqual(t, ObjectHandle(InvalidHandle), handle)

			assert.Equal(t, tc.value, oracle.unwrapped,
				"the round trip must recover the original key bytes")
		})
	}
}

// wrapRoundTripCase is one mechanism's round trip, with key material sized for
// the mechanism's own constraints.
type wrapRoundTripCase struct {
	mechType  MechanismType
	value     []byte
	mechanism func() *Mechanism
}

func wrapRoundTripCases() []wrapRoundTripCase {
	// aligned is one AES block, which the unpadded CBC mechanism requires and
	// every other mechanism accepts.
	aligned := []byte("SECRETKEYVALUE!!")
	cbcIV := []byte("wrap-cbc-iv-0123")

	return []wrapRoundTripCase{
		{CKM_AES_KEY_WRAP, aligned, func() *Mechanism { return &Mechanism{Type: CKM_AES_KEY_WRAP} }},
		{CKM_AES_KEY_WRAP_KWP, []byte("odd length key"), func() *Mechanism { return &Mechanism{Type: CKM_AES_KEY_WRAP_KWP} }},
		{CKM_AES_KEY_WRAP_PAD, []byte("odd length key"), func() *Mechanism { return &Mechanism{Type: CKM_AES_KEY_WRAP_PAD} }},
		{CKM_AES_GCM, aligned, func() *Mechanism {
			return NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(nil, 128))
		}},
		{CKM_AES_CBC, aligned, func() *Mechanism {
			return NewMechanismWithTypedParams(CKM_AES_CBC, newAESCBCParams(cbcIV))
		}},
		{CKM_AES_CBC_PAD, []byte("odd length key"), func() *Mechanism {
			return NewMechanismWithTypedParams(CKM_AES_CBC_PAD, newAESCBCParams(cbcIV))
		}},
		{CKM_RSA_PKCS_OAEP, aligned, func() *Mechanism {
			return NewMechanismWithTypedParams(CKM_RSA_PKCS_OAEP, NewRSAOAEPParams(CKM_SHA256))
		}},
		{CKM_RSA_PKCS, aligned, func() *Mechanism { return &Mechanism{Type: CKM_RSA_PKCS} }},
	}
}

func newAESCBCParams(iv []byte) *AESCBCParams {
	params := &AESCBCParams{}
	copy(params.IV[:], iv)
	return params
}

// TestWrapMechanismsAllRoundTrip is the completeness guard on the table above.
//
// A mechanism that C_WrapKey and C_UnwrapKey both accept but that no round trip
// covers is exactly how a wrap that emits an unrecoverable blob survives a
// green test run: the mechanism was gated, named and routed, and nothing ever
// asked whether the two directions agreed.
func TestWrapMechanismsAllRoundTrip(t *testing.T) {
	covered := make(map[MechanismType]bool, len(wrapRoundTripCases()))
	for _, tc := range wrapRoundTripCases() {
		covered[tc.mechType] = true
	}

	routed := []MechanismType{CKM_RSA_PKCS_OAEP}
	for mechType := range wrapAlgorithmNames {
		routed = append(routed, mechType)
	}

	for _, mechType := range routed {
		if !CanWrap(mechType) || !CanUnwrap(mechType) {
			continue
		}
		assert.True(t, covered[mechType],
			"%s is wrapped and unwrapped by this token but no round trip proves the two agree",
			GetMechanismName(mechType))
	}
}

// TestWrapKeyCarriesLocalKeyMaterialToTheService proves a key this token could
// not import travels as material rather than being encrypted here.
//
// This is the routing decision the whole framing fix rests on: such a target
// has no backend key id, and the alternative -- encrypting its value locally --
// is what produced blobs framed differently from the ones C_UnwrapKey parses.
//
// The target is 20 bytes, which is a legal generic secret and a legal AES-GCM
// input but not an AES key length, so C_CreateObject keeps it local. That is
// the remaining population for this path: since C_CreateObject began importing
// secret keys, a target of an importable length is named by id instead, and
// TestWrapKeyNamesABackendResidentTargetByID covers that half.
func TestWrapKeyCarriesLocalKeyMaterialToTheService(t *testing.T) {
	value := []byte("TWENTY-BYTE-SECRET!!")
	require.Len(t, value, 20, "the point of this fixture is a length the token cannot import")

	m, oracle, session, wrappingKey, _ := newWrapRoundTripModule(t, []byte("SECRETKEYVALUE!!"))
	defer m.Finalize()

	targetKey, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
		NewStringAttribute(CKA_LABEL, "unimportable-target"),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_EXTRACTABLE, true),
		NewAttribute(CKA_VALUE, value),
	})
	require.Equal(t, CKR_OK, rv)

	obj, err := m.objectManager.getObjectUnchecked(targetKey)
	require.NoError(t, err)
	require.Empty(t, obj.KeyID, "a 20-byte secret has no AES algorithm to be imported as")

	kekID := requireBoundToBackend(t, m, wrappingKey)

	_, rv = m.WrapKey(session, NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(nil, 128)),
		wrappingKey, targetKey)
	require.Equal(t, CKR_OK, rv)

	require.NotNil(t, oracle.lastWrapReq)
	assert.Equal(t, value, oracle.lastWrapReq.TargetKeyMaterial)
	assert.Empty(t, oracle.lastWrapReq.TargetKeyID,
		"a key resident in no backend must not be named by an id the service cannot resolve")
	assert.Equal(t, kekID, oracle.lastWrapReq.WrappingKeyID)
}

// TestWrapKeyNamesABackendResidentTargetByID is the other half: a key the
// backend holds must still be named by id, so its plaintext is never assembled
// in this process.
func TestWrapKeyNamesABackendResidentTargetByID(t *testing.T) {
	m, oracle, session, wrappingKey, targetKey := newWrapRoundTripModule(t, []byte("SECRETKEYVALUE!!"))
	defer m.Finalize()

	bindObjectToBackend(t, m, targetKey, "resident-target")
	oracle.material["resident-target"] = []byte("MATERIALHELDINTHEBACKEND--------")

	wrapped, rv := m.WrapKey(session, NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(nil, 128)),
		wrappingKey, targetKey)
	require.Equal(t, CKR_OK, rv)
	require.NotEmpty(t, wrapped)

	require.NotNil(t, oracle.lastWrapReq)
	assert.Equal(t, "resident-target", oracle.lastWrapReq.TargetKeyID)
	assert.Empty(t, oracle.lastWrapReq.TargetKeyMaterial,
		"a backend-resident key's plaintext must never leave the backend through this module")

	// Both forms produce the same framing, so the resident form round trips too.
	_, rv = m.UnwrapKey(session, NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(nil, 128)),
		wrappingKey, wrapped, unwrapTemplate())
	require.Equal(t, CKR_OK, rv)
	assert.Equal(t, []byte("MATERIALHELDINTHEBACKEND--------"), oracle.unwrapped)
}

// TestWrapKeyThreadsGCMParameters proves CK_GCM_PARAMS survives the trip to the
// service on both C_WrapKey and C_UnwrapKey.
//
// The pIv, pAAD and ulTagBits fields were honoured on the local wrap path and
// dropped on the backend one, so the same call behaved differently depending on
// where the key lived. Here they must arrive intact and the round trip must
// still recover the original bytes, which it cannot do if either direction
// drops the AAD or resolves a different tag length.
func TestWrapKeyThreadsGCMParameters(t *testing.T) {
	value := []byte("SECRETKEYVALUE!!")
	m, oracle, session, wrappingKey, targetKey := newWrapRoundTripModule(t, value)
	defer m.Finalize()

	nonce := []byte("caller-nonce")
	aad := []byte("tenant-42")
	mech := func() *Mechanism {
		params := NewAESGCMParams(nonce, 96)
		params.AAD = aad
		return NewMechanismWithTypedParams(CKM_AES_GCM, params)
	}

	wrapped, rv := m.WrapKey(session, mech(), wrappingKey, targetKey)
	require.Equal(t, CKR_OK, rv)

	require.NotNil(t, oracle.lastWrapReq)
	assert.Equal(t, nonce, oracle.lastWrapReq.IV)
	assert.Equal(t, aad, oracle.lastWrapReq.AAD)
	assert.Equal(t, 96, oracle.lastWrapReq.TagBits)

	// The framing must carry the caller's nonce, and the tag must be the 12
	// bytes ulTagBits asked for rather than the full 16.
	require.Equal(t, oracleGCMNonceSize+len(value)+12, len(wrapped))
	assert.Equal(t, nonce, wrapped[:oracleGCMNonceSize])

	_, rv = m.UnwrapKey(session, mech(), wrappingKey, wrapped, unwrapTemplate())
	require.Equal(t, CKR_OK, rv)
	require.NotNil(t, oracle.lastUnwrapReq)
	assert.Equal(t, aad, oracle.lastUnwrapReq.AAD, "AAD is not carried in the blob, so the unwrap must repeat it")
	assert.Equal(t, 96, oracle.lastUnwrapReq.TagBits)
	assert.Equal(t, value, oracle.unwrapped)
}

// TestWrapKeyThreadsOAEPLabel proves CK_RSA_PKCS_OAEP_PARAMS.pSourceData
// reaches the service on both directions.
//
// This is the failure a self-round trip could not see: the wrap encrypted under
// the empty label and reported success, and because C_UnwrapKey dropped the
// label too, the module's own inverse still recovered the key. Asserting the
// request field is what makes the omission visible from inside this package;
// pkg/xkms proves crypto/rsa refuses the same blob without the label.
func TestWrapKeyThreadsOAEPLabel(t *testing.T) {
	value := []byte("SECRETKEYVALUE!!")
	m, oracle, session, wrappingKey, targetKey := newWrapRoundTripModule(t, value)
	defer m.Finalize()

	label := []byte("tenant-42")
	mech := func() *Mechanism {
		params := NewRSAOAEPParams(CKM_SHA256)
		params.Source = CKZ_DATA_SPECIFIED
		params.SourceData = label
		return NewMechanismWithTypedParams(CKM_RSA_PKCS_OAEP, params)
	}

	wrapped, rv := m.WrapKey(session, mech(), wrappingKey, targetKey)
	require.Equal(t, CKR_OK, rv)

	require.NotNil(t, oracle.lastWrapReq)
	assert.Equal(t, label, oracle.lastWrapReq.OAEPLabel)
	assert.Equal(t, string(types.WrapRSAOAEPSHA256), oracle.lastWrapReq.Algorithm)

	// A peer that honours the label must be the one able to read it: decoding
	// with the empty label must fail.
	_, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, oracle.rsaKey, wrapped, nil)
	assert.Error(t, err, "the blob must be bound to the label, not to the empty label")

	recovered, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, oracle.rsaKey, wrapped, label)
	require.NoError(t, err)
	assert.Equal(t, value, recovered)

	_, rv = m.UnwrapKey(session, mech(), wrappingKey, wrapped, unwrapTemplate())
	require.Equal(t, CKR_OK, rv)
	assert.Equal(t, label, oracle.lastUnwrapReq.OAEPLabel)
	assert.Equal(t, value, oracle.unwrapped)
}

// TestWrapKeyThreadsCBCIV proves the CK_AES_CBC IV reaches the service and is
// the IV the blob carries.
func TestWrapKeyThreadsCBCIV(t *testing.T) {
	value := []byte("SECRETKEYVALUE!!")
	m, oracle, session, wrappingKey, targetKey := newWrapRoundTripModule(t, value)
	defer m.Finalize()

	iv := []byte("wrap-cbc-iv-0123")
	mech := NewMechanismWithTypedParams(CKM_AES_CBC, newAESCBCParams(iv))

	wrapped, rv := m.WrapKey(session, mech, wrappingKey, targetKey)
	require.Equal(t, CKR_OK, rv)

	require.NotNil(t, oracle.lastWrapReq)
	assert.Equal(t, iv, oracle.lastWrapReq.IV)
	assert.Equal(t, iv, wrapped[:oracleCBCIVSize],
		"the blob must carry the IV at the front, which is where C_UnwrapKey reads it")
}

// TestWrapKeyRejectsMechanismParametersItCannotHonour is the bad-input half of
// the parameter threading. Every case names a parameter the token cannot
// perform, and every one must be refused rather than performed under some other
// parameter and reported as success.
func TestWrapKeyRejectsMechanismParametersItCannotHonour(t *testing.T) {
	for _, tc := range []struct {
		name string
		mech func() *Mechanism
	}{
		{
			// PKCS#11 v3.2 §6.13.3 fixes the AES-GCM IV at 96 bits here.
			name: "gcm nonce of the wrong length",
			mech: func() *Mechanism {
				return NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams([]byte("short"), 128))
			},
		},
		{
			// NIST SP 800-38D admits 96..128 bits and nothing below.
			name: "gcm tag length outside SP 800-38D",
			mech: func() *Mechanism {
				return NewMechanismWithTypedParams(CKM_AES_GCM, NewAESGCMParams(nil, 64))
			},
		},
		{
			// §6.10: the CBC mechanism parameter is the IV, and it is required.
			name: "cbc with no IV parameter",
			mech: func() *Mechanism { return &Mechanism{Type: CKM_AES_CBC} },
		},
		{
			// The service performs MGF1 over hashAlg and nothing else, so a
			// different MGF must be refused rather than silently replaced.
			name: "oaep MGF that does not match hashAlg",
			mech: func() *Mechanism {
				params := NewRSAOAEPParams(CKM_SHA256)
				params.MGF = CKG_MGF1_SHA512
				return NewMechanismWithTypedParams(CKM_RSA_PKCS_OAEP, params)
			},
		},
		{
			// §6.1.8 defines CKZ_DATA_SPECIFIED as the only source.
			name: "oaep source the spec does not define",
			mech: func() *Mechanism {
				params := NewRSAOAEPParams(CKM_SHA256)
				params.Source = 0x99
				return NewMechanismWithTypedParams(CKM_RSA_PKCS_OAEP, params)
			},
		},
		{
			name: "oaep label with no source naming it",
			mech: func() *Mechanism {
				params := NewRSAOAEPParams(CKM_SHA256)
				params.Source = 0
				params.SourceData = []byte("tenant-42")
				return NewMechanismWithTypedParams(CKM_RSA_PKCS_OAEP, params)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, oracle, session, wrappingKey, targetKey := newWrapRoundTripModule(t, []byte("SECRETKEYVALUE!!"))
			defer m.Finalize()

			_, rv := m.WrapKey(session, tc.mech(), wrappingKey, targetKey)
			assert.Equal(t, CKR_MECHANISM_PARAM_INVALID, rv)
			assert.Nil(t, oracle.lastWrapReq,
				"a parameter the token cannot honour must be refused before any wrap happens")

			_, rv = m.UnwrapKey(session, tc.mech(), wrappingKey, []byte("wrapped-blob-value-long-enough--"), unwrapTemplate())
			assert.Equal(t, CKR_MECHANISM_PARAM_INVALID, rv)
			assert.Nil(t, oracle.lastUnwrapReq,
				"C_UnwrapKey must apply the same parameter validation as C_WrapKey")
		})
	}
}

// TestWrapMechanismParametersAcceptsAMechanismWithoutParameters proves the
// permitted cases are still permitted: a token-generated AES-GCM IV (v3.2
// §6.13.3), an OAEP mechanism with defaulted parameters (§6.1.8), and a
// mechanism that takes no parameters at all.
func TestWrapMechanismParametersAcceptsAMechanismWithoutParameters(t *testing.T) {
	for _, mech := range []*Mechanism{
		{Type: CKM_AES_GCM},
		{Type: CKM_RSA_PKCS_OAEP},
		{Type: CKM_AES_KEY_WRAP},
		{Type: CKM_RSA_PKCS},
	} {
		params, rv := wrapMechanismParameters(mech)
		assert.Equal(t, CKR_OK, rv, "%s", GetMechanismName(mech.Type))
		assert.Empty(t, params.IV)
		assert.Empty(t, params.AAD)
		assert.Zero(t, params.TagBits)
		assert.Empty(t, params.OAEPLabel)
	}
}

// TestWrapMechanismParametersRejectsNil covers the nil mechanism, which reaches
// here only if a caller bypasses C_WrapKey's own mechanism validation.
func TestWrapMechanismParametersRejectsNil(t *testing.T) {
	_, rv := wrapMechanismParameters(nil)
	assert.Equal(t, CKR_MECHANISM_INVALID, rv)
}

// TestImportedKEKIsUsableForWrapAndUnwrap states this module's key wrapping
// contract: a key-encryption key an application supplied with C_CreateObject
// works, because C_CreateObject imports it into the backend.
//
// This test previously pinned the opposite. C_WrapKey and C_UnwrapKey perform
// their cryptography in the service, under a KEK the service resolves by
// (backend, key id), and an imported key used to receive no such id -- only
// C_GenerateKey, C_GenerateKeyPair and C_UnwrapKey assigned one. Both verbs
// therefore refused, and the refusal was recorded as the contract because
// carrying the KEK's plaintext on every wrap was the only module-side
// alternative, and no RPC wraps under caller-supplied key bytes.
//
// The resolution was to give the key an id rather than to send its bytes: the
// import happens once, at C_CreateObject, through the ceremony the wire already
// had. What the old test's third subtest arranged by hand -- an object with the
// same attributes that happened to name a backend key -- is now what every
// imported secret key looks like, so the case it isolated is the general one
// and is asserted here as such.
//
// The KEK is deliberately never bound by the test. Its id has to come from the
// import, or this proves nothing about the path an application takes.
func TestImportedKEKIsUsableForWrapAndUnwrap(t *testing.T) {
	const kekValue = "0123456789ABCDEF0123456789ABCDEF"
	const targetValue = "SECRETKEYVALUE!!"

	newImportedKEKModule := func(t *testing.T) (*Module, *wrapOracleTransport, SessionHandle, ObjectHandle, ObjectHandle) {
		t.Helper()

		m := initializeTestModule(t)
		oracle := newWrapOracleTransport(t)
		m.cryptoManager.client = oracle
		session := loginAsNormalUser(t, m)

		kek, rv := m.CreateObject(session, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, "imported-kek"),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_WRAP, true),
			NewBoolAttribute(CKA_UNWRAP, true),
			NewAttribute(CKA_VALUE, []byte(kekValue)),
		})
		require.Equal(t, CKR_OK, rv)

		target, rv := m.CreateObject(session, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, "imported-kek-target"),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
			NewAttribute(CKA_VALUE, []byte(targetValue)),
		})
		require.Equal(t, CKR_OK, rv)

		return m, oracle, session, kek, target
	}

	t.Run("C_CreateObject imports the KEK's material into the backend", func(t *testing.T) {
		m, oracle, _, kek, _ := newImportedKEKModule(t)
		defer m.Finalize()

		keyID := requireBoundToBackend(t, m, kek)
		assert.Equal(t, []byte(kekValue), oracle.material[keyID],
			"the backend must hold the exact bytes the template supplied, or the KEK is a different key")

		// The material reached the backend wrapped, never in the clear. This is
		// the property that makes importing acceptable for a TPM or an HSM at
		// all, and nothing else in this file observes it.
		require.NotNil(t, oracle.lastImportKeyReq)
		assert.NotContains(t, string(oracle.lastImportKeyReq.WrappedKeyMaterial), kekValue,
			"key material must never cross the transport in plaintext")
		assert.True(t, oracle.importParamsCalled,
			"the module must obtain import parameters rather than invent its own wrapping key")
	})

	t.Run("C_WrapKey accepts it", func(t *testing.T) {
		m, _, session, kek, target := newImportedKEKModule(t)
		defer m.Finalize()

		wrapped, rv := m.WrapKey(session, &Mechanism{Type: CKM_AES_KEY_WRAP}, kek, target)
		require.Equal(t, CKR_OK, rv,
			"an imported KEK names a backend key, so a service-side wrap can resolve it")
		require.NotEmpty(t, wrapped)
		assert.NotEqual(t, []byte(targetValue), wrapped, "the blob must not be the plaintext")
	})

	t.Run("C_UnwrapKey accepts it and the round trip recovers the key", func(t *testing.T) {
		m, oracle, session, kek, target := newImportedKEKModule(t)
		defer m.Finalize()

		wrapped, rv := m.WrapKey(session, &Mechanism{Type: CKM_AES_KEY_WRAP}, kek, target)
		require.Equal(t, CKR_OK, rv)

		handle, rv := m.UnwrapKey(session, &Mechanism{Type: CKM_AES_KEY_WRAP}, kek, wrapped, unwrapTemplate())
		require.Equal(t, CKR_OK, rv,
			"C_UnwrapKey must accept for the same reason C_WrapKey does, not diverge from it")
		require.NotEqual(t, ObjectHandle(InvalidHandle), handle)

		// Both halves agreeing on CKR_OK would still be satisfied by a blob
		// that decrypted to the wrong bytes. The recovered plaintext is the
		// assertion that cannot be satisfied by accident.
		assert.Equal(t, []byte(targetValue), oracle.unwrapped,
			"the unwrap must recover exactly the key the wrap consumed")
	})

	t.Run("a KEK that could not be imported is still refused", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()
		oracle := newWrapOracleTransport(t)
		m.cryptoManager.client = oracle
		session := loginAsNormalUser(t, m)

		// CKA_EXTRACTABLE=CK_FALSE keeps the key out of the backend, because
		// the import ceremony cannot carry that protection and creating an
		// extractable backend copy would silently widen it. Such a key has no
		// key id, so the two verbs refuse exactly as they did for every
		// imported key before this change -- which is the limitation the
		// fallback is documented to keep.
		kek, rv := m.CreateObject(session, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, "unextractable-kek"),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_WRAP, true),
			NewBoolAttribute(CKA_UNWRAP, true),
			NewBoolAttribute(CKA_EXTRACTABLE, false),
			NewAttribute(CKA_VALUE, []byte(kekValue)),
		})
		require.Equal(t, CKR_OK, rv)

		obj, err := m.objectManager.getObjectUnchecked(kek)
		require.NoError(t, err)
		require.Empty(t, obj.KeyID,
			"CKA_EXTRACTABLE=CK_FALSE must keep the key local rather than widen it in the backend")

		target, rv := m.CreateObject(session, []Attribute{
			NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
			NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
			NewStringAttribute(CKA_LABEL, "unextractable-kek-target"),
			NewBoolAttribute(CKA_TOKEN, false),
			NewBoolAttribute(CKA_EXTRACTABLE, true),
			NewAttribute(CKA_VALUE, []byte(targetValue)),
		})
		require.Equal(t, CKR_OK, rv)

		wrapped, rv := m.WrapKey(session, &Mechanism{Type: CKM_AES_KEY_WRAP}, kek, target)
		assert.Equal(t, CKR_WRAPPING_KEY_HANDLE_INVALID, rv,
			"a KEK that names no backend key cannot be the wrapping key of a service-side wrap")
		assert.Empty(t, wrapped, "a refused wrap must return no blob")

		handle, rv := m.UnwrapKey(session, &Mechanism{Type: CKM_AES_KEY_WRAP}, kek,
			[]byte("0123456789abcdef01234567"), unwrapTemplate())
		assert.Equal(t, CKR_UNWRAPPING_KEY_HANDLE_INVALID, rv,
			"C_UnwrapKey must refuse for the same reason C_WrapKey does, not a different one")
		assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	})
}
