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

package module

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// deriveRecordingClient captures the DeriveKey request the module builds.
//
// The whole defect this file guards against was invisible from outside: the
// module produced a well-formed, repeatable derived key whether or not the
// base key's material reached the KDF. What distinguishes the two is the
// request that crosses the transport, so the request is what is asserted.
type deriveRecordingClient struct {
	*mockClient
	lastDerive *transport.DeriveKeyRequest
}

func newDeriveRecordingClient() *deriveRecordingClient {
	return &deriveRecordingClient{mockClient: newMockClient()}
}

func (c *deriveRecordingClient) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	c.lastDerive = req
	return &transport.DeriveKeyResponse{
		DerivedKey: bytes.Repeat([]byte{0xA5}, 32),
		Algorithm:  req.Algorithm,
		KeyLength:  req.KeyLength,
	}, nil
}

var _ PKCS11Transport = (*deriveRecordingClient)(nil)

// deriveFixture returns an initialized, logged-in module whose transport
// records the derive request.
func deriveFixture(t *testing.T) (*Module, *deriveRecordingClient, SessionHandle) {
	t.Helper()

	ResetGlobalModule()
	client := newDeriveRecordingClient()
	m, err := New(WithClient(client), WithConfig(DefaultConfig()))
	require.NoError(t, err)
	require.Equal(t, CKR_OK, m.Initialize(nil))
	t.Cleanup(func() { m.Finalize() })

	return m, client, loginAsNormalUser(t, m)
}

// hkdfMechanism builds a CKM_HKDF_DERIVE mechanism with a complete
// CK_HKDF_PARAMS (v3.2 §6.62.2).
func hkdfMechanism(salt, info []byte) *Mechanism {
	return &Mechanism{
		Type: CKM_HKDF_DERIVE,
		TypedParameter: &HKDFParams{
			Extract:     true,
			Expand:      true,
			PRFHashMech: CKM_SHA256,
			SaltType:    CKF_HKDF_SALT_DATA,
			Salt:        salt,
			Info:        info,
		},
	}
}

// availableDeriveMechanism builds a derivation the token performs in either
// mode, for tests whose subject is the base key or the template rather than
// the KDF. HKDF over SHA-256 is inside the Go Cryptographic Module, so FIPS
// mode performs it too.
func availableDeriveMechanism() *Mechanism {
	return hkdfMechanism([]byte("salt"), []byte("info"))
}

// derivedKeyTemplate is the template C_DeriveKey is given for the new key.
func derivedKeyTemplate(valueLen uint32) []Attribute {
	return []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
		NewBoolAttribute(CKA_TOKEN, false),
		NewUint32Attribute(CKA_VALUE_LEN, valueLen),
	}
}

// generateDerivableSecret creates a secret key the way an application does:
// through C_GenerateKey, which creates the material inside the backend and
// leaves no CKA_VALUE on the object.
func generateDerivableSecret(t *testing.T, m *Module, session SessionHandle, label string) ObjectHandle {
	t.Helper()

	handle, rv := m.GenerateKey(session, &Mechanism{Type: CKM_AES_KEY_GEN}, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewStringAttribute(CKA_LABEL, label),
		NewBoolAttribute(CKA_DERIVE, true),
		NewBoolAttribute(CKA_TOKEN, false),
		NewUint32Attribute(CKA_VALUE_LEN, 32),
	})
	require.Equal(t, CKR_OK, rv)
	return handle
}

// TestDeriveKeySendsTheBaseKeyIdentityNotItsName is the regression test for the
// defect this change fixes.
//
// C_GenerateKey creates the key material inside the backend and keeps only the
// handle, the label and the backend key identifier on the object; nothing ever
// sets CKA_VALUE. module.DeriveKey used to substitute []byte(baseKeyObj.KeyID)
// — the "label-<unixnano>-<counter>" string — as the input keying material in
// exactly that case, so every derivation from a generated base key ran the KDF
// over the key's NAME. The result was well-formed, repeatable, and reproducible
// by anyone who knew the label.
//
// The request that crosses the transport is what tells the two apart. It must
// carry the base key's IDENTITY so the backend can run the KDF over the key it
// holds, and it must carry no input keying material at all — least of all the
// identifier bytes.
func TestDeriveKeySendsTheBaseKeyIdentityNotItsName(t *testing.T) {
	m, client, session := deriveFixture(t)

	base := generateDerivableSecret(t, m, session, "derive-base")

	_, rv := m.DeriveKey(session, hkdfMechanism([]byte("salt"), []byte("info")), base, derivedKeyTemplate(32))
	require.Equal(t, CKR_OK, rv)

	req := client.lastDerive
	require.NotNil(t, req, "C_DeriveKey must reach the transport")

	require.NotEmpty(t, req.KeyID,
		"the base key's identity is the only thing that lets the backend run the KDF over the "+
			"key it holds; without it the derivation has no base key at all")

	assert.Empty(t, req.InputKeyMaterial,
		"the module does not hold this key's material — C_GenerateKey created it in the backend — "+
			"so it must send none, and the backend must derive from the key it has")

	assert.NotEqual(t, []byte(req.KeyID), req.InputKeyMaterial,
		"the key identifier is not secret: deriving from it produces a key anyone who knows the "+
			"label can reproduce, which is the defect this test exists to catch")

	assert.Equal(t, "software", req.Backend,
		"the identity is a (backend, key id) pair; without the backend the service layer cannot "+
			"reach the key the identifier names")
	assert.Equal(t, "HKDF", req.Algorithm)
	assert.Equal(t, []byte("salt"), req.Salt)
	assert.Equal(t, []byte("info"), req.Info)
	assert.Equal(t, "SHA-256", req.Hash)
	assert.Equal(t, 32, req.KeyLength)
}

// TestDeriveKeySendsCKAValueWhenTheApplicationSuppliedIt covers the other half
// of the base-key contract.
//
// A key the application built with C_CreateObject carries its own CKA_VALUE, so
// the module already holds the material and sends it. PKCS#11 v3.2 §5.18.5
// places no extractability requirement on a base key, and this path must keep
// working: it is the only one that does not need the backend to hold the key.
//
// The identity must NOT also be sent. The two name different base keys, and a
// request carrying both lets the service layer pick one and answer with a key
// derived from material the caller did not select.
func TestDeriveKeySendsCKAValueWhenTheApplicationSuppliedIt(t *testing.T) {
	m, client, session := deriveFixture(t)

	material := bytes.Repeat([]byte{0x2B}, 32)
	base, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
		NewStringAttribute(CKA_LABEL, "app-supplied-base"),
		NewBoolAttribute(CKA_DERIVE, true),
		NewBoolAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_VALUE, material),
	})
	require.Equal(t, CKR_OK, rv)

	_, rv = m.DeriveKey(session, availableDeriveMechanism(), base, derivedKeyTemplate(32))
	require.Equal(t, CKR_OK, rv)

	req := client.lastDerive
	require.NotNil(t, req)

	assert.Equal(t, material, req.InputKeyMaterial,
		"the application supplied this key's bytes, so they are what the KDF must run over")
	assert.Empty(t, req.KeyID,
		"sending an identity alongside the material names a second base key; the request must "+
			"name exactly one")
}

// TestDeriveKeyRefusesABaseKeyWithNoMaterialAnywhere is the bad-input case.
//
// An object marked CKA_DERIVE that carries neither CKA_VALUE nor a backend key
// identifier names no key material at all. There is nothing to derive from, and
// there is no substitute: the fallback that used to stand in here is exactly
// what made derivations reproducible from a label.
//
// CKR_KEY_HANDLE_INVALID is in C_DeriveKey's return table (v3.2 §5.18.5) and
// §5.1 defines it to cover "a valid handle for an object which is not a key",
// which is what this object is for derivation purposes.
// CKR_KEY_FUNCTION_NOT_PERMITTED already means "not marked for derivation" a
// few lines earlier in the same function and is deliberately not reused.
func TestDeriveKeyRefusesABaseKeyWithNoMaterialAnywhere(t *testing.T) {
	m, client, session := deriveFixture(t)

	base, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_GENERIC_SECRET)),
		NewStringAttribute(CKA_LABEL, "no-material"),
		NewBoolAttribute(CKA_DERIVE, true),
		NewBoolAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_VALUE, make([]byte, 32)),
	})
	require.Equal(t, CKR_OK, rv)

	// The material is removed after creation. C_CreateObject requires CKA_VALUE
	// for a generic secret key (v3.2 §6.19, Table 13 footnote 1), but an object
	// can still reach this state through restore-from-storage or C_UnwrapKey --
	// which is the case C_DeriveKey's refusal below defends.
	baseObj, baseErr := m.objectManager.getObjectUnchecked(base)
	require.NoError(t, baseErr)
	delete(baseObj.Attributes, CKA_VALUE)
	baseObj.KeyID = ""

	handle, rv := m.DeriveKey(session, availableDeriveMechanism(), base, derivedKeyTemplate(32))
	assert.Equal(t, CKR_KEY_HANDLE_INVALID, rv)
	assert.Equal(t, ObjectHandle(InvalidHandle), handle)
	assert.Nil(t, client.lastDerive,
		"a base key that resolves to no material must be refused before anything reaches the "+
			"backend; sending the request would let the backend answer it with something")
}

// TestDeriveKeySP800108SendsTheBaseKeyIdentity proves the identity reaches the
// backend for the SP 800-108 modes too, carrying the label and context the
// CK_PRF_DATA_PARAM array encodes (v3.2 §6.42).
//
// All three modes are covered because they take the same CK_SP800_108_KDF_PARAMS
// and differ only in the algorithm name the request carries; a mode wired to the
// wrong name derives a different key with no error raised.
func TestDeriveKeySP800108SendsTheBaseKeyIdentity(t *testing.T) {
	label := []byte("purpose")
	context := []byte("context")

	dataParams := []SP800108DataParam{
		{Type: SP800108IterationVariable},
		{Type: SP800108ByteArray, Value: label},
		{Type: SP800108ByteArray, Value: []byte{0x00}},
		{Type: SP800108ByteArray, Value: context},
	}

	for _, tc := range []struct {
		mechanism MechanismType
		algorithm string
	}{
		{CKM_SP800_108_COUNTER_KDF, "SP800-108-COUNTER"},
		{CKM_SP800_108_FEEDBACK_KDF, "SP800-108-FEEDBACK"},
		{CKM_SP800_108_DOUBLE_PIPELINE_KDF, "SP800-108-DOUBLE-PIPELINE"},
	} {
		t.Run(tc.algorithm, func(t *testing.T) {
			m, client, session := deriveFixture(t)
			base := generateDerivableSecret(t, m, session, "sp800108-base")

			mech := &Mechanism{
				Type: tc.mechanism,
				TypedParameter: &SP800108KDFParams{
					PRF:        CKM_SHA256_HMAC,
					DataParams: dataParams,
				},
			}
			_, rv := m.DeriveKey(session, mech, base, derivedKeyTemplate(32))
			require.Equal(t, CKR_OK, rv)

			req := client.lastDerive
			require.NotNil(t, req)

			assert.Equal(t, tc.algorithm, req.Algorithm,
				"the mode must reach the backend by name; a mis-wired name derives a different key silently")
			assert.NotEmpty(t, req.KeyID,
				"SP 800-108r1 derives from a key-derivation key, and the backend can only reach it by identity")
			assert.Empty(t, req.InputKeyMaterial)
			assert.Equal(t, label, req.Label)
			assert.Equal(t, context, req.Context)
		})
	}
}

// TestCryptoManagerDeriveKeyRefusesARequestWithNoBaseKey covers the transport
// layer directly.
//
// Module.DeriveKey rejects this first, but CryptoManager.DeriveKey is the
// function that would otherwise build a request naming no base key at all — the
// service layer would answer that with a generic failure instead of the real
// problem — so it refuses on its own.
func TestCryptoManagerDeriveKeyRefusesARequestWithNoBaseKey(t *testing.T) {
	client := newDeriveRecordingClient()
	cm := NewCryptoManager(client, nil)

	op, err := cm.DeriveKeyInit(hkdfMechanism([]byte("salt"), []byte("info")), ObjectHandle(1), "", "software")
	require.NoError(t, err)

	_, err = cm.DeriveKey(context.Background(), op, nil, 32)
	require.Error(t, err)

	var pkcsErr *PKCS11Error
	require.ErrorAs(t, err, &pkcsErr)
	assert.Equal(t, CKR_KEY_HANDLE_INVALID, pkcsErr.Code)
	assert.Nil(t, client.lastDerive, "nothing must reach the transport")
}
