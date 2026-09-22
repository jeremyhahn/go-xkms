// Copyright (C) 2025 go-xkms authors
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License as published
//    by the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html

package module

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// C4: the message-based AES-GCM encrypt path generates a fully random IV when
// asked to generate one. It cannot honour a caller-fixed IV prefix
// (ulIvFixedBits) or a counter construction, so a request that depends on
// either must be refused rather than silently downgraded to a different,
// caller-uncontrolled IV (§6.13.5).

func TestEncryptMessage_RefusesFixedBitsAndCounterIVGenerators(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	keyHandle, rv := m.CreateObject(session, aesKeyTemplate("gcm-msg-iv", make([]byte, 32), NewBoolAttribute(CKA_ENCRYPT, true)))
	require.Equal(t, CKR_OK, rv)

	cases := []struct {
		name   string
		params *AESGCMMessageParams
	}{
		{
			name: "nonzero IVFixedBits with CKG_GENERATE",
			params: &AESGCMMessageParams{
				IV:          make([]byte, GCMNonceSize),
				IVGenerator: CKG_GENERATE,
				IVFixedBits: 32,
				TagBits:     128,
			},
		},
		{
			name: "CKG_GENERATE_COUNTER",
			params: &AESGCMMessageParams{
				IV:          make([]byte, GCMNonceSize),
				IVGenerator: CKG_GENERATE_COUNTER,
				TagBits:     128,
			},
		},
		{
			name: "CKG_GENERATE_COUNTER_XOR",
			params: &AESGCMMessageParams{
				IV:          make([]byte, GCMNonceSize),
				IVGenerator: CKG_GENERATE_COUNTER_XOR,
				TagBits:     128,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, CKR_OK, m.MessageEncryptInit(session, NewMechanism(CKM_AES_GCM), keyHandle))
			_, rv := m.EncryptMessage(session, tc.params, nil, []byte("plaintext-block!"))
			assert.Equal(t, CKR_MECHANISM_PARAM_INVALID, rv,
				"a token that cannot preserve caller-fixed IV bits must refuse the request, not substitute a random IV")
			// Leave the session clean for the next case.
			m.FinishOperation(session, OperationEncrypt)
		})
	}
}

func TestEncryptMessage_AcceptsRandomIVGenerator(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	keyHandle, rv := m.CreateObject(session, aesKeyTemplate("gcm-msg-ok", make([]byte, 32), NewBoolAttribute(CKA_ENCRYPT, true)))
	require.Equal(t, CKR_OK, rv)

	// CKG_GENERATE_RANDOM with no fixed bits is exactly what this token can do,
	// so it must pass the IV-generator gate. Whether the mock backend then
	// completes the AES-GCM is out of scope for this parameter-validation test;
	// the point is that the request is not rejected at the gate.
	require.Equal(t, CKR_OK, m.MessageEncryptInit(session, NewMechanism(CKM_AES_GCM), keyHandle))
	_, rv = m.EncryptMessage(session, &AESGCMMessageParams{
		IV:          make([]byte, GCMNonceSize),
		IVGenerator: CKG_GENERATE_RANDOM,
		TagBits:     128,
	}, nil, []byte("plaintext-block!"))
	assert.NotEqual(t, CKR_MECHANISM_PARAM_INVALID, rv,
		"a random IV with no fixed bits must pass the IV-generator gate")
}

// C25: the multi-part message path (C_EncryptMessageNext) shares the C4 rule —
// it must refuse a caller-fixed IV prefix or a counter construction rather than
// silently substituting a random IV, exactly as the single-part path does.

func TestEncryptMessageNext_RefusesFixedBitsAndCounterIVGenerators(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	keyHandle, rv := m.CreateObject(session, aesKeyTemplate("gcm-next-iv", make([]byte, 32), NewBoolAttribute(CKA_ENCRYPT, true)))
	require.Equal(t, CKR_OK, rv)

	cases := []struct {
		name   string
		params *AESGCMMessageParams
	}{
		{"nonzero IVFixedBits", &AESGCMMessageParams{IV: make([]byte, GCMNonceSize), IVGenerator: CKG_GENERATE, IVFixedBits: 32, TagBits: 128}},
		{"CKG_GENERATE_COUNTER", &AESGCMMessageParams{IV: make([]byte, GCMNonceSize), IVGenerator: CKG_GENERATE_COUNTER, TagBits: 128}},
		{"CKG_GENERATE_COUNTER_XOR", &AESGCMMessageParams{IV: make([]byte, GCMNonceSize), IVGenerator: CKG_GENERATE_COUNTER_XOR, TagBits: 128}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, CKR_OK, m.MessageEncryptInit(session, NewMechanism(CKM_AES_GCM), keyHandle))
			require.Equal(t, CKR_OK, m.EncryptMessageBegin(session, nil, nil))
			_, rv := m.EncryptMessageNext(session, tc.params, []byte("plaintext-block!"), true)
			assert.Equal(t, CKR_MECHANISM_PARAM_INVALID, rv,
				"the multi-part path must refuse a request it cannot honour, not substitute a random IV")
			m.FinishOperation(session, OperationEncrypt)
		})
	}
}

// C17: the message *Begin entry points receive CK_GCM_MESSAGE_PARAMS too, and
// must validate it at the start of the message rather than dropping it — an
// unhonourable IV request is refused at Begin, and a decrypt Begin requires the
// IV it will verify with.

func TestEncryptMessageBegin_RejectsUnhonourableIVParams(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	keyHandle, rv := m.CreateObject(session, aesKeyTemplate("gcm-begin-enc", make([]byte, 32), NewBoolAttribute(CKA_ENCRYPT, true)))
	require.Equal(t, CKR_OK, rv)

	require.Equal(t, CKR_OK, m.MessageEncryptInit(session, NewMechanism(CKM_AES_GCM), keyHandle))
	rv = m.EncryptMessageBegin(session, &AESGCMMessageParams{
		IV:          make([]byte, GCMNonceSize),
		IVGenerator: CKG_GENERATE_COUNTER,
		TagBits:     128,
	}, nil)
	assert.Equal(t, CKR_MECHANISM_PARAM_INVALID, rv,
		"a counter IV the token cannot honour must be refused at C_EncryptMessageBegin")
}

func TestDecryptMessageBegin_RequiresIV(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	keyHandle, rv := m.CreateObject(session, aesKeyTemplate("gcm-begin-dec", make([]byte, 32), NewBoolAttribute(CKA_DECRYPT, true)))
	require.Equal(t, CKR_OK, rv)

	require.Equal(t, CKR_OK, m.MessageDecryptInit(session, NewMechanism(CKM_AES_GCM), keyHandle))
	rv = m.DecryptMessageBegin(session, &AESGCMMessageParams{
		IV:      nil, // decryption cannot generate an IV; it must be supplied
		TagBits: 128,
	}, nil)
	assert.Equal(t, CKR_MECHANISM_PARAM_INVALID, rv,
		"C_DecryptMessageBegin must refuse an absent IV rather than fail later as tampered ciphertext")
}

// C6: a malformed CK_RSA_PKCS_OAEP_PARAMS must be rejected at C_EncryptInit /
// C_DecryptInit (§5.9.1 / §5.10.1 both list CKR_MECHANISM_PARAM_INVALID),
// matching the fail-fast validation every other parameterized mechanism does,
// rather than surfacing only at C_Encrypt / C_Decrypt.

func oaepMech(params *RSAOAEPParams) *Mechanism {
	return &Mechanism{Type: CKM_RSA_PKCS_OAEP, TypedParameter: params}
}

// Driven at the CryptoManager layer, where the OAEP validation lives: the
// module-level C_EncryptInit gates on the key's CKA_ENCRYPT usage first and
// would mask the parameter check behind CKR_KEY_FUNCTION_NOT_PERMITTED.
func TestEncryptDecryptInit_ValidatesOAEPParamsAtInit(t *testing.T) {
	bad := []struct {
		name   string
		params *RSAOAEPParams
	}{
		{
			name:   "unknown hashAlg",
			params: &RSAOAEPParams{HashAlg: CKM_AES_GCM},
		},
		{
			name:   "source names a non-CKZ_DATA_SPECIFIED value",
			params: &RSAOAEPParams{HashAlg: CKM_SHA256, Source: 0x99},
		},
		{
			name:   "source data without CKZ_DATA_SPECIFIED source",
			params: &RSAOAEPParams{HashAlg: CKM_SHA256, SourceData: []byte("label")},
		},
	}

	for _, tc := range bad {
		t.Run("EncryptInit/"+tc.name, func(t *testing.T) {
			cm, _ := newTestCryptoManager()
			_, err := cm.EncryptInit(oaepMech(tc.params), 1, "test-key", "backend1")
			requireCKRV(t, err, CKR_MECHANISM_PARAM_INVALID,
				"malformed OAEP params must be refused at C_EncryptInit")
		})
		t.Run("DecryptInit/"+tc.name, func(t *testing.T) {
			cm, _ := newTestCryptoManager()
			_, err := cm.DecryptInit(oaepMech(tc.params), 1, "test-key", "backend1")
			requireCKRV(t, err, CKR_MECHANISM_PARAM_INVALID,
				"malformed OAEP params must be refused at C_DecryptInit")
		})
	}

	t.Run("well-formed OAEP params are accepted at Init", func(t *testing.T) {
		cm, _ := newTestCryptoManager()
		_, err := cm.EncryptInit(oaepMech(&RSAOAEPParams{HashAlg: CKM_SHA256}), 1, "test-key", "backend1")
		require.NoError(t, err)
	})
}

// C5: GetQuantumMechanismDescriptor is the single FIPS choke point for the
// vendor PQC registry, mirroring GetMechanismDescriptor for the classical
// registry. Every mechanism in quantumMechanismRegistry is a genuine FIPS
// 203/204 algorithm and must be marked approved, so it stays reachable under
// FIPS mode; the guard exists so a future non-approved PQC mechanism added to
// the registry is refused rather than silently reachable.

func TestQuantumRegistry_AllMechanismsAreFIPSApproved(t *testing.T) {
	for mechType, desc := range quantumMechanismRegistry {
		assert.True(t, desc.FIPSApproved,
			"quantum mechanism 0x%08X (%s) must be marked FIPSApproved: it backs a FIPS 203/204 algorithm and would otherwise be filtered out under FIPS mode",
			mechType, desc.Name)
	}
}

func TestGetQuantumMechanismDescriptor_HonoursFIPSChokePoint(t *testing.T) {
	withFIPSMode(t, true)
	require.True(t, fipsModeEnabled(), "the test must run with FIPS mode on")

	// Every advertised vendor PQC mechanism stays reachable under FIPS mode.
	for mechType, desc := range quantumMechanismRegistry {
		got := GetQuantumMechanismDescriptor(mechType)
		require.NotNil(t, got,
			"approved mechanism %s must remain resolvable under FIPS mode", desc.Name)
		assert.Equal(t, mechType, got.Type)
	}
}
