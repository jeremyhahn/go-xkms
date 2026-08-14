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
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- oracles ---
//
// The oracle for every signature below is cloudflare/circl's ML-DSA verifier
// called directly, not pkg/quantum's wrapper and not the module's own
// verification path. A signature the module produced under its own inverse
// proves only that the two agree; a signature an independent FIPS 204
// implementation accepts under the public key the token published proves the
// token signed with the private key it claims to hold.

// circlVerifyMLDSA44 verifies a signature with cloudflare/circl's ML-DSA-44.
func circlVerifyMLDSA44(publicKey, message, signature []byte) bool {
	var pk mldsa44.PublicKey
	if err := pk.UnmarshalBinary(publicKey); err != nil {
		return false
	}
	return mldsa44.Verify(&pk, message, nil, signature)
}

// circlVerifyMLDSA65 verifies a signature with cloudflare/circl's ML-DSA-65.
func circlVerifyMLDSA65(publicKey, message, signature []byte) bool {
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(publicKey); err != nil {
		return false
	}
	return mldsa65.Verify(&pk, message, nil, signature)
}

// circlVerifyMLDSA87 verifies a signature with cloudflare/circl's ML-DSA-87.
func circlVerifyMLDSA87(publicKey, message, signature []byte) bool {
	var pk mldsa87.PublicKey
	if err := pk.UnmarshalBinary(publicKey); err != nil {
		return false
	}
	return mldsa87.Verify(&pk, message, nil, signature)
}

// circlSignMLDSA65 signs with cloudflare/circl's ML-DSA-65 from a seed, so a
// verification test has a signature the module did not make.
func circlSignMLDSA65(t *testing.T, seed, message []byte) []byte {
	t.Helper()
	require.Len(t, seed, mldsa65.SeedSize)
	var seedArr [mldsa65.SeedSize]byte
	copy(seedArr[:], seed)
	_, priv := mldsa65.NewKeyFromSeed(&seedArr)
	signature, err := priv.Sign(nil, message, nil)
	require.NoError(t, err)
	return signature
}

// --- drivers for the C_Sign / C_Verify dispatch ---
//
// These run the exact sequence Module.SignInit and Module.Sign perform around
// the quantum dispatch: the session manager claims the operation slot, the
// dispatch attaches the in-process operation, and the terminal call reads it
// back out of session state. Module.SignInit's own body between those steps
// (key resolution, mechanism validation) is exercised separately by the
// C_GenerateKeyPair and mechanism tests.

// claimSignSlot claims the session's signing operation slot the way
// Module.SignInit does before reaching the crypto layer.
func claimSignSlot(t *testing.T, m *Module, session SessionHandle, mech *Mechanism, key ObjectHandle, opType OperationType) {
	t.Helper()
	slotID, _, rv := m.findSession(session)
	require.Equal(t, CKR_OK, rv)
	sm, ok := m.sessionManagers[slotID]
	require.True(t, ok)
	require.NoError(t, sm.InitializeOperation(session, opType, mech.Type, key))
}

// signThroughQuantumDispatch drives C_SignInit followed by C_Sign for a key
// that holds its own ML-DSA material.
func signThroughQuantumDispatch(t *testing.T, m *Module, session SessionHandle, mech *Mechanism, priv ObjectHandle, data []byte) ([]byte, CK_RV) {
	t.Helper()

	sess := mustSession(t, m, session)
	keyObj, err := m.objectManager.GetObjectFor(NewAccessContext(session, sess), priv)
	require.NoError(t, err)

	claimSignSlot(t, m, session, mech, priv, OperationSign)

	handled, rv := m.quantumSignInit(sess, mech, priv, keyObj)
	require.True(t, handled, "a locally generated ML-DSA key must be claimed by the in-process path")
	if rv != CKR_OK {
		return nil, rv
	}

	opState := sess.GetOperationByType(OperationSign)
	require.NotNil(t, opState)

	signature, handled, rv := m.quantumSign(sess, opState, data)
	require.True(t, handled, "the stored operation must be recognized as an in-process one")
	return signature, rv
}

// verifyThroughQuantumDispatch drives C_VerifyInit followed by C_Verify.
func verifyThroughQuantumDispatch(t *testing.T, m *Module, session SessionHandle, mech *Mechanism, pub ObjectHandle, data, signature []byte) CK_RV {
	t.Helper()

	sess := mustSession(t, m, session)
	keyObj, err := m.objectManager.GetObjectFor(NewAccessContext(session, sess), pub)
	require.NoError(t, err)

	claimSignSlot(t, m, session, mech, pub, OperationVerify)

	handled, rv := m.quantumVerifyInit(sess, mech, pub, keyObj)
	require.True(t, handled)
	if rv != CKR_OK {
		return rv
	}

	opState := sess.GetOperationByType(OperationVerify)
	require.NotNil(t, opState)

	handled, rv = m.quantumVerify(opState, data, signature)
	require.True(t, handled)

	slotID, _, findRV := m.findSession(session)
	require.Equal(t, CKR_OK, findRV)
	require.NoError(t, m.sessionManagers[slotID].FinalizeOperationType(session, OperationVerify))

	return rv
}

// --- the signature itself ---

// TestQuantumSignProducesARealMLDSASignature is the load-bearing test for the
// signing half of the post-quantum key lifecycle.
//
// C_GenerateKeyPair produces an ML-DSA pair in process, so the private object
// carries its seed in CKA_VALUE and names no backend key. Routing its C_Sign to
// the transport sent a SignRequest with KeyID="" and Hash="NONE", which against
// the mock client returned a 14-byte artifact and against a real daemon matched
// a key whose CN is the empty string. Neither is a signature.
//
// The assertion that settles it is cloudflare/circl verifying the output under
// the public key the token published: an independent FIPS 204 implementation
// accepts it, so the token signed with the private key it claims to hold and at
// the parameter set that was asked for. The length check is kept alongside
// because a 14-byte result is the exact shape of the old failure.
func TestQuantumSignProducesARealMLDSASignature(t *testing.T) {
	message := []byte("C_Sign must reach the seed the token generated")

	cases := []struct {
		name          string
		generateWith  MechanismType
		extra         []Attribute
		signWith      MechanismType
		signatureSize int
		verify        func(publicKey, message, signature []byte) bool
	}{
		{
			name:          "ML-DSA-44 vendor mechanism",
			generateWith:  CKM_VENDOR_ML_DSA_44_KEY_PAIR_GEN,
			signWith:      CKM_VENDOR_ML_DSA_44,
			signatureSize: mldsa44.SignatureSize,
			verify:        circlVerifyMLDSA44,
		},
		{
			name:          "ML-DSA-65 vendor mechanism",
			generateWith:  CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN,
			signWith:      CKM_VENDOR_ML_DSA_65,
			signatureSize: mldsa65.SignatureSize,
			verify:        circlVerifyMLDSA65,
		},
		{
			name:          "ML-DSA-87 vendor mechanism",
			generateWith:  CKM_VENDOR_ML_DSA_87_KEY_PAIR_GEN,
			signWith:      CKM_VENDOR_ML_DSA_87,
			signatureSize: mldsa87.SignatureSize,
			verify:        circlVerifyMLDSA87,
		},
		{
			// The v3.2 standard mechanism carries no level (§6.67.4), so the
			// parameter set has to come off the key object. Getting this wrong
			// expands the seed at another level and produces a well-formed
			// signature no verifier accepts.
			name:          "ML-DSA-65 standard CKM_ML_DSA over a key generated by parameter set",
			generateWith:  CKM_ML_DSA_KEY_PAIR_GEN,
			extra:         []Attribute{parameterSetAttribute(CKP_ML_DSA_65)},
			signWith:      CKM_ML_DSA,
			signatureSize: mldsa65.SignatureSize,
			verify:        circlVerifyMLDSA65,
		},
		{
			name:          "ML-DSA-87 standard CKM_ML_DSA over a key generated by parameter set",
			generateWith:  CKM_ML_DSA_KEY_PAIR_GEN,
			extra:         []Attribute{parameterSetAttribute(CKP_ML_DSA_87)},
			signWith:      CKM_ML_DSA,
			signatureSize: mldsa87.SignatureSize,
			verify:        circlVerifyMLDSA87,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := initializeTestModule(t)
			defer m.Finalize()
			session := loginAsNormalUser(t, m)

			pub, priv := generatePQCKeyPair(t, m, session, tc.generateWith, "mldsa-sign", tc.extra...)
			publicKey := objectAttribute(t, m, pub, CKA_VALUE)

			signature, rv := signThroughQuantumDispatch(t, m, session, &Mechanism{Type: tc.signWith}, priv, message)
			require.Equal(t, CKR_OK, rv, "C_Sign must succeed for a key the token generated")

			require.Len(t, signature, tc.signatureSize,
				"the signature must be the FIPS 204 size for this parameter set")
			require.NotEqual(t, 14, len(signature),
				"a 14-byte result is the transport mock's artifact, not an ML-DSA signature")

			assert.True(t, tc.verify(publicKey, message, signature),
				"an independent ML-DSA implementation must accept the signature under the published public key")
			assert.False(t, tc.verify(publicKey, append(message, '!'), signature),
				"the same signature must not verify over different data")
		})
	}
}

// TestQuantumSignRejectsAKeyThatCarriesNoMaterial proves the in-process path
// claims an ML-DSA key with no backend identity even when it has nothing to
// sign with, rather than letting it fall through to the transport.
//
// Falling through is the original defect: the request reached the daemon under
// KeyID="", where it either matched nothing or matched an unrelated record. The
// module owns the answer for its own keys, and CKR_KEY_HANDLE_INVALID is in
// C_SignInit's return table (v3.2 §5.13.1).
func TestQuantumSignRejectsAKeyThatCarriesNoMaterial(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)
	sess := mustSession(t, m, session)

	stripped := &Object{
		Class:      CKO_PRIVATE_KEY,
		KeyType:    CKK_ML_DSA,
		Attributes: map[AttributeType][]byte{},
	}

	handled, rv := m.quantumSignInit(sess, &Mechanism{Type: CKM_VENDOR_ML_DSA_65}, ObjectHandle(1), stripped)
	assert.True(t, handled, "an ML-DSA key naming no backend key must never reach the transport")
	assert.Equal(t, CKR_KEY_HANDLE_INVALID, rv)

	// The same answer is required through the v3.2 standard mechanism, which
	// has a parameter set to resolve before it can dispatch. Resolving first
	// reports CKR_MECHANISM_PARAM_INVALID for a key that has no material at
	// all, sending the application to look at a mechanism parameter CKM_ML_DSA
	// does not even have (§6.67.4). The missing material is the fault, so the
	// material is checked first.
	handled, rv = m.quantumSignInit(sess, &Mechanism{Type: CKM_ML_DSA}, ObjectHandle(1), stripped)
	assert.True(t, handled)
	assert.Equal(t, CKR_KEY_HANDLE_INVALID, rv,
		"a key with no material must be reported as such, whichever mechanism named it")

	handled, rv = m.quantumVerifyInit(sess, &Mechanism{Type: CKM_ML_DSA}, ObjectHandle(1),
		&Object{Class: CKO_PUBLIC_KEY, KeyType: CKK_ML_DSA, Attributes: map[AttributeType][]byte{}})
	assert.True(t, handled)
	assert.Equal(t, CKR_KEY_HANDLE_INVALID, rv,
		"verification answers a key with no material the same way signing does")
}

// TestQuantumSignInitRefusesWithoutAQuantumCryptoManager proves a build with no
// post-quantum crypto still claims the request and refuses it determinately,
// rather than handing an ML-DSA key to the transport.
func TestQuantumSignInitRefusesWithoutAQuantumCryptoManager(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)
	sess := mustSession(t, m, session)

	pub, priv := generatePQCKeyPair(t, m, session, CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN, "no-qcm")
	keyObj, err := m.objectManager.GetObjectFor(NewAccessContext(session, sess), priv)
	require.NoError(t, err)
	pubObj, err := m.objectManager.GetObjectFor(NewAccessContext(session, sess), pub)
	require.NoError(t, err)

	m.quantumCrypto = nil

	handled, rv := m.quantumSignInit(sess, &Mechanism{Type: CKM_VENDOR_ML_DSA_65}, priv, keyObj)
	assert.True(t, handled)
	assert.Equal(t, CKR_MECHANISM_INVALID, rv)

	handled, rv = m.quantumVerifyInit(sess, &Mechanism{Type: CKM_VENDOR_ML_DSA_65}, pub, pubObj)
	assert.True(t, handled)
	assert.Equal(t, CKR_MECHANISM_INVALID, rv)
}

// --- verification ---

// TestQuantumVerifyAcceptsOnlyTheRightSignature drives C_VerifyInit/C_Verify
// over a signature the module did not produce.
//
// The signature comes from cloudflare/circl built on the seed the token stored,
// so a pass means the token's public key object and its private key object are
// halves of one FIPS 204 pair and the verification really ran; a tampered
// signature must fail with CKR_SIGNATURE_INVALID and not merely a generic
// failure, because an application distinguishes "wrong signature" from "broken
// token" by that code (v3.2 §5.15.2).
func TestQuantumVerifyAcceptsOnlyTheRightSignature(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	message := []byte("C_Verify must run against the published public key")

	pub, priv := generatePQCKeyPair(t, m, session, CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN, "mldsa-verify")
	seed := objectAttribute(t, m, priv, CKA_VALUE)
	signature := circlSignMLDSA65(t, seed, message)

	assert.Equal(t, CKR_OK,
		verifyThroughQuantumDispatch(t, m, session, &Mechanism{Type: CKM_VENDOR_ML_DSA_65}, pub, message, signature),
		"a signature from an independent implementation over the same key must verify")

	tampered := copyBytes(signature)
	tampered[0] ^= 0xFF
	assert.Equal(t, CKR_SIGNATURE_INVALID,
		verifyThroughQuantumDispatch(t, m, session, &Mechanism{Type: CKM_VENDOR_ML_DSA_65}, pub, message, tampered),
		"a tampered signature must be reported as invalid, not as a token failure")

	assert.Equal(t, CKR_SIGNATURE_INVALID,
		verifyThroughQuantumDispatch(t, m, session, &Mechanism{Type: CKM_VENDOR_ML_DSA_65}, pub, append(message, '!'), signature),
		"a signature over different data must be reported as invalid")
}

// TestQuantumSignAndVerifyAcrossMultipleParts proves the multi-part forms
// accumulate the message rather than signing each part.
//
// ML-DSA signs the message itself, not a digest of it (FIPS 204 §5.2), so
// C_SignUpdate has to buffer. The oracle is circl verifying the C_SignFinal
// output against the concatenation of the parts: a per-part signature, or one
// that dropped a part, fails there.
func TestQuantumSignAndVerifyAcrossMultipleParts(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	parts := [][]byte{[]byte("first part, "), []byte("second part, "), []byte("third part")}
	var whole []byte
	for _, part := range parts {
		whole = append(whole, part...)
	}

	pub, priv := generatePQCKeyPair(t, m, session, CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN, "mldsa-multipart")
	publicKey := objectAttribute(t, m, pub, CKA_VALUE)

	sess := mustSession(t, m, session)
	mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_65}

	// Sign: init, three updates, final.
	privObj, err := m.objectManager.GetObjectFor(NewAccessContext(session, sess), priv)
	require.NoError(t, err)
	claimSignSlot(t, m, session, mech, priv, OperationSign)
	handled, rv := m.quantumSignInit(sess, mech, priv, privObj)
	require.True(t, handled)
	require.Equal(t, CKR_OK, rv)

	for _, part := range parts {
		opState := sess.GetOperationByType(OperationSign)
		require.NotNil(t, opState)
		handled, rv = m.quantumSignUpdate(sess, opState, part)
		require.True(t, handled)
		require.Equal(t, CKR_OK, rv)
		require.True(t, sess.GetOperationByType(OperationSign).MultiPart,
			"C_SignUpdate must mark the operation multi-part so C_Sign refuses to terminate it")
	}

	opState := sess.GetOperationByType(OperationSign)
	require.NotNil(t, opState)
	signature, handled, rv := m.quantumSignFinal(sess, opState)
	require.True(t, handled)
	require.Equal(t, CKR_OK, rv)

	require.Len(t, signature, mldsa65.SignatureSize)
	assert.True(t, circlVerifyMLDSA65(publicKey, whole, signature),
		"C_SignFinal must sign the concatenation of every part fed to C_SignUpdate")
	assert.False(t, circlVerifyMLDSA65(publicKey, parts[0], signature),
		"the signature must not be over only the first part")

	// Verify the same signature back through the multi-part verification form.
	pubObj, err := m.objectManager.GetObjectFor(NewAccessContext(session, sess), pub)
	require.NoError(t, err)
	claimSignSlot(t, m, session, mech, pub, OperationVerify)
	handled, rv = m.quantumVerifyInit(sess, mech, pub, pubObj)
	require.True(t, handled)
	require.Equal(t, CKR_OK, rv)

	for _, part := range parts {
		verifyState := sess.GetOperationByType(OperationVerify)
		require.NotNil(t, verifyState)
		handled, rv = m.quantumVerifyUpdate(sess, verifyState, part)
		require.True(t, handled)
		require.Equal(t, CKR_OK, rv)
	}

	verifyState := sess.GetOperationByType(OperationVerify)
	require.NotNil(t, verifyState)
	handled, rv = m.quantumVerifyFinal(verifyState, signature)
	require.True(t, handled)
	assert.Equal(t, CKR_OK, rv,
		"C_VerifyFinal must verify against everything C_VerifyUpdate accumulated")
}

// TestQuantumSignFinalRejectsATamperedMessage is the bad-input counterpart of
// the multi-part test: a verification fed a different set of parts than the
// signature covers must be reported invalid.
func TestQuantumSignFinalRejectsATamperedMessage(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)

	pub, priv := generatePQCKeyPair(t, m, session, CKM_VENDOR_ML_DSA_65_KEY_PAIR_GEN, "mldsa-multipart-bad")
	sess := mustSession(t, m, session)
	mech := &Mechanism{Type: CKM_VENDOR_ML_DSA_65}

	privObj, err := m.objectManager.GetObjectFor(NewAccessContext(session, sess), priv)
	require.NoError(t, err)
	claimSignSlot(t, m, session, mech, priv, OperationSign)
	handled, rv := m.quantumSignInit(sess, mech, priv, privObj)
	require.True(t, handled)
	require.Equal(t, CKR_OK, rv)

	signState := sess.GetOperationByType(OperationSign)
	handled, rv = m.quantumSignUpdate(sess, signState, []byte("signed content"))
	require.True(t, handled)
	require.Equal(t, CKR_OK, rv)

	signState = sess.GetOperationByType(OperationSign)
	signature, handled, rv := m.quantumSignFinal(sess, signState)
	require.True(t, handled)
	require.Equal(t, CKR_OK, rv)

	pubObj, err := m.objectManager.GetObjectFor(NewAccessContext(session, sess), pub)
	require.NoError(t, err)
	claimSignSlot(t, m, session, mech, pub, OperationVerify)
	handled, rv = m.quantumVerifyInit(sess, mech, pub, pubObj)
	require.True(t, handled)
	require.Equal(t, CKR_OK, rv)

	verifyState := sess.GetOperationByType(OperationVerify)
	handled, rv = m.quantumVerifyUpdate(sess, verifyState, []byte("different content"))
	require.True(t, handled)
	require.Equal(t, CKR_OK, rv)

	verifyState = sess.GetOperationByType(OperationVerify)
	handled, rv = m.quantumVerifyFinal(verifyState, signature)
	require.True(t, handled)
	assert.Equal(t, CKR_SIGNATURE_INVALID, rv)
}

// --- routing ---

// TestHoldsOwnQuantumSignatureMaterialRoutesOnlyLocalKeys proves the predicate
// that decides between the in-process path and the transport.
//
// Both mistakes it can make are damaging. Claiming a classical key would take
// RSA and ECDSA away from the backend that holds them; declining a locally
// generated ML-DSA key is the original defect, a signature request sent to the
// daemon under an empty KeyID.
func TestHoldsOwnQuantumSignatureMaterialRoutesOnlyLocalKeys(t *testing.T) {
	local := &Object{Class: CKO_PRIVATE_KEY, KeyType: CKK_ML_DSA}
	backed := &Object{Class: CKO_PRIVATE_KEY, KeyType: CKK_ML_DSA, KeyID: "daemon-key-1", BackendName: "software"}

	assert.True(t, holdsOwnQuantumSignatureMaterial(&Mechanism{Type: CKM_ML_DSA}, local),
		"the v3.2 standard ML-DSA mechanism on a key with no backend identity signs in process")
	assert.True(t, holdsOwnQuantumSignatureMaterial(&Mechanism{Type: CKM_VENDOR_ML_DSA_87}, local),
		"a per-level vendor mechanism routes identically")

	assert.False(t, holdsOwnQuantumSignatureMaterial(&Mechanism{Type: CKM_ML_DSA}, backed),
		"an ML-DSA key that names a backend key belongs to the transport")
	assert.False(t, holdsOwnQuantumSignatureMaterial(&Mechanism{Type: CKM_RSA_PKCS}, local),
		"a classical mechanism must never be claimed by the post-quantum path")
	assert.False(t, holdsOwnQuantumSignatureMaterial(&Mechanism{Type: CKM_ECDSA}, local),
		"a classical mechanism must never be claimed by the post-quantum path")
	assert.False(t, holdsOwnQuantumSignatureMaterial(nil, local),
		"a nil mechanism is a termination request, not a signing request")
	assert.False(t, holdsOwnQuantumSignatureMaterial(&Mechanism{Type: CKM_ML_DSA}, nil),
		"there is no key to read material from")
}

// TestQuantumSignInitDeclinesAClassicalKey proves the dispatch leaves the
// transport path untouched, which is what keeps every classical mechanism
// working.
func TestQuantumSignInitDeclinesAClassicalKey(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)
	sess := mustSession(t, m, session)

	rsaKey := &Object{Class: CKO_PRIVATE_KEY, KeyType: CKK_RSA, KeyID: "rsa-1", BackendName: "software"}

	handled, rv := m.quantumSignInit(sess, &Mechanism{Type: CKM_RSA_PKCS}, ObjectHandle(1), rsaKey)
	assert.False(t, handled, "a classical signing request must fall through to the transport")
	assert.Equal(t, CKR_OK, rv)

	handled, rv = m.quantumVerifyInit(sess, &Mechanism{Type: CKM_RSA_PKCS}, ObjectHandle(1), rsaKey)
	assert.False(t, handled)
	assert.Equal(t, CKR_OK, rv)
}

// TestQuantumTerminalCallsDeclineAClassicalOperation proves the terminal calls
// claim by the type of the stored operation, so a transport-path signature is
// still produced by the transport.
func TestQuantumTerminalCallsDeclineAClassicalOperation(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)
	sess := mustSession(t, m, session)

	classical := &OperationState{
		Type:     OperationSign,
		CryptoOp: newSignOperation(&Mechanism{Type: CKM_RSA_PKCS}, ObjectHandle(1), "rsa-1", "software"),
	}

	_, handled, rv := m.quantumSign(sess, classical, []byte("data"))
	assert.False(t, handled)
	assert.Equal(t, CKR_OK, rv)

	handled, rv = m.quantumSignUpdate(sess, classical, []byte("data"))
	assert.False(t, handled)
	assert.Equal(t, CKR_OK, rv)

	_, handled, rv = m.quantumSignFinal(sess, classical)
	assert.False(t, handled)
	assert.Equal(t, CKR_OK, rv)

	verifyState := &OperationState{
		Type:     OperationVerify,
		CryptoOp: newVerifyOperation(&Mechanism{Type: CKM_RSA_PKCS}, ObjectHandle(1), "rsa-1", "software"),
	}

	handled, rv = m.quantumVerify(verifyState, []byte("data"), []byte("sig"))
	assert.False(t, handled)
	assert.Equal(t, CKR_OK, rv)

	handled, rv = m.quantumVerifyUpdate(sess, verifyState, []byte("data"))
	assert.False(t, handled)
	assert.Equal(t, CKR_OK, rv)

	handled, rv = m.quantumVerifyFinal(verifyState, []byte("sig"))
	assert.False(t, handled)
	assert.Equal(t, CKR_OK, rv)
}

// --- parameter set resolution ---

// TestResolveMLDSALevelPrefersTheParameterSet proves the level comes from the
// key object rather than from a length.
//
// The private half is a 32-byte seed at every level, so nothing but
// CKA_PARAMETER_SET can say which generator to reconstruct it with. Expanding a
// seed at the wrong level yields a signature that verifies under nothing.
func TestResolveMLDSALevelPrefersTheParameterSet(t *testing.T) {
	withParameterSet := func(parameterSet ParameterSetType) *Object {
		obj := &Object{Attributes: map[AttributeType][]byte{}}
		obj.SetAttribute(CKA_PARAMETER_SET, NewUint32Attribute(CKA_PARAMETER_SET, uint32(parameterSet)).Value)
		return obj
	}

	assert.Equal(t, 44, resolveMLDSALevel(withParameterSet(CKP_ML_DSA_44), mldsaSeedSize))
	assert.Equal(t, 65, resolveMLDSALevel(withParameterSet(CKP_ML_DSA_65), mldsaSeedSize))
	assert.Equal(t, 87, resolveMLDSALevel(withParameterSet(CKP_ML_DSA_87), mldsaSeedSize))

	// The parameter set outranks a length that names a different level.
	assert.Equal(t, 44, resolveMLDSALevel(withParameterSet(CKP_ML_DSA_44), MLDSA87PublicKeySize))

	// With no parameter set only a public key length resolves.
	bare := &Object{Attributes: map[AttributeType][]byte{}}
	assert.Equal(t, 44, resolveMLDSALevel(bare, MLDSA44PublicKeySize))
	assert.Equal(t, 65, resolveMLDSALevel(bare, MLDSA65PublicKeySize))
	assert.Equal(t, 87, resolveMLDSALevel(bare, MLDSA87PublicKeySize))

	assert.Equal(t, 0, resolveMLDSALevel(bare, mldsaSeedSize),
		"a seed length says nothing about the level and must not be guessed at")

	// A parameter set from another algorithm names no ML-DSA level; v3.2 §2.3
	// scopes parameter set values per algorithm.
	assert.Equal(t, 0, resolveMLDSALevel(withParameterSet(CKP_SLH_DSA_SHAKE_256F), mldsaSeedSize))
}

// TestResolveMLDSADispatchMechanismRefusesAnUnresolvableKey proves the standard
// mechanism resolves to a per-level one, and that an unresolvable key is an
// error rather than a default.
func TestResolveMLDSADispatchMechanismRefusesAnUnresolvableKey(t *testing.T) {
	obj := &Object{Attributes: map[AttributeType][]byte{}}
	obj.SetAttribute(CKA_PARAMETER_SET, NewUint32Attribute(CKA_PARAMETER_SET, uint32(CKP_ML_DSA_87)).Value)

	resolved, err := resolveMLDSADispatchMechanism(&Mechanism{Type: CKM_ML_DSA}, obj, mldsaSeedSize)
	require.NoError(t, err)
	assert.Equal(t, CKM_VENDOR_ML_DSA_87, resolved.Type)

	// A caller that named a level itself is left alone.
	vendor := &Mechanism{Type: CKM_VENDOR_ML_DSA_44}
	resolved, err = resolveMLDSADispatchMechanism(vendor, obj, mldsaSeedSize)
	require.NoError(t, err)
	assert.Same(t, vendor, resolved, "a per-level mechanism must pass through untouched")

	bare := &Object{Attributes: map[AttributeType][]byte{}}
	_, err = resolveMLDSADispatchMechanism(&Mechanism{Type: CKM_ML_DSA}, bare, mldsaSeedSize)
	require.Error(t, err)
	assert.Equal(t, CKR_MECHANISM_PARAM_INVALID, FromError(err),
		"a key that names no parameter set must fail rather than sign at a guessed level")
}

// TestQuantumSignInitRefusesAKeyWithNoParameterSet proves the refusal reaches
// C_SignInit and is not confined to the resolver.
func TestQuantumSignInitRefusesAKeyWithNoParameterSet(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)
	sess := mustSession(t, m, session)

	// A seed with no CKA_PARAMETER_SET: nothing says which generator to
	// reconstruct it with.
	seedOnly := &Object{Class: CKO_PRIVATE_KEY, KeyType: CKK_ML_DSA, Attributes: map[AttributeType][]byte{}}
	seedOnly.SetAttribute(CKA_VALUE, make([]byte, mldsaSeedSize))

	handled, rv := m.quantumSignInit(sess, &Mechanism{Type: CKM_ML_DSA}, ObjectHandle(1), seedOnly)
	assert.True(t, handled)
	assert.Equal(t, CKR_MECHANISM_PARAM_INVALID, rv)
}
