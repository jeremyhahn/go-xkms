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
	"context"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wrapTransport is the wrap half of PKCS11Transport backed by a real AES-GCM
// wrap, so a test can measure what C_WrapKey actually put on the wire.
//
// It honours WrapKeyByIDRequest.IV exactly as a service must -- a wrap
// performed under an IV other than the one the caller named is undecryptable
// by the peer that named it -- and frames the result nonce || ciphertext ||
// tag, which is what pkg/xkms wrapAESGCM emits. mockClient's own WrapKeyByID
// answers with a fixed string, which cannot show whether an IV reached the
// service or what was done with it.
type wrapTransport struct {
	*mockClient

	// keys maps a wrapping key id to its material, so one transport can serve
	// several keys and a test can say which two ids share material.
	keys map[string][]byte

	// wraps counts the requests that reached this transport. A guard that
	// refuses a wrap must refuse it before the request goes out, and the count
	// is how a test sees the difference between "the module refused" and "the
	// service was asked and something else went wrong".
	wraps int

	// lastReq is the request the transport last received.
	lastReq *transport.WrapKeyByIDRequest
}

func newWrapTransport(keys map[string][]byte) *wrapTransport {
	return &wrapTransport{mockClient: newMockClient(), keys: keys}
}

func (w *wrapTransport) WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	w.wraps++
	w.lastReq = req

	kek, ok := w.keys[req.WrappingKeyID]
	if !ok {
		return nil, ErrKeyHandleInvalid
	}

	nonce := req.IV
	if len(nonce) == 0 {
		nonce = make([]byte, GCMNonceSize)
	}

	sealed := gcmSealOracleBytes(kek, nonce, req.TargetKeyMaterial, req.AAD)
	blob := make([]byte, 0, len(nonce)+len(sealed))
	blob = append(blob, nonce...)
	blob = append(blob, sealed...)

	return &transport.WrapKeyByIDResponse{WrappedKey: blob, Algorithm: req.Algorithm}, nil
}

// gcmSealOracleBytes is gcmSealOracle without a *testing.T, for use inside the
// transport above. Both seal with crypto/cipher for the same reason: the
// module's output has to be measured against an implementation that is not the
// module.
func gcmSealOracleBytes(key, nonce, plaintext, aad []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return gcm.Seal(nil, nonce, plaintext, aad)
}

// gcmWrapRequest builds the C_WrapKey request the module's WrapKey verb builds
// for a locally held target key: the target travels as material, the wrapping
// key as a backend id (see CryptoManager.WrapKeyByIDRequest).
func gcmWrapRequest(backend, wrappingKeyID string, iv, target []byte) *WrapKeyByIDRequest {
	return &WrapKeyByIDRequest{
		WrappingKeyID:      wrappingKeyID,
		WrappingKeyBackend: backend,
		TargetKeyMaterial:  target,
		Algorithm:          string(types.WrapAESGCM),
		Params:             WrapMechanismParams{IV: iv, TagBits: 128},
	}
}

// TestWrapKeyByIDRefusesAReusedIVUnderOneKey is the probe that demonstrates the
// flaw C_WrapKey had: one KEK, one caller-supplied IV, two different target
// keys.
//
// AES-GCM is counter mode underneath, so both wraps encrypt under the identical
// keystream and ct_a XOR ct_b XOR pt_a reproduces pt_b byte for byte. The
// plaintext of a key wrap is key material, so anyone holding the two blobs
// recovers BOTH wrapped keys -- and the GHASH subkey H the two share makes
// forging tags on further blobs under that KEK feasible on top of it (NIST SP
// 800-38D section 8.2).
//
// The first half performs that recovery against crypto/cipher and asserts it
// works, so the requirement in the second half is measured against a
// demonstrated attack rather than an assumed one. The second half then requires
// the module to refuse the second wrap -- and requires the first wrap to equal
// the standard library's own output, so a guard cannot pass by emitting
// something nobody can decrypt.
func TestWrapKeyByIDRefusesAReusedIVUnderOneKey(t *testing.T) {
	kek := []byte("wrapbyid-KEK-001") // AES-128
	targetA := []byte("target-key-AAAAA")
	targetB := []byte("target-key-BBBBB")
	iv := uniqueTestIV(t)

	// The attack, outside the module, against the standard library.
	oracleA := gcmSealOracle(t, kek, iv, targetA, nil)
	oracleB := gcmSealOracle(t, kek, iv, targetB, nil)
	recovered := xorBytes(xorBytes(oracleA[:len(targetA)], oracleB[:len(targetB)]), targetA)
	require.Equal(t, targetB, recovered,
		"the premise of this test: two GCM seals under one (key, IV) leak the XOR of their plaintexts")

	client := newWrapTransport(map[string][]byte{"reuse-kek": kek})
	cm := NewCryptoManager(client, &CryptoManagerConfig{DefaultBackend: "wrapnonce-be"})

	blobA, err := cm.WrapKeyByID(context.Background(),
		gcmWrapRequest("wrapnonce-be", "reuse-kek", iv, targetA))
	require.NoError(t, err, "the first use of an IV under a key is legitimate")
	require.Equal(t, append(append([]byte{}, iv...), oracleA...), blobA,
		"the wrap must agree with the standard library for the same key, IV and plaintext")

	blobB, err := cm.WrapKeyByID(context.Background(),
		gcmWrapRequest("wrapnonce-be", "reuse-kek", iv, targetB))
	require.Error(t, err, "a second wrap under the same (KEK, IV) discloses both wrapped keys and must be refused")
	assert.Nil(t, blobB, "a refused wrap must return no ciphertext")
	assert.True(t, errorHasCode(err, CKR_MECHANISM_PARAM_INVALID),
		"the caller has to change the IV in CK_GCM_PARAMS, so the code names that parameter: got %v", err)
	assert.Equal(t, 1, client.wraps,
		"the refusal must happen in the module: the second request must never reach the service")
}

// TestWrapKeyByIDAcceptsAFreshIVUnderTheSameKey is the other half of the guard.
// It must refuse repeats, not refuse everything: a guard that answered
// CKR_MECHANISM_PARAM_INVALID to every wrap would satisfy the test above and
// make C_WrapKey useless.
func TestWrapKeyByIDAcceptsAFreshIVUnderTheSameKey(t *testing.T) {
	kek := []byte("wrapbyid-KEK-256-bytes-long-abcd") // AES-256
	target := []byte("fresh-iv-target-")

	client := newWrapTransport(map[string][]byte{"fresh-kek": kek})
	cm := NewCryptoManager(client, &CryptoManagerConfig{DefaultBackend: "wrapnonce-be"})

	first := uniqueTestIV(t)
	second := uniqueTestIV(t)

	blobFirst, err := cm.WrapKeyByID(context.Background(),
		gcmWrapRequest("wrapnonce-be", "fresh-kek", first, target))
	require.NoError(t, err)

	blobSecond, err := cm.WrapKeyByID(context.Background(),
		gcmWrapRequest("wrapnonce-be", "fresh-kek", second, target))
	require.NoError(t, err, "a different IV under the same key is exactly what the caller is told to do")
	assert.NotEqual(t, blobFirst, blobSecond, "different IVs must produce different blobs")
	assert.Equal(t, 2, client.wraps)

	// Both blobs must still be the real thing, checked outside the module.
	plainFirst, err := gcmOpenOracle(t, kek, first, blobFirst[GCMNonceSize:], nil)
	require.NoError(t, err)
	assert.Equal(t, target, plainFirst)

	plainSecond, err := gcmOpenOracle(t, kek, second, blobSecond[GCMNonceSize:], nil)
	require.NoError(t, err)
	assert.Equal(t, target, plainSecond)
}

// TestWrapKeyByIDAcceptsOneIVUnderTwoDifferentKeys proves the claim is keyed by
// the key as well as by the nonce. SP 800-38D section 8.2 constrains the PAIR:
// the same IV under a different key is a different pair and is perfectly safe,
// so refusing it would turn the guard into a global ban on IVs and break every
// unrelated caller.
func TestWrapKeyByIDAcceptsOneIVUnderTwoDifferentKeys(t *testing.T) {
	target := []byte("two-kek-target--")
	iv := uniqueTestIV(t)

	client := newWrapTransport(map[string][]byte{
		"two-kek-one": []byte("two-kek-ONE-5678"),
		"two-kek-two": []byte("two-kek-TWO-5678"),
	})
	cm := NewCryptoManager(client, &CryptoManagerConfig{DefaultBackend: "wrapnonce-be"})

	_, err := cm.WrapKeyByID(context.Background(),
		gcmWrapRequest("wrapnonce-be", "two-kek-one", iv, target))
	require.NoError(t, err)

	_, err = cm.WrapKeyByID(context.Background(),
		gcmWrapRequest("wrapnonce-be", "two-kek-two", iv, target))
	require.NoError(t, err, "one IV under two distinct keys is two distinct pairs and must be allowed")

	// The same key id in a second backend is likewise a different key here.
	// This module never holds the wrapping key's material, so a name is all it
	// has to key on; a key material genuinely reachable under two names is
	// refused by the service, which does hold the bytes (see
	// TestWrapAESGCMRefusesAReusedIVAcrossBackendsAndNames in pkg/xkms).
	other := newWrapTransport(map[string][]byte{"two-kek-one": []byte("two-kek-ONE-5678")})
	otherCM := NewCryptoManager(other, &CryptoManagerConfig{DefaultBackend: "wrapnonce-be-2"})
	_, err = otherCM.WrapKeyByID(context.Background(),
		gcmWrapRequest("wrapnonce-be-2", "two-kek-one", iv, target))
	require.NoError(t, err)
}

// TestWrapKeyByIDDoesNotConsumeTheIVOfARefusedWrap pins where in the sequence
// the pair is claimed: after every check this module makes, not before.
//
// The guard is a one-way door -- a pair it has recorded can never be used again
// in this process -- so claiming it for a wrap that was going to be refused
// anyway destroys an IV the caller never got to use. The caller's corrected
// retry, with the same IV it had prepared, would then be refused as a reuse of
// a wrap that never happened, and nothing it could change would make that call
// succeed.
//
// The refusal used here is a malformed request rather than a bad mechanism, so
// the identical mechanism and IV must still be good afterwards.
func TestWrapKeyByIDDoesNotConsumeTheIVOfARefusedWrap(t *testing.T) {
	kek := []byte("refused-wrap-KEK")
	target := []byte("free-to-go-targt")
	iv := uniqueTestIV(t)

	client := newWrapTransport(map[string][]byte{"refused-kek": kek})
	cm := NewCryptoManager(client, &CryptoManagerConfig{DefaultBackend: "wrapnonce-be"})

	bad := gcmWrapRequest("wrapnonce-be", "refused-kek", iv, target)
	bad.TargetKeyID = "also-named-by-id" // mutually exclusive with the material
	_, err := cm.WrapKeyByID(context.Background(), bad)
	require.Error(t, err)
	require.True(t, errorHasCode(err, CKR_ARGUMENTS_BAD),
		"the premise of this test is a refusal on the request, not on the mechanism: got %v", err)
	require.Equal(t, 0, client.wraps, "a malformed request must not reach the service")

	blob, err := cm.WrapKeyByID(context.Background(),
		gcmWrapRequest("wrapnonce-be", "refused-kek", iv, target))
	require.NoError(t, err,
		"the refused wrap must not have claimed the IV: the caller's corrected retry has nothing else to change")

	plaintext, err := gcmOpenOracle(t, kek, iv, blob[GCMNonceSize:], nil)
	require.NoError(t, err)
	assert.Equal(t, target, plaintext)
}

// TestWrapKeyByIDDoesNotClaimTheIVOfANonAEADMechanism keeps the claim where it
// belongs. CKM_AES_KEY_WRAP (RFC 3394) is a deterministic construction with no
// nonce at all: claiming the IV field for it would consume a value the caller
// can legitimately use for a later AES-GCM wrap under the same key, refusing a
// wrap that is not a reuse of anything.
func TestWrapKeyByIDDoesNotClaimTheIVOfANonAEADMechanism(t *testing.T) {
	kek := []byte("kw-then-gcm-KEK1")
	target := []byte("kw-target-16byte")
	iv := uniqueTestIV(t)

	client := newWrapTransport(map[string][]byte{"kw-kek": kek})
	cm := NewCryptoManager(client, &CryptoManagerConfig{DefaultBackend: "wrapnonce-be"})

	kw := gcmWrapRequest("wrapnonce-be", "kw-kek", iv, target)
	kw.Algorithm = string(types.WrapAESKW)
	_, err := cm.WrapKeyByID(context.Background(), kw)
	require.NoError(t, err)

	_, err = cm.WrapKeyByID(context.Background(),
		gcmWrapRequest("wrapnonce-be", "kw-kek", iv, target))
	require.NoError(t, err,
		"AES-KW consumes no IV, so the same value must still be available to AES-GCM")
}

// TestWrapKeyByIDLeavesAGeneratedNonceToTheService proves an empty IV is not
// claimed here.
//
// An empty CK_GCM_PARAMS.pIv asks the service to generate the nonce, and this
// module never learns which value that was; claiming the empty value instead
// would fail the guard's own input check on the very first such wrap and make
// every token-generated-IV wrap impossible. The generated nonce is claimed by
// the service that produced it, against this same process-wide guard.
func TestWrapKeyByIDLeavesAGeneratedNonceToTheService(t *testing.T) {
	kek := []byte("generated-iv-KEK")
	target := []byte("generated-target")

	client := newWrapTransport(map[string][]byte{"generated-kek": kek})
	cm := NewCryptoManager(client, &CryptoManagerConfig{DefaultBackend: "wrapnonce-be"})

	first, err := cm.WrapKeyByID(context.Background(),
		gcmWrapRequest("wrapnonce-be", "generated-kek", nil, target))
	require.NoError(t, err)
	require.Len(t, first, GCMNonceSize+len(target)+GCMTagSize)

	_, err = cm.WrapKeyByID(context.Background(),
		gcmWrapRequest("wrapnonce-be", "generated-kek", nil, target))
	require.NoError(t, err,
		"a wrap that supplies no IV must not be refused by a claim this module cannot make")
	assert.Equal(t, 2, client.wraps)
}

// TestEncryptRefusesAReusedIVAcrossTwoCryptoManagers is why the claim goes to
// the process-wide guard rather than to a map owned by the manager.
//
// One key, one IV, two CryptoManagers -- which is what a host gets when it
// builds a second manager for a second slot, a second connection, or a second
// component. The pair repeats and the keystream repeats with it, so the second
// encryption must be refused; a per-manager tracker sees two unrelated
// operations and lets it through.
func TestEncryptRefusesAReusedIVAcrossTwoCryptoManagers(t *testing.T) {
	iv := uniqueTestIV(t)
	plaintext := []byte("two-managers-one-key-one-iv")

	firstCM := NewCryptoManager(newGCMTransport(t), &CryptoManagerConfig{DefaultBackend: "twocm-be"})
	secondCM := NewCryptoManager(newGCMTransport(t), &CryptoManagerConfig{DefaultBackend: "twocm-be"})

	op, err := firstCM.EncryptInit(gcmMechanism(iv, nil, 128), 1, "twocm-key", "twocm-be")
	require.NoError(t, err)
	_, err = firstCM.Encrypt(context.Background(), op, plaintext)
	require.NoError(t, err)

	secondOp, err := secondCM.EncryptInit(gcmMechanism(iv, nil, 128), 1, "twocm-key", "twocm-be")
	require.NoError(t, err, "the mechanism is well formed: the pair is what is wrong with this call")
	ciphertext, err := secondCM.Encrypt(context.Background(), secondOp, plaintext)
	require.Error(t, err,
		"a second manager encrypting under the same (key, IV) repeats the pair SP 800-38D section 8.2 forbids")
	assert.Nil(t, ciphertext)
	assert.True(t, errorHasCode(err, CKR_MECHANISM_PARAM_INVALID), "got %v", err)
}

// TestCheckGCMNonceRejectsAnEmptyNonce covers the input the guard cannot key
// on. An empty nonce is a caller bug rather than a reuse, and accepting it
// would map every such call onto one tracker entry: the first would pass and
// every later one -- under any key -- would be reported as a repeat of it.
func TestCheckGCMNonceRejectsAnEmptyNonce(t *testing.T) {
	cm, _ := newTestCryptoManager()

	err := cm.checkGCMNonce("empty-nonce-be", "empty-nonce-key", nil)
	require.Error(t, err, "an empty IV names no pair and must not be recorded as one")
	assert.True(t, errorHasCode(err, CKR_FUNCTION_FAILED),
		"an unusable input is a failed call, not a reused IV: got %v", err)

	// The key itself is untouched by the rejected call.
	require.NoError(t, cm.checkGCMNonce("empty-nonce-be", "empty-nonce-key", uniqueTestIV(t)))
}

// TestRemoteKeyGuardIdentityIsUnambiguous proves the identity encoding cannot
// make two different keys look like one. The separator is what does it: with
// the fields simply concatenated, ("a", "bc") and ("ab", "c") would produce one
// identity, and an IV consumed under either key would silently forbid the
// other.
func TestRemoteKeyGuardIdentityIsUnambiguous(t *testing.T) {
	assert.NotEqual(t, remoteKeyGuardIdentity("a", "bc"), remoteKeyGuardIdentity("ab", "c"))
	assert.Equal(t, remoteKeyGuardIdentity("a", "bc"), remoteKeyGuardIdentity("a", "bc"),
		"one key must always produce one identity, or the guard would never match anything")
	assert.Contains(t, string(remoteKeyGuardIdentity("be", "kid")), remoteKeyGuardDomain,
		"the domain tag is what keeps a name from colliding with a real key's bytes")
}

// TestReusedNonceRefusalReadsForEveryCallerOfTheGuard pins the wording of the
// one refusal both callers of guardGCMNonce share.
//
// The guard was written for module_authwrap.go's in-process wrap and said so:
// "a fresh IV is required for every wrap". CryptoManager.checkGCMNonce now
// delegates to it as well, so the same sentence answers a C_Encrypt that never
// wrapped anything -- telling an application to change something it is not
// doing. The code is right either way; the sentence has to cover both.
func TestReusedNonceRefusalReadsForEveryCallerOfTheGuard(t *testing.T) {
	// The encryption caller: CryptoManager.checkGCMNonce, keyed by (backend,
	// key id).
	cm, _ := newTestCryptoManager()
	iv := uniqueTestIV(t)
	require.NoError(t, cm.checkGCMNonce("wording-be", "wording-key", iv),
		"the first use of an IV under a key is legitimate")

	encryptErr := cm.checkGCMNonce("wording-be", "wording-key", iv)
	require.Error(t, encryptErr)
	require.True(t, errorHasCode(encryptErr, CKR_MECHANISM_PARAM_INVALID),
		"the caller has to change the IV in CK_GCM_PARAMS: got %v", encryptErr)

	// The wrap caller: guardGCMNonce keyed by the wrapping key's own CKA_VALUE.
	keyMaterial := []byte("wording-KEK-0123")
	wrapIV := uniqueTestIV(t)
	require.NoError(t, guardGCMNonce(keyMaterial, wrapIV))

	wrapErr := guardGCMNonce(keyMaterial, wrapIV)
	require.Error(t, wrapErr)

	for name, err := range map[string]error{"C_Encrypt": encryptErr, "C_WrapKeyAuthenticated": wrapErr} {
		assert.Contains(t, err.Error(), "encryption or wrap",
			"%s reaches this refusal, so it must not name a wrap alone", name)
	}
}
