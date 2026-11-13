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

package pairingproto

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The published #129 interop vectors, byte for byte.
//
// These are the SHARED vectors: xkey-android's Kotlin prover asserts the same
// inputs produce the same bytes, and the two repositories co-merge only when
// both are green against them. They are literals rather than values computed
// from the constants above them on purpose — a vector derived from the code it
// is meant to pin moves whenever the code does, and would agree with a
// regression as readily as with the contract.
//
// A failure here is a WIRE BREAK, not a test to update: changing any of these
// values makes every already-paired device fail to re-attest. Changing the
// contract means a new protocol version, not new literals.
//
// Inputs (all 32 bytes each):
//
//	nonce             0x00,0x01,…,0x1f
//	channelBinding    0x40,0x41,…,0x5f
//	deviceFingerprint 0x80,0x81,…,0x9f
//	initiatorStatic   0x11 ×32
//	responderStatic   0x22 ×32
//	prologue          0x33 ×32
const (
	vecTranscriptPair = "786b65792d6174746573742d7472616e7363726970742d76310470616972" +
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
		"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
		"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
	vecTranscriptPairSHA256 = "9596fd4bb233398dde69c6d396fca68efe4f8f78340938c5ed4312c3c16fb464"

	vecTranscriptReattest = "786b65792d6174746573742d7472616e7363726970742d76310872656174746573" +
		"74000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
		"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
		"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
	vecTranscriptReattestSHA256 = "73558f75434804633b3148cb2f4f9c478fcc99f8e02930976abc6ebe68e60784"

	vecChannelBindingWithPrologue = "f6cdd5b309152e44264c49cd523a88c0e9ee18e4e59da14b7278d99dfd16b6b6"
	vecChannelBindingNoPrologue   = "53bfe5540b4862f534eb0990978b81d4277f5923d67a7b83be7271801a1bae22"

	// The same two keys with the ROLES REVERSED: initiator 0x22, responder
	// 0x11. Published because the two vectors above cannot, on their own,
	// catch a role-BLIND derivation — one that sorts the keys, or hashes
	// "mine then theirs".
	//
	// Found by the xkey-android lane while implementing the prover: in the
	// vectors above the initiator (0x11) already sorts before the responder
	// (0x22), so a sorted derivation reproduces them EXACTLY. Worse, and this
	// is the part that makes a third vector worth publishing rather than just
	// asserting locally: the real-path interop test does not catch it either,
	// because both ends call the same derivation, so a mutation to it moves
	// the oracle along with the subject. Measured — sorting the keys leaves
	// both the vector test and TestPairThenReconnectThenReattest_Interop
	// green, and only TestComputeAttestChannelBindingIsOrderedAndSeparated
	// red.
	//
	// A vector set that cannot catch role-blindness is an incomplete contract
	// for the next implementer, who has no reason to write the assertion
	// unless the vectors make them.
	vecChannelBindingRoleReversedWithPrologue = "c3a3a274dde29ad887300714f44bdb804c70722767463cac91ac0b99a0619244"
	vecChannelBindingRoleReversedNoPrologue   = "da49360dad9f9f97fc05c1135a18c7905e06bb8ddc156fd3df907665d503b2e6"

	vecGenesisChallengeHex = "786b65792d6465766963652d6174746573746174696f6e2d7631"
	vecTranscriptDomainHex = "786b65792d6174746573742d7472616e7363726970742d7631"
	vecChannelDomainHex    = "786b65792d6174746573742d6368616e6e656c2d7631"

	// local.verifyUser (rulings 167 and 180): the version 2 transcript under
	// the "verify-user" purpose, with the UVK fingerprint in its last field,
	// followed by SHA-256 of the RP name "example.com". Ruling 180 added the
	// RP name hash; the ruling 167 transcript without it hashed to
	// 30f3f98d0ccfa8302dbc2768119257aa0cbf18b5e2391fe8c08a1dca8dd11a04.
	vecTranscriptVerifyUser = "786b65792d6174746573742d7472616e7363726970742d76310b7665726966792d75736572" +
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
		"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
		"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
		"a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947"
	vecTranscriptVerifyUserSHA256       = "a47b57bab3657a8ee22312c3b9d6e30517bb0470275f4140e1ef6887beaa141c"
	vecPurposeVerifyUserHex             = "7665726966792d75736572"
	vecUserVerificationGenesisChallenge = "786b65792d757365722d766572696669636174696f6e2d7631"
	vecVerifyUserRPName                 = "example.com"
	vecVerifyUserRPNameHex              = "6578616d706c652e636f6d"
)

// vecRamp returns 32 bytes counting up from start, the shape the published
// vectors use so a misaligned field shows up as an obvious offset.
func vecRamp(start byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

// TestAttestVectorsMatchThePublishedBytes is the interop anchor.
func TestAttestVectorsMatchThePublishedBytes(t *testing.T) {
	nonce := vecRamp(0x00)
	binding := vecRamp(0x40)
	fingerprint := vecRamp(0x80)

	t.Run("transcript pair", func(t *testing.T) {
		transcript, err := BuildAttestTranscript(AttestPurposePair, nonce, binding, fingerprint)
		require.NoError(t, err)
		assert.Equal(t, vecTranscriptPair, hex.EncodeToString(transcript))

		digest := sha256.Sum256(transcript)
		assert.Equal(t, vecTranscriptPairSHA256, hex.EncodeToString(digest[:]),
			"this digest is what SHA256withECDSA signs; a Kotlin prover must reach the same one")
	})

	t.Run("transcript reattest", func(t *testing.T) {
		transcript, err := BuildAttestTranscript(AttestPurposeReattest, nonce, binding, fingerprint)
		require.NoError(t, err)
		assert.Equal(t, vecTranscriptReattest, hex.EncodeToString(transcript))

		digest := sha256.Sum256(transcript)
		assert.Equal(t, vecTranscriptReattestSHA256, hex.EncodeToString(digest[:]))
	})

	t.Run("channel binding", func(t *testing.T) {
		initiator := fixed(0x11, AttestStaticKeySize)
		responder := fixed(0x22, AttestStaticKeySize)

		withPrologue, err := ComputeAttestChannelBinding(initiator, responder, fixed(0x33, 32))
		require.NoError(t, err)
		assert.Equal(t, vecChannelBindingWithPrologue, hex.EncodeToString(withPrologue))

		noPrologue, err := ComputeAttestChannelBinding(initiator, responder, nil)
		require.NoError(t, err)
		assert.Equal(t, vecChannelBindingNoPrologue, hex.EncodeToString(noPrologue),
			"the first-pairing case, where the identity exchange has no fingerprint to bind")
	})

	t.Run("channel binding with the roles reversed", func(t *testing.T) {
		// Same two keys, swapped roles. A role-blind derivation would produce
		// the values asserted above for THIS input too; these differ, which is
		// the whole reason the vector is published.
		initiator := fixed(0x22, AttestStaticKeySize)
		responder := fixed(0x11, AttestStaticKeySize)

		withPrologue, err := ComputeAttestChannelBinding(initiator, responder, fixed(0x33, 32))
		require.NoError(t, err)
		assert.Equal(t, vecChannelBindingRoleReversedWithPrologue, hex.EncodeToString(withPrologue))
		assert.NotEqual(t, vecChannelBindingWithPrologue, hex.EncodeToString(withPrologue),
			"reversing the roles must change the binding; if these match, the derivation is role-blind")

		noPrologue, err := ComputeAttestChannelBinding(initiator, responder, nil)
		require.NoError(t, err)
		assert.Equal(t, vecChannelBindingRoleReversedNoPrologue, hex.EncodeToString(noPrologue))
		assert.NotEqual(t, vecChannelBindingNoPrologue, hex.EncodeToString(noPrologue))
	})

	t.Run("domain constants", func(t *testing.T) {
		// Spelled in hex because these travel to a repository that cannot
		// import them: a Kotlin string literal with a stray character is
		// exactly the failure these bytes are here to catch.
		assert.Equal(t, vecGenesisChallengeHex, hex.EncodeToString([]byte(AttestGenesisChallenge)))
		assert.Equal(t, vecTranscriptDomainHex, hex.EncodeToString([]byte(AttestTranscriptDomain)))
		assert.Equal(t, vecChannelDomainHex, hex.EncodeToString([]byte(AttestChannelBindingDomain)))
	})

	t.Run("transcript verify-user", func(t *testing.T) {
		transcript, err := BuildVerifyUserTranscript(vecVerifyUserRPName, nonce, binding, fingerprint)
		require.NoError(t, err)
		assert.Equal(t, vecTranscriptVerifyUser, hex.EncodeToString(transcript))

		digest := sha256.Sum256(transcript)
		assert.Equal(t, vecTranscriptVerifyUserSHA256, hex.EncodeToString(digest[:]),
			"the digest the UVK signs after a fresh user authentication")
	})

	t.Run("verify-user constants", func(t *testing.T) {
		assert.Equal(t, vecPurposeVerifyUserHex, hex.EncodeToString([]byte(AttestPurposeVerifyUser)))
		assert.Equal(t, vecVerifyUserRPNameHex, hex.EncodeToString([]byte(vecVerifyUserRPName)))
		assert.Equal(t, vecUserVerificationGenesisChallenge,
			hex.EncodeToString([]byte(UserVerificationGenesisChallenge)))
	})
}
