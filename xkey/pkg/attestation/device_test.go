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

package attestation_test

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// These tests cover the device-attestation DECISION (#95, #93, #129).
//
// They moved here with the decision itself. While they lived in the command
// package they were gated behind the `ble` build tag and ran only via a
// hand-maintained list of test names in CI — so the GUI, which makes the same
// decision, was covered by none of them. Here they run in the ordinary suite
// for every consumer.

// testChallenge builds a challenge with deterministic, distinguishable bytes.
func testChallenge(purpose string, nonceFill, bindingFill byte) *attestation.Challenge {
	return &attestation.Challenge{
		Purpose:        purpose,
		Nonce:          attesttest.FixedBytes(nonceFill, pairing.AttestNonceSize),
		ChannelBinding: attesttest.FixedBytes(bindingFill, pairing.AttestChannelBindingSize),
	}
}

// respond is the contract-faithful answer for a challenge.
func respond(t *testing.T, dak *attesttest.DAK, c *attestation.Challenge) *pairing.LocalAttestDeviceResult {
	t.Helper()
	return dak.Respond(t, c.Purpose, c.Nonce, c.ChannelBinding)
}

// sha256Hex is the fingerprint encoding the pairing record stores.
func sha256Hex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// TestPairingRefusesASelfSignedAttestationChain is the acceptance criterion
// from #95: a peer that generates its own certificate must not get that
// certificate's hash written into the pairing record as a DeviceFingerprint.
//
// The chain here is otherwise perfect — a real attestation extension, the
// contract's genesis challenge, and a valid live signature over this
// pairing's challenge. Only the anchor is wrong, which is the whole point:
// before the fix nothing looked at the anchor at all, and a live signature
// does not make an unvouched-for key trustworthy.
func TestPairingRefusesASelfSignedAttestationChain(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	challenge := testChallenge(pairing.AttestPurposePair, 0x01, 0x02)

	dak := attesttest.NewDAK(t, nil, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())

	verified, err := attestation.VerifyDeviceAttestation(respond(t, dak, challenge), challenge, &attestation.Trust{Pool: ca.Pool()})

	require.Error(t, err, "a self-signed chain must be refused")
	require.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
	assert.Nil(t, verified, "nothing may be produced for persistence from an unverified chain")
	assert.NotContains(t, errString(err), sha256Hex(dak.Chain[0]),
		"the peer's own certificate hash must not surface as a fingerprint")
}

// TestPairingRefusesALeafNotIssuedByTheAnchorItPresents is the test that
// actually pins chain verification.
//
// The self-signed case above does not: it is refused by the anchor comparison
// alone, so it still passes with TrustedRoots dropped from the verify options
// (measured -- that mutant survived). This chain ENDS in the genuine trusted
// root, which is public information any peer can append, so the anchor
// comparison is satisfied. Only verifying that the leaf was really issued
// under that root refuses it.
func TestPairingRefusesALeafNotIssuedByTheAnchorItPresents(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	impostor := attesttest.NewCA(t, "Impostor Root")
	challenge := testChallenge(pairing.AttestPurposePair, 0x03, 0x04)

	// Issued by a root nobody trusts, presented alongside one everybody does.
	dak := attesttest.NewDAK(t, impostor, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	response := respond(t, dak, challenge)
	response.CertificateChain = [][]byte{dak.Chain[0], ca.Cert.Raw}

	verified, err := attestation.VerifyDeviceAttestation(response, challenge, &attestation.Trust{Pool: ca.Pool()})

	require.Error(t, err, "a leaf not issued under the presented anchor must be refused")
	require.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
	assert.Nil(t, verified)
}

// TestPairingRefusesAReplayedChallengeSignature is the #129 replacement for
// the replayed-attestation-challenge test.
//
// Under the old model freshness lived in the certificate, so a replay was a
// stale chain. Under challenge-response the chain is EXPECTED to be the same
// every time — it certifies a persistent key — and what must not be reusable
// is the signature. So the replay this test performs is the one that now
// matters: a signature captured from an earlier exchange, presented against a
// current chain and a current challenge.
//
// The device is genuine, the chain verifies, the key is the right one. Only
// the signature answers the wrong nonce.
func TestPairingRefusesAReplayedChallengeSignature(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())

	captured := testChallenge(pairing.AttestPurposePair, 0xaa, 0xab)
	thisPairing := testChallenge(pairing.AttestPurposePair, 0xbb, 0xab)

	response := respond(t, dak, thisPairing)
	response.Signature = dak.Sign(t, captured.Purpose, captured.Nonce, captured.ChannelBinding)

	verified, err := attestation.VerifyDeviceAttestation(response, thisPairing, &attestation.Trust{Pool: ca.Pool()})

	require.Error(t, err, "a signature answering an older challenge must be refused")
	require.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
	require.ErrorIs(t, err, pairing.ErrAttestSignatureInvalid)
	assert.Nil(t, verified)
}

// TestPairingRefusesASignatureRelayedFromAnotherConnection is the anti-relay
// property the channel binding exists for.
//
// The attacker completes its own Noise session with this desktop and forwards
// the desktop's nonce to a genuine phone on a second session. The phone signs
// honestly — same key, same purpose, THIS nonce — but binds its signature to
// the session it is actually speaking on, which is not this one. Without the
// binding in the transcript that answer would verify here and the attacker
// would have borrowed the phone's hardware identity.
func TestPairingRefusesASignatureRelayedFromAnotherConnection(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())

	ours := testChallenge(pairing.AttestPurposePair, 0x5a, 0x11)
	relayed := testChallenge(pairing.AttestPurposePair, 0x5a, 0x22) // same nonce, other session

	response := respond(t, dak, relayed)

	verified, err := attestation.VerifyDeviceAttestation(response, ours, &attestation.Trust{Pool: ca.Pool()})

	require.Error(t, err, "a signature bound to another connection must be refused")
	require.ErrorIs(t, err, pairing.ErrAttestSignatureInvalid)
	assert.Nil(t, verified)
}

// TestPairingRefusesASignatureForAnotherPurpose pins the purpose field.
//
// Pairing and re-attestation ask the same key the same kind of question, so
// without a purpose in the transcript a signature gathered during one would
// satisfy the other. Here the device answers a "reattest" transcript while the
// verifier asked to pair.
func TestPairingRefusesASignatureForAnotherPurpose(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())

	challenge := testChallenge(pairing.AttestPurposePair, 0x6c, 0x6d)

	response := respond(t, dak, challenge)
	response.Signature = dak.Sign(t, pairing.AttestPurposeReattest, challenge.Nonce, challenge.ChannelBinding)

	verified, err := attestation.VerifyDeviceAttestation(response, challenge, &attestation.Trust{Pool: ca.Pool()})

	require.Error(t, err, "a signature for a different purpose must be refused")
	require.ErrorIs(t, err, pairing.ErrAttestSignatureInvalid)
	assert.Nil(t, verified)
}

// TestPairingRefusesAChainWithoutAMatchingSignature is the case that separates
// the two halves of the proof.
//
// The chain is genuine and verifies to the trusted anchor — it is a public
// document, and a chain captured from any earlier exchange with this phone
// looks exactly like this. What the attacker cannot produce is a signature by
// the key it certifies. Before #129 a chain alone was the whole of the
// evidence at reconnect.
func TestPairingRefusesAChainWithoutAMatchingSignature(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	genuine := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	impostor := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())

	challenge := testChallenge(pairing.AttestPurposePair, 0x7e, 0x7f)

	// The genuine device's chain, signed by a key the attacker actually holds.
	response := respond(t, impostor, challenge)
	response.CertificateChain = genuine.Chain

	verified, err := attestation.VerifyDeviceAttestation(response, challenge, &attestation.Trust{Pool: ca.Pool()})

	require.Error(t, err, "replaying another device's chain must be refused")
	require.ErrorIs(t, err, pairing.ErrAttestSignatureInvalid)
	assert.Nil(t, verified)
}

// TestPairingRefusesAMissingSignature covers the omission directly: a response
// that simply leaves the signature out must not fall through to "verified".
func TestPairingRefusesAMissingSignature(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	challenge := testChallenge(pairing.AttestPurposePair, 0x8a, 0x8b)

	response := respond(t, dak, challenge)
	response.Signature = nil

	verified, err := attestation.VerifyDeviceAttestation(response, challenge, &attestation.Trust{Pool: ca.Pool()})

	require.Error(t, err)
	require.ErrorIs(t, err, pairing.ErrAttestSignatureMissing)
	assert.Nil(t, verified)
}

// TestPairingRefusesAProtocolDowngrade is the flag-day guard.
//
// A device that answers a version 2 challenge with version 1 is claiming it
// cannot prove liveness. Accepting that would put the choice of which checks
// apply in the hands of the party being checked — the same defect the
// identity-ack "unknown" path was fixed for.
func TestPairingRefusesAProtocolDowngrade(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	challenge := testChallenge(pairing.AttestPurposePair, 0x9c, 0x9d)

	for name, version := range map[string]int{
		"claims version 1":  pairing.AttestProtocolV1,
		"claims no version": 0,
		"claims a version this build does not implement": 99,
	} {
		t.Run(name, func(t *testing.T) {
			// Everything else about the response is perfect, including a valid
			// signature: only the version is wrong, so nothing but the version
			// check can be what refuses it.
			response := respond(t, dak, challenge)
			response.ProtocolVersion = version

			verified, err := attestation.VerifyDeviceAttestation(response, challenge, &attestation.Trust{Pool: ca.Pool()})

			require.Error(t, err, "a downgraded attestation must be refused, never accommodated")
			require.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
			assert.Contains(t, errString(err), "attestation protocol version")
			assert.Nil(t, verified)
		})
	}
}

// TestPairingRefusesAKeyNotGeneratedForThisProtocol pins the genesis
// challenge.
//
// The chain verifies, the boot state is good, and the device holds the key and
// signs correctly with it — but the key was generated under someone else's
// attestation challenge, so it was never created to be an xkey device key. A
// chain minted for an unrelated Android attestation must not be presentable
// here.
func TestPairingRefusesAKeyNotGeneratedForThisProtocol(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, []byte("some-other-app-challenge"),
		xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	challenge := testChallenge(pairing.AttestPurposePair, 0xa1, 0xa2)

	verified, err := attestation.VerifyDeviceAttestation(respond(t, dak, challenge), challenge, &attestation.Trust{Pool: ca.Pool()})

	require.Error(t, err)
	require.ErrorIs(t, err, pairing.ErrAttestGenesisChallenge)
	assert.Nil(t, verified)
}

// TestPairingAcceptsAVerifiedDeviceAndRecordsTheAttestedKey is the happy path,
// and pins where each persisted value comes from.
func TestPairingAcceptsAVerifiedDeviceAndRecordsTheAttestedKey(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	challenge := testChallenge(pairing.AttestPurposePair, 0xc1, 0xc2)

	verified, err := attestation.VerifyDeviceAttestation(respond(t, dak, challenge), challenge, &attestation.Trust{Pool: ca.Pool()})
	require.NoError(t, err)
	require.NotNil(t, verified)

	// The identity is the attested KEY, derived here from the key itself
	// rather than from anything the verifier produced.
	assert.Equal(t, hex.EncodeToString(dak.Fingerprint()), verified.Result.DeviceFingerprint,
		"the fingerprint is the SHA-256 of the attested key's SubjectPublicKeyInfo")
	assert.NotEqual(t, sha256Hex(ca.Cert.Raw), verified.Result.DeviceFingerprint,
		"the anchor is a vendor CA shared across handsets, not a device identity")
	assert.NotEqual(t, sha256Hex(dak.Chain[0]), verified.Result.DeviceFingerprint,
		"hashing the whole leaf would move on every honest re-attestation")

	assert.Equal(t, pairing.AttestProtocolV2, verified.Result.ProtocolVersion,
		"the record must carry the model it was established under")

	// From the signed extension, not from the RPC's sibling JSON fields.
	assert.Equal(t, "strongbox", verified.Result.SecurityLevel)

	// The boot claim comes from the signed extension too. Reaching this line at
	// all means the extension CARRIED a RootOfTrust: pairing refuses one that
	// does not, so BootStateVerified can no longer be false here and the boot
	// hash can no longer be empty. The old code read bootState == 0 off the
	// peer's JSON and recorded BootStateVerified: true from it.
	assert.True(t, verified.Result.BootStateVerified)
	assert.Equal(t, hex.EncodeToString(attesttest.AttestedBootState().VerifiedBootHash), verified.Result.BootHashHex)
	assert.Equal(t, "verified", verified.BootState)
}

// TestAttestedKeyFingerprintIsStableAcrossReAttestation is the rotation
// semantics #93 requires, and the reason the fingerprint hashes the SPKI
// rather than the leaf.
//
// Re-attesting the SAME key reissues the leaf with a fresh serial and validity
// window. If the identity moved on that, every honest re-attestation would
// read as a new device and the fail-closed refusal would fire on the normal
// case; if it did not move on a genuinely new key, a rotated device would keep
// the old identity.
func TestAttestedKeyFingerprintIsStableAcrossReAttestation(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())

	first := testChallenge(pairing.AttestPurposePair, 0xd1, 0xd2)
	firstVerified, err := attestation.VerifyDeviceAttestation(respond(t, dak, first), first, &attestation.Trust{Pool: ca.Pool()})
	require.NoError(t, err)

	// A second attestation of the same key: a new leaf, same key.
	reissuedDER := attesttest.AttestedLeafDER(t, ca, dak.Key, attesttest.GenesisChallenge(),
		xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	require.NotEqual(t, dak.Chain[0], reissuedDER, "the fixture must actually reissue the leaf")

	second := testChallenge(pairing.AttestPurposeReattest, 0xd3, 0xd4)
	reissued := respond(t, dak, second)
	reissued.CertificateChain = [][]byte{reissuedDER, ca.Cert.Raw}

	secondVerified, err := attestation.VerifyDeviceAttestation(reissued, second, &attestation.Trust{Pool: ca.Pool()})
	require.NoError(t, err)

	assert.Equal(t, firstVerified.Result.DeviceFingerprint, secondVerified.Result.DeviceFingerprint,
		"an honest re-attestation of the same key must not read as a new device")

	// A genuinely different key must move it, or the value identifies nothing.
	rotated := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	third := testChallenge(pairing.AttestPurposeReattest, 0xd5, 0xd6)
	rotatedVerified, err := attestation.VerifyDeviceAttestation(respond(t, rotated, third), third, &attestation.Trust{Pool: ca.Pool()})
	require.NoError(t, err)

	assert.NotEqual(t, firstVerified.Result.DeviceFingerprint, rotatedVerified.Result.DeviceFingerprint,
		"a rotated key must produce a different identity")
}

// TestPairingRefusesAnAttestationThatClaimsNothingAboutBoot is the second of
// Codex's round-4 findings.
//
// AndroidVerifyOptions.VerifyBootState is "if a RootOfTrust is PRESENT, it must
// say verified", so an extension carrying none passes it. Before this, a
// trusted, nonce-matching, StrongBox chain with no RootOfTrust was reported as
// "Chain Status: VERIFIED", got a security level and an attestation timestamp
// written to the record, and paired -- having claimed nothing whatsoever about
// its boot chain. For a phone-as-HSM pairing that claim IS the product.
//
// The three subtests are the three ways the claim can fail to hold. The first
// is the one the SDK cannot catch by construction; the other two prove the
// check is not merely a nil test.
func TestPairingRefusesAnAttestationThatClaimsNothingAboutBoot(t *testing.T) {
	unlocked := attesttest.AttestedBootState()
	unlocked.DeviceLocked = false

	unverified := attesttest.AttestedBootState()
	unverified.VerifiedBootState = xkms.AndroidVerifiedBootUnverified

	for _, tc := range []struct {
		name string
		rot  *xkms.AndroidRootOfTrust
		why  string
	}{
		{
			name: "no root of trust at all", rot: nil,
			why: "the SDK's VerifyBootState passes an absent claim, so refusing it " +
				"is the caller's job and this is the caller",
		},
		{
			name: "bootloader unlocked", rot: unlocked,
			why: "an unlocked bootloader can run an arbitrary image, so a verified " +
				"boot chain from one is replaceable at will",
		},
		{
			name: "boot state not verified", rot: unverified,
			why: "an explicit unverified state is a refusal, not a warning",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := attesttest.NewCA(t, "Trusted Attestation Root")
			dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, tc.rot)
			challenge := testChallenge(pairing.AttestPurposePair, 0xe1, 0xe2)

			verified, err := attestation.VerifyDeviceAttestation(respond(t, dak, challenge), challenge, &attestation.Trust{Pool: ca.Pool()})
			require.Error(t, err, tc.why)
			require.Nil(t, verified,
				"a refused attestation must yield no record; everything in it would be "+
					"a claim the chain did not make")
			require.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
		})
	}
}

// TestPairingAcceptsAKeyGeneratedInTEEAndAuthorizedToSign pins the accept
// path for the go-xkms#132 check: attesttest's default TEE-enforced claims --
// Origin GENERATED, Purpose including SIGN -- must not, by themselves, refuse
// an otherwise healthy attestation.
func TestPairingAcceptsAKeyGeneratedInTEEAndAuthorizedToSign(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	challenge := testChallenge(pairing.AttestPurposePair, 0x51, 0x52)

	verified, err := attestation.VerifyDeviceAttestation(respond(t, dak, challenge), challenge, &attestation.Trust{Pool: ca.Pool()})

	require.NoError(t, err, "a TEE-enforced GENERATED origin and a SIGN purpose must be accepted")
	require.NotNil(t, verified)
}

// TestPairingRefusesAnAttestedKeyNotGeneratedInTEEOrNotAuthorizedToSign is the
// go-xkms#132 acceptance test end-to-end: the TEE-enforced authorization list
// must claim the key was GENERATED and may SIGN, and each way that claim can
// fail to hold is its own subtest.
func TestPairingRefusesAnAttestedKeyNotGeneratedInTEEOrNotAuthorizedToSign(t *testing.T) {
	imported := attesttest.DeviceKeyClaims()
	imported.RootOfTrust = attesttest.AttestedBootState()
	imported.Origin = xkms.AndroidOriginImported

	noSign := attesttest.DeviceKeyClaims()
	noSign.RootOfTrust = attesttest.AttestedBootState()
	noSign.Purpose = []int{xkms.AndroidPurposeVerify}

	noClaimAtAll := &xkms.AndroidAttestationExtensionOptions{
		RootOfTrust: attesttest.AttestedBootState(),
		// HasOrigin left false and Purpose left nil: the TEE makes neither
		// claim, the shape a pre-#132 fixture or an attestation with no
		// secure hardware produces (see the real-chain evidence in
		// pkg/attestation/android's TestParseKeyAttestation_RealChainOriginAndPurpose).
	}

	for _, tc := range []struct {
		name   string
		claims *xkms.AndroidAttestationExtensionOptions
		want   error
		why    string
	}{
		{
			name: "origin imported, not generated", claims: imported,
			want: attestation.ErrAttestationKeyOriginNotGenerated,
			why: "everything else this chain proves is equally consistent with a " +
				"key generated elsewhere and imported into the TEE",
		},
		{
			name: "purpose does not include sign", claims: noSign,
			want: attestation.ErrAttestationKeyPurposeNotSign,
			why:  "a key the TEE never authorized to sign must not attest a signing protocol",
		},
		{
			name: "TEE makes no origin or purpose claim at all", claims: noClaimAtAll,
			want: attestation.ErrAttestationKeyOriginNotGenerated,
			why:  "absence is evidence of neither claim, so it must fail exactly as a wrong value would",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := attesttest.NewCA(t, "Trusted Attestation Root")
			dak := attesttest.NewDAKWithClaims(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, tc.claims)
			challenge := testChallenge(pairing.AttestPurposePair, 0x61, 0x62)

			verified, err := attestation.VerifyDeviceAttestation(respond(t, dak, challenge), challenge, &attestation.Trust{Pool: ca.Pool()})

			require.Error(t, err, tc.why)
			require.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
			require.ErrorIs(t, err, tc.want)
			require.Nil(t, verified, "a refused attestation must yield no record")
		})
	}
}

// TestRequireAttestedKeyOrigin_Succeeds is the direct unit test for the
// go-xkms#132 check's accept path, isolated from chain verification and boot
// state so a future regression there cannot mask one here.
func TestRequireAttestedKeyOrigin_Succeeds(t *testing.T) {
	desc := &xkms.AndroidKeyDescription{
		TeeEnforced: xkms.AndroidAuthorizationList{
			Origin:  xkms.AndroidOriginGenerated,
			Purpose: []int{xkms.AndroidPurposeSign},
		},
	}

	require.NoError(t, attestation.RequireAttestedKeyOrigin(desc))
}

// TestRequireAttestedKeyOrigin_Refuses covers every way the TEE-enforced
// claim can fail to hold, including the one full-flow fixtures cannot
// construct directly: a claim present only in SoftwareEnforced (go-xkms#132).
//
// The "claim present only in softwareEnforced" subtest is the mutation guard
// the issue names: if RequireAttestedKeyOrigin were changed to read
// desc.SoftwareEnforced instead of desc.TeeEnforced, this is the subtest that
// turns red, because SoftwareEnforced here carries a perfectly valid
// GENERATED+SIGN claim -- exactly what a real (non-TEE) Android attestation
// looks like, per the emulator chain in pkg/attestation/android.
func TestRequireAttestedKeyOrigin_Refuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		desc *xkms.AndroidKeyDescription
		want error
	}{
		{
			name: "origin imported",
			desc: &xkms.AndroidKeyDescription{
				TeeEnforced: xkms.AndroidAuthorizationList{
					Origin:  xkms.AndroidOriginImported,
					Purpose: []int{xkms.AndroidPurposeSign},
				},
			},
			want: attestation.ErrAttestationKeyOriginNotGenerated,
		},
		{
			name: "purpose without sign",
			desc: &xkms.AndroidKeyDescription{
				TeeEnforced: xkms.AndroidAuthorizationList{
					Origin:  xkms.AndroidOriginGenerated,
					Purpose: []int{xkms.AndroidPurposeVerify},
				},
			},
			want: attestation.ErrAttestationKeyPurposeNotSign,
		},
		{
			name: "no TEE-enforced claim at all",
			desc: &xkms.AndroidKeyDescription{
				TeeEnforced: xkms.AndroidAuthorizationList{Origin: xkms.AndroidOriginUnknown},
			},
			want: attestation.ErrAttestationKeyOriginNotGenerated,
		},
		{
			name: "claim present only in softwareEnforced",
			desc: &xkms.AndroidKeyDescription{
				TeeEnforced: xkms.AndroidAuthorizationList{Origin: xkms.AndroidOriginUnknown},
				SoftwareEnforced: xkms.AndroidAuthorizationList{
					Origin:  xkms.AndroidOriginGenerated,
					Purpose: []int{xkms.AndroidPurposeSign},
				},
			},
			want: attestation.ErrAttestationKeyOriginNotGenerated,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := attestation.RequireAttestedKeyOrigin(tc.desc)
			require.Error(t, err)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// TestPairingIgnoresACertificateAppendedAfterTheVerifiedAnchor is the
// regression for the finding Codex raised on the first round of #124.
//
// The first version carried a flat list of roots beside the pool so the anchor
// could be looked up by fingerprint. The list was built from the trust store's
// certificates for EVERY purpose while the pool held the Android-hardware ones
// alone, so a peer could append the public DER of a certificate stored under
// an unrelated purpose: verification succeeded through the genuine root, and
// the lookup then named the appended certificate as "the anchor" and persisted
// its hash.
//
// Under #93 the persisted value is the attested key, so an appended
// certificate cannot become the identity by construction. The test still pins
// that the appended certificate does not break the chain, and that neither it
// nor the anchor is what gets recorded.
func TestPairingIgnoresACertificateAppendedAfterTheVerifiedAnchor(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	otherPurpose := attesttest.NewCA(t, "Stored For Another Purpose")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	challenge := testChallenge(pairing.AttestPurposePair, 0xf1, 0xf2)

	response := respond(t, dak, challenge)
	response.CertificateChain = [][]byte{dak.Chain[0], ca.Cert.Raw, otherPurpose.Cert.Raw}

	verified, err := attestation.VerifyDeviceAttestation(response, challenge, &attestation.Trust{Pool: ca.Pool()})

	require.NoError(t, err, "an unused trailing certificate must not break a valid chain")
	require.NotNil(t, verified)

	assert.Equal(t, hex.EncodeToString(dak.Fingerprint()), verified.Result.DeviceFingerprint,
		"the fingerprint must be the attested key, whatever the peer appended")
	assert.NotEqual(t, sha256Hex(otherPurpose.Cert.Raw), verified.Result.DeviceFingerprint,
		"a certificate the peer appended must never become the recorded identity")
}

// TestPairingRefusesASoftwareProtectedKey pins the minimum this path admits.
//
// Without it pairing accepted a software-protected key on a perfectly valid
// chain and reported "Chain Status: VERIFIED" over it — while `device
// attest-device`, which runs on the very next re-attestation, requires at
// least TrustedEnvironment. The gate that ESTABLISHES the binding was the
// weaker of the two.
func TestPairingRefusesASoftwareProtectedKey(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelSoftware, attesttest.AttestedBootState())
	challenge := testChallenge(pairing.AttestPurposePair, 0x21, 0x22)

	verified, err := attestation.VerifyDeviceAttestation(respond(t, dak, challenge), challenge, &attestation.Trust{Pool: ca.Pool()})

	require.Error(t, err, "a software-protected key must not pair as a hardware-backed device")
	require.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
	assert.Nil(t, verified)
}

// TestPairingAcceptsATrustedEnvironmentKey fixes the minimum at the level
// attest-device uses, so raising it further is a deliberate change rather than
// an accident: TEE is admitted, and the test above shows software is not.
func TestPairingAcceptsATrustedEnvironmentKey(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelTrustedEnvironment, attesttest.AttestedBootState())
	challenge := testChallenge(pairing.AttestPurposePair, 0x31, 0x32)

	verified, err := attestation.VerifyDeviceAttestation(respond(t, dak, challenge), challenge, &attestation.Trust{Pool: ca.Pool()})

	require.NoError(t, err)
	require.NotNil(t, verified)
	assert.Equal(t, "tee", verified.Result.SecurityLevel)
}

// TestPairingVerifyOptionsRequestTheHardwareBar pins the policy pairing asks
// for, including the two fields this package's fixtures cannot exercise.
//
// It also pins the #129 change to those options: ExpectedNonce must be UNSET.
// Setting it would compare the live nonce against the DAK's genesis challenge,
// which is fixed at key generation and can never equal it, so a device with a
// stable identity could never pair. That the freshness check moved is a
// deliberate design change, and this assertion is what makes reintroducing the
// old one a test failure rather than a silent regression to per-pairing keys.
func TestPairingVerifyOptionsRequestTheHardwareBar(t *testing.T) {
	pool := x509.NewCertPool()

	opts := attestation.VerifyOptions(pool)

	require.NotNil(t, opts)
	assert.Same(t, pool, opts.TrustedRoots,
		"a nil pool makes VerifyKeyAttestation skip chain verification entirely")
	assert.Nil(t, opts.ExpectedNonce,
		"freshness is the live challenge signature now; comparing the genesis "+
			"challenge against a live nonce could only ever refuse a stable device")
	assert.Equal(t, xkms.AndroidSecurityLevelTrustedEnvironment, opts.MinSecurityLevel,
		"pairing must not admit a device that device attest-device would refuse")
	assert.True(t, opts.VerifyBootState,
		"an explicitly unverified boot state must not pair")
}

// TestVerifyPairingAttestationRefusesMissingTrustMaterial guards the inputs
// whose absence would turn a check into a no-op: a nil TrustedRoots makes
// VerifyKeyAttestation skip chain verification, and a missing challenge leaves
// nothing for the signature to be checked against.
func TestVerifyPairingAttestationRefusesMissingTrustMaterial(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	good := testChallenge(pairing.AttestPurposePair, 0x41, 0x42)
	response := respond(t, dak, good)

	cases := map[string]struct {
		trust     *attestation.Trust
		challenge *attestation.Challenge
		response  *pairing.LocalAttestDeviceResult
	}{
		"nil trust":        {trust: nil, challenge: good, response: response},
		"nil pool":         {trust: &attestation.Trust{}, challenge: good, response: response},
		"empty pool":       {trust: &attestation.Trust{Pool: x509.NewCertPool()}, challenge: good, response: response},
		"nil challenge":    {trust: &attestation.Trust{Pool: ca.Pool()}, challenge: nil, response: response},
		"empty nonce":      {trust: &attestation.Trust{Pool: ca.Pool()}, challenge: &attestation.Challenge{Purpose: pairing.AttestPurposePair}, response: response},
		"no response":      {trust: &attestation.Trust{Pool: ca.Pool()}, challenge: good, response: nil},
		"empty cert chain": {trust: &attestation.Trust{Pool: ca.Pool()}, challenge: good, response: &pairing.LocalAttestDeviceResult{ProtocolVersion: pairing.AttestProtocolV2}},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			verified, err := attestation.VerifyDeviceAttestation(tc.response, tc.challenge, tc.trust)
			require.Error(t, err)
			require.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
			assert.Nil(t, verified)
		})
	}
}

// errString renders an error for assertions without tripping on a nil.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestReattestationAppliesTheSamePolicyAsPairing is the regression for both of
// Codex's blocking findings on #124, which shared one root cause: `device
// attest-device` re-implemented the verification sequence beside the one in
// device_pair.go, and the copies diverged.
//
// The divergence that mattered was the boot claim. `AndroidVerifyOptions`
// enforces "if a RootOfTrust is present it must say verified", so an extension
// carrying NONE passes it. Pairing refuses that case in requireAttestedBootState;
// the re-attestation copy read the RootOfTrust only when present and recorded
// BootStateVerified false with an empty boot hash. That was survivable while the
// record it wrote was just a timestamp — but #129 made it also write the
// attestation PROTOCOL VERSION, so the weaker path could mark a device as bound
// under challenge-response on evidence the binding path refuses.
//
// Both commands now go through attestOverSession, so the property under test is
// that ONE decision serves both purposes. The test drives verifyPairingAttestation
// with purpose "reattest" — what attest-device now asks for — over each fixture
// the pairing gate refuses, and requires the same refusal.
func TestReattestationAppliesTheSamePolicyAsPairing(t *testing.T) {
	unlocked := attesttest.AttestedBootState()
	unlocked.DeviceLocked = false

	unverified := attesttest.AttestedBootState()
	unverified.VerifiedBootState = xkms.AndroidVerifiedBootUnverified

	for name, rot := range map[string]*xkms.AndroidRootOfTrust{
		"no root of trust at all": nil,
		"bootloader unlocked":     unlocked,
		"boot state not verified": unverified,
	} {
		t.Run(name, func(t *testing.T) {
			ca := attesttest.NewCA(t, "Trusted Attestation Root")
			dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, rot)
			challenge := testChallenge(pairing.AttestPurposeReattest, 0xb1, 0xb2)

			verified, err := attestation.VerifyDeviceAttestation(respond(t, dak, challenge), challenge, &attestation.Trust{Pool: ca.Pool()})

			require.Error(t, err,
				"re-attestation must not admit a boot claim pairing refuses; otherwise the "+
					"weaker gate is the one recording the stronger binding")
			require.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
			require.Nil(t, verified,
				"nothing may be recorded, including the protocol version: marking a device "+
					"as bound under challenge-response is itself a claim")
		})
	}
}

// TestReattestationOfAHealthyDeviceRecordsTheProtocolVersion is the positive
// half — without it the test above would pass against a re-attestation path
// that refused everything.
func TestReattestationOfAHealthyDeviceRecordsTheProtocolVersion(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	challenge := testChallenge(pairing.AttestPurposeReattest, 0xb3, 0xb4)

	verified, err := attestation.VerifyDeviceAttestation(respond(t, dak, challenge), challenge, &attestation.Trust{Pool: ca.Pool()})
	require.NoError(t, err)
	require.NotNil(t, verified)

	assert.True(t, verified.Result.BootStateVerified)
	assert.NotEmpty(t, verified.Result.BootHashHex,
		"a recorded boot hash is what validateBootHashMatch compares on the next run")
	assert.Equal(t, pairing.AttestProtocolV2, verified.Result.ProtocolVersion)
}

// TestAVersionTwoBindingWithoutAFingerprintIsRefused is the regression for the
// fail-open Codex found on #124.
//
// The path was short and entirely plausible: the record says protocol v2, so
// the reconnect path requires the liveness proof; the peer's chain and
// signature verify honestly; and then the identity comparison sees an EMPTY
// stored fingerprint, reads it as a first attestation, and accepts whichever
// trusted Android device just answered. The pre-handshake comparison does not
// catch it either — DecodeDeviceFingerprint("") deliberately means "no
// fingerprint configured".
//
// So clearing one YAML field turned a device-bound record into "any
// hardware-attested handset will do", for anyone holding the copied paired
// Noise key. A valid signature from SOMEONE is not the thing being checked.
func TestAVersionTwoBindingWithoutAFingerprintIsRefused(t *testing.T) {
	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(),
		xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	challenge := testChallenge(pairing.AttestPurposeReattest, 0x11, 0x12)

	// The evidence is genuine throughout — only the record is incomplete.
	response := respond(t, dak, challenge)
	verified, err := attestation.VerifyDeviceAttestation(response, challenge,
		&attestation.Trust{Pool: ca.Pool()})
	require.NoError(t, err, "the device's own evidence is valid; the record is what is wrong")

	for name, binding := range map[string]attestation.DeviceBinding{
		"empty fingerprint":     {ProtocolVersion: pairing.AttestProtocolV2},
		"not hex":               {Fingerprint: "zzzz", ProtocolVersion: pairing.AttestProtocolV2},
		"truncated fingerprint": {Fingerprint: "abcd", ProtocolVersion: pairing.AttestProtocolV2},
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, binding.Validate(), attestation.ErrDeviceBindingIncomplete,
				"a record that demands the proof must carry something to judge it against")

			// And the comparison itself refuses, so a caller reaching it
			// directly cannot reintroduce the hole by skipping Validate.
			require.ErrorIs(t,
				binding.ValidateAttestedKeyMatch(verified.Result.DeviceFingerprint),
				attestation.ErrDeviceBindingIncomplete,
				"an empty fingerprint on a v2 record is an incomplete record, not an enrolment")
		})
	}
}

// TestALegacyBindingIsRejected documents the removal of the #129/#130 grace
// period for a record with no protocol version, or version 1 (BREAKING,
// go-xkms compat cleanup PR5): such a record no longer enrolls on its first
// attestation, it is refused outright and the operator must re-pair.
func TestALegacyBindingIsRejected(t *testing.T) {
	legacy := attestation.DeviceBinding{}

	require.ErrorIs(t, legacy.Validate(), attestation.ErrDeviceAttestationVersionUnsupported,
		"a record below version 2 must be refused, not treated as a first enrolment")
	require.ErrorIs(t, legacy.ValidateAttestedKeyMatch("whatever-the-first-attestation-yields"),
		attestation.ErrDeviceAttestationVersionUnsupported)

	v1 := attestation.DeviceBinding{ProtocolVersion: pairing.AttestProtocolV1}
	require.ErrorIs(t, v1.Validate(), attestation.ErrDeviceAttestationVersionUnsupported,
		"an explicit version 1 record is refused the same as an absent version")
}

// TestVerifyReattestationRefusesAnIncompleteBindingBeforeAsking pins WHERE the
// refusal happens.
//
// The transport is nil: if the incomplete binding were only caught after the
// exchange, this would panic instead of returning. A record with nothing to
// compare against cannot be made safe by a valid answer, so it must not reach
// the point of asking for one.
func TestVerifyReattestationRefusesAnIncompleteBindingBeforeAsking(t *testing.T) {
	binding := attestation.DeviceBinding{ProtocolVersion: pairing.AttestProtocolV2}

	err := attestation.VerifyReattestation(
		context.Background(), nil, nil, binding, nil, nil)

	require.ErrorIs(t, err, attestation.ErrDeviceBindingIncomplete)
}
