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

//go:build ble

package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	android "github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// These tests cover the pairing-time attestation decision (#95). They drive
// verifyPairingAttestation rather than performPairingAttestation because the
// decision is what the issue is about; the RPC round trip above it only
// fetches the bytes the decision judges.
//
// The trust material is a locally generated root rather than Google's, so the
// tests state their own trust anchor instead of depending on which embedded
// roots ship — the property under test is "verified against the anchors this
// machine trusts", and substituting the anchor set does not weaken it.

// pairingTestCA is a generated attestation root plus its key.
type pairingTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// newPairingTestCA generates a self-signed CA to stand in for a hardware
// attestation root.
func newPairingTestCA(t *testing.T, cn string) *pairingTestCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &pairingTestCA{cert: cert, key: key}
}

// trust builds the trust material verifyPairingAttestation takes, anchored on
// this CA alone.
func (ca *pairingTestCA) trust() *pairingAttestationTrust {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return &pairingAttestationTrust{pool: pool}
}

// attestedBootState is the RootOfTrust a healthy phone presents: verified boot
// on a locked bootloader. Pairing requires exactly this, so every fixture that
// is meant to SUCCEED carries it and the refusal fixtures vary one field.
func attestedBootState() *android.RootOfTrust {
	return &android.RootOfTrust{
		VerifiedBootKey:   []byte("verified-boot-key"),
		DeviceLocked:      true,
		VerifiedBootState: android.VerifiedBootVerified,
		VerifiedBootHash:  []byte("verified-boot-hash"),
	}
}

// attestedLeafDER issues a leaf carrying an Android key-attestation extension
// whose attestationChallenge is challenge and whose teeEnforced list carries
// rot. When issuer is nil the leaf is self-signed, which is the case the issue
// names: a peer that generates its own chain a moment before sending it.
//
// rot is a parameter rather than a constant because absence is one of the
// cases under test: an extension with no RootOfTrust passes the SDK's
// VerifyBootState (its contract is "verify what is claimed") while claiming
// nothing at all, and pairing must refuse it.
func attestedLeafDER(t *testing.T, issuer *pairingTestCA, challenge []byte, level android.SecurityLevel, rot *android.RootOfTrust) []byte {
	t.Helper()

	ext, err := android.BuildAttestationExtension(
		4, level, 100, level, challenge, []byte("unique-id"), rot,
	)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "attested key"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: android.AndroidKeyAttestationOID, Value: ext},
		},
	}

	parent, signer := template, any(key)
	if issuer != nil {
		parent, signer = issuer.cert, any(issuer.key)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	require.NoError(t, err)

	return der
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
// The chain here is otherwise perfect — it carries a real attestation
// extension with THIS pairing's challenge. Only the anchor is wrong, which is
// the whole point: before the fix nothing looked at the anchor at all.
func TestPairingRefusesASelfSignedAttestationChain(t *testing.T) {
	ca := newPairingTestCA(t, "Trusted Attestation Root")
	nonce := []byte("0123456789abcdef0123456789abcdef")

	selfSigned := attestedLeafDER(t, nil, nonce, android.SecurityLevelStrongBox, attestedBootState())

	verified, err := verifyPairingAttestation([][]byte{selfSigned}, nonce, ca.trust())

	require.Error(t, err, "a self-signed chain must be refused")
	require.ErrorIs(t, err, ErrDeviceAttestVerifyFailed)
	assert.Nil(t, verified, "nothing may be produced for persistence from an unverified chain")
	assert.NotContains(t, errString(err), sha256Hex(selfSigned),
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
	ca := newPairingTestCA(t, "Trusted Attestation Root")
	impostor := newPairingTestCA(t, "Impostor Root")
	nonce := []byte("ffffffffffffffffffffffffffffffff")

	// Issued by a root nobody trusts, presented alongside one everybody does.
	leaf := attestedLeafDER(t, impostor, nonce, android.SecurityLevelStrongBox, attestedBootState())

	verified, err := verifyPairingAttestation(
		[][]byte{leaf, ca.cert.Raw}, nonce, ca.trust())

	require.Error(t, err, "a leaf not issued under the presented anchor must be refused")
	require.ErrorIs(t, err, ErrDeviceAttestVerifyFailed)
	assert.Nil(t, verified)
}

// TestPairingRefusesAReplayedAttestationChallenge covers the second acceptance
// criterion. The chain verifies to the trusted anchor; only its challenge is
// stale, as a captured attestation replayed from an earlier session would be.
//
// Before the fix the nonce was generated, sent, and never referenced again, so
// this chain was accepted.
func TestPairingRefusesAReplayedAttestationChallenge(t *testing.T) {
	ca := newPairingTestCA(t, "Trusted Attestation Root")

	captured := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	thisPairing := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	leaf := attestedLeafDER(t, ca, captured, android.SecurityLevelStrongBox, attestedBootState())

	verified, err := verifyPairingAttestation([][]byte{leaf, ca.cert.Raw}, thisPairing, ca.trust())

	require.Error(t, err, "an attestation answering an older challenge must be refused")
	require.ErrorIs(t, err, ErrDeviceAttestVerifyFailed)
	assert.Nil(t, verified)
}

// TestPairingAcceptsAVerifiedChainAndRecordsTheAnchorItVerifiedUnder is the
// happy path, and pins where each persisted value comes from.
func TestPairingAcceptsAVerifiedChainAndRecordsTheAnchorItVerifiedUnder(t *testing.T) {
	ca := newPairingTestCA(t, "Trusted Attestation Root")
	nonce := []byte("cccccccccccccccccccccccccccccccc")

	leaf := attestedLeafDER(t, ca, nonce, android.SecurityLevelStrongBox, attestedBootState())

	verified, err := verifyPairingAttestation([][]byte{leaf, ca.cert.Raw}, nonce, ca.trust())
	require.NoError(t, err)
	require.NotNil(t, verified)

	assert.Equal(t, sha256Hex(ca.cert.Raw), verified.result.DeviceFingerprint,
		"the fingerprint is the anchor the chain verified under")
	assert.NotEqual(t, sha256Hex(leaf), verified.result.DeviceFingerprint)

	// From the signed extension, not from the RPC's sibling JSON fields --
	// which verifyPairingAttestation is not even given.
	assert.Equal(t, "strongbox", verified.result.SecurityLevel)

	// The boot claim comes from the signed extension too. Reaching this line at
	// all means the extension CARRIED a RootOfTrust: pairing refuses one that
	// does not, so BootStateVerified can no longer be false here and the boot
	// hash can no longer be empty. The old code read bootState == 0 off the
	// peer's JSON and recorded BootStateVerified: true from it.
	assert.True(t, verified.result.BootStateVerified)
	assert.Equal(t, hex.EncodeToString(attestedBootState().VerifiedBootHash), verified.result.BootHashHex)
	assert.Equal(t, "verified", verified.bootState)
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
	unlocked := attestedBootState()
	unlocked.DeviceLocked = false

	unverified := attestedBootState()
	unverified.VerifiedBootState = android.VerifiedBootUnverified

	for _, tc := range []struct {
		name string
		rot  *android.RootOfTrust
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
			ca := newPairingTestCA(t, "Trusted Attestation Root")
			nonce := []byte("dddddddddddddddddddddddddddddddd")

			leaf := attestedLeafDER(t, ca, nonce, android.SecurityLevelStrongBox, tc.rot)

			verified, err := verifyPairingAttestation([][]byte{leaf, ca.cert.Raw}, nonce, ca.trust())
			require.Error(t, err, tc.why)
			require.Nil(t, verified,
				"a refused attestation must yield no record; everything in it would be "+
					"a claim the chain did not make")
			require.ErrorIs(t, err, ErrDeviceAttestVerifyFailed)
		})
	}
}

// TestPairingIgnoresACertificateAppendedAfterTheVerifiedAnchor is the
// regression for the finding Codex raised on the first round of this PR.
//
// The first version carried a flat list of roots beside the pool so the anchor
// could be looked up by fingerprint. The list was built from the trust store's
// certificates for EVERY purpose while the pool held the Android-hardware ones
// alone, so a peer could append the public DER of a certificate stored under
// an unrelated purpose: verification succeeded through the genuine root, and
// the lookup then named the appended certificate as "the anchor" and persisted
// its hash.
//
// The anchor now comes from the chain x509 built, so the appended certificate
// is what it actually is — an unused extra — and the recorded fingerprint is
// the real anchor's. The pool here holds ONLY the Android root, and the
// appended certificate is a valid CA that simply is not in it, which is
// exactly the shape of the finding.
func TestPairingIgnoresACertificateAppendedAfterTheVerifiedAnchor(t *testing.T) {
	ca := newPairingTestCA(t, "Trusted Attestation Root")
	otherPurpose := newPairingTestCA(t, "Stored For Another Purpose")
	nonce := []byte("11111111111111111111111111111111")

	leaf := attestedLeafDER(t, ca, nonce, android.SecurityLevelStrongBox, attestedBootState())

	verified, err := verifyPairingAttestation(
		[][]byte{leaf, ca.cert.Raw, otherPurpose.cert.Raw}, nonce, ca.trust())

	require.NoError(t, err, "an unused trailing certificate must not break a valid chain")
	require.NotNil(t, verified)

	assert.Equal(t, sha256Hex(ca.cert.Raw), verified.result.DeviceFingerprint,
		"the fingerprint must be the anchor x509 verified under")
	assert.NotEqual(t, sha256Hex(otherPurpose.cert.Raw), verified.result.DeviceFingerprint,
		"a certificate the peer appended must never become the recorded anchor")
}

// TestPairingRefusesASoftwareProtectedKey pins the minimum this path admits.
//
// Without it pairing accepted a software-protected key on a perfectly valid
// chain and reported "Chain Status: VERIFIED" over it — while `device
// attest-device`, which runs on the very next re-attestation, requires at
// least TrustedEnvironment. The gate that ESTABLISHES the binding was the
// weaker of the two.
func TestPairingRefusesASoftwareProtectedKey(t *testing.T) {
	ca := newPairingTestCA(t, "Trusted Attestation Root")
	nonce := []byte("22222222222222222222222222222222")

	leaf := attestedLeafDER(t, ca, nonce, android.SecurityLevelSoftware, attestedBootState())

	verified, err := verifyPairingAttestation([][]byte{leaf, ca.cert.Raw}, nonce, ca.trust())

	require.Error(t, err, "a software-protected key must not pair as a hardware-backed device")
	require.ErrorIs(t, err, ErrDeviceAttestVerifyFailed)
	assert.Nil(t, verified)
}

// TestPairingAcceptsATrustedEnvironmentKey fixes the minimum at the level
// attest-device uses, so raising it further is a deliberate change rather than
// an accident: TEE is admitted, and the test above shows software is not.
func TestPairingAcceptsATrustedEnvironmentKey(t *testing.T) {
	ca := newPairingTestCA(t, "Trusted Attestation Root")
	nonce := []byte("33333333333333333333333333333333")

	leaf := attestedLeafDER(t, ca, nonce, android.SecurityLevelTrustedEnvironment, attestedBootState())

	verified, err := verifyPairingAttestation([][]byte{leaf, ca.cert.Raw}, nonce, ca.trust())

	require.NoError(t, err)
	require.NotNil(t, verified)
	assert.Equal(t, "tee", verified.result.SecurityLevel)
}

// TestPairingVerifyOptionsRequestTheHardwareBar pins the policy pairing asks
// for, including the two fields this package's fixtures cannot exercise.
//
// No exported builder produces an attestation extension carrying a
// RootOfTrust, so a chain that would trip VerifyBootState cannot be
// constructed here — and a test that cannot construct the input it names
// proves nothing. Asserting the requested policy is what this package CAN
// prove; that the policy is enforced is proved by pkg/attestation/android's
// own suite (ErrInsufficientSecurityLevel, ErrUnverifiedBoot). Together they
// cover the path; separately neither claims more than it shows.
func TestPairingVerifyOptionsRequestTheHardwareBar(t *testing.T) {
	pool := x509.NewCertPool()
	nonce := []byte("44444444444444444444444444444444")

	opts := pairingVerifyOptions(pool, nonce)

	require.NotNil(t, opts)
	assert.Same(t, pool, opts.TrustedRoots,
		"a nil pool makes VerifyKeyAttestation skip chain verification entirely")
	assert.Equal(t, nonce, opts.ExpectedNonce,
		"a nil nonce makes it skip the freshness challenge entirely")
	assert.Equal(t, xkms.AndroidSecurityLevelTrustedEnvironment, opts.MinSecurityLevel,
		"pairing must not admit a device that device attest-device would refuse")
	assert.True(t, opts.VerifyBootState,
		"an explicitly unverified boot state must not pair")
}

// TestVerifyPairingAttestationRefusesMissingTrustMaterial guards the two nil
// values VerifyKeyAttestation treats as "skip this check": a nil TrustedRoots
// skips chain verification and a nil ExpectedNonce skips the challenge
// comparison, either of which would report success while checking nothing.
func TestVerifyPairingAttestationRefusesMissingTrustMaterial(t *testing.T) {
	ca := newPairingTestCA(t, "Trusted Attestation Root")
	nonce := []byte("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	leaf := attestedLeafDER(t, ca, nonce, android.SecurityLevelStrongBox, attestedBootState())
	chain := [][]byte{leaf, ca.cert.Raw}

	cases := map[string]struct {
		trust *pairingAttestationTrust
		nonce []byte
	}{
		"nil trust":   {trust: nil, nonce: nonce},
		"nil pool":    {trust: &pairingAttestationTrust{}, nonce: nonce},
		"empty pool":  {trust: &pairingAttestationTrust{pool: x509.NewCertPool()}, nonce: nonce},
		"empty nonce": {trust: ca.trust(), nonce: nil},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			verified, err := verifyPairingAttestation(chain, tc.nonce, tc.trust)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrDeviceAttestVerifyFailed)
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
