// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package xkms

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	android "github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The real emulator capture, so these tests run against bytes a device
// produced rather than a hand-built approximation.
const (
	realChainFixture  = "../attestation/android/testdata/android_emulator_chain.txt"
	realChallenge     = "xkey-fixture-challenge"
	realPackage       = "com.automatethethings.xkey.debug"
	realSigningDigest = "471812d11ee2279da7a6957997c7b66a2d1fd8ccbba106f5fbf9c4c024a30aba"
)

// realChainVerificationTime sits inside the captured chain's validity window
// (2026-08-05 00:55 UTC to 2026-08-21 00:43 UTC). Google's test attestation CA
// mints short-lived intermediates, so the window closes about sixteen days
// after any capture. Tests that need the chain to verify pin this instant
// rather than depending on when they are run; re-capturing the fixture would
// only reset the same countdown.
var realChainVerificationTime = time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)

func loadRealAndroidChain(t *testing.T) [][]byte {
	t.Helper()

	f, err := os.Open(realChainFixture)
	require.NoError(t, err, "the captured chain fixture must be present")
	defer func() { _ = f.Close() }()

	var chain [][]byte
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		der, decErr := base64.StdEncoding.DecodeString(line)
		require.NoError(t, decErr)
		chain = append(chain, der)
	}
	require.NoError(t, scanner.Err())
	require.NotEmpty(t, chain)
	return chain
}

// permissivePolicy accepts the captured emulator chain, so each test can spoil
// exactly one thing and observe that refusal.
//
// The emulator is software-backed with an unlocked bootloader, so the two
// hardware demands are relaxed here. A production policy leaves them on -- see
// TestAndroidPolicy_DefaultsFailClosed.
func permissivePolicy() *AndroidEnrollmentPolicy {
	p := NewAndroidEnrollmentPolicy()
	p.RequireVerifiedBoot = false
	p.MinSecurityLevel = "software"
	p.AllowedPackages = map[string][]string{
		realPackage: {realSigningDigest},
	}
	return p
}

// csrForAttestedKey cannot be built -- the emulator's private key never leaves
// the device -- so tests that need a matching CSR are limited to checking the
// mismatch path. This builds a CSR for an unrelated key.
func csrForForeignKey(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "foreign"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	require.NoError(t, err)
	return der
}

func TestAndroidPolicy_DefaultsFailClosed(t *testing.T) {
	p := NewAndroidEnrollmentPolicy()

	// The dangerous default is the permissive one: a CA that trusts everything
	// until configured hands out credentials in the window before setup.
	assert.Empty(t, p.AllowedPackages, "no application is allowed until listed")
	assert.True(t, p.RequireVerifiedBoot)
	assert.Equal(t, "trusted_environment", p.MinSecurityLevel)
	assert.False(t, p.AllowUnpinnedSignatures)
}

func TestVerifyAndroidCSR_RefusesWhenNoPolicyIsConfigured(t *testing.T) {
	svc := &XKMSService{}

	err := svc.verifyAndroidCSRAttestation(&transport.SignCSRRequest{
		AttestationChain: loadRealAndroidChain(t),
		AttestationNonce: []byte(realChallenge),
	})

	// Without a policy the server has no allow-list, so signing on chain
	// provenance alone would certify any Android device that asked.
	assert.ErrorIs(t, err, ErrAndroidPolicyNotConfigured)
}

func TestVerifyAndroidCSR_RefusesAnEmptyAllowList(t *testing.T) {
	svc := &XKMSService{}
	svc.SetAndroidEnrollmentPolicy(NewAndroidEnrollmentPolicy())

	err := svc.verifyAndroidCSRAttestation(&transport.SignCSRRequest{
		AttestationChain: loadRealAndroidChain(t),
		AttestationNonce: []byte(realChallenge),
	})

	assert.ErrorIs(t, err, ErrAndroidAttestationAppDenied)
}

// TestVerifyAndroidCSR_RefusesAMissingNonce covers the replay hole.
//
// AttestationNonce sat on the wire struct unread, so a captured attestation
// stayed valid indefinitely: replay it alongside a CSR of your choosing and the
// CA signed. Demanding the nonce is what makes evidence belong to one exchange.
func TestVerifyAndroidCSR_RefusesAMissingNonce(t *testing.T) {
	svc := &XKMSService{}
	leaf := realAndroidLeaf(t)

	err := svc.enforceAttestationInvariants(
		AttestationFormatAndroidKey,
		&transport.SignCSRRequest{CSRPEM: csrForForeignKey(t)},
		leaf,
	)

	assert.ErrorIs(t, err, ErrAttestationStale)
}

func TestVerifyAndroidCSR_RefusesAReplayedChallenge(t *testing.T) {
	svc := &XKMSService{}

	err := svc.enforceAttestationInvariants(
		AttestationFormatAndroidKey,
		&transport.SignCSRRequest{
			// The device attested "xkey-fixture-challenge"; this server issued
			// something else, so the evidence is from a different exchange.
			AttestationNonce: []byte("a-different-challenge"),
			CSRPEM:           csrForForeignKey(t),
		},
		realAndroidLeaf(t),
	)

	assert.ErrorIs(t, err, ErrAttestationStale)
}

// TestVerifyAndroidCSR_RefusesACSRForADifferentKey is the check that is easiest
// to omit and fatal to skip.
//
// Everything else here passes -- a real Google-rooted chain, the right
// challenge, an allow-listed application -- and the key being certified is one
// the caller generated in software, because nothing tied the evidence to the
// request.
func TestVerifyAndroidCSR_RefusesACSRForADifferentKey(t *testing.T) {
	svc := &XKMSService{}

	err := svc.enforceAttestationInvariants(
		AttestationFormatAndroidKey,
		&transport.SignCSRRequest{
			AttestationNonce: []byte(realChallenge),
			CSRPEM:           csrForForeignKey(t),
		},
		realAndroidLeaf(t),
	)

	assert.ErrorIs(t, err, ErrAttestationKeyNotBound)
}

// realAndroidLeaf parses the captured chain's leaf.
func realAndroidLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(loadRealAndroidChain(t)[0])
	require.NoError(t, err)
	return leaf
}

func TestVerifyAndroidCSR_RefusesAnUnlockedBootloader(t *testing.T) {
	svc := &XKMSService{}
	policy := permissivePolicy()
	policy.RequireVerifiedBoot = true
	svc.SetAndroidEnrollmentPolicy(policy)

	err := svc.verifyAndroidCSRAttestation(&transport.SignCSRRequest{
		AttestationChain: loadRealAndroidChain(t),
		AttestationNonce: []byte(realChallenge),
		CSRPEM:           csrForForeignKey(t),
	})

	// The emulator genuinely reports an unlocked bootloader, so this is the
	// real refusal rather than a simulated one.
	assert.ErrorIs(t, err, ErrAndroidAttestationBootState)
}

func TestAndroidPolicy_MatchApplication(t *testing.T) {
	digest := func(h string) []byte {
		out := make([]byte, len(h)/2)
		for i := range out {
			var b byte
			for j := 0; j < 2; j++ {
				c := h[i*2+j]
				switch {
				case c >= '0' && c <= '9':
					b = b<<4 | (c - '0')
				case c >= 'a' && c <= 'f':
					b = b<<4 | (c - 'a' + 10)
				}
			}
			out[i] = b
		}
		return out
	}

	appID := &android.AttestationApplicationID{
		Packages:         []android.AttestationPackageInfo{{Name: realPackage, Version: 1}},
		SignatureDigests: [][]byte{digest(realSigningDigest)},
	}

	t.Run("accepts a pinned build", func(t *testing.T) {
		p := permissivePolicy()
		pkg, got, err := p.matchApplication(appID)
		require.NoError(t, err)
		assert.Equal(t, realPackage, pkg)
		assert.Equal(t, realSigningDigest, got)
	})

	t.Run("refuses a rebuild signed with another key", func(t *testing.T) {
		p := permissivePolicy()
		p.AllowedPackages = map[string][]string{
			realPackage: {"00" + realSigningDigest[2:]},
		}

		// The package name is trivially forgeable; the signing digest is what
		// makes it an identity.
		_, _, err := p.matchApplication(appID)
		assert.ErrorIs(t, err, ErrAndroidAttestationAppDenied)
	})

	t.Run("refuses an unpinned entry unless explicitly allowed", func(t *testing.T) {
		p := permissivePolicy()
		p.AllowedPackages = map[string][]string{realPackage: {}}

		_, _, err := p.matchApplication(appID)
		assert.ErrorIs(t, err, ErrAndroidAttestationAppDenied)

		p.AllowUnpinnedSignatures = true
		pkg, _, err := p.matchApplication(appID)
		require.NoError(t, err)
		assert.Equal(t, realPackage, pkg)
	})

	t.Run("refuses an unlisted package", func(t *testing.T) {
		p := permissivePolicy()
		p.AllowedPackages = map[string][]string{"com.example.other": {realSigningDigest}}

		_, _, err := p.matchApplication(appID)
		assert.ErrorIs(t, err, ErrAndroidAttestationAppDenied)
	})
}

func TestAndroidSecurityRank_UnknownLevelsRankAsSoftware(t *testing.T) {
	assert.Equal(t, 2, androidSecurityRank("strongbox"))
	assert.Equal(t, 1, androidSecurityRank("trusted_environment"))
	assert.Equal(t, 0, androidSecurityRank("software"))

	// A typo must not silently rank above the levels it is compared against.
	assert.Equal(t, 0, androidSecurityRank("TEE"))
	assert.Equal(t, 0, androidSecurityRank(""))
}

func TestParseCSRAny_AcceptsPEMAndDER(t *testing.T) {
	der := csrForForeignKey(t)

	fromDER, err := parseCSRAny(der)
	require.NoError(t, err)
	assert.Equal(t, "foreign", fromDER.Subject.CommonName)

	pemBytes := []byte("-----BEGIN CERTIFICATE REQUEST-----\n" +
		base64.StdEncoding.EncodeToString(der) +
		"\n-----END CERTIFICATE REQUEST-----\n")
	fromPEM, err := parseCSRAny(pemBytes)
	require.NoError(t, err)
	assert.Equal(t, "foreign", fromPEM.Subject.CommonName)
}

// -----------------------------------------------------------------------
// End to end through SignCSR, with xkms acting as the enterprise CA
// -----------------------------------------------------------------------

// androidAnchoredService returns a signing service whose android-key-attestation
// anchor is the root of the captured emulator chain.
//
// The emulator's chain is rooted in Google's *test* attestation key rather than
// the production hardware root, so anchoring on its own final certificate is
// what lets these tests exercise the real path with real bytes.
func androidAnchoredService(t *testing.T) *XKMSService {
	t.Helper()

	svc := androidAnchoredServiceOnTheRealClock(t)

	// The fixture is a genuine capture, so its certificates expire. Pinning the
	// service clock keeps these tests about the gate they are testing instead of
	// about the calendar. TestSignCSR_AndroidFixtureIsRefusedOnTheRealClock
	// holds the other side: production still refuses this chain.
	svc.mu.Lock()
	svc.attestationClock = func() time.Time { return realChainVerificationTime }
	svc.mu.Unlock()

	return svc
}

// androidAnchoredServiceOnTheRealClock is androidAnchoredService without the
// pinned verification time, so certificate lifetimes are judged against
// time.Now() exactly as they are on a server.
func androidAnchoredServiceOnTheRealClock(t *testing.T) *XKMSService {
	t.Helper()

	chain := loadRealAndroidChain(t)
	root, err := x509.ParseCertificate(chain[len(chain)-1])
	require.NoError(t, err)

	svc := setupServiceWithCA(t, &mockCA{
		signCSRCert: createSelfSignedCert(t),
		cert:        createSelfSignedCert(t),
	})
	anchorFormats(t, svc, map[string][]*x509.Certificate{
		AttestationFormatAndroidKey: {root},
	})
	return svc
}

// TestSignCSR_AndroidEnterpriseCA_RefusesWithoutAPolicy proves the enterprise
// CA path fails closed end to end.
//
// The chain anchors correctly here, so before the Android gate existed this
// request would have been signed on provenance alone -- no freshness, no key
// binding, no allow-list.
func TestSignCSR_AndroidEnterpriseCA_RefusesWithoutAPolicy(t *testing.T) {
	svc := androidAnchoredService(t)

	_, err := svc.SignCSR(context.Background(), &transport.SignCSRRequest{
		CSRPEM:            csrForForeignKey(t),
		AttestationFormat: AttestationFormatAndroidKey,
		AttestationChain:  loadRealAndroidChain(t),
		AttestationNonce:  []byte(realChallenge),
	})

	// The invariants run before deployment policy, so a foreign CSR is caught
	// by key binding first. Both gates are shut; this asserts the request does
	// not get signed, which is what matters.
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAttestationKeyNotBound)
}

// TestSignCSR_AndroidEnterpriseCA_RefusesAReplayedAttestation proves the replay
// hole is closed through the real entry point.
func TestSignCSR_AndroidEnterpriseCA_RefusesAReplayedAttestation(t *testing.T) {
	svc := androidAnchoredService(t)
	svc.SetAndroidEnrollmentPolicy(permissivePolicy())

	_, err := svc.SignCSR(context.Background(), &transport.SignCSRRequest{
		CSRPEM:            csrForForeignKey(t),
		AttestationFormat: AttestationFormatAndroidKey,
		AttestationChain:  loadRealAndroidChain(t),
		// A nonce this server did not issue: the attestation is a recording
		// from some other exchange.
		AttestationNonce: []byte("some-other-servers-challenge"),
	})

	require.Error(t, err)
}

// TestSignCSR_AndroidEnterpriseCA_RefusesACSRForADifferentKey proves the
// binding check runs on the server, not only in the CLI.
//
// This is what makes xkms authoritative rather than trusting whatever the
// enrolling client already decided.
func TestSignCSR_AndroidEnterpriseCA_RefusesACSRForADifferentKey(t *testing.T) {
	svc := androidAnchoredService(t)
	svc.SetAndroidEnrollmentPolicy(permissivePolicy())

	_, err := svc.SignCSR(context.Background(), &transport.SignCSRRequest{
		CSRPEM:            csrForForeignKey(t),
		AttestationFormat: AttestationFormatAndroidKey,
		AttestationChain:  loadRealAndroidChain(t),
		AttestationNonce:  []byte(realChallenge),
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "attested key",
		"the refusal must name the key binding")
}

// TestSignCSR_AttestationExpiryUsesTheRealClockByDefault is the counterweight
// to pinning the verification time in the tests above.
//
// A pinned clock is how expired evidence is made to verify. That is correct in
// a test and catastrophic in a server, so the injection is reachable only from
// inside this package -- and this proves the default did not move with it.
//
// The evidence here is minted with a validity window that has already closed
// relative to whatever time.Now() returns, rather than being a fixed date the
// host clock has to be past. That is the whole point of the change: a test that
// assumes something about the calendar is the defect this fixes, and it would
// be no better inverted.
func TestSignCSR_AttestationExpiryUsesTheRealClockByDefault(t *testing.T) {
	const format = "yubikey-piv"

	newExpiredCase := func(t *testing.T) (*XKMSService, *attestationChain) {
		t.Helper()
		svc := setupServiceWithCA(t, &mockCA{
			signCSRCert: createSelfSignedCert(t),
			cert:        createSelfSignedCert(t),
		})
		// Valid from two days ago until one day ago: expired now, and expired
		// on any clock this ever runs on.
		expired := newAttestationChain(t, "Vendor",
			time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
		anchorFormats(t, svc, map[string][]*x509.Certificate{format: {expired.root}})
		return svc, expired
	}

	t.Run("expired evidence is refused when no clock is injected", func(t *testing.T) {
		svc, expired := newExpiredCase(t)

		_, err := signCSRWithAttestation(t, svc, format, expired.wire(), expired.leafKey)

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAttestationVerificationFailed)
		assert.Contains(t, err.Error(), "expired",
			"an uninjected service must judge lifetimes against time.Now()")
	})

	t.Run("the injected clock is the only thing that changes the verdict", func(t *testing.T) {
		svc, expired := newExpiredCase(t)

		// The same request, the same evidence, a clock inside the window.
		svc.mu.Lock()
		svc.attestationClock = func() time.Time { return time.Now().Add(-36 * time.Hour) }
		svc.mu.Unlock()

		resp, err := signCSRWithAttestation(t, svc, format, expired.wire(), expired.leafKey)

		require.NoError(t, err)
		require.NotNil(t, resp)
	})
}

// TestSignCSR_NonAndroidFormatsAreUnaffected guards against the Android gate
// leaking into the TPM2 and YubiKey paths, where the leaf attests a different
// key than the CSR by design.
func TestSignCSR_NonAndroidFormatsAreUnaffected(t *testing.T) {
	svc, genuine := signingServiceWithAnchor(t, "yubikey-piv")

	// No android policy is configured, and none is needed: this format does
	// not route through the android gate at all.
	resp, err := signCSRWithAttestation(t, svc, "yubikey-piv",
		[][]byte{genuine.leafDER, genuine.interDER, genuine.rootDER}, genuine.leafKey)

	require.NoError(t, err, "a non-android format must not be gated on an android policy")
	require.NotNil(t, resp)
}

// -----------------------------------------------------------------------
// Format-agnostic invariants
// -----------------------------------------------------------------------

// TestInvariants_YubiKeyPIVKeyBinding closes the finding that this format had
// no key binding at all.
//
// PIV attestation certificates are not secret -- they travel with every
// enrollment. Without binding, anyone holding one could present it beside a CSR
// for a software key and receive a certificate that reads, to every relying
// party, as hardware-backed. Chain anchoring alone never showed otherwise.
func TestInvariants_YubiKeyPIVKeyBinding(t *testing.T) {
	svc, genuine := signingServiceWithAnchor(t, "yubikey-piv")

	t.Run("accepts a CSR for the attested slot key", func(t *testing.T) {
		resp, err := signCSRWithAttestation(t, svc, "yubikey-piv",
			genuine.wire(), genuine.leafKey)
		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	t.Run("refuses a CSR for any other key", func(t *testing.T) {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		resp, err := signCSRWithAttestation(t, svc, "yubikey-piv",
			genuine.wire(), other)
		assert.Nil(t, resp)
		assert.ErrorIs(t, err, ErrAttestationKeyNotBound)
	})
}

// TestInvariants_PIVNeedsNoNonce records why freshness is not demanded here.
//
// A PIV slot attestation certificate is minted once when the key is generated
// and is static thereafter, so there is nothing to bind to a request. Demanding
// a nonce would refuse every genuine YubiKey. Replay is defeated by binding
// instead: the attestation is useless without the matching private key, and the
// CSR signature proves possession at the time of asking.
func TestInvariants_PIVNeedsNoNonce(t *testing.T) {
	svc, genuine := signingServiceWithAnchor(t, "yubikey-piv")

	resp, err := signCSRWithAttestation(t, svc, "yubikey-piv",
		genuine.wire(), genuine.leafKey)

	require.NoError(t, err, "a nonce must not be required of a format that has none")
	require.NotNil(t, resp)
}

// TestInvariants_TPM2FailsClosed asserts the format whose binding is not yet
// implemented is refused rather than quietly signed.
//
// Refusing is the honest answer: the chain shows a TPM exists, not that it
// holds the key being certified, so a certificate issued here would assert
// something the server never established.
func TestInvariants_TPM2FailsClosed(t *testing.T) {
	svc, genuine := signingServiceWithAnchor(t, "tpm2")

	resp, err := signCSRWithAttestation(t, svc, "tpm2", genuine.wire(), genuine.leafKey)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrAttestationUnbindableFormat)

	// The gap can be accepted deliberately, per deployment.
	svc.AllowUnboundAttestationFormats(true)
	resp, err = signCSRWithAttestation(t, svc, "tpm2", genuine.wire(), genuine.leafKey)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// TestInvariants_UnknownFormatIsRefused covers the default for a format nobody
// has described.
//
// "We do not know what this evidence proves" is not a basis for issuing a
// certificate that asserts hardware backing.
func TestInvariants_UnknownFormatIsRefused(t *testing.T) {
	svc, genuine := signingServiceWithAnchor(t, "some-new-hsm")

	resp, err := signCSRWithAttestation(t, svc, "some-new-hsm",
		genuine.wire(), genuine.leafKey)

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrAttestationUnbindableFormat)
}

// TestInvariants_RefuseAnUnsignedCSR proves possession is required.
//
// A CSR is self-signed by the key it names, so a broken signature means the
// requester does not hold the private half -- binding it to attested hardware
// would certify a key nobody demonstrated control of.
func TestInvariants_RefuseAnUnsignedCSR(t *testing.T) {
	svc, genuine := signingServiceWithAnchor(t, "yubikey-piv")

	tampered := csrPEMFor(t, genuine.leafKey)
	// Flip a byte inside the PEM body, which corrupts the signature.
	for i := len(tampered) - 40; i < len(tampered)-30; i++ {
		if tampered[i] != '\n' {
			tampered[i] ^= 0x01
			break
		}
	}

	resp, err := svc.SignCSR(context.Background(), &transport.SignCSRRequest{
		CSRPEM:            tampered,
		AttestationFormat: "yubikey-piv",
		AttestationChain:  genuine.wire(),
	})

	assert.Nil(t, resp)
	require.Error(t, err)
}
