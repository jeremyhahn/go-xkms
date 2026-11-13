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

package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// leafFor returns a certificate carrying key's public half, standing in for an
// attestation leaf where only the certified key matters.
func leafFor(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "attestation leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// TestVerifyInvariants_KeyBindingHoldsForEveryLeafBoundFormat is the point of
// having one gate.
//
// Both carriers deliver evidence for formats whose leaf certifies the subject
// key directly, and both must refuse a CSR for some other key. Before these
// converged, each route reached its own conclusion by its own code, and they
// had already drifted -- one had binding, the other did not.
func TestVerifyInvariants_KeyBindingHoldsForEveryLeafBoundFormat(t *testing.T) {
	// PIV only in this loop: it carries no challenge, so binding is reachable
	// with a synthetic leaf. Android runs its freshness check first and needs a
	// real attestation extension, so it is covered against the captured device
	// chain in TestVerifyInvariants_AndroidBindingAgainstARealChain.
	for _, format := range []string{FormatYubiKeyPIV} {
		t.Run(format, func(t *testing.T) {
			attested := newKey(t)
			leaf := leafFor(t, attested)

			t.Run("refuses a CSR for another key", func(t *testing.T) {
				stranger := leafFor(t, newKey(t))

				err := VerifyInvariants(&Evidence{
					Format:      format,
					Leaf:        leaf,
					SubjectSPKI: stranger.RawSubjectPublicKeyInfo,
				})

				assert.ErrorIs(t, err, ErrKeyNotBound)
			})

			t.Run("refuses evidence with no subject key", func(t *testing.T) {
				err := VerifyInvariants(&Evidence{Format: format, Leaf: leaf})
				assert.ErrorIs(t, err, ErrKeyNotBound)
			})

			t.Run("refuses evidence with no leaf", func(t *testing.T) {
				err := VerifyInvariants(&Evidence{
					Format:      format,
					SubjectSPKI: leaf.RawSubjectPublicKeyInfo,
				})
				assert.ErrorIs(t, err, ErrBindingUnavailable)
			})
		})
	}
}

// TestVerifyInvariants_PIVAcceptsTheAttestedKeyWithoutANonce records the
// deliberate asymmetry between the two leaf-bound formats.
//
// PIV slot attestation is minted once when the key is generated and is static
// thereafter, so there is no challenge to check. Demanding one would refuse
// every genuine YubiKey.
func TestVerifyInvariants_PIVAcceptsTheAttestedKeyWithoutANonce(t *testing.T) {
	attested := newKey(t)
	leaf := leafFor(t, attested)

	err := VerifyInvariants(&Evidence{
		Format:      FormatYubiKeyPIV,
		Leaf:        leaf,
		SubjectSPKI: leaf.RawSubjectPublicKeyInfo,
	})

	assert.NoError(t, err)
}

// TestVerifyInvariants_PIVRefusesAChallengeItCannotCheck stops a caller
// believing freshness was verified when the format cannot express it.
//
// Silently ignoring the nonce would be the dangerous behaviour: the caller
// supplied one, so it thinks replay is covered, and nothing said otherwise.
func TestVerifyInvariants_PIVRefusesAChallengeItCannotCheck(t *testing.T) {
	leaf := leafFor(t, newKey(t))

	err := VerifyInvariants(&Evidence{
		Format:            FormatYubiKeyPIV,
		Leaf:              leaf,
		SubjectSPKI:       leaf.RawSubjectPublicKeyInfo,
		ExpectedChallenge: []byte("a nonce PIV cannot carry"),
	})

	assert.ErrorIs(t, err, ErrStaleEvidence)
}

// TestVerifyInvariants_AndroidDemandsAChallenge is the other half of that
// asymmetry: a format that carries a challenge must be given one to check.
func TestVerifyInvariants_AndroidDemandsAChallenge(t *testing.T) {
	leaf := leafFor(t, newKey(t))

	err := VerifyInvariants(&Evidence{
		Format:      FormatAndroidKey,
		Leaf:        leaf,
		SubjectSPKI: leaf.RawSubjectPublicKeyInfo,
	})

	// The leaf here carries no attestation extension, so reading the challenge
	// fails before the comparison -- either way the request does not proceed
	// without freshness being established.
	require.Error(t, err)
	assert.True(t,
		errors.Is(err, ErrStaleEvidence) || errors.Is(err, ErrBindingUnavailable),
		"expected a freshness or binding refusal, got %v", err)
}

// TestVerifyInvariants_TPM2NeedsBothPublicAreas is why the generic carrier
// cannot serve TPM today.
//
// The TPM Name is a digest over the public *area* and cannot be derived from a
// public key, so a PKCS#10 with a certificate chain has no way to express this
// binding. Reporting that plainly is what keeps the format failing closed
// instead of being waved through as "chain looked fine".
func TestVerifyInvariants_TPM2NeedsBothPublicAreas(t *testing.T) {
	err := VerifyInvariants(&Evidence{Format: FormatTPM2})

	assert.ErrorIs(t, err, ErrBindingUnavailable)
}

// TestVerifyInvariants_UnknownFormatIsRefused covers the default for evidence
// nobody has described.
func TestVerifyInvariants_UnknownFormatIsRefused(t *testing.T) {
	leaf := leafFor(t, newKey(t))

	err := VerifyInvariants(&Evidence{
		Format:      "some-new-hsm",
		Leaf:        leaf,
		SubjectSPKI: leaf.RawSubjectPublicKeyInfo,
	})

	assert.ErrorIs(t, err, ErrUnknownFormat)
	assert.False(t, KnownFormat("some-new-hsm"))
}

func TestVerifyInvariants_RefusesNilEvidence(t *testing.T) {
	assert.ErrorIs(t, VerifyInvariants(nil), ErrBindingUnavailable)
}

func TestNormalize_IsCaseAndSpaceInsensitive(t *testing.T) {
	assert.Equal(t, FormatTPM2, Normalize("  TPM2 "))
	assert.True(t, KnownFormat("  Android-Key-Attestation  "))
	assert.True(t, KnownFormat("YubiKey-PIV"))
}

// TestVerifyInvariants_AndroidBindingAgainstARealChain covers the Android half
// of the shared binding rule using evidence a device actually produced.
//
// A synthetic leaf cannot serve here: Android establishes freshness from the
// attestation extension, which only a real device writes, so binding is not
// reachable without one.
func TestVerifyInvariants_AndroidBindingAgainstARealChain(t *testing.T) {
	chain := loadAndroidFixtureChain(t)
	leaf := chain[0]

	t.Run("accepts the attested key with the right challenge", func(t *testing.T) {
		err := VerifyInvariants(&Evidence{
			Format:            FormatAndroidKey,
			Leaf:              leaf,
			SubjectSPKI:       leaf.RawSubjectPublicKeyInfo,
			ExpectedChallenge: []byte(androidFixtureChallenge),
		})
		assert.NoError(t, err)
	})

	t.Run("refuses a CSR for another key", func(t *testing.T) {
		stranger := leafFor(t, newKey(t))

		err := VerifyInvariants(&Evidence{
			Format:            FormatAndroidKey,
			Leaf:              leaf,
			SubjectSPKI:       stranger.RawSubjectPublicKeyInfo,
			ExpectedChallenge: []byte(androidFixtureChallenge),
		})
		assert.ErrorIs(t, err, ErrKeyNotBound)
	})

	t.Run("refuses a replayed challenge", func(t *testing.T) {
		err := VerifyInvariants(&Evidence{
			Format:            FormatAndroidKey,
			Leaf:              leaf,
			SubjectSPKI:       leaf.RawSubjectPublicKeyInfo,
			ExpectedChallenge: []byte("some other server's challenge"),
		})
		assert.ErrorIs(t, err, ErrStaleEvidence)
	})
}

const androidFixtureChallenge = "xkey-fixture-challenge"

// loadAndroidFixtureChain reads the captured emulator attestation chain.
func loadAndroidFixtureChain(t *testing.T) []*x509.Certificate {
	t.Helper()

	raw, err := os.ReadFile("android/testdata/android_emulator_chain.txt")
	require.NoError(t, err, "the captured device chain must be present")

	var chain []*x509.Certificate
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		der, decErr := base64.StdEncoding.DecodeString(line)
		require.NoError(t, decErr)
		cert, parseErr := x509.ParseCertificate(der)
		require.NoError(t, parseErr)
		chain = append(chain, cert)
	}
	require.NotEmpty(t, chain)
	return chain
}

// -----------------------------------------------------------------------
// Convergence: both carriers reach the same verdict
// -----------------------------------------------------------------------

// TestBothCarriersRefuseTheSameThings is the test that makes the convergence
// meaningful rather than merely structural.
//
// Two carriers deliver attestation evidence -- a PKCS#10 CSR with format-tagged
// evidence alongside it, and the TCG-CSR-IDEVID packed structure. Neither is
// ours to redesign, so both will always exist. What must not exist is two
// answers to "is this evidence good enough to sign", and that is exactly what
// had happened: the generic route grew freshness and key-binding checks while
// the TCG route reached its own conclusions by its own code.
//
// Each case below is expressed once and asserted against the evidence each
// carrier would hand the gate. A check that regresses on one route and not the
// other fails here, which is the drift that started this.
func TestBothCarriersRefuseTheSameThings(t *testing.T) {
	// Generic carrier: leaf certifies the subject key directly.
	genericAttested := newKey(t)
	genericLeaf := leafFor(t, genericAttested)
	genericStranger := leafFor(t, newKey(t))

	t.Run("a substituted subject key is refused on both", func(t *testing.T) {
		// Generic: the CSR names a key the leaf does not certify.
		genericErr := VerifyInvariants(&Evidence{
			Format:      FormatYubiKeyPIV,
			Leaf:        genericLeaf,
			SubjectSPKI: genericStranger.RawSubjectPublicKeyInfo,
		})

		// TCG: the certification covers a key other than the one submitted.
		// Supplying mismatched public areas is the same substitution expressed
		// in the shape that carrier uses.
		tcgErr := VerifyInvariants(&Evidence{
			Format:             FormatTPM2,
			AttesterPublicArea: []byte{0x00, 0x01},
			SubjectPublicArea:  []byte{0x00, 0x02},
			CertifyInfo:        []byte{0x03},
			CertifySignature:   []byte{0x04},
		})

		assert.ErrorIs(t, genericErr, ErrKeyNotBound,
			"the generic carrier must refuse a key the evidence does not cover")
		assert.ErrorIs(t, tcgErr, ErrKeyNotBound,
			"the TCG carrier must refuse the same substitution")
	})

	t.Run("an unknown format is refused on both", func(t *testing.T) {
		genericErr := VerifyInvariants(&Evidence{
			Format:      "invented-hsm",
			Leaf:        genericLeaf,
			SubjectSPKI: genericLeaf.RawSubjectPublicKeyInfo,
		})
		tcgErr := VerifyInvariants(&Evidence{
			Format:             "invented-hsm",
			AttesterPublicArea: []byte{0x00},
			SubjectPublicArea:  []byte{0x01},
		})

		assert.ErrorIs(t, genericErr, ErrUnknownFormat)
		assert.ErrorIs(t, tcgErr, ErrUnknownFormat)
	})

	t.Run("evidence that cannot express its binding is refused on both", func(t *testing.T) {
		// Generic: a leaf-bound format with no leaf.
		genericErr := VerifyInvariants(&Evidence{
			Format:      FormatYubiKeyPIV,
			SubjectSPKI: genericLeaf.RawSubjectPublicKeyInfo,
		})
		// TCG: a Name-bound format with no public areas.
		tcgErr := VerifyInvariants(&Evidence{Format: FormatTPM2})

		assert.ErrorIs(t, genericErr, ErrBindingUnavailable)
		assert.ErrorIs(t, tcgErr, ErrBindingUnavailable)

		// Both must be the *same* sentinel, so a caller's fail-closed handling
		// works identically whichever carrier delivered the request.
		assert.True(t, errors.Is(genericErr, ErrBindingUnavailable) &&
			errors.Is(tcgErr, ErrBindingUnavailable))
	})
}

// TestEveryProfileDeclaresABindingMechanism stops a format being added that
// silently binds nothing.
//
// A profile with neither mechanism set would fall through verifyBinding's
// default and be refused -- correct, but only by accident. Asserting it here
// means a new format has to state how it binds before it can be registered.
func TestEveryProfileDeclaresABindingMechanism(t *testing.T) {
	require.NotEmpty(t, profiles)

	for format, profile := range profiles {
		assert.True(t, profile.bindLeafSPKI || profile.bindTPMCertify,
			"format %q declares no binding mechanism", format)
		assert.NotEmpty(t, profile.note,
			"format %q has no note explaining its profile to an operator", format)
	}
}
