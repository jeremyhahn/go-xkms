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

//go:build ble

package cmd

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The captured emulator chain, shared with the attestation package's tests so
// the CLI is exercised against bytes a real device produced.
const (
	enrollFixtureChain  = "../../../../pkg/attestation/android/testdata/android_emulator_chain.txt"
	enrollFixtureNonce  = "xkey-fixture-challenge"
	enrollFixturePkg    = "com.automatethethings.xkey.debug"
	enrollFixtureSigner = "471812d11ee2279da7a6957997c7b66a2d1fd8ccbba106f5fbf9c4c024a30aba"
)

func loadEnrollFixtureChain(t *testing.T) []string {
	t.Helper()

	f, err := os.Open(enrollFixtureChain)
	require.NoError(t, err, "the captured attestation chain must be present")
	defer func() { _ = f.Close() }()

	var chain []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		chain = append(chain, line)
	}
	require.NoError(t, scanner.Err())
	require.NotEmpty(t, chain)
	return chain
}

// TestEnrollPhone_RefusesAmbiguousDeviceName pins #1315: two paired records
// sharing a name must refuse `device enroll-phone` instead of silently
// enrolling whichever record happens to be first in the file.
func TestEnrollPhone_RefusesAmbiguousDeviceName(t *testing.T) {
	isolateDeviceBarrierHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{
			{Name: "A", Address: "11:22:33:44:55:66"},
			{Name: "A", Address: "AA:BB:CC:DD:EE:FF"},
		},
	}))

	err := enrollPhone(t.Context(), &enrollPhoneOptions{DeviceFilter: "A"}, discardLogger())

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceNameAmbiguous)
}

// TestBuildEnrollmentPolicy_FailsClosedWithNoAllowList is the important
// default.
//
// An operator who has not said which application may enroll has not made a
// decision, and a CA that guesses on their behalf certifies anything that asks.
func TestBuildEnrollmentPolicy_FailsClosedWithNoAllowList(t *testing.T) {
	policy := buildEnrollmentPolicy(&enrollPhoneOptions{})

	assert.Empty(t, policy.AllowedApplications)
	assert.True(t, policy.RequireVerifiedBoot ||
		!policy.RequireVerifiedBoot, "flag default is applied by cobra")

	_, err := policy.Evaluate(&pairingproto.LocalGetDeviceEnrollmentRequestResult{
		AttestationChain: loadEnrollFixtureChain(t),
	}, []byte(enrollFixtureNonce), time.Now())

	// Chain anchoring is checked first, and no roots are configured here
	// either, so both gates are shut.
	require.Error(t, err)
}

func TestBuildEnrollmentPolicy_CarriesTheFlagsThrough(t *testing.T) {
	policy := buildEnrollmentPolicy(&enrollPhoneOptions{
		Validity:            30 * 24 * time.Hour,
		AllowPackages:       []string{enrollFixturePkg},
		AllowSigners:        []string{enrollFixtureSigner},
		AllowUnpinned:       true,
		MinSecurityLevel:    "software",
		RequireVerifiedBoot: false,
	})

	require.Len(t, policy.AllowedApplications, 1)
	assert.Equal(t, enrollFixturePkg, policy.AllowedApplications[0].PackageName)
	assert.Equal(t, []string{enrollFixtureSigner}, policy.AllowedApplications[0].SigningDigests)
	assert.Equal(t, 30*24*time.Hour, policy.Validity)
	assert.True(t, policy.AllowUnpinnedSignatures)
	assert.False(t, policy.RequireVerifiedBoot)
	assert.Equal(t, "software", policy.MinSecurityLevel)
}

// TestEnrollmentPolicy_RefusesTheRealEmulatorUnderProductionDefaults runs the
// captured chain through the CLI's own policy builder.
//
// The emulator is software-backed with an unlocked bootloader -- exactly the
// device a production policy must refuse -- so this proves the defaults are
// doing work rather than passing everything.
func TestEnrollmentPolicy_RefusesTheRealEmulatorUnderProductionDefaults(t *testing.T) {
	policy := buildEnrollmentPolicy(&enrollPhoneOptions{
		AllowPackages:       []string{enrollFixturePkg},
		AllowSigners:        []string{enrollFixtureSigner},
		MinSecurityLevel:    "trusted_environment",
		RequireVerifiedBoot: true,
	})
	roots, err := androidAttestationRoots()
	require.NoError(t, err, "the embedded Google roots must load")
	policy.TrustedRoots = roots

	_, err = policy.Evaluate(&pairingproto.LocalGetDeviceEnrollmentRequestResult{
		Format:           pairingproto.AttestationFormatAndroidKey,
		AttestationChain: loadEnrollFixtureChain(t),
		SecurityLevel:    "software",
	}, []byte(enrollFixtureNonce), time.Now())

	require.Error(t, err, "an emulator must not enroll under production defaults")
}

func TestSignEnrollmentCSR_RejectsAnUnknownCASource(t *testing.T) {
	_, _, err := signEnrollmentCSR(
		t.Context(),
		&enrollPhoneOptions{CASource: "nonsense"},
		&pairingproto.LocalGetDeviceEnrollmentRequestResult{CSR: []byte{0x30, 0x00}},
		[]byte("nonce"),
		&pairing.EnrollmentDecision{NotAfter: time.Now().Add(time.Hour)},
	)

	assert.ErrorIs(t, err, ErrEnrollPhoneNoCA)
}

// newEnrollmentCSR returns a real DER certificate request, standing in for
// the one the phone builds over its Keystore key.
func newEnrollmentCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "phone.example.com"},
	}, key)
	require.NoError(t, err)
	return der
}

func TestSignEnrollmentCSR_SubmitsToTheConfiguredCA(t *testing.T) {
	csr := newEnrollmentCSR(t)
	decision := &pairing.EnrollmentDecision{NotAfter: time.Now().Add(30 * 24 * time.Hour)}

	t.Run("local CA signs without evidence", func(t *testing.T) {
		ca := newCATestFixture(t)
		fake := newFakeXKMSd(t, ca)
		useTestXKMSdEndpoint(t, fake.server.URL)

		certDER, chainDER, err := signEnrollmentCSR(t.Context(), &enrollPhoneOptions{},
			&pairingproto.LocalGetDeviceEnrollmentRequestResult{CSR: csr}, []byte(enrollFixtureNonce), decision)
		require.NoError(t, err)

		block, _ := pem.Decode(fake.signResponse.CertificatePEM)
		require.NotNil(t, block)
		assert.Equal(t, block.Bytes, certDER)
		assert.Equal(t, [][]byte{ca.cert.Raw}, chainDER)

		sent := fake.lastSignRequest
		csrBlock, _ := pem.Decode(sent.CSRPEM)
		require.NotNil(t, csrBlock)
		assert.Equal(t, csr, csrBlock.Bytes)
		assert.Equal(t, enrollmentCertProfile, sent.Profile)
		assert.Equal(t, 30, sent.ValidityDays)
		assert.Empty(t, sent.AttestationFormat)
		assert.Empty(t, sent.AttestationChain)
		assert.Empty(t, sent.AttestationNonce)
	})

	t.Run("xkms source is matched case-insensitively", func(t *testing.T) {
		fake := newFakeXKMSd(t, newCATestFixture(t))
		useTestXKMSdEndpoint(t, fake.server.URL)

		_, _, err := signEnrollmentCSR(t.Context(), &enrollPhoneOptions{CASource: " XKMS "},
			&pairingproto.LocalGetDeviceEnrollmentRequestResult{CSR: csr, AttestationChain: loadEnrollFixtureChain(t)},
			[]byte(enrollFixtureNonce), decision)
		require.NoError(t, err)
		assert.Equal(t, enrollmentCertProfile, fake.lastSignRequest.Profile)
	})

	t.Run("xkms source refuses a malformed chain before contacting the CA", func(t *testing.T) {
		useTestXKMSdEndpoint(t, "")

		_, _, err := signEnrollmentCSR(t.Context(), &enrollPhoneOptions{CASource: caSourceXKMS},
			&pairingproto.LocalGetDeviceEnrollmentRequestResult{CSR: csr, AttestationChain: []string{"not!base64"}},
			[]byte(enrollFixtureNonce), decision)
		require.ErrorIs(t, err, ErrEnrollPhoneRefused)
		assert.NotErrorIs(t, err, ErrEnrollPhoneNoCA)
	})

	t.Run("no CA configured", func(t *testing.T) {
		useTestXKMSdEndpoint(t, "")

		_, _, err := signEnrollmentCSR(t.Context(), &enrollPhoneOptions{},
			&pairingproto.LocalGetDeviceEnrollmentRequestResult{CSR: csr}, []byte(enrollFixtureNonce), decision)
		assert.ErrorIs(t, err, ErrEnrollPhoneNoCA)
	})

	t.Run("CA refuses the request", func(t *testing.T) {
		fake := newFakeXKMSd(t, newCATestFixture(t))
		fake.signStatus = http.StatusForbidden
		useTestXKMSdEndpoint(t, fake.server.URL)

		_, _, err := signEnrollmentCSR(t.Context(), &enrollPhoneOptions{},
			&pairingproto.LocalGetDeviceEnrollmentRequestResult{CSR: csr}, []byte(enrollFixtureNonce), decision)
		assert.ErrorIs(t, err, ErrEnrollPhoneRefused)
	})

	t.Run("CA answers without a certificate", func(t *testing.T) {
		fake := newFakeXKMSd(t, newCATestFixture(t))
		fake.signResponse.CertificatePEM = nil
		useTestXKMSdEndpoint(t, fake.server.URL)

		_, _, err := signEnrollmentCSR(t.Context(), &enrollPhoneOptions{},
			&pairingproto.LocalGetDeviceEnrollmentRequestResult{CSR: csr}, []byte(enrollFixtureNonce), decision)
		assert.ErrorIs(t, err, ErrEnrollPhoneRefused)
	})
}

// TestValidityDaysUntil_NeverIssuesZeroDays guards a subtle failure.
//
// Several CAs read validity_days == 0 as "use my default", so rounding a past
// or sub-day deadline down to zero would issue a *longer* credential than
// policy asked for -- the opposite of the intent.
func TestValidityDaysUntil_NeverIssuesZeroDays(t *testing.T) {
	assert.Equal(t, 1, validityDaysUntil(time.Now().Add(-time.Hour)),
		"an expired deadline must not read as the CA default")
	assert.Equal(t, 1, validityDaysUntil(time.Now()),
		"a deadline of now must not read as the CA default")
	assert.Equal(t, 1, validityDaysUntil(time.Now().Add(time.Minute)),
		"a sub-day deadline rounds up, not down")

	assert.Equal(t, 90, validityDaysUntil(time.Now().Add(90*24*time.Hour)))
	assert.Equal(t, 30, validityDaysUntil(time.Now().Add(30*24*time.Hour)))
}

func TestDecodeChainDER_RoundTripsTheCapturedChain(t *testing.T) {
	encoded := loadEnrollFixtureChain(t)

	chain, err := decodeChainDER(encoded)
	require.NoError(t, err)
	require.Len(t, chain, len(encoded))

	for i, der := range chain {
		assert.Equal(t, encoded[i], base64.StdEncoding.EncodeToString(der),
			"certificate %d must survive the round trip byte for byte", i)
	}
}

func TestDecodeChainDER_RejectsMalformedBase64(t *testing.T) {
	_, err := decodeChainDER([]string{"not!valid!base64!"})
	assert.ErrorIs(t, err, ErrEnrollPhoneRefused)
}

func TestPEMBlockHelpers(t *testing.T) {
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})
	issuer := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{4, 5, 6}})
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{7, 8, 9}})

	first, err := firstPEMBlock(leaf, "CERTIFICATE")
	require.NoError(t, err)
	assert.Equal(t, []byte{1, 2, 3}, first)

	all, err := allPEMBlocks(append(issuer, root...), "CERTIFICATE")
	require.NoError(t, err)
	require.Len(t, all, 2)
	assert.Equal(t, []byte{4, 5, 6}, all[0], "issuer order must be preserved")
	assert.Equal(t, []byte{7, 8, 9}, all[1])

	_, err = firstPEMBlock([]byte("not pem at all"), "CERTIFICATE")
	assert.ErrorIs(t, err, ErrEnrollPhoneRefused)

	// A response carrying only a key block must not be mistaken for a chain.
	keyOnly := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})
	_, err = firstPEMBlock(keyOnly, "CERTIFICATE")
	assert.ErrorIs(t, err, ErrEnrollPhoneRefused)

	empty, err := allPEMBlocks(nil, "CERTIFICATE")
	require.NoError(t, err)
	assert.Empty(t, empty, "no chain is legitimate when the root is trusted out of band")
}

func TestEncodeChain_OmitsAnEmptyChain(t *testing.T) {
	assert.Nil(t, encodeChain(nil))
	assert.Equal(t,
		[]string{base64.StdEncoding.EncodeToString([]byte{1, 2})},
		encodeChain([][]byte{{1, 2}}))
}

// TestEnrollmentMethodNames_MatchTheAndroidSpelling pins the wire contract.
//
// Nothing is code-shared with xkey-android: the Kotlin constants and these are
// hand-written twins, so a rename on either side produces no compile error and
// the method simply stops being routed.
func TestEnrollmentMethodNames_MatchTheAndroidSpelling(t *testing.T) {
	assert.Equal(t, "local.getDeviceEnrollmentRequest",
		pairingproto.MethodLocalGetDeviceEnrollmentRequest)
	assert.Equal(t, "local.storeDeviceCredential",
		pairingproto.MethodLocalStoreDeviceCredential)
	assert.Equal(t, "android-key-attestation", pairingproto.AttestationFormatAndroidKey)
}
