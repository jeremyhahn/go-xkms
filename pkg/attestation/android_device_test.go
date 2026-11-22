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

package attestation

import (
	"bufio"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// galaxyS23UltraChain is a StrongBox attestation captured from a Galaxy
// S23 Ultra by the com.automatethethings.xkey.capture build (#1305).
const galaxyS23UltraChain = "android/testdata/android_sm_s918u_chain.txt"

const captureApplication = "com.automatethethings.xkey.capture"

var errApplicationDenied = errors.New("test: application denied")

// packageMatcher allows exactly one package name.
type packageMatcher string

func (m packageMatcher) Match(appID *android.AttestationApplicationID) (string, string, error) {
	if appID != nil {
		for _, pkg := range appID.Packages {
			if pkg.Name == string(m) {
				return pkg.Name, "", nil
			}
		}
	}
	return "", "", errApplicationDenied
}

func loadDERChain(t *testing.T, path string) [][]byte {
	t.Helper()

	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })

	var chain [][]byte
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(line)
		require.NoError(t, err)
		chain = append(chain, der)
	}
	require.NoError(t, scanner.Err())
	require.NotEmpty(t, chain)
	return chain
}

func googleRoots(t *testing.T) *x509.CertPool {
	t.Helper()

	roots, err := truststore.GoogleHardwareAttestationRoots()
	require.NoError(t, err)
	pool := x509.NewCertPool()
	for _, root := range roots {
		pool.AddCert(root)
	}
	return pool
}

func (ca *testCA) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

func TestVerifyAndroidDeviceKey_RealHandsetSatisfiesTheHardwarePolicy(t *testing.T) {
	trust := &AndroidDeviceTrust{Roots: googleRoots(t), Applications: packageMatcher(captureApplication), Revocation: noRevocations(t)}

	key, err := VerifyAndroidDeviceKey(loadDERChain(t, galaxyS23UltraChain), trust)
	require.NoError(t, err)

	desc := key.Description
	assert.Equal(t, android.SecurityLevelStrongBox, desc.AttestationSecurityLevel)
	assert.Equal(t, android.SecurityLevelStrongBox, desc.KeymasterSecurityLevel)
	// Samsung's StrongBox records its claims in the hardware-enforced list,
	// which the parser exposes as TeeEnforced whichever element enforced them.
	assert.Equal(t, android.OriginGenerated, desc.TeeEnforced.Origin, "TEE-enforced Origin (tag 702)")
	assert.Contains(t, desc.TeeEnforced.Purpose, android.PurposeSign, "TEE-enforced Purpose (tag 1)")
	assert.True(t, key.RootOfTrust.DeviceLocked)
	assert.Equal(t, android.VerifiedBootVerified, key.RootOfTrust.VerifiedBootState)
	assert.Equal(t, key.Chain[len(key.Chain)-1].Raw, key.TrustAnchor.Raw, "the chain must anchor at its own Google root")
	assert.Equal(t, "xkey-fixture-challenge", string(desc.AttestationChallenge))
}

func TestVerifyAndroidDeviceKey_Refuses(t *testing.T) {
	chainDER := loadDERChain(t, galaxyS23UltraChain)

	t.Run("another application", func(t *testing.T) {
		trust := &AndroidDeviceTrust{Roots: googleRoots(t), Applications: packageMatcher("com.automatethethings.xkey"), Revocation: noRevocations(t)}

		key, err := VerifyAndroidDeviceKey(chainDER, trust)

		require.ErrorIs(t, err, android.ErrApplicationRefused)
		require.ErrorIs(t, err, errApplicationDenied)
		assert.Nil(t, key)
	})

	t.Run("no application policy", func(t *testing.T) {
		_, err := VerifyAndroidDeviceKey(chainDER, &AndroidDeviceTrust{Roots: googleRoots(t), Revocation: noRevocations(t)})
		require.ErrorIs(t, err, android.ErrNilApplicationMatcher)
	})

	t.Run("no revocation status list", func(t *testing.T) {
		_, err := VerifyAndroidDeviceKey(chainDER, &AndroidDeviceTrust{Roots: googleRoots(t), Applications: packageMatcher(captureApplication)})
		require.ErrorIs(t, err, ErrNoRevocationSource, "the revocation check is required, not optional")
	})

	t.Run("roots it does not anchor in", func(t *testing.T) {
		trust := &AndroidDeviceTrust{Roots: generateTestCA(t, "Foreign Root").pool(), Applications: packageMatcher(captureApplication), Revocation: noRevocations(t)}

		_, err := VerifyAndroidDeviceKey(chainDER, trust)

		require.ErrorIs(t, err, android.ErrChainVerificationFailed)
	})

	t.Run("no roots", func(t *testing.T) {
		_, err := VerifyAndroidDeviceKey(chainDER, &AndroidDeviceTrust{Applications: packageMatcher(captureApplication)})
		require.ErrorIs(t, err, ErrNoTrustAnchors, "a nil pool would skip chain verification outright")
	})

	t.Run("nil trust", func(t *testing.T) {
		_, err := VerifyAndroidDeviceKey(chainDER, nil)
		require.ErrorIs(t, err, ErrNoTrustAnchors)
	})

	t.Run("empty chain", func(t *testing.T) {
		_, err := VerifyAndroidDeviceKey(nil, &AndroidDeviceTrust{Roots: googleRoots(t), Applications: packageMatcher(captureApplication), Revocation: noRevocations(t)})
		require.ErrorIs(t, err, ErrEmptyCertificateChain)
	})
}

// noRevocations is a status list that lists no certificate.
func noRevocations(t *testing.T) *android.StatusList {
	t.Helper()
	list, err := android.ParseStatusList([]byte(`{"entries":{}}`))
	require.NoError(t, err)
	return list
}

// listing returns a status list naming one certificate with a status.
func listing(t *testing.T, cert *x509.Certificate, status android.CertificateStatus) *android.StatusList {
	t.Helper()
	doc := fmt.Sprintf(`{"entries":{%q:{"status":%q,"reason":"KEY_COMPROMISE"}}}`,
		android.StatusListSerial(cert.SerialNumber), status)
	list, err := android.ParseStatusList([]byte(doc))
	require.NoError(t, err)
	return list
}

// unavailableStatusList is a source that cannot supply a list.
type unavailableStatusList struct{}

func (unavailableStatusList) Current() (*android.StatusList, error) {
	return nil, &android.StatusListUnavailableError{Source: "test", Cause: errUnreachable}
}

var errUnreachable = errors.New("test: status list endpoint unreachable")

func TestVerifyAndroidDeviceKey_RevocationStatusList(t *testing.T) {
	chainDER := loadDERChain(t, galaxyS23UltraChain)
	chain, err := ParseDERChain(chainDER)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(chain), 3, "the fixture must carry a leaf, an intermediate and a root")

	verify := func(revocation android.StatusListSource) error {
		_, err := VerifyAndroidDeviceKey(chainDER, &AndroidDeviceTrust{
			Roots: googleRoots(t), Applications: packageMatcher(captureApplication), Revocation: revocation,
		})
		return err
	}

	cases := []struct {
		name   string
		cert   *x509.Certificate
		status android.CertificateStatus
	}{
		{"revoked leaf", chain[0], android.CertificateStatusRevoked},
		{"revoked intermediate", chain[1], android.CertificateStatusRevoked},
		{"revoked root", chain[len(chain)-1], android.CertificateStatusRevoked},
		{"suspended intermediate", chain[1], android.CertificateStatusSuspended},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verify(listing(t, tc.cert, tc.status))

			require.ErrorIs(t, err, android.ErrCertificateRevoked)
			var revoked *android.RevokedCertificateError
			require.ErrorAs(t, err, &revoked)
			assert.Equal(t, android.StatusListSerial(tc.cert.SerialNumber), revoked.Serial)
			assert.Equal(t, tc.status, revoked.Status)
			assert.Contains(t, err.Error(), revoked.Serial, "the error names the serial")
		})
	}

	t.Run("unlisted chain passes", func(t *testing.T) {
		require.NoError(t, verify(noRevocations(t)))
	})

	t.Run("list unavailable fails closed", func(t *testing.T) {
		err := verify(unavailableStatusList{})
		require.ErrorIs(t, err, android.ErrStatusListUnavailable)
		require.ErrorIs(t, err, errUnreachable)
	})
}

func TestParseDERChain(t *testing.T) {
	ca := generateTestCA(t, "Root")
	leaf := generateLeafCert(t, ca, "leaf")

	chain, err := ParseDERChain([][]byte{leaf.Raw, ca.cert.Raw})

	require.NoError(t, err)
	require.Len(t, chain, 2)
	assert.Equal(t, leaf.Raw, chain[0].Raw)
	assert.Equal(t, ca.cert.Raw, chain[1].Raw)
}

func TestParseDERChain_Refuses(t *testing.T) {
	_, err := ParseDERChain(nil)
	require.ErrorIs(t, err, ErrEmptyCertificateChain)

	_, err = ParseDERChain([][]byte{generateTestCA(t, "Root").cert.Raw, []byte("not a certificate")})
	require.ErrorIs(t, err, ErrCertificateParseFailed)
	assert.Contains(t, err.Error(), "certificate 1", "the error must name the offending position")
}

func TestVerifiedTrustAnchor(t *testing.T) {
	ca := generateTestCA(t, "Trusted Root")
	appended := generateTestCA(t, "Appended By The Peer")
	leaf := generateLeafCert(t, ca, "leaf")

	anchor, err := VerifiedTrustAnchor([]*x509.Certificate{leaf, ca.cert, appended.cert}, ca.pool())

	require.NoError(t, err)
	assert.Equal(t, ca.cert.Raw, anchor.Raw, "a certificate the peer appended must never become the anchor")
}

func TestVerifiedTrustAnchor_Refuses(t *testing.T) {
	ca := generateTestCA(t, "Trusted Root")
	leaf := generateLeafCert(t, ca, "leaf")

	_, err := VerifiedTrustAnchor(nil, ca.pool())
	require.ErrorIs(t, err, ErrEmptyCertificateChain)

	_, err = VerifiedTrustAnchor([]*x509.Certificate{leaf}, nil)
	require.ErrorIs(t, err, ErrNoTrustAnchors)

	_, err = VerifiedTrustAnchor([]*x509.Certificate{leaf}, generateTestCA(t, "Other Root").pool())
	require.ErrorIs(t, err, ErrChainNotAnchored)
}

func TestFormatTrustAnchor(t *testing.T) {
	assert.Equal(t, "unknown", FormatTrustAnchor(nil))

	withCN := &x509.Certificate{Subject: pkix.Name{CommonName: "Google Hardware Attestation Root"}}
	assert.Equal(t, "Google Hardware Attestation Root", FormatTrustAnchor(withCN))

	withOrgOnly := &x509.Certificate{Subject: pkix.Name{Organization: []string{"Example Corp"}}}
	assert.Equal(t, "Example Corp", FormatTrustAnchor(withOrgOnly))

	withNeither := &x509.Certificate{Subject: pkix.Name{Country: []string{"US"}}}
	assert.Equal(t, withNeither.Subject.String(), FormatTrustAnchor(withNeither))
}
