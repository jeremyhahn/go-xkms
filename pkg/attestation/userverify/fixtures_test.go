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

package userverify_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
)

// appPackage and appDigest name the one application the fixture trust
// allows; every fixture key attests under them.
const appPackage = "com.automatethethings.xkey"

var appDigest = bytes.Repeat([]byte{0x5a}, 32)

var errApplicationDenied = errors.New("application not allowed")

// appMatcher allows appPackage signed by appDigest and nothing else.
type appMatcher struct{}

func (appMatcher) Match(appID *android.AttestationApplicationID) (string, string, error) {
	if appID == nil || len(appID.Packages) != 1 || appID.Packages[0].Name != appPackage ||
		len(appID.SignatureDigests) != 1 || !bytes.Equal(appID.SignatureDigests[0], appDigest) {
		return "", "", errApplicationDenied
	}
	return appPackage, "", nil
}

// testCA is a self-signed attestation root.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, commonName string) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
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
	return &testCA{cert: cert, key: key}
}

func (c *testCA) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.cert)
	return pool
}

// trustOf is the trust material every test judges under: ca's root, the
// fixture application, and an empty revocation status list.
func trustOf(ca *testCA) *attestation.AndroidDeviceTrust {
	return &attestation.AndroidDeviceTrust{
		Roots:        ca.pool(),
		Applications: appMatcher{},
		Revocation:   &android.StatusList{},
	}
}

// uvkClaims are the claims of an honest UVK: a generated StrongBox signing
// key of the fixture application on a locked, verified device, unlocked by a
// biometric or the device credential on every use.
func uvkClaims() *android.AttestationExtensionOptions {
	return &android.AttestationExtensionOptions{
		HasOrigin: true,
		Origin:    android.OriginGenerated,
		Purpose:   []int{android.PurposeSign},
		ApplicationID: &android.AttestationApplicationID{
			Packages:         []android.AttestationPackageInfo{{Name: appPackage, Version: 1}},
			SignatureDigests: [][]byte{appDigest},
		},
		UserAuthType: android.UserAuthTypeFingerprint | android.UserAuthTypePassword,
		RootOfTrust: &android.RootOfTrust{
			VerifiedBootKey:   []byte("verified-boot-key"),
			DeviceLocked:      true,
			VerifiedBootState: android.VerifiedBootVerified,
			VerifiedBootHash:  []byte("verified-boot-hash"),
		},
	}
}

// phoneKey is an attested P-256 key the fixture phone signs with.
type phoneKey struct {
	key   *ecdsa.PrivateKey
	chain [][]byte

	// fp is the key's identity, the SHA-256 of its own marshalled
	// SubjectPublicKeyInfo, computed here and never by the verifier's
	// helper, so the two sides derive it independently.
	fp []byte
}

// newUVK issues a user-verification key under issuer with claims.
func newUVK(t *testing.T, issuer *testCA, claims *android.AttestationExtensionOptions) *phoneKey {
	t.Helper()
	return newPhoneKey(t, issuer, []byte(pairingproto.UserVerificationGenesisChallenge), claims)
}

// newPhoneKey issues a key whose leaf carries genesis as its attestation
// challenge.
func newPhoneKey(t *testing.T, issuer *testCA, genesis []byte, claims *android.AttestationExtensionOptions) *phoneKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ext, err := android.BuildAttestationExtensionWithOptions(
		4, android.SecurityLevelStrongBox, 100, android.SecurityLevelStrongBox, genesis, []byte("unique-id"), claims)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(time.Now().UnixNano() + 1),
		Subject:         pkix.Name{CommonName: "attested key"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: android.AndroidKeyAttestationOID, Value: ext}},
	}
	leaf, err := x509.CreateCertificate(rand.Reader, template, issuer.cert, &key.PublicKey, issuer.key)
	require.NoError(t, err)

	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	sum := sha256.Sum256(spki)

	return &phoneKey{key: key, chain: [][]byte{leaf, issuer.cert.Raw}, fp: sum[:]}
}

// sign signs the version 2 transcript for purpose, built by hand from the
// wire layout rather than by the verifier's builder; rpName, when non-empty,
// is appended length-prefixed as verify-user does.
func (k *phoneKey) sign(t *testing.T, purpose string, nonce, channelBinding []byte, rpName string) []byte {
	t.Helper()

	transcript := []byte(pairingproto.AttestTranscriptDomain)
	transcript = append(transcript, byte(len(purpose)))
	transcript = append(transcript, purpose...)
	transcript = append(transcript, nonce...)
	transcript = append(transcript, channelBinding...)
	transcript = append(transcript, k.fp...)
	if rpName != "" {
		transcript = append(transcript, byte(len(rpName)))
		transcript = append(transcript, rpName...)
	}
	digest := sha256.Sum256(transcript)
	sig, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
	require.NoError(t, err)
	return sig
}

// respond answers local.verifyUser for nonce, channelBinding and rpName.
func (k *phoneKey) respond(t *testing.T, nonce, channelBinding []byte, rpName string) *pairingproto.LocalVerifyUserResult {
	t.Helper()

	return &pairingproto.LocalVerifyUserResult{
		ProtocolVersion:    pairingproto.AttestProtocolV2,
		CertificateChain:   k.chain,
		Signature:          k.sign(t, pairingproto.AttestPurposeVerifyUser, nonce, channelBinding, rpName),
		SignatureAlgorithm: pairingproto.AttestSignatureES256,
	}
}

// fixedBytes returns n copies of b.
func fixedBytes(b byte, n int) []byte {
	return bytes.Repeat([]byte{b}, n)
}
