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

// Package attesttest provides the device-attestation fixtures shared by the
// packages that consume the attestation decision.
//
// It exists because those fixtures were needed in two places at once — the
// package that makes the decision and the command package that wires it — and
// the alternative was a second copy. A duplicated fixture is worse than
// duplicated production code: the copies drift silently, and each side then
// proves something about its own copy of the contract rather than about the
// contract.
//
// Everything here builds evidence a PROVER would produce. It deliberately does
// not import the verifier: the transcript is laid out by hand from the wire
// contract, so a passing test is two independent readings of that contract
// agreeing rather than one implementation checking itself. That is the same
// property xkey-android's Kotlin prover has to reproduce.
package attesttest

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

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/stretchr/testify/require"
)

// CA is a generated attestation root plus its key, standing in for a hardware
// attestation root.
//
// Tests state their own trust anchor rather than depending on which embedded
// roots ship: the property under test is "verified against the anchors this
// machine trusts", and substituting the anchor set does not weaken it.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// NewCA generates a self-signed CA.
func NewCA(t *testing.T, commonName string) *CA {
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

	return &CA{Cert: cert, Key: key}
}

// Pool is a cert pool anchored on this CA alone.
func (ca *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return pool
}

// AttestedBootState is the RootOfTrust a healthy phone presents: verified boot
// on a locked bootloader. Every fixture meant to SUCCEED carries it, and the
// refusal fixtures vary one field.
func AttestedBootState() *xkms.AndroidRootOfTrust {
	return &xkms.AndroidRootOfTrust{
		VerifiedBootKey:   []byte("verified-boot-key"),
		DeviceLocked:      true,
		VerifiedBootState: xkms.AndroidVerifiedBootVerified,
		VerifiedBootHash:  []byte("verified-boot-hash"),
	}
}

// GenesisChallenge is the attestation challenge a contract-faithful device
// generates its attestation key under.
func GenesisChallenge() []byte { return []byte(pairing.AttestGenesisChallenge) }

// AppPackage is the package name the fixture application attests under.
const AppPackage = "com.automatethethings.xkey"

// AppSigningDigest is the SHA-256 signing-certificate digest the fixture
// application attests under.
func AppSigningDigest() []byte { return FixedBytes(0x5a, 32) }

// AttestedApplication is the attestationApplicationId the fixture application
// presents: AppPackage signed by AppSigningDigest. A test proving the #1305
// refusal replaces it on DeviceKeyClaims() to vary the package or the signer.
func AttestedApplication() *xkms.AndroidAttestationApplicationID {
	return &xkms.AndroidAttestationApplicationID{
		Packages:         []xkms.AndroidAttestationPackageInfo{{Name: AppPackage, Version: 1}},
		SignatureDigests: [][]byte{AppSigningDigest()},
	}
}

// Applications is the allow-list that accepts AttestedApplication(), and only
// it: the policy a verifier configured for the fixture application holds.
func Applications() pairing.ApplicationPolicy {
	return pairing.ApplicationPolicy{AllowedApplications: []pairing.AllowedApplication{{
		PackageName:    AppPackage,
		SigningDigests: []string{hex.EncodeToString(AppSigningDigest())},
	}}}
}

// DeviceKeyClaims is the claims a contract-faithful device's attestation
// carries: the TEE-enforced key was GENERATED inside secure hardware and is
// authorized to SIGN (go-xkms#132), and the softwareEnforced
// attestationApplicationId names the fixture application (go-xkms#1305).
//
// AttestedLeafDER and NewDAK default to this, because it is what every
// SUCCEED fixture needs and what a real device answers. A test proving the
// #132 refusal calls AttestedLeafDERWithClaims / NewDAKWithClaims to vary
// Origin or Purpose alone, the same pattern AttestedBootState's rot parameter
// already uses for boot state.
func DeviceKeyClaims() *xkms.AndroidAttestationExtensionOptions {
	return &xkms.AndroidAttestationExtensionOptions{
		HasOrigin:     true,
		Origin:        xkms.AndroidOriginGenerated,
		Purpose:       []int{xkms.AndroidPurposeSign},
		ApplicationID: AttestedApplication(),
	}
}

// AttestedLeafDER issues a leaf for key carrying an Android key-attestation
// extension whose attestationChallenge is challenge, whose teeEnforced
// RootOfTrust is rot, and whose teeEnforced Origin/Purpose are
// DeviceKeyClaims() -- GENERATED and SIGN. When issuer is nil the leaf is
// self-signed, which is the case go-xkms#95 names: a peer that generates its
// own chain a moment before sending it.
//
// The key is a PARAMETER rather than generated here because under #129 the
// attested key is the device's persistent identity and the same key must both
// appear in the leaf and sign the challenge. A helper that kept the key to
// itself could only ever produce a chain nobody can prove possession of.
//
// rot is a parameter because absence is one of the cases under test: an
// extension with no RootOfTrust passes the SDK's VerifyBootState (its contract
// is "verify what is claimed") while claiming nothing at all, and a consumer
// must refuse it.
//
// A test that needs to vary Origin or Purpose instead calls
// AttestedLeafDERWithClaims.
func AttestedLeafDER(
	t *testing.T,
	issuer *CA,
	key *ecdsa.PrivateKey,
	challenge []byte,
	level xkms.AndroidSecurityLevel,
	rot *xkms.AndroidRootOfTrust,
) []byte {
	t.Helper()

	claims := DeviceKeyClaims()
	claims.RootOfTrust = rot
	return AttestedLeafDERWithClaims(t, issuer, key, challenge, level, claims)
}

// AttestedLeafDERWithClaims is AttestedLeafDER with full control over the
// teeEnforced claims, for tests that vary Origin or Purpose to prove the
// go-xkms#132 refusal. A nil claims produces a teeEnforced list that makes no
// claim about origin, purpose, or boot state at all.
func AttestedLeafDERWithClaims(
	t *testing.T,
	issuer *CA,
	key *ecdsa.PrivateKey,
	challenge []byte,
	level xkms.AndroidSecurityLevel,
	claims *xkms.AndroidAttestationExtensionOptions,
) []byte {
	t.Helper()

	ext, err := xkms.BuildAndroidAttestationExtensionWithOptions(
		4, level, 100, level, challenge, []byte("unique-id"), claims,
	)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "attested key"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: xkms.AndroidKeyAttestationOID, Value: ext},
		},
	}

	parent, signer := template, any(key)
	if issuer != nil {
		parent, signer = issuer.Cert, any(issuer.Key)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	require.NoError(t, err)

	return der
}

// DAK is a stand-in for a phone's Device Attestation Key under the #129 model:
// ONE persistent EC key, attested once when it was generated, that answers
// every later challenge with a live signature.
type DAK struct {
	Key   *ecdsa.PrivateKey
	Leaf  *x509.Certificate
	Chain [][]byte

	// FP is the device identity, computed once at construction from the key's
	// own marshalled SubjectPublicKeyInfo — never by calling the verifier's
	// helper, so the two sides derive it independently.
	FP []byte
}

// NewDAK generates a device key and attests it once under issuer, exactly as a
// handset does at first run. genesis is the attestation challenge baked in at
// key generation; every test that expects to SUCCEED passes GenesisChallenge().
// The teeEnforced Origin/Purpose claims are DeviceKeyClaims() -- GENERATED and
// SIGN; a test that needs to vary them calls NewDAKWithClaims.
func NewDAK(
	t *testing.T,
	issuer *CA,
	genesis []byte,
	level xkms.AndroidSecurityLevel,
	rot *xkms.AndroidRootOfTrust,
) *DAK {
	t.Helper()

	claims := DeviceKeyClaims()
	claims.RootOfTrust = rot
	return NewDAKWithClaims(t, issuer, genesis, level, claims)
}

// NewDAKWithClaims is NewDAK with full control over the teeEnforced claims,
// for tests that vary Origin or Purpose to prove the go-xkms#132 refusal.
func NewDAKWithClaims(
	t *testing.T,
	issuer *CA,
	genesis []byte,
	level xkms.AndroidSecurityLevel,
	claims *xkms.AndroidAttestationExtensionOptions,
) *DAK {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafDER := AttestedLeafDERWithClaims(t, issuer, key, genesis, level, claims)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	chain := [][]byte{leafDER}
	if issuer != nil {
		chain = append(chain, issuer.Cert.Raw)
	}

	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	sum := sha256.Sum256(spki)

	return &DAK{Key: key, Leaf: leaf, Chain: chain, FP: sum[:]}
}

// Fingerprint is the device identity the contract derives: SHA-256 over the
// attested key's SubjectPublicKeyInfo.
func (d *DAK) Fingerprint() []byte { return d.FP }

// SignRaw produces the live challenge signature: the transcript laid out by
// hand per the wire contract, hashed with SHA-256, signed ASN.1 DER by the
// device key.
//
// It takes no *testing.T because responders call it from a goroutine, where a
// require would abort the wrong test.
func (d *DAK) SignRaw(purpose string, nonce, channelBinding []byte) ([]byte, error) {
	transcript := make([]byte, 0, 160)
	transcript = append(transcript, []byte(pairing.AttestTranscriptDomain)...)
	transcript = append(transcript, byte(len(purpose)))
	transcript = append(transcript, []byte(purpose)...)
	transcript = append(transcript, nonce...)
	transcript = append(transcript, channelBinding...)
	transcript = append(transcript, d.FP...)

	digest := sha256.Sum256(transcript)
	return ecdsa.SignASN1(rand.Reader, d.Key, digest[:])
}

// Sign is SignRaw for synchronous tests, which want a failure to abort.
func (d *DAK) Sign(t *testing.T, purpose string, nonce, channelBinding []byte) []byte {
	t.Helper()

	sig, err := d.SignRaw(purpose, nonce, channelBinding)
	require.NoError(t, err)
	return sig
}

// Respond is the whole local.attestDevice answer a contract-faithful phone
// returns for the given purpose, nonce and channel binding.
func (d *DAK) Respond(t *testing.T, purpose string, nonce, channelBinding []byte) *pairing.LocalAttestDeviceResult {
	t.Helper()

	return &pairing.LocalAttestDeviceResult{
		ProtocolVersion:    pairing.AttestProtocolV2,
		Format:             "android-keystore",
		CertificateChain:   d.Chain,
		SecurityLevel:      "strongbox",
		Nonce:              nonce,
		Purpose:            purpose,
		Signature:          d.Sign(t, purpose, nonce, channelBinding),
		SignatureAlgorithm: pairing.AttestSignatureES256,
	}
}

// FixedBytes returns n bytes of b. Deterministic, distinguishable fillers make
// a mismatch legible in a failure message; nothing in these tests needs
// randomness, because the property under test is that the verifier rebuilds
// the transcript from its OWN record of what it asked.
func FixedBytes(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
