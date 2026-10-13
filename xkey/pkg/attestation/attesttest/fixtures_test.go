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

package attesttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	pairing "github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// The fixtures stand in for an Android Keystore attestation that the
// verifiers under test must accept, so each of these checks the fixture
// against the production parser or verifier rather than against itself.

func TestAttestedLeafDER_ChainsToTheCAAndCarriesTheClaims(t *testing.T) {
	ca := NewCA(t, "attestation root")
	key := newKey(t)

	leaf, err := x509.ParseCertificate(AttestedLeafDER(t, ca, key, []byte("the challenge"),
		xkms.AndroidSecurityLevelStrongBox, AttestedBootState()))
	require.NoError(t, err)

	_, err = leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	require.NoError(t, err, "the leaf does not chain to the CA that issued it")
	require.Equal(t, &key.PublicKey, leaf.PublicKey)

	desc, err := xkms.ParseAndroidKeyAttestation(leaf)
	require.NoError(t, err)
	require.Equal(t, []byte("the challenge"), desc.AttestationChallenge)
	require.Equal(t, xkms.AndroidSecurityLevelStrongBox, desc.AttestationSecurityLevel)

	pkg, digest, err := Applications().Match(pairing.AttestedApplication(desc))
	require.NoError(t, err, "the fixture's own allow-list refuses the application it attests")
	require.Equal(t, AppPackage, pkg)
	require.Equal(t, hex.EncodeToString(AppSigningDigest()), digest)
}

func TestAttestedLeafDER_NilIssuerSelfSigns(t *testing.T) {
	ca := NewCA(t, "unrelated root")
	leaf, err := x509.ParseCertificate(AttestedLeafDER(t, nil, newKey(t), []byte("c"),
		xkms.AndroidSecurityLevelTrustedEnvironment, AttestedBootState()))
	require.NoError(t, err)

	require.NoError(t, leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature),
		"a leaf with no issuer is not signed by its own key")
	require.Equal(t, leaf.Subject.String(), leaf.Issuer.String())

	_, err = leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	require.Error(t, err, "a self-signed leaf chained to a CA that never issued it")
}

func TestNewDAK_FingerprintIsTheSPKIHashAndTheChainIsLeafFirst(t *testing.T) {
	ca := NewCA(t, "dak root")
	dak := NewDAK(t, ca, GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, AttestedBootState())

	spki, err := x509.MarshalPKIXPublicKey(&dak.Key.PublicKey)
	require.NoError(t, err)
	sum := sha256.Sum256(spki)
	require.Equal(t, sum[:], dak.Fingerprint())

	require.Len(t, dak.Chain, 2)
	require.Equal(t, dak.Leaf.Raw, dak.Chain[0])
	require.Equal(t, ca.Cert.Raw, dak.Chain[1])
	require.Equal(t, &dak.Key.PublicKey, dak.Leaf.PublicKey)

	desc, err := xkms.ParseAndroidKeyAttestation(dak.Leaf)
	require.NoError(t, err)
	require.Equal(t, []byte(pairing.AttestGenesisChallenge), desc.AttestationChallenge)
}

func TestNewDAK_WithoutAnIssuerCarriesOnlyTheLeaf(t *testing.T) {
	dak := NewDAK(t, nil, GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, AttestedBootState())

	require.Equal(t, [][]byte{dak.Leaf.Raw}, dak.Chain)
}

func TestDAKSignRaw_VerifiesUnderTheProductionTranscript(t *testing.T) {
	dak := NewDAK(t, NewCA(t, "root"), GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, AttestedBootState())
	nonce := FixedBytes(0x11, pairing.AttestNonceSize)
	binding := FixedBytes(0x22, pairing.AttestChannelBindingSize)

	sig, err := dak.SignRaw(pairing.AttestPurposePair, nonce, binding)
	require.NoError(t, err)

	transcript, err := pairing.BuildAttestTranscript(pairing.AttestPurposePair, nonce, binding, dak.FP)
	require.NoError(t, err)
	require.NoError(t, pairing.VerifyAttestChallengeSignature(dak.Leaf, pairing.AttestSignatureES256, sig, transcript),
		"the fixture's hand-built transcript drifted from BuildAttestTranscript")

	// The purpose is in the transcript: a pairing signature must not satisfy
	// a reconnect.
	reattest, err := pairing.BuildAttestTranscript(pairing.AttestPurposeReattest, nonce, binding, dak.FP)
	require.NoError(t, err)
	require.Error(t, pairing.VerifyAttestChallengeSignature(dak.Leaf, pairing.AttestSignatureES256, sig, reattest))
}

func TestDAKRespond_IsAVersion2ResponseOverTheGivenChallenge(t *testing.T) {
	dak := NewDAK(t, NewCA(t, "root"), GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, AttestedBootState())
	nonce := FixedBytes(0x33, pairing.AttestNonceSize)
	binding := FixedBytes(0x44, pairing.AttestChannelBindingSize)

	res := dak.Respond(t, pairing.AttestPurposeReattest, nonce, binding)

	require.Equal(t, pairing.AttestProtocolV2, res.ProtocolVersion)
	require.Equal(t, pairing.AttestSignatureES256, res.SignatureAlgorithm)
	require.Equal(t, pairing.AttestPurposeReattest, res.Purpose)
	require.Equal(t, nonce, res.Nonce)
	require.Equal(t, dak.Chain, res.CertificateChain)

	transcript, err := pairing.BuildAttestTranscript(res.Purpose, nonce, binding, dak.FP)
	require.NoError(t, err)
	require.NoError(t, pairing.VerifyAttestChallengeSignature(dak.Leaf, res.SignatureAlgorithm, res.Signature, transcript))
}

func TestFixedBytes(t *testing.T) {
	require.Equal(t, []byte{0x5a, 0x5a, 0x5a}, FixedBytes(0x5a, 3))
	require.Empty(t, FixedBytes(0x5a, 0))
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}
