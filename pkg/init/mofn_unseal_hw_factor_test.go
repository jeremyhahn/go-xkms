// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package initialize

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"log/slog"
	"math/big"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/factor"
	xkmspiv "github.com/jeremyhahn/go-xkms/pkg/factor/piv"
	xkmspkcs11 "github.com/jeremyhahn/go-xkms/pkg/factor/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/stretchr/testify/require"
)

// The unseal key domain and operation of go-qrdb's share-holder quorum.
const (
	unsealDomain = "unseal"
	unsealOp     = "unseal"
)

// mofnHolder is one enrolled share holder: the certificate key the ceremony
// seals its share envelope to, the issued certificate, the factor it
// authenticates with, its claimed share and, for a PKCS#11 holder, the token
// key pair its factor enrolment records.
type mofnHolder struct {
	username string
	factor   string
	key      *ecdsa.PrivateKey
	cert     *x509.Certificate
	share    []byte
	tokenKey *ecdsa.PrivateKey
}

// mofnForgery replaces a holder's own answer to its quorum challenge: the
// response it signs and, when peer is set, the certificate its connection
// presents.
type mofnForgery struct {
	response func(challenge *qrdbsdk.QuorumChallenge) []byte
	peer     *x509.Certificate
}

// mofnRig is a Shamir-custody system barrier with go-qrdb's ceremony as its
// share-holder authority, authenticating holders through the factor registry
// the node is built with (factor.NewNodeRegistry, via
// server.NewNodeFactorRegistry).
type mofnRig struct {
	barrier  *qrdbsdk.StorageBarrier
	service  qrdbsdk.BarrierServicer
	ceremony *qrdbsdk.CeremonyService
	piv      *xkmspiv.Factor
	holders  map[string]*mofnHolder
}

// newMofnRig enrols three holders -- holder-piv on the xkms PIV factor
// (backed by the software PIV key generator), holder-mtls on mtls (served by
// go-qrdb's own factor) and holder-token on the xkms PKCS#11 factor --
// initializes the barrier 2-of-3 under the designated factor policy, has
// every holder claim its share and seals the barrier.
func newMofnRig(t *testing.T) *mofnRig {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)

	registry, err := factor.NewNodeRegistry(factor.Config{})
	require.NoError(t, err)
	plugin, err := registry.Lookup(xkmspiv.FactorName)
	require.NoError(t, err)
	pivFactor, ok := plugin.(*xkmspiv.Factor)
	require.True(t, ok, "the registry's piv factor is the xkms PIV factor")

	shamir, err := qrdbsdk.NewShamirStrategy(2, 3)
	require.NoError(t, err)
	barrier, err := qrdbsdk.NewStorageBarrier(logger, qrdbsdk.NewMemoryBackend(), qrdbsdk.BarrierConfig{
		PreferenceOrder: []qrdbsdk.StrategyID{qrdbsdk.StrategyShamir},
		RootKeyPath:     "core/seal",
		Shamir:          &qrdbsdk.ShamirConfig{Threshold: 2, TotalShares: 3},
	}, shamir)
	require.NoError(t, err)

	ceremony, err := qrdbsdk.NewCeremonyService(&qrdbsdk.CeremonyConfig{DataDir: t.TempDir()}, barrier, logger)
	require.NoError(t, err)
	t.Cleanup(ceremony.Cleanup)
	ceremony.SetCA(NewCAAdapter(newMockCA(t), ""))
	ceremony.SetFactorRegistry(registry)

	rig := &mofnRig{
		barrier:  barrier,
		service:  qrdbsdk.NewBarrierServiceWithCeremony(barrier, ceremony),
		ceremony: ceremony,
		piv:      pivFactor,
		holders:  map[string]*mofnHolder{},
	}
	rig.register(t, "holder-piv", xkmspiv.FactorName)
	rig.register(t, "holder-mtls", qrdbsdk.QuorumFactorMTLS)
	rig.register(t, "holder-token", xkmspkcs11.FactorName)

	params, err := ceremony.InitializeShamir(ctx, "designated")
	require.NoError(t, err)
	require.Equal(t, 3, params.ShareCount)

	for _, h := range rig.holders {
		rig.claim(t, h)
	}
	require.NoError(t, barrier.Seal())
	require.True(t, barrier.IsSealed())
	return rig
}

// register enrols username with factorName as its designated factor. An
// mtls holder is enrolled by its issued certificate alone; a PKCS#11 holder enrols the public half of a fresh P-256 key standing in for
// the key pair resident on its token.
func (r *mofnRig) register(t *testing.T, username, factorName string) {
	t.Helper()
	csrPEM, key := generateTestCSR(t, username)
	holder := &mofnHolder{username: username, factor: factorName, key: key}
	req := qrdbsdk.RegisterOfficerRequest{Username: username, CSRPEM: csrPEM, Designated: factorName}
	switch factorName {
	case qrdbsdk.QuorumFactorMTLS:
		// The ceremony enrols mtls from the certificate it issues.
	case xkmspkcs11.FactorName:
		var err error
		holder.tokenKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		der, err := x509.MarshalPKIXPublicKey(&holder.tokenKey.PublicKey)
		require.NoError(t, err)
		req.Factors = []qrdbsdk.FactorEnrolment{{Name: factorName, Params: map[string]any{"public_key_der": der}}}
	default:
		req.Factors = []qrdbsdk.FactorEnrolment{{Name: factorName}}
	}
	res, err := r.ceremony.RegisterOfficer(context.Background(), unsealDomain, req)
	require.NoError(t, err)
	require.Equal(t, factorName, res.Designated)

	block, _ := pem.Decode(res.CertPEM)
	require.NotNil(t, block)
	holder.cert, err = x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	r.holders[username] = holder
}

// claim runs the share-claim handshake for h and opens its envelope.
func (r *mofnRig) claim(t *testing.T, h *mofnHolder) {
	t.Helper()
	ctx := context.Background()
	thumbprint := qrdbsdk.CertThumbprint(h.cert.Raw)

	challenge, err := r.ceremony.BeginClaimShare(ctx, unsealDomain, h.username, thumbprint)
	require.NoError(t, err)
	sig, err := qrdbsdk.SignShareClaim(h.key, qrdbsdk.SystemClaimLabel, h.username, challenge.Nonce)
	require.NoError(t, err)
	claimed, err := r.ceremony.CompleteClaimShare(ctx, unsealDomain, h.username, hex.EncodeToString(challenge.Nonce), sig, thumbprint)
	require.NoError(t, err)

	envelope, err := qrdbsdk.ParseShareEnvelope(claimed.Envelope)
	require.NoError(t, err)
	h.share, err = envelope.OpenWithKey(h.key)
	require.NoError(t, err)
}

// submit answers h's quorum challenge -- with h's own factor and
// certificate, or with what forge replaces -- and submits its share toward
// the unseal round.
func (r *mofnRig) submit(t *testing.T, h *mofnHolder, forge *mofnForgery) (*qrdbsdk.QuorumOutcomeInfo, error) {
	t.Helper()
	ctx := context.Background()
	challenge, err := r.ceremony.BeginQuorum(ctx, unsealDomain, unsealOp, h.username, h.factor)
	require.NoError(t, err)

	var response []byte
	switch {
	case forge != nil && forge.response != nil:
		response = forge.response(challenge)
	case h.factor == xkmspiv.FactorName:
		response, err = r.piv.SignNonce(ctx, pivcert.PIVSlotAuthentication, challenge.Nonce)
		require.NoError(t, err)
	case h.factor == qrdbsdk.QuorumFactorMTLS:
		response = signQuorumChallenge(t, h.key, challenge)
	default:
		response = signNonce(t, h.tokenKey, challenge.Nonce)
	}

	peer := h.cert
	if forge != nil && forge.peer != nil {
		peer = forge.peer
	}
	return r.service.BarrierQuorumSubmit(ctx, &qrdbsdk.QuorumSubmitRequest{
		Domain:             unsealDomain,
		Op:                 unsealOp,
		Username:           h.username,
		ChallengeID:        challenge.ChallengeID,
		Factor:             h.factor,
		Response:           response,
		PeerCertThumbprint: qrdbsdk.CertThumbprint(peer.Raw),
		Share:              append([]byte(nil), h.share...),
	})
}

// signNonce is a token's answer to a PKCS#11 or PIV challenge: an ASN.1 ECDSA
// signature over SHA-256(nonce).
func signNonce(t *testing.T, key *ecdsa.PrivateKey, nonce []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(nonce)
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	return sig
}

// signQuorumChallenge is an mtls holder's answer to its quorum challenge,
// signed with key.
func signQuorumChallenge(t *testing.T, key *ecdsa.PrivateKey, challenge *qrdbsdk.QuorumChallenge) []byte {
	t.Helper()
	purpose := challenge.MethodData[qrdbsdk.QuorumChallengePurposeKey]
	require.NotEmpty(t, purpose, "an mtls quorum challenge carries its purpose")
	sig, err := qrdbsdk.SignQuorumChallenge(key, challenge.ChallengeID, purpose, challenge.Nonce)
	require.NoError(t, err)
	return sig
}

// selfSignedCert is a certificate for key that no ceremony issued.
func selfSignedCert(t *testing.T, key *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestMofNUnseal_HardwareFactorHolderCompletesQuorum proves #1355's
// verification on the node's factor registry: a 2-of-3 unseal succeeds with
// one holder authenticating through the xkms PIV factor and the other over
// mtls.
func TestMofNUnseal_HardwareFactorHolderCompletesQuorum(t *testing.T) {
	rig := newMofnRig(t)

	out, err := rig.submit(t, rig.holders["holder-piv"], nil)
	require.NoError(t, err)
	require.False(t, out.Complete)
	require.Equal(t, 1, out.Submitted)
	require.True(t, rig.barrier.IsSealed())

	out, err = rig.submit(t, rig.holders["holder-mtls"], nil)
	require.NoError(t, err)
	require.True(t, out.Complete)
	require.Equal(t, 2, out.Required)
	require.False(t, rig.barrier.IsSealed(), "a completed 2-of-3 quorum unseals the barrier")
}

// TestMofNUnseal_InvalidHardwareFactorAssertionIsRefused proves a holder
// whose PIV assertion does not verify is refused: its share is not counted
// and two valid holders are still needed to unseal.
func TestMofNUnseal_InvalidHardwareFactorAssertionIsRefused(t *testing.T) {
	rig := newMofnRig(t)

	impostor, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	forged := &mofnForgery{response: func(ch *qrdbsdk.QuorumChallenge) []byte {
		return signNonce(t, impostor, ch.Nonce)
	}}

	_, err = rig.submit(t, rig.holders["holder-piv"], forged)
	require.Error(t, err, "a PIV assertion by a key other than the enrolled card's is refused")
	require.True(t, rig.barrier.IsSealed())

	out, err := rig.submit(t, rig.holders["holder-mtls"], nil)
	require.NoError(t, err)
	require.False(t, out.Complete, "the refused holder's share was not counted")
	require.Equal(t, 1, out.Submitted)
	require.True(t, rig.barrier.IsSealed())

	out, err = rig.submit(t, rig.holders["holder-token"], nil)
	require.NoError(t, err)
	require.True(t, out.Complete)
	require.False(t, rig.barrier.IsSealed())
}

// TestMofNUnseal_MismatchedMTLSCertificateIsRefused proves an mtls holder
// whose connection presents a certificate other than its enrolled one, and
// answers with that certificate's key, is refused and its share not counted.
func TestMofNUnseal_MismatchedMTLSCertificateIsRefused(t *testing.T) {
	rig := newMofnRig(t)

	impostor, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	forged := &mofnForgery{
		response: func(ch *qrdbsdk.QuorumChallenge) []byte { return signQuorumChallenge(t, impostor, ch) },
		peer:     selfSignedCert(t, impostor, "holder-mtls"),
	}

	_, err = rig.submit(t, rig.holders["holder-mtls"], forged)
	require.Error(t, err, "a certificate whose key is not the enrolled one is refused")
	require.True(t, rig.barrier.IsSealed())

	out, err := rig.submit(t, rig.holders["holder-piv"], nil)
	require.NoError(t, err)
	require.False(t, out.Complete, "the refused holder's share was not counted")
	require.Equal(t, 1, out.Submitted)

	out, err = rig.submit(t, rig.holders["holder-token"], nil)
	require.NoError(t, err)
	require.True(t, out.Complete)
	require.False(t, rig.barrier.IsSealed())
}
