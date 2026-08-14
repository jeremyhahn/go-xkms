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

package xkms

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ecdhSharedSecret is a fixed stand-in for the ECDH shared secret so every
// derivation below is deterministic and the derived bytes are a function of the
// KDF parameters alone.
var ecdhSharedSecret = []byte("fixed-ecdh-shared-secret-32bytes")

// derivingAgreementProvider is a types.KeyAgreementProvider that runs the KDF
// parameters it is handed against a fixed shared secret. It records the
// parameters as well, so a test can assert both what reached the KDF and what
// the KDF produced from it — recording alone would not prove the label is
// actually bound into the derivation.
type derivingAgreementProvider struct {
	*boostIEKeyProvider
	seenKDF *types.KDFParams
}

func newDerivingAgreementProvider() *derivingAgreementProvider {
	return &derivingAgreementProvider{boostIEKeyProvider: newBoostIEKeyProvider()}
}

func (p *derivingAgreementProvider) DeriveKeyECDH(_ context.Context, _ *types.KeyAttributes, _ []byte, params *types.KDFParams) ([]byte, error) {
	p.seenKDF = params
	return params.Derive(ecdhSharedSecret)
}

func (p *derivingAgreementProvider) SupportedCurves() []string {
	return []string{"P-256", "P-384"}
}

// setupECDHService wires one deriving ECDH backend named "hsm" and returns the
// service together with the provider so tests can inspect what reached the KDF.
func setupECDHService(t *testing.T) (*XKMSService, *derivingAgreementProvider) {
	t.Helper()
	provider := newDerivingAgreementProvider()
	stores := setupKeyOpsService(t, map[string]types.KeyProvider{"hsm": provider})
	addKeyOpsKey(t, stores["hsm"], &types.KeyAttributes{CN: "ecdh-key", KeyAlgorithm: x509.ECDSA})
	return keyOpsService(t), provider
}

func ecdhRequest() *transport.DeriveKeyECDHRequest {
	return &transport.DeriveKeyECDHRequest{
		KeyID:         "ecdh-key",
		Backend:       "hsm",
		PeerPublicKey: []byte("peer-public-key"),
		KDFAlgorithm:  "SP800-108-COUNTER",
		KDFHash:       "SHA-256",
		KDFInfo:       []byte("shared-context"),
		KeyLength:     32,
	}
}

// TestDeriveKeyECDH_LabelReachesTheKDF proves the SP 800-108 Label supplied on
// the wire is bound into the derivation rather than dropped on the way down.
func TestDeriveKeyECDH_LabelReachesTheKDF(t *testing.T) {
	svc, provider := setupECDHService(t)

	req := ecdhRequest()
	req.KDFLabel = []byte("tls-exporter")

	resp, err := svc.DeriveKeyECDH(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	require.NotNil(t, provider.seenKDF)
	assert.Equal(t, []byte("tls-exporter"), provider.seenKDF.Label,
		"the caller's label must reach the KDF")
	assert.Equal(t, []byte("shared-context"), provider.seenKDF.Context)

	// And it must be bound into the output, not merely carried alongside it.
	want, err := (&types.KDFParams{
		Algorithm: types.KDFAlgorithmSP800108Counter,
		Hash:      "SHA-256",
		Label:     []byte("tls-exporter"),
		Context:   []byte("shared-context"),
		KeyLength: 32,
	}).Derive(ecdhSharedSecret)
	require.NoError(t, err)
	assert.Equal(t, want, resp.DerivedKey)
}

// TestDeriveKeyECDH_LabelProvidesDomainSeparation is the point of the field.
// Two protocols deriving from the same shared secret with the same context must
// get different keys when they use different labels; without a label field on
// the wire they got the same key, which is what SP 800-108r1 §4 binds the label
// to prevent.
func TestDeriveKeyECDH_LabelProvidesDomainSeparation(t *testing.T) {
	svc, _ := setupECDHService(t)
	ctx := context.Background()

	for _, algorithm := range []string{"SP800-108-COUNTER", "SP800-108-FEEDBACK"} {
		t.Run(algorithm, func(t *testing.T) {
			first := ecdhRequest()
			first.KDFAlgorithm = algorithm
			first.KDFLabel = []byte("protocol-a")

			second := ecdhRequest()
			second.KDFAlgorithm = algorithm
			second.KDFLabel = []byte("protocol-b")

			respA, err := svc.DeriveKeyECDH(ctx, first)
			require.NoError(t, err)
			respB, err := svc.DeriveKeyECDH(ctx, second)
			require.NoError(t, err)

			assert.NotEqual(t, respA.DerivedKey, respB.DerivedKey,
				"derivations differing only by label must produce different keys")

			// Same label, same everything else: still deterministic.
			respARepeat, err := svc.DeriveKeyECDH(ctx, first)
			require.NoError(t, err)
			assert.Equal(t, respA.DerivedKey, respARepeat.DerivedKey)
		})
	}
}

// TestDeriveKeyECDH_AbsentLabelIsUnchanged pins the compatibility guarantee: a
// request that omits the label must derive exactly the bytes it derived before
// the field existed.
//
// It is asserted twice over. First against an independent types.KDFParams
// derivation carrying no label, which is by construction what the request
// assembled before the field existed. Second against hex constants, so a later
// edit to the parameter assembly cannot move these bytes without failing here.
func TestDeriveKeyECDH_AbsentLabelIsUnchanged(t *testing.T) {
	svc, provider := setupECDHService(t)
	ctx := context.Background()

	golden := map[string]string{
		"HKDF":               "ab3c520a3c2af6be3bca6197200e084c62f0ab310b3cb499b88b8f405196a135",
		"SP800-108-COUNTER":  "575ccf15320e43089258d904470dd2bf32f78cf6dfb912a4a26f2f785dc3fc6c",
		"SP800-108-FEEDBACK": "575ccf15320e43089258d904470dd2bf32f78cf6dfb912a4a26f2f785dc3fc6c",
		"X963":               "1cf6bc5fe32515989143378f5ad5377a60fe9e0ed5e73aea6ab84d2b0a060fd3",
		"SP800-56A":          "4a2c56a0c9ae7bd08c08e4fae269fe9f5b60f1bf365b11033093d6c8e2d15e55",
	}

	for algorithm, want := range golden {
		t.Run(algorithm, func(t *testing.T) {
			req := ecdhRequest()
			req.KDFAlgorithm = algorithm

			resp, err := svc.DeriveKeyECDH(ctx, req)
			require.NoError(t, err)

			// No label was sent, so none may be invented on the way down.
			require.NotNil(t, provider.seenKDF)
			assert.Empty(t, provider.seenKDF.Label, "an absent label must stay absent")

			// The bytes must equal what the same parameters produce without a
			// label, which is what this request derived before the field
			// existed.
			wantHex := want
			want, deriveErr := (&types.KDFParams{
				Algorithm: types.KDFAlgorithm(algorithm),
				Hash:      "SHA-256",
				Salt:      provider.seenKDF.Salt,
				Info:      provider.seenKDF.Info,
				Context:   provider.seenKDF.Context,
				IV:        provider.seenKDF.IV,
				KeyLength: 32,
			}).Derive(ecdhSharedSecret)
			require.NoError(t, deriveErr)
			assert.Equal(t, want, resp.DerivedKey)

			// And it must equal the constant captured from the implementation,
			// so a later edit to the parameter assembly cannot move these bytes
			// without failing here.
			assert.Equal(t, wantHex, hex.EncodeToString(resp.DerivedKey))
		})
	}
}

// TestDeriveKeyECDH_LabelRejectedWhereItHasNoInput asserts the label is refused
// rather than dropped by the constructions that have no label: HKDF and the two
// concatenation KDFs. Accepting and ignoring it would tell a caller it had
// domain separation when it had none.
func TestDeriveKeyECDH_LabelRejectedWhereItHasNoInput(t *testing.T) {
	svc, _ := setupECDHService(t)
	ctx := context.Background()

	for _, algorithm := range []string{"HKDF", "X963", "SP800-56A"} {
		t.Run(algorithm, func(t *testing.T) {
			req := ecdhRequest()
			req.KDFAlgorithm = algorithm
			req.KDFLabel = []byte("no-home-here")

			resp, err := svc.DeriveKeyECDH(ctx, req)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
			assert.Contains(t, err.Error(), "kdf_label is not an input to")
			assert.Nil(t, resp)
		})
	}
}

// TestDeriveKeyECDH_UnknownKDFAlgorithmIsRefused is the ECDH-path guard for the
// silent HKDF fallback: an unrecognized KDF name must not be answered with HKDF
// keying material and a success response.
func TestDeriveKeyECDH_UnknownKDFAlgorithmIsRefused(t *testing.T) {
	svc, provider := setupECDHService(t)
	ctx := context.Background()

	for _, algorithm := range []string{"SP800-108-COUNTR", "HKDF2", "not-a-kdf"} {
		t.Run(algorithm, func(t *testing.T) {
			req := ecdhRequest()
			req.KDFAlgorithm = algorithm

			resp, err := svc.DeriveKeyECDH(ctx, req)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidKDFAlgorithm)
			assert.Nil(t, resp)
			assert.Nil(t, provider.seenKDF, "a refused algorithm must not reach the KDF")
		})
	}

	// The empty name still selects the documented HKDF default.
	req := ecdhRequest()
	req.KDFAlgorithm = ""
	req.KDFInfo = nil
	resp, err := svc.DeriveKeyECDH(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, provider.seenKDF)
	assert.Equal(t, types.KDFAlgorithmHKDF, provider.seenKDF.Algorithm)
}
