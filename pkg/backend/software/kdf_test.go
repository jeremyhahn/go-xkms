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

package software

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

// Convergence anchors. These literals are duplicated verbatim in the KDF
// tests of pkg/types, pkg/backend/tpm2, pkg/backend/pkcs11, and
// pkg/backend/phone. Four independently asserted copies are the point: they
// prove the backends share one KDF implementation rather than four that
// happen to be close. Their correctness is established by the NIST CAVP
// vectors in pkg/crypto/kdf/sp800108_test.go.
//
// Inputs: sharedSecret = 32 bytes of 0x42, Label = "xkms-convergence",
// Context = "backend-parity", SHA-256, 64-byte output. The length spans two
// SHA-256 PRF blocks so counter mode and feedback mode diverge.
const (
	convergenceLabel     = "xkms-convergence"
	convergenceContext   = "backend-parity"
	convergenceKeyLength = 64

	convergenceSP800108Counter = "b2b1c48c1f3282fe4be0e659653963733359b841e176e7bd39dac36bc31a7a37" +
		"79bc86106be0de29d2a74eb0b87ba4a0e2de5da0150c7e2a2c56c3a957e7e855"

	convergenceSP800108Feedback = "b2b1c48c1f3282fe4be0e659653963733359b841e176e7bd39dac36bc31a7a37" +
		"08ef3fb21ccf13af443722edfd6a91bc9c0b7286da80d4b269ee2156590d0706"
)

func convergenceSecret() []byte {
	return bytes.Repeat([]byte{0x42}, 32)
}

func convergenceParams(algorithm types.KDFAlgorithm) *types.KDFParams {
	return &types.KDFParams{
		Algorithm: algorithm,
		Hash:      "SHA-256",
		KeyLength: convergenceKeyLength,
		Label:     []byte(convergenceLabel),
		Context:   []byte(convergenceContext),
	}
}

// newSoftwareBackendForKDF builds a software backend for the KDF tests. The
// KDF path touches no key storage, but applyKDF is a method so a backend
// instance is needed to reach it.
func newSoftwareBackendForKDF(t *testing.T) *SoftwareBackend {
	t.Helper()

	b, err := NewBackend(&Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })

	return b.(*SoftwareBackend)
}

// TestApplyKDF_SP800108ConvergesWithOtherBackends asserts the software backend
// derives the same bytes as every other backend for the same inputs.
func TestApplyKDF_SP800108ConvergesWithOtherBackends(t *testing.T) {
	sb := newSoftwareBackendForKDF(t)

	for _, tc := range []struct {
		algorithm types.KDFAlgorithm
		want      string
	}{
		{types.KDFAlgorithmSP800108Counter, convergenceSP800108Counter},
		{types.KDFAlgorithmSP800108Feedback, convergenceSP800108Feedback},
	} {
		t.Run(tc.algorithm.String(), func(t *testing.T) {
			key, err := sb.applyKDF(convergenceSecret(), convergenceParams(tc.algorithm))
			require.NoError(t, err)

			want, err := hex.DecodeString(tc.want)
			require.NoError(t, err)
			assert.Equal(t, want, key, "backend diverged from the canonical KDF")
		})
	}
}

// TestApplyKDF_SP800108IsNotHKDF is the regression that catches a return to
// deriving these algorithm labels with HKDF.
func TestApplyKDF_SP800108IsNotHKDF(t *testing.T) {
	sb := newSoftwareBackendForKDF(t)
	secret := convergenceSecret()

	bareHKDF := make([]byte, convergenceKeyLength)
	_, err := io.ReadFull(hkdf.New(sha256.New, secret, nil, nil), bareHKDF)
	require.NoError(t, err)

	for _, algorithm := range []types.KDFAlgorithm{types.KDFAlgorithmSP800108Counter, types.KDFAlgorithmSP800108Feedback} {
		t.Run(algorithm.String(), func(t *testing.T) {
			key, err := sb.applyKDF(secret, convergenceParams(algorithm))
			require.NoError(t, err)
			assert.NotEqual(t, bareHKDF, key, "the SP 800-108 construction has regressed to HKDF")
		})
	}
}

// TestApplyKDF_LabelAndContextReachTheKDF proves the backend forwards the
// caller's SP 800-108 inputs rather than dropping them.
func TestApplyKDF_LabelAndContextReachTheKDF(t *testing.T) {
	sb := newSoftwareBackendForKDF(t)
	secret := convergenceSecret()

	reference, err := sb.applyKDF(secret, convergenceParams(types.KDFAlgorithmSP800108Counter))
	require.NoError(t, err)

	changedLabel := convergenceParams(types.KDFAlgorithmSP800108Counter)
	changedLabel.Label = []byte("a different label")
	key, err := sb.applyKDF(secret, changedLabel)
	require.NoError(t, err)
	assert.NotEqual(t, reference, key, "changing Label did not change the derived key")

	changedContext := convergenceParams(types.KDFAlgorithmSP800108Counter)
	changedContext.Context = []byte("a different context")
	key, err = sb.applyKDF(secret, changedContext)
	require.NoError(t, err)
	assert.NotEqual(t, reference, key, "changing Context did not change the derived key")
}

// TestApplyKDF_RejectsInapplicableParameters proves a parameter the selected
// algorithm does not consume is rejected rather than silently dropped.
func TestApplyKDF_RejectsInapplicableParameters(t *testing.T) {
	sb := newSoftwareBackendForKDF(t)

	cases := []struct {
		name   string
		params *types.KDFParams
	}{
		{"SP800-108 with HKDF salt", &types.KDFParams{Algorithm: types.KDFAlgorithmSP800108Counter, Hash: "SHA-256", KeyLength: 32, Salt: []byte("salt")}},
		{"SP800-108 with HKDF info", &types.KDFParams{Algorithm: types.KDFAlgorithmSP800108Counter, Hash: "SHA-256", KeyLength: 32, Info: []byte("info")}},
		{"HKDF with an SP800-108 label", &types.KDFParams{Algorithm: types.KDFAlgorithmHKDF, Hash: "SHA-256", KeyLength: 32, Label: []byte("label")}},
		{"counter mode with a feedback IV", &types.KDFParams{Algorithm: types.KDFAlgorithmSP800108Counter, Hash: "SHA-256", KeyLength: 32, IV: []byte("iv")}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sb.applyKDF(convergenceSecret(), tc.params)
			assert.ErrorIs(t, err, types.ErrKDFParamNotApplicable)
		})
	}
}

// TestApplyKDF_OutputLengths covers requested lengths that do and do not span
// the PRF block boundary.
func TestApplyKDF_OutputLengths(t *testing.T) {
	sb := newSoftwareBackendForKDF(t)

	for _, algorithm := range []types.KDFAlgorithm{
		types.KDFAlgorithmSP800108Counter,
		types.KDFAlgorithmSP800108Feedback,
		types.KDFAlgorithmX963,
		types.KDFAlgorithmSP80056A,
	} {
		t.Run(algorithm.String(), func(t *testing.T) {
			for _, length := range []int{1, 31, 32, 33, 64, 65} {
				params := convergenceParams(algorithm)
				params.KeyLength = length
				if algorithm == types.KDFAlgorithmX963 || algorithm == types.KDFAlgorithmSP80056A {
					params.Label = nil
					params.Context = nil
					params.Info = []byte("shared-info")
				}
				key, err := sb.applyKDF(convergenceSecret(), params)
				require.NoErrorf(t, err, "length %d", length)
				assert.Lenf(t, key, length, "length %d", length)
			}
		})
	}
}
