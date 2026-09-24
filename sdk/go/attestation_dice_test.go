// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-License-Identifier: commercial

package xkms_test

import (
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time proof the DICE aliases ARE the upstream types rather than
// lookalikes, following the peer surface's pattern.
//
// A lookalike would compile, pass every test in this package, and then fail at
// the one place it matters: a consumer handing a value across the SDK boundary
// into the canonical implementation. Assignability in both directions is what
// rules that out.
var (
	_ dice.Evidence         = xkms.DICEEvidence{}
	_ xkms.DICEEvidence     = dice.Evidence{}
	_ dice.VerifyOptions    = xkms.DICEVerifyOptions{}
	_ dice.TcbInfo          = xkms.DICETcbInfo{}
	_ dice.FWID             = xkms.DICEFWID{}
	_ dice.OperationalFlags = xkms.DICEOperationalFlags{}
	_ dice.Ueid             = xkms.DICEUeid{}
	_ dice.ClaimsSet        = xkms.DICEClaimsSet{}
)

// The SDK surface must reach the real implementation, not a copy of its shape.
// This builds an extension through the SDK alias and reads it back through the
// canonical package; if the two ever diverge the round trip stops working.
func TestDICEAliasesReachTheCanonicalImplementation(t *testing.T) {
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}

	extension, err := xkms.DICECreateUccsEvidenceExtension(&xkms.DICEClaimsSet{Nonce: nonce})
	require.NoError(t, err)

	claims, err := dice.ParseUccsEvidence(extension.Value)
	require.NoError(t, err)
	assert.Equal(t, nonce, claims.Nonce)
}

// A caller reaching the SDK must be able to answer "did this device echo my
// challenge" without importing pkg/. That is the whole reason this file exists:
// go-trusted-platform's layer guard refuses a direct go-xkms/pkg import, so an
// unexposed capability is an unreachable one.
func TestDICEChallengeIsReachableFromTheSDK(t *testing.T) {
	require.NotNil(t, xkms.DICEChallenge)
	require.NotNil(t, xkms.DICEVerify)
	require.NotNil(t, xkms.DICEUccsFromCertificate)
	require.NotNil(t, xkms.DICEHasExtensions)
}

// TestDICEErrorsAreTheCanonicalSentinels is why the errors are re-exported at
// all.
//
// A consumer outside this repository cannot import pkg/attestation/dice --
// go-trusted-platform's layer guard refuses it -- so without these aliases the
// only thing it can do with a DICEVerify failure is read its text. errors.Is
// against a copy would compile and never match; these assert identity, which is
// the property that makes the whole surface usable.
func TestDICEErrorsAreTheCanonicalSentinels(t *testing.T) {
	pairs := []struct {
		name string
		sdk  error
		pkg  error
	}{
		{"nonce mismatch", xkms.ErrDICENonceMismatch, dice.ErrNonceMismatch},
		{"nonce required", xkms.ErrDICENonceRequired, dice.ErrNonceRequired},
		{"chain verification failed", xkms.ErrDICEChainVerificationFailed, dice.ErrChainVerificationFailed},
		{"unsupported key type", xkms.ErrDICEUnsupportedKeyType, dice.ErrUnsupportedKeyType},
		{"unsupported signature algorithm", xkms.ErrDICEUnsupportedSignatureAlgorithm, dice.ErrUnsupportedSignatureAlgorithm},
		{"uccs evidence not found", xkms.ErrDICEUccsEvidenceNotFound, dice.ErrUccsEvidenceNotFound},
		{"nonce claim missing", xkms.ErrDICENonceClaimMissing, dice.ErrNonceClaimMissing},
		{"operational state not permitted", xkms.ErrDICEOperationalStateNotPermitted, dice.ErrOperationalStateNotPermitted},
		{"no measurement", xkms.ErrDICENoMeasurement, dice.ErrNoMeasurement},
		{"critical evidence unreadable", xkms.ErrDICECriticalEvidenceUnreadable, dice.ErrCriticalEvidenceUnreadable},
		{"tcb info not found", xkms.ErrDICETcbInfoNotFound, dice.ErrTcbInfoNotFound},
		{"empty chain", xkms.ErrDICEEmptyChain, dice.ErrEmptyChain},
		{"nil verify options", xkms.ErrDICENilVerifyOptions, dice.ErrNilVerifyOptions},
	}

	for _, pair := range pairs {
		t.Run(pair.name, func(t *testing.T) {
			assert.Same(t, pair.pkg, pair.sdk, "the SDK re-exports a copy rather than the sentinel")
		})
	}
}

// And the property a consumer actually relies on: an error out of the SDK's own
// entry point is classifiable through the SDK's own sentinel.
func TestDICEVerifyFailureIsClassifiableThroughTheSDK(t *testing.T) {
	_, err := xkms.DICEVerify(nil, &xkms.DICEVerifyOptions{ExpectedNonce: make([]byte, 32)})
	require.Error(t, err)
	assert.ErrorIs(t, err, xkms.ErrDICEEmptyChain)

	_, err = xkms.DICEVerify([]*x509.Certificate{{}}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, xkms.ErrDICENilVerifyOptions)
}
