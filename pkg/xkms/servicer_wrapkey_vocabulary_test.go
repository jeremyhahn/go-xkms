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
	"crypto"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestWrapVocabulary_CanonicalAlgorithms pins every algorithm the service
// accepts, keyed on the types.KeyWrapAlgorithm constants that are the
// project's single wrap vocabulary. The expectations are read from types.*
// rather than written out, so a renamed constant fails here instead of
// silently narrowing what the wire accepts.
func TestWrapVocabulary_CanonicalAlgorithms(t *testing.T) {
	allowLegacyWrap(t)
	tests := map[types.KeyWrapAlgorithm]struct {
		kind   wrapKind
		digest crypto.Hash
	}{
		types.WrapAESKW:         {kind: kindAESKW},
		types.WrapAESKWP:        {kind: kindAESKWP},
		types.WrapAES128KWP:     {kind: kindAESKWP},
		types.WrapAES256KWP:     {kind: kindAESKWP},
		types.WrapAESGCM:        {kind: kindAESGCM},
		types.WrapRSAPKCS1v15:   {kind: kindRSAPKCS1v15},
		types.WrapRSAOAEPSHA256: {kind: kindRSAOAEP, digest: crypto.SHA256},
		types.WrapRSAOAEPSHA384: {kind: kindRSAOAEP, digest: crypto.SHA384},
		types.WrapRSAOAEPSHA512: {kind: kindRSAOAEP, digest: crypto.SHA512},
	}

	for alg, want := range tests {
		t.Run(string(alg), func(t *testing.T) {
			mech, err := resolveWrapMechanism(string(alg), "wrap")
			require.NoError(t, err, "canonical algorithm %q must be accepted", alg)
			assert.Equal(t, want.kind, mech.kind)
			assert.Equal(t, want.digest, mech.digest,
				"the digest must come from the algorithm name, not a default")
		})
	}
}

// TestWrapVocabulary_NoLegacyLowercaseNames proves the second vocabulary is
// gone rather than merely unused.
//
// The PKCS#11 module used to emit these lowercase mechanism names, which no
// other transport spoke; the service accepted only those and rejected the
// canonical names its own proto publishes, breaking wrap over gRPC and MCP.
// The module now emits canonical constants, so these must NOT be quietly
// accepted as aliases — an alias would let the old spelling creep back in and
// re-create the divergence.
func TestWrapVocabulary_NoLegacyLowercaseNames(t *testing.T) {
	for _, legacy := range []string{"aes-kw", "aes-kwp", "aes-gcm", "rsa-oaep", "rsa-pkcs", "aes-cbc"} {
		t.Run(legacy, func(t *testing.T) {
			_, err := resolveWrapMechanism(legacy, "wrap")
			require.Error(t, err, "the legacy lowercase vocabulary must be gone, not aliased")
			assert.True(t, errors.Is(err, ErrOperationNotSupported))
		})
	}
}

// TestWrapVocabulary_RejectsSHA1OAEP pins the policy, not merely the
// rejection: SHA-1 OAEP must be refused as WEAK, distinctly from an unknown
// algorithm. Reporting it as "unsupported" would send an operator looking for
// a missing feature, and silently substituting SHA-256 would return a wrong
// answer as success. This matches ResolveOAEPHash, which refuses SHA-1 for
// the same reason: OAEP has no legacy blobs to read.
func TestWrapVocabulary_RejectsSHA1OAEP(t *testing.T) {
	for _, op := range []string{"wrap", "unwrap"} {
		t.Run(op, func(t *testing.T) {
			_, err := resolveWrapMechanism(string(types.WrapRSAOAEPSHA1), op)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrWeakOAEPHash),
				"want ErrWeakOAEPHash, got %v", err)
			assert.False(t, errors.Is(err, ErrOperationNotSupported),
				"a refused-by-policy digest must not be reported as unsupported")
		})
	}
}

// TestWrapVocabulary_UnknownIsRejected proves an unrecognized name fails
// closed, naming the operation so wrap and unwrap errors stay distinguishable.
func TestWrapVocabulary_UnknownIsRejected(t *testing.T) {
	_, err := resolveWrapMechanism("not-an-algorithm", "wrap")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
	assert.Contains(t, err.Error(), "unsupported wrap algorithm")

	_, err = resolveWrapMechanism("not-an-algorithm", "unwrap")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported unwrap algorithm")
}

// TestWrapVocabulary_WrapAndUnwrapAgree proves the two directions accept
// exactly the same set. A name wrappable but not unwrappable would strand key
// material in a blob nothing can open — which a single shared table makes
// structurally impossible, and this test keeps it that way.
func TestWrapVocabulary_WrapAndUnwrapAgree(t *testing.T) {
	for alg := range wrapMechanisms {
		name := string(alg)
		wrapMech, wrapErr := resolveWrapMechanism(name, "wrap")
		unwrapMech, unwrapErr := resolveWrapMechanism(name, "unwrap")

		assert.Equal(t, wrapErr == nil, unwrapErr == nil,
			"%q must be accepted by both directions or neither", name)
		if wrapErr == nil && unwrapErr == nil {
			assert.Equal(t, wrapMech, unwrapMech,
				"%q must normalize identically in both directions", name)
		}
	}
}

// TestWrapVocabulary_EveryKindIsDispatchable proves every mechanism the table
// can produce is one the dispatch switches actually handle. A kind with no
// case would fall to the default and report a supported algorithm as
// unsupported.
func TestWrapVocabulary_EveryKindIsDispatchable(t *testing.T) {
	dispatchable := map[wrapKind]bool{
		kindAESKW:       true,
		kindAESKWP:      true,
		kindAESGCM:      true,
		kindAESCBC:      true,
		kindAESCBCPad:   true,
		kindRSAOAEP:     true,
		kindRSAPKCS1v15: true,
	}

	for alg, mech := range wrapMechanisms {
		assert.True(t, dispatchable[mech.kind],
			"algorithm %q normalizes to kind %d, which no dispatch case handles", alg, mech.kind)
	}
}
