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

// Tests for the crypto.allow_legacy_key_wrap gate: the key-wrap constructions
// that authenticate nothing are refused unless an operator opts in.

import (
	"context"
	"crypto/rand"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// gatedAlgorithms is the set the gate covers, with the block-aligned key
// material each one can carry. AES-CBC without padding only wraps a whole
// number of blocks, which is why the sizes differ.
var gatedAlgorithms = []struct {
	algorithm types.KeyWrapAlgorithm
	material  []byte
}{
	{algorithm: types.WrapAESCBC, material: []byte("0123456789ABCDEF0123456789ABCDEF")},
	{algorithm: types.WrapAESCBCPad, material: []byte("twenty-byte-key-mat!")},
	{algorithm: types.WrapRSAPKCS1v15, material: []byte("rsa-target-key-material")},
}

// TestLegacyWrapGate_RefusedByDefault is the bad-input half: with no policy
// set -- the state a library or a daemon started from a default configuration
// is in -- every gated mechanism is refused for both wrap and unwrap, with the
// typed policy error and not with "unsupported algorithm".
//
// The distinction is the point of the separate sentinel. An operator who reads
// "unsupported" goes looking for an unimplemented mechanism and files a bug;
// this refusal is answered by a configuration setting, and the detail has to
// say which one.
func TestLegacyWrapGate_RefusedByDefault(t *testing.T) {
	types.SetAllowLegacyKeyWrap(false)

	for _, tc := range gatedAlgorithms {
		t.Run(string(tc.algorithm), func(t *testing.T) {
			for _, operation := range []string{"wrap", "unwrap"} {
				_, err := resolveWrapMechanism(string(tc.algorithm), operation)
				require.Errorf(t, err, "%s %s must be refused by default", tc.algorithm, operation)
				assert.ErrorIs(t, err, ErrLegacyWrapDisabled)
				assert.NotErrorIsf(t, err, ErrOperationNotSupported,
					"a policy refusal must not read as a missing feature")

				message := err.Error()
				assert.Containsf(t, message, string(tc.algorithm),
					"the refusal must name the mechanism the caller asked for")
				assert.Containsf(t, message, operation,
					"the refusal must say which half of the operation it refused")
				assert.Contains(t, message, "crypto.allow_legacy_key_wrap",
					"the refusal must name the setting that enables it")
			}
		})
	}
}

// TestLegacyWrapGate_RefusesAtTheServiceBoundary proves the gate is reached by
// the real wrap/unwrap entry points and not only by resolveWrapMechanism: a
// caller that hands wrapKeyMaterial or unwrapKeyMaterial a gated algorithm is
// refused before any key material is produced or any ciphertext is touched.
func TestLegacyWrapGate_RefusesAtTheServiceBoundary(t *testing.T) {
	types.SetAllowLegacyKeyWrap(false)
	ctx := context.Background()

	aesStore, aesAttrs := newAESWrappingBackend(t)
	rsaStore, rsaAttrs, _ := newRSAWrappingBackend(t)

	for _, tc := range gatedAlgorithms {
		t.Run(string(tc.algorithm), func(t *testing.T) {
			store, attrs := aesStore, aesAttrs
			if tc.algorithm == types.WrapRSAPKCS1v15 {
				store, attrs = rsaStore, rsaAttrs
			}

			wrapped, err := wrapKeyMaterial(ctx, store, attrs, string(tc.algorithm), wrapParams{}, tc.material)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrLegacyWrapDisabled)
			assert.Empty(t, wrapped, "a refused wrap must not return a blob")

			// The unwrap side is what carries the oracle, so it is checked with
			// a blob an attacker could supply: 48 random bytes, which unpadded
			// CBC would otherwise turn into 32 bytes of key material with a nil
			// error.
			blob := make([]byte, 48)
			_, err = rand.Read(blob)
			require.NoError(t, err)

			material, err := unwrapKeyMaterial(ctx, store, attrs, string(tc.algorithm), wrapParams{}, blob)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrLegacyWrapDisabled)
			assert.Empty(t, material, "a refused unwrap must not return key material")
		})
	}
}

// TestLegacyWrapGate_EnabledRoundTrips is the success half: with the policy
// enabled, every gated mechanism performs and round-trips, so the gate is a
// switch and not a removal. PKCS#11 v3.2 section 6.10 (the AES-CBC pair) and
// section 6.1 (CKM_RSA_PKCS) sanction all three, and an operator who must
// interoperate with an application that requires one has to be able to get it.
func TestLegacyWrapGate_EnabledRoundTrips(t *testing.T) {
	allowLegacyWrap(t)
	ctx := context.Background()

	aesStore, aesAttrs := newAESWrappingBackend(t)
	rsaStore, rsaAttrs, _ := newRSAWrappingBackend(t)

	for _, tc := range gatedAlgorithms {
		t.Run(string(tc.algorithm), func(t *testing.T) {
			store, attrs := aesStore, aesAttrs
			if tc.algorithm == types.WrapRSAPKCS1v15 {
				store, attrs = rsaStore, rsaAttrs
			}

			wrapped, err := wrapKeyMaterial(ctx, store, attrs, string(tc.algorithm), wrapParams{}, tc.material)
			require.NoError(t, err)
			assert.NotContains(t, string(wrapped), string(tc.material),
				"the blob must not contain the plaintext key material")

			recovered, err := unwrapKeyMaterial(ctx, store, attrs, string(tc.algorithm), wrapParams{}, wrapped)
			require.NoError(t, err)
			assert.Equal(t, tc.material, recovered)
		})
	}
}

// TestLegacyWrapGate_DoesNotWidenToWeakOAEP proves enabling the legacy gate
// cannot re-admit RSA-OAEP-SHA1 by accident.
//
// The two refusals are separate fields with separate sentinels precisely so
// that the operator-facing switch has a bounded blast radius: SHA-1 OAEP has no
// legacy blobs to read in this codebase, so no interop argument reaches it, and
// it stays refused in both states with the error that says it is weak rather
// than the error that says it is disabled.
func TestLegacyWrapGate_DoesNotWidenToWeakOAEP(t *testing.T) {
	ctx := context.Background()
	store, attrs, _ := newRSAWrappingBackend(t)

	for _, allowed := range []bool{false, true} {
		previous := types.AllowLegacyKeyWrap()
		types.SetAllowLegacyKeyWrap(allowed)

		_, wrapErr := wrapKeyMaterial(ctx, store, attrs, string(types.WrapRSAOAEPSHA1), wrapParams{}, []byte("key-material"))
		_, unwrapErr := unwrapKeyMaterial(ctx, store, attrs, string(types.WrapRSAOAEPSHA1), wrapParams{}, make([]byte, 256))

		types.SetAllowLegacyKeyWrap(previous)

		for name, err := range map[string]error{"wrap": wrapErr, "unwrap": unwrapErr} {
			require.Errorf(t, err, "RSA-OAEP-SHA1 %s with allow_legacy_key_wrap=%t", name, allowed)
			assert.ErrorIsf(t, err, ErrWeakOAEPHash,
				"RSA-OAEP-SHA1 %s must stay refused as weak with allow_legacy_key_wrap=%t", name, allowed)
			assert.NotErrorIs(t, err, ErrLegacyWrapDisabled)
		}

		assert.Falsef(t, types.IsLegacyKeyWrapAlgorithm(types.WrapRSAOAEPSHA1),
			"RSA-OAEP-SHA1 must not be part of the gated set")
	}
}

// TestLegacyWrapGate_LeavesAuthenticatedMechanismsAlone proves the gate is
// scoped to the constructions that authenticate nothing: the AEAD and key-wrap
// mechanisms work with the policy off, which is the state every default
// deployment runs in.
//
// Without this, a gate that accidentally refused everything would still pass
// the refusal tests above.
func TestLegacyWrapGate_LeavesAuthenticatedMechanismsAlone(t *testing.T) {
	types.SetAllowLegacyKeyWrap(false)
	ctx := context.Background()

	store, attrs := newAESWrappingBackend(t)
	target := []byte("0123456789ABCDEF")

	for _, algorithm := range []types.KeyWrapAlgorithm{types.WrapAESKW, types.WrapAESKWP, types.WrapAESGCM} {
		t.Run(string(algorithm), func(t *testing.T) {
			assert.Falsef(t, types.IsLegacyKeyWrapAlgorithm(algorithm),
				"%s authenticates its blob and must not be gated", algorithm)

			wrapped, err := wrapKeyMaterial(ctx, store, attrs, string(algorithm), wrapParams{}, target)
			require.NoError(t, err)
			recovered, err := unwrapKeyMaterial(ctx, store, attrs, string(algorithm), wrapParams{}, wrapped)
			require.NoError(t, err)
			assert.Equal(t, target, recovered)
		})
	}

	rsaStore, rsaAttrs, _ := newRSAWrappingBackend(t)
	for _, algorithm := range []types.KeyWrapAlgorithm{types.WrapRSAOAEPSHA256, types.WrapRSAOAEPSHA384, types.WrapRSAOAEPSHA512} {
		t.Run(string(algorithm), func(t *testing.T) {
			assert.False(t, types.IsLegacyKeyWrapAlgorithm(algorithm))

			wrapped, err := wrapKeyMaterial(ctx, rsaStore, rsaAttrs, string(algorithm), wrapParams{}, target)
			require.NoError(t, err)
			recovered, err := unwrapKeyMaterial(ctx, rsaStore, rsaAttrs, string(algorithm), wrapParams{}, wrapped)
			require.NoError(t, err)
			assert.Equal(t, target, recovered)
		})
	}
}

// TestLegacyWrapGate_ClosesTheKeyInjectionPrimitive is the measurement this
// gate was built for, kept as a regression.
//
// With the policy enabled, a random 48-byte blob unwraps under unpadded
// CKM_AES_CBC into 32 bytes of key material with a nil error -- no search, no
// padding to satisfy, first try. UnwrapKeyByID imports whatever comes back as a
// usable key, so that is a key-injection primitive and, for an exportable
// target, a plain decryption oracle on the wrapping key. With the policy off it
// is refused, which is the whole difference the gate makes.
//
// The assertion is deliberately on the injection itself rather than on an error
// string: if unpadded CBC ever stops accepting arbitrary input, this test fails
// and the reasoning behind the gate has to be revisited rather than assumed.
func TestLegacyWrapGate_ClosesTheKeyInjectionPrimitive(t *testing.T) {
	ctx := context.Background()
	store, attrs := newAESWrappingBackend(t)

	blob := make([]byte, 48)
	_, err := rand.Read(blob)
	require.NoError(t, err)

	types.SetAllowLegacyKeyWrap(false)
	injected, err := unwrapKeyMaterial(ctx, store, attrs, string(types.WrapAESCBC), wrapParams{}, blob)
	require.Error(t, err, "unpadded CBC must not turn attacker-supplied bytes into a key by default")
	assert.ErrorIs(t, err, ErrLegacyWrapDisabled)
	assert.Empty(t, injected)

	allowLegacyWrap(t)
	injected, err = unwrapKeyMaterial(ctx, store, attrs, string(types.WrapAESCBC), wrapParams{}, blob)
	require.NoError(t, err, "with the policy enabled the mechanism is performed as PKCS#11 v3.2 section 6.10 describes")
	assert.Len(t, injected, 32,
		"an unwrap success here is decryption, not authentication: the caller chose the ciphertext")
}

// TestLegacyWrapGate_PaddingOracleIsMeasurable is the CKM_AES_CBC_PAD
// counterpart: with the policy enabled, random blobs are accepted at roughly
// the 1-in-256 rate a PKCS#7 last-byte check predicts, which is the Vaudenay
// oracle's answer bit. With the policy off, none of them is accepted for that
// reason -- every one is refused by policy before any ciphertext is examined.
//
// The loop is bounded and runs entirely in memory over a software AES key, so
// it is a fast arithmetic check rather than a search.
//
// The sample size is chosen against the false-failure rate, not the run time:
// at 1 in 256 the chance that NO blob of n is accepted is (255/256)^n, which
// is 4e-4 for 2,000 blobs — once in a few thousand CI jobs, and this test runs
// in three jobs per pull request — and 1e-14 for 8,192, which is never. A
// clean run at 2,000 proved nothing about the rate that a lucky run does not.
func TestLegacyWrapGate_PaddingOracleIsMeasurable(t *testing.T) {
	ctx := context.Background()
	store, attrs := newAESWrappingBackend(t)

	const attempts = 8192
	blobs := make([][]byte, attempts)
	for i := range blobs {
		blobs[i] = make([]byte, 48)
		_, err := rand.Read(blobs[i])
		require.NoError(t, err)
	}

	types.SetAllowLegacyKeyWrap(false)
	for i, blob := range blobs {
		_, err := unwrapKeyMaterial(ctx, store, attrs, string(types.WrapAESCBCPad), wrapParams{}, blob)
		require.Errorf(t, err, "blob %d was accepted while the mechanism is disabled", i)
		require.ErrorIs(t, err, ErrLegacyWrapDisabled)
	}

	allowLegacyWrap(t)
	accepted := 0
	for _, blob := range blobs {
		if _, err := unwrapKeyMaterial(ctx, store, attrs, string(types.WrapAESCBCPad), wrapParams{}, blob); err == nil {
			accepted++
		}
	}
	assert.Positivef(t, accepted,
		"%d random blobs produced no accepted padding; the ~1-in-256 rate this gate is justified by "+
			"no longer holds, so revisit the reasoning rather than the number", attempts)
}

// TestLegacyWrapGate_ReasonsAreOperatorReadable proves every gated mechanism
// carries a reason, and that the reason reaches the refusal an operator sees.
// A gate whose message does not say why is a gate that gets turned on without
// the decision being made.
func TestLegacyWrapGate_ReasonsAreOperatorReadable(t *testing.T) {
	types.SetAllowLegacyKeyWrap(false)

	for _, tc := range gatedAlgorithms {
		t.Run(string(tc.algorithm), func(t *testing.T) {
			reason, gated := types.LegacyKeyWrapReason(tc.algorithm)
			require.True(t, gated)
			require.NotEmpty(t, reason)

			_, err := resolveWrapMechanism(string(tc.algorithm), "unwrap")
			require.Error(t, err)
			assert.Contains(t, err.Error(), reason,
				"the refusal must carry the reason types records for the mechanism")
		})
	}

	reason, gated := types.LegacyKeyWrapReason(types.WrapAESGCM)
	assert.False(t, gated, "an authenticated mechanism has no gate reason")
	assert.Empty(t, reason)
}

// defaultPolicyProbeEnv puts the test binary into the child role of
// TestLegacyWrapGate_PolicyDefaultsToRefused.
const defaultPolicyProbeEnv = "XKMS_LEGACY_WRAP_DEFAULT_PROBE"

// TestLegacyWrapGate_PolicyDefaultsToRefused proves the process-wide default is
// the safe one: a library that embeds this package and never touches the
// setting refuses the unauthenticated constructions. Only the composition root
// (pkg/server) sets it, from configuration.
//
// A default is a property of a process that has not been configured, so it
// cannot be observed from a test that shares its process with the twelve other
// tests in this file -- several of which call SetAllowLegacyKeyWrap. Calling
// the setter first and then reading the accessor back, which is what this test
// used to do, only proves the setter works: it passes unchanged if the
// declaration in pkg/types is flipped to initialise true.
//
// So the assertion is made in a second process. The child re-executes this same
// test binary with only this test selected, reaches the branch below, and reads
// the accessor before anything in the process has written to it. That is the
// guarantee stated above, tested as stated.
func TestLegacyWrapGate_PolicyDefaultsToRefused(t *testing.T) {
	if os.Getenv(defaultPolicyProbeEnv) == "1" {
		// Child role. Nothing in this process has called
		// SetAllowLegacyKeyWrap -- the sole production caller is
		// pkg/server, which pkg/xkms does not import -- so what the
		// accessor reports here is the package default itself.
		if types.AllowLegacyKeyWrap() {
			t.Fatal("the untouched process-wide default admits the unauthenticated key-wrap constructions; it must refuse them")
		}
		// And the default must actually reach the decision, not merely be
		// readable: every gated mechanism is refused before any test has
		// configured anything.
		for _, tc := range gatedAlgorithms {
			if _, err := resolveWrapMechanism(string(tc.algorithm), "unwrap"); err == nil {
				t.Fatalf("%s is performed by an unconfigured process", tc.algorithm)
			}
		}
		return
	}

	binary, err := os.Executable()
	require.NoError(t, err, "the test binary must be locatable to re-execute it")

	probe := exec.Command(binary, "-test.run=^"+t.Name()+"$", "-test.count=1")
	probe.Env = append(os.Environ(), defaultPolicyProbeEnv+"=1")
	output, err := probe.CombinedOutput()
	require.NoError(t, err, "the unconfigured child process must refuse the gated mechanisms:\n%s", output)
}

// TestLegacyWrapGate_NamesAreCompleteAndSorted covers the operator-facing list
// of gated mechanisms, which diagnostics and refusal messages render.
func TestLegacyWrapGate_NamesAreCompleteAndSorted(t *testing.T) {
	names := types.LegacyKeyWrapNames()
	require.Len(t, names, 3)
	assert.Equal(t, []string{
		string(types.WrapAESCBC),
		string(types.WrapAESCBCPad),
		string(types.WrapRSAPKCS1v15),
	}, names, "the operator-facing list is sorted and complete")
	assert.NotContains(t, strings.Join(names, ","), string(types.WrapRSAOAEPSHA1))
}
