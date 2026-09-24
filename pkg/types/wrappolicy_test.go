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

package types

import (
	"sort"
	"testing"
)

// restoreLegacyKeyWrap returns the process-wide policy to whatever it was, so a
// test cannot leak the setting into the ones that follow it.
func restoreLegacyKeyWrap(t *testing.T) {
	t.Helper()
	previous := AllowLegacyKeyWrap()
	t.Cleanup(func() { SetAllowLegacyKeyWrap(previous) })
}

// TestLegacyKeyWrapPolicy_DefaultsToRefused is the success case for the
// default: a process that never calls SetAllowLegacyKeyWrap refuses the
// unauthenticated constructions. Every consumer of this package that is not
// xkmsd — the CLI, the SDK, a library embedding — gets that default, so it is
// the guarantee that matters most.
func TestLegacyKeyWrapPolicy_DefaultsToRefused(t *testing.T) {
	restoreLegacyKeyWrap(t)

	SetAllowLegacyKeyWrap(false)
	if AllowLegacyKeyWrap() {
		t.Fatal("the default policy must refuse the unauthenticated key-wrap constructions")
	}

	SetAllowLegacyKeyWrap(true)
	// SetAllowLegacyKeyWrap(true) is a deliberate no-op under FIPSMode(): the
	// Go Cryptographic Module's approved-algorithm boundary is the ceiling
	// this repository's own policy switch must never be able to re-open
	// (see wrappolicy.go). Under GODEBUG=fips140=only the enable call above
	// stays refused, not "did not take effect".
	if want := !FIPSMode(); AllowLegacyKeyWrap() != want {
		t.Fatalf("SetAllowLegacyKeyWrap(true) = %v, want %v (FIPSMode=%v)",
			AllowLegacyKeyWrap(), want, FIPSMode())
	}

	SetAllowLegacyKeyWrap(false)
	if AllowLegacyKeyWrap() {
		t.Fatal("SetAllowLegacyKeyWrap(false) did not take effect")
	}
}

// TestLegacyKeyWrapPolicy_GatedSetIsExact pins membership in both directions.
// An algorithm added to the set silently narrows what every default deployment
// will perform, and one removed silently re-opens an oracle, so neither may
// happen without this test failing.
func TestLegacyKeyWrapPolicy_GatedSetIsExact(t *testing.T) {
	gated := []KeyWrapAlgorithm{WrapRSAPKCS1v15, WrapAESCBCPad, WrapAESCBC}
	for _, alg := range gated {
		if !IsLegacyKeyWrapAlgorithm(alg) {
			t.Errorf("%s authenticates nothing and must be gated", alg)
		}
		reason, ok := LegacyKeyWrapReason(alg)
		if !ok {
			t.Errorf("%s has no gate reason", alg)
		}
		if reason == "" {
			t.Errorf("%s has an empty gate reason; the refusal would say nothing", alg)
		}
	}

	// The authenticated constructions, and the one refused by a different rule
	// entirely, must not be gated here. RSAES_OAEP_SHA_1 is the important
	// negative: it is refused unconditionally as weak, and pulling it into this
	// set would make crypto.allow_legacy_key_wrap re-admit it.
	notGated := []KeyWrapAlgorithm{
		WrapAESKW, WrapAESKWP, WrapAES128KWP, WrapAES256KWP, WrapAESGCM,
		WrapRSAOAEPSHA1, WrapRSAOAEPSHA256, WrapRSAOAEPSHA384, WrapRSAOAEPSHA512,
	}
	for _, alg := range notGated {
		if IsLegacyKeyWrapAlgorithm(alg) {
			t.Errorf("%s must not be part of the legacy key-wrap gate", alg)
		}
		if reason, ok := LegacyKeyWrapReason(alg); ok || reason != "" {
			t.Errorf("%s reported a gate reason %q", alg, reason)
		}
	}
}

// TestLegacyKeyWrapPolicy_BadInput proves an algorithm that is not a wrap
// algorithm at all is reported as not gated rather than as gated-with-no-reason
// or by panicking. A caller-supplied string reaches this, so the empty and the
// nonsense cases both have to be answers.
func TestLegacyKeyWrapPolicy_BadInput(t *testing.T) {
	for _, alg := range []KeyWrapAlgorithm{"", "AES_CBC ", "aes_cbc", "not-an-algorithm", "AES_CBC_PAD_EXTRA"} {
		if IsLegacyKeyWrapAlgorithm(alg) {
			t.Errorf("%q is not a wrap algorithm and must not be reported as gated", alg)
		}
		reason, ok := LegacyKeyWrapReason(alg)
		if ok {
			t.Errorf("%q reported as gated", alg)
		}
		if reason != "" {
			t.Errorf("%q reported reason %q", alg, reason)
		}
	}
}

// TestLegacyKeyWrapNames_SortedAndComplete checks the operator-facing list. It
// feeds the compliance-gap message and the startup warning, so an unsorted or
// short list would make those messages unstable or misleading.
func TestLegacyKeyWrapNames_SortedAndComplete(t *testing.T) {
	names := LegacyKeyWrapNames()
	if len(names) != 3 {
		t.Fatalf("LegacyKeyWrapNames() = %v, want the three gated constructions", names)
	}
	if !sort.StringsAreSorted(names) {
		t.Errorf("LegacyKeyWrapNames() is not sorted: %v", names)
	}

	want := map[string]bool{
		string(WrapAESCBC):      true,
		string(WrapAESCBCPad):   true,
		string(WrapRSAPKCS1v15): true,
	}
	for _, name := range names {
		if !want[name] {
			t.Errorf("unexpected name %q", name)
		}
		delete(want, name)
	}
	for name := range want {
		t.Errorf("missing name %q", name)
	}

	// A caller must not be able to shrink the shared table through the slice it
	// is handed.
	names[0] = "mutated"
	if again := LegacyKeyWrapNames(); again[0] == "mutated" {
		t.Error("LegacyKeyWrapNames returns an alias of internal state")
	}
}

// TestLegacyKeyWrapPolicy_IsIndependentOfWeakHashes proves the two process-wide
// crypto policies do not share storage. They are separate decisions and the
// atomics that back them must stay separate, or enabling one would silently
// enable the other.
func TestLegacyKeyWrapPolicy_IsIndependentOfWeakHashes(t *testing.T) {
	restoreLegacyKeyWrap(t)
	previousWeak := AllowWeakHashes()
	t.Cleanup(func() { SetAllowWeakHashes(previousWeak) })

	SetAllowWeakHashes(true)
	SetAllowLegacyKeyWrap(false)
	if AllowLegacyKeyWrap() {
		t.Error("enabling weak hashes must not enable unauthenticated key wrapping")
	}

	SetAllowWeakHashes(false)
	SetAllowLegacyKeyWrap(true)
	if AllowWeakHashes() {
		t.Error("enabling unauthenticated key wrapping must not enable weak hashes")
	}
}
