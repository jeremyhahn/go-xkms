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

package module

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"golang.org/x/crypto/argon2"
)

// testArgonMemoryKiB is the Argon2id memory cost the test binary uses.
//
// The suite performs roughly 1400 derivations and asserts nothing about their
// COST -- only that verifiers round-trip, that two derivations of the same PIN
// differ, and that the admission gate bounds concurrency. None of that depends
// on the memory parameter, so paying the production 64 MiB per derivation buys
// the suite nothing and costs the Race Detector job most of its runtime.
//
// 8 MiB rather than the minimum: it still exercises multi-lane Argon2id with a
// real working set, so the code path under test stays representative. Measured
// on a development workstation: 24.1 ms per derivation at 64 MiB, 3.7 ms at
// 8 MiB -- 6.5x, before the race detector's own multiplier on memory-heavy
// work.
const testArgonMemoryKiB = 8 * 1024

// TestMain lowers the cost once for the whole binary rather than per test.
// Per-test opt-in would leave the default in place wherever someone forgot,
// which is most of the ~1400 derivations.
//
// It checks the SHIPPED default first, because it is the only code here that
// can: it runs before any test and is the thing that destroys the evidence.
// Asserting the constant is not the same guarantee -- lowering the variable's
// initializer while leaving the constant at 64 MiB would weaken every shipped
// derivation, and no ordinary test could tell, because by the time one runs
// this function has already overwritten the value.
func TestMain(m *testing.M) {
	if argonMemoryKiB != pinArgonMemory {
		fmt.Fprintf(os.Stderr,
			"argonMemoryKiB defaults to %d KiB, want %d (pinArgonMemory): a shipped "+
				"binary would derive PIN verifiers at this cost, and lowering it "+
				"silently weakens resistance to offline attack on a stolen verifier\n",
			argonMemoryKiB, pinArgonMemory)
		os.Exit(1)
	}

	argonMemoryKiB = testArgonMemoryKiB
	os.Exit(m.Run())
}

// withProductionPINHashCost restores the shipped Argon2id cost for one test.
//
// The binary runs at the cheap cost throughout (see TestMain), which is the
// point of #18 -- roughly 1400 derivations at 64 MiB is what made the Race
// Detector the longest job in CI. But "most tests" is not "all tests": with
// every derivation at 8 MiB, nothing executed the configuration a shipped
// binary actually uses, so a break in the production wiring would have been
// invisible. One test at the real cost costs ~24 ms and closes that.
func withProductionPINHashCost(t *testing.T) {
	t.Helper()

	original := argonMemoryKiB
	t.Cleanup(func() { argonMemoryKiB = original })
	argonMemoryKiB = pinArgonMemory
}

// The shipped derivation path, executed at the shipped settings.
//
// The constant assertions below detect VALUE drift and nothing else: they
// would still pass if derivePinKey stopped passing those constants to Argon2
// at all. This runs the real function at the production cost and compares it
// against argon2.IDKey called with the parameters written out as LITERALS --
// not read back from the same constants, which would make the test agree with
// whatever the code does.
//
// So it fails on two distinct breakages: the wiring changing (derivePinKey no
// longer using the production parameters) and the parameters changing (the
// constants being lowered), and it names which.
func TestPINDerivationUsesProductionParameters(t *testing.T) {
	withProductionPINHashCost(t)

	const pin = "1234"
	salt := bytes.Repeat([]byte{0x42}, pinSaltLen)

	// The specification, stated independently of the constants under test.
	want := argon2.IDKey([]byte(pin), salt, 1, 64*1024, 4, 32)

	if got := derivePinKey(pin, salt); !bytes.Equal(got, want) {
		t.Fatalf("derivePinKey does not produce the production derivation:\n"+
			" got %x\nwant %x\n"+
			"either the shipped Argon2 parameters changed (time=%d memory=%d lanes=%d keylen=%d) "+
			"or derivePinKey stopped passing them",
			got, want, pinArgonTime, pinArgonMemory, pinArgonLanes, pinKeyLen)
	}
}

// And the round trip at the production cost: a verifier produced by the
// shipped configuration must validate under it. hashPin and verifyPin read the
// same mutable cost, so a cheap-cost round trip proves they agree with each
// OTHER, not that either matches what ships.
func TestPINHashVerifyRoundTripAtProductionCost(t *testing.T) {
	withProductionPINHashCost(t)

	stored, err := hashPin("user-pin-1234")
	if err != nil {
		t.Fatalf("hashPin: %v", err)
	}
	if !verifyPin(stored, "user-pin-1234") {
		t.Fatal("a production-cost verifier did not validate its own PIN")
	}
	if verifyPin(stored, "wrong-pin-9999") {
		t.Fatal("a production-cost verifier accepted the wrong PIN")
	}
}

// The PRODUCTION cost must not drift. TestMain overrides the variable, never
// the constant, so this still fails if someone lowers what a shipped binary
// uses -- which would silently weaken the control that makes a stolen PIN
// verifier expensive to attack.
func TestPINHashCostIsProductionByDefault(t *testing.T) {
	if pinArgonMemory != 64*1024 {
		t.Fatalf("production Argon2id memory cost = %d KiB, want 65536 (64 MiB): "+
			"lowering this weakens PIN verifier resistance in shipped binaries",
			pinArgonMemory)
	}
	if pinArgonTime != 1 {
		t.Fatalf("production Argon2id time cost = %d, want 1", pinArgonTime)
	}
	if pinArgonLanes != 4 {
		t.Fatalf("production Argon2id lanes = %d, want 4", pinArgonLanes)
	}
	if testArgonMemoryKiB >= pinArgonMemory {
		t.Fatalf("the test cost (%d KiB) is not cheaper than production (%d KiB); "+
			"the override buys nothing", testArgonMemoryKiB, pinArgonMemory)
	}
}
