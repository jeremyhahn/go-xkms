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

//go:build integration && fips

package fips

import (
	"sort"
	"testing"

	"github.com/miekg/pkcs11"
)

// TestFIPSFilter_MechanismListShrinksUnderFIPS is the assertion the rest of the
// suite depends on: it proves the FIPS filter runs at all.
//
// Every other test here would still pass if the filter were dead code -- the
// approved mechanisms would work, the mechanism info would be self-consistent,
// and no non-approved mechanism would be reachable simply because none was
// asked for. Comparing the two regimes is the only check that fails when
// C_GetMechanismList is computed without consulting the FIPS policy, which is
// exactly the defect it exists to catch: a second, hand-maintained mechanism
// table feeding C_GetMechanismList while the FIPS-aware registry feeds
// everything else.
func TestFIPSFilter_MechanismListShrinksUnderFIPS(t *testing.T) {
	off := mechanismsInRegime(t, "")
	on := mechanismsInRegime(t, fipsRuntimeValue)

	offSet := off.set()
	onSet := on.set()

	var extra []uint
	for mech := range onSet {
		if _, ok := offSet[mech]; !ok {
			extra = append(extra, mech)
		}
	}
	sort.Slice(extra, func(i, j int) bool { return extra[i] < extra[j] })
	if len(extra) != 0 {
		t.Errorf("FIPS mode advertises mechanisms the non-FIPS module does not: %v\n"+
			"a FIPS build may only ever narrow the surface, never widen it", mechNames(extra))
	}

	var withheld []uint
	for mech := range offSet {
		if _, ok := onSet[mech]; !ok {
			withheld = append(withheld, mech)
		}
	}
	sort.Slice(withheld, func(i, j int) bool { return withheld[i] < withheld[j] })

	t.Logf("C_GetMechanismList without FIPS: %d mechanisms", len(offSet))
	t.Logf("C_GetMechanismList with FIPS:    %d mechanisms", len(onSet))
	t.Logf("withheld under FIPS: %v", mechNames(withheld))

	if len(withheld) == 0 {
		t.Fatalf("C_GetMechanismList is identical with and without FIPS (%d mechanisms both ways): "+
			"the FIPS filter is not running. The module registry marks at least CKM_SHA1_RSA_PKCS "+
			"as not FIPS-approved, so a running filter must withhold it",
			len(onSet))
	}
}

// TestFIPSFilter_SHA1RSAPKCSOfferedOnlyOutsideFIPS pins the motivating case for
// the whole feature.
//
// OASIS conformance requires the module to offer CKM_SHA1_RSA_PKCS, and FIPS
// requires a validated module to withhold it, so the two claims can only both
// hold if the mechanism's availability tracks the mode. Asserting each half
// separately is what distinguishes "the filter works" from "the mechanism was
// deleted", which would satisfy FIPS and break conformance.
func TestFIPSFilter_SHA1RSAPKCSOfferedOnlyOutsideFIPS(t *testing.T) {
	off := mechanismsInRegime(t, "").set()
	on := mechanismsInRegime(t, fipsRuntimeValue).set()

	if _, ok := off[pkcs11.CKM_SHA1_RSA_PKCS]; !ok {
		t.Error("CKM_SHA1_RSA_PKCS is absent from C_GetMechanismList outside FIPS mode; " +
			"OASIS PKCS#11 conformance expects the module to offer it when no FIPS policy applies")
	}
	if _, ok := on[pkcs11.CKM_SHA1_RSA_PKCS]; ok {
		t.Error("CKM_SHA1_RSA_PKCS is present in C_GetMechanismList under FIPS mode; " +
			"FIPS 140-3 does not approve SHA-1 for signature generation, so a validated " +
			"module must not offer it")
	}
}

// TestFIPSFilter_MechanismInfoAgreesWithMechanismList catches the two halves of
// mechanism discovery disagreeing with each other.
//
// C_GetMechanismList and C_GetMechanismInfo are answered from different places
// in this module, so a mechanism can be listed and then denied a description.
// An application that enumerates the list and asks about each entry -- which is
// what every PKCS#11 wrapper does at startup -- sees that as a broken token.
func TestFIPSFilter_MechanismInfoAgreesWithMechanismList(t *testing.T) {
	on := mechanismsInRegime(t, fipsRuntimeValue)

	for _, rec := range on.Mechanisms {
		if rec.InfoError != "" {
			t.Errorf("C_GetMechanismList offers %s (0x%08X) but C_GetMechanismInfo refuses it: %s",
				mechName(rec.Mechanism), rec.Mechanism, rec.InfoError)
		}
	}
}

// TestFIPSFilter_EveryListedMechanismHasAnExerciser refuses to let this suite
// grow a silent coverage hole.
//
// The operational tests are driven by C_GetMechanismList, so a mechanism that
// gains the Advertised flag tomorrow would be exercised by nothing and the
// suite would still report success. Failing here forces the exerciser table to
// keep pace with what the module promises.
func TestFIPSFilter_EveryListedMechanismHasAnExerciser(t *testing.T) {
	on := mechanismsInRegime(t, fipsRuntimeValue)

	var missing []uint
	for _, rec := range on.Mechanisms {
		if _, ok := exercisers[rec.Mechanism]; !ok {
			missing = append(missing, rec.Mechanism)
		}
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i] < missing[j] })

	if len(missing) != 0 {
		t.Fatalf("C_GetMechanismList advertises mechanisms this suite does not exercise: %v\n"+
			"add an entry to the exercisers table -- an advertised mechanism that no test "+
			"runs to completion is a promise nobody has checked", mechNames(missing))
	}
	t.Logf("%d advertised mechanisms, all with an exerciser", len(on.Mechanisms))
}
