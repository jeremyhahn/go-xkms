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

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A StoreType is declared in three places that must agree: the constant, the
// IsValid predicate and the ParseStoreType parser. Nothing makes them agree,
// and a constant added to the first alone compiles, passes review and looks
// right everywhere except where a key's store type is read back -- where it
// becomes StoreUnknown and the key is attributed to no backend at all.
//
// That is not hypothetical: StorePhone was added as a constant and to neither
// the predicate nor the parser, so a phone key's store round-tripped to
// unknown for as long as the phone backend existed. This test is the check
// that would have caught it.
//
// EVERY StoreType constant except StoreUnknown belongs in this list. Adding a
// constant without adding it here leaves the list wrong rather than the code,
// which is the trade this test is making: one list to maintain, in the file
// whose only job is to notice.
var everyStoreType = []StoreType{
	StoreSoftware,
	StorePKCS11,
	StoreTPM2,
	StoreAWSKMS,
	StoreGCPKMS,
	StoreAzureKV,
	StoreVault,
	StoreQuantum,
	StoreFrost,
	StorePhone,
	StoreAVR,
}

func TestEveryStoreTypeIsValid(t *testing.T) {
	for _, st := range everyStoreType {
		assert.True(t, st.IsValid(), "%s is a declared store type but IsValid refuses it", st)
	}
}

func TestEveryStoreTypeRoundTripsThroughItsParser(t *testing.T) {
	for _, st := range everyStoreType {
		got := ParseStoreType(string(st))
		assert.Equal(t, st, got,
			"%s does not survive ParseStoreType; a key in this store reads back as %s", st, got)
	}
}

// The parser lower-cases and trims, so a value that reached it from a config
// file or a URL path still resolves.
func TestEveryStoreTypeRoundTripsFromUntidyInput(t *testing.T) {
	for _, st := range everyStoreType {
		assert.Equal(t, st, ParseStoreType("  "+string(st)+"  "), "%s with surrounding space", st)
	}
	assert.Equal(t, StoreAVR, ParseStoreType("AVR"))
	assert.Equal(t, StorePhone, ParseStoreType("Phone"))
}

// Unknown stays unknown. The parser's job is to refuse what it does not
// recognise, not to guess: a store type nothing declared must not become one
// that something did.
func TestParseStoreTypeStillRefusesWhatItDoesNotKnow(t *testing.T) {
	for _, s := range []string{"", "unknown", "avr2", "av", "phonez", "softhsm"} {
		assert.Equal(t, StoreUnknown, ParseStoreType(s), "%q", s)
	}
	assert.False(t, StoreUnknown.IsValid())
}

// StoreAVR is the store a key in an AVR device's secure element is recorded
// under. Its spelling is the same as the backend type's, because
// backendTypeToStoreType derives one from the other.
func TestStoreAVRSpelling(t *testing.T) {
	assert.Equal(t, "avr", StoreAVR.String())
	assert.Equal(t, string(BackendTypeAVR), StoreAVR.String())
}
