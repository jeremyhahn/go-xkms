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

package validation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateKeyID_RefusesTheIdentifierSeparator is the core of #168.
//
// KeyAttributes.ID() joins its fields with ':' and parseStorageKeyID
// disambiguates purely by segment count, so a colon inside a key ID shifts
// every field after it. A key ID of "b:c" is written as
// "software:signing:b:c:rsa" and read back with CN == "c": stored, listed
// under a name the caller never asked for, and unreachable by get_key or sign.
//
// A value the validator accepts must be one the storage identifier can round
// trip. The colon is the one character that cannot be.
func TestValidateKeyID_RefusesTheIdentifierSeparator(t *testing.T) {
	for _, keyID := range []string{
		"b:c",
		"acme:evil",
		"a:b:c:d",
		":leading",
		"trailing:",
		"software:signing:rsa:mykey", // the reference form is not a key ID
	} {
		assert.Error(t, ValidateKeyID(keyID),
			"a key ID containing the identifier separator must be refused: %q", keyID)
	}
}

// TestValidateKeyID_AcceptsSimpleNames is the companion: tightening must not
// refuse the names callers legitimately use.
func TestValidateKeyID_AcceptsSimpleNames(t *testing.T) {
	for _, keyID := range []string{
		"mykey",
		"my-key",
		"my_key",
		"my.key",
		"MyKey2026",
		"tenant-a-signing-key",
	} {
		assert.NoError(t, ValidateKeyID(keyID), "%q is a legal simple key ID", keyID)
	}
}

// TestValidateKeyReference_ExtendedFormSurvives is the reason tightening the
// simple validator is safe.
//
// ValidateKeyReference splits on colons BEFORE delegating to ValidateKeyID, so
// the extended format never reaches the simple validator with a separator
// still attached. #168 worried that forbidding the colon would break a real
// feature; it does not, because the feature is implemented by a different
// function that takes the colons apart first.
func TestValidateKeyReference_ExtendedFormSurvives(t *testing.T) {
	for _, ref := range []string{
		"my-key",
		":::my-key",
		"pkcs11:::my-key",
		"pkcs11:signing:ecdsa-p256:my-key",
		"software:tls:rsa:server-key",
	} {
		assert.NoError(t, ValidateKeyReference(ref),
			"the extended reference form must keep working: %q", ref)
	}
}

// TestValidateKeyReference_RefusesColonInKeyname covers what tightening the
// simple validator additionally buys: a keyname component that itself carries
// a separator would shift the identifier exactly as #169 describes, and it is
// now refused inside a reference too.
func TestValidateKeyReference_RefusesColonInKeyname(t *testing.T) {
	// Five colons: four segments plus one buried in the keyname.
	assert.Error(t, ValidateKeyReference("pkcs11:signing:ecdsa-p256:my:key"),
		"a separator inside the keyname must be refused")
}

// TestValidateKeyID_StillRefusesTheOtherUnsafeShapes guards the checks that
// were already there, so narrowing the charset does not quietly drop them.
func TestValidateKeyID_StillRefusesTheOtherUnsafeShapes(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"null byte":      "key\x00id",
		"absolute path":  "/etc/passwd",
		"path traversal": "../../etc/passwd",
		"control char":   "key\x01id",
		"slash":          "a/b",
		"space":          "my key",
		"percent":        "my%key",
	}
	for name, keyID := range cases {
		t.Run(name, func(t *testing.T) {
			require.Error(t, ValidateKeyID(keyID))
		})
	}

	long := make([]byte, 256)
	for i := range long {
		long[i] = 'a'
	}
	assert.Error(t, ValidateKeyID(string(long)), "over the length limit")
}
