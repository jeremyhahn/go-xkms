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

package staticpw

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePassword_DefaultLength(t *testing.T) {
	pw, err := GeneratePassword(DefaultLength, CharsetAlphanumeric)
	require.NoError(t, err)
	assert.Len(t, pw, DefaultLength)
}

func TestGeneratePassword_SpecificLength(t *testing.T) {
	pw, err := GeneratePassword(24, CharsetAlphanumeric)
	require.NoError(t, err)
	assert.Len(t, pw, 24)
}

func TestGeneratePassword_MinLength(t *testing.T) {
	pw, err := GeneratePassword(MinLength, CharsetAlphanumeric)
	require.NoError(t, err)
	assert.Len(t, pw, MinLength)
}

func TestGeneratePassword_MaxLength(t *testing.T) {
	pw, err := GeneratePassword(MaxLength, CharsetAlphanumeric)
	require.NoError(t, err)
	assert.Len(t, pw, MaxLength)
}

func TestGeneratePassword_TooShort(t *testing.T) {
	_, err := GeneratePassword(MinLength-1, CharsetAlphanumeric)
	assert.ErrorIs(t, err, ErrInvalidLength)
}

func TestGeneratePassword_TooLong(t *testing.T) {
	_, err := GeneratePassword(MaxLength+1, CharsetAlphanumeric)
	assert.ErrorIs(t, err, ErrInvalidLength)
}

func TestGeneratePassword_ZeroLength_DefaultsToDefaultLength(t *testing.T) {
	// Zero length defaults to DefaultLength (32) per implementation.
	pw, err := GeneratePassword(0, CharsetAlphanumeric)
	require.NoError(t, err)
	assert.Len(t, pw, DefaultLength)
}

func TestGeneratePassword_NegativeLength(t *testing.T) {
	_, err := GeneratePassword(-1, CharsetAlphanumeric)
	assert.ErrorIs(t, err, ErrInvalidLength)
}

func TestGeneratePassword_EmptyCharset_DefaultsToAll(t *testing.T) {
	// Empty charset defaults to CharsetAll per resolveCharset.
	pw, err := GeneratePassword(DefaultLength, "")
	require.NoError(t, err)
	assert.Len(t, pw, DefaultLength)
	for _, c := range pw {
		assert.True(t, strings.ContainsRune(CharsetAll, c),
			"unexpected character: %c", c)
	}
}

func TestGeneratePassword_Alphanumeric_OnlyContainsValidChars(t *testing.T) {
	pw, err := GeneratePassword(64, CharsetAlphanumeric)
	require.NoError(t, err)
	for _, c := range pw {
		assert.True(t, strings.ContainsRune(CharsetAlphanumeric, c),
			"unexpected character: %c", c)
	}
}

func TestGeneratePassword_AllCharset_ContainsValidChars(t *testing.T) {
	pw, err := GeneratePassword(64, CharsetAll)
	require.NoError(t, err)
	for _, c := range pw {
		assert.True(t, strings.ContainsRune(CharsetAll, c),
			"unexpected character: %c", c)
	}
}

func TestGeneratePassword_DigitsOnly(t *testing.T) {
	// Using a literal digit string as the charset produces digits-only output.
	const digitCharset = "0123456789"
	pw, err := GeneratePassword(32, digitCharset)
	require.NoError(t, err)
	assert.Len(t, pw, 32)
	for _, c := range pw {
		assert.True(t, c >= '0' && c <= '9',
			"expected digit, got: %c", c)
	}
}

func TestGeneratePassword_SingleCharCharset(t *testing.T) {
	pw, err := GeneratePassword(MinLength, "x")
	require.NoError(t, err)
	assert.Equal(t, strings.Repeat("x", MinLength), pw)
}

func TestGeneratePassword_Uniqueness(t *testing.T) {
	passwords := make(map[string]struct{})
	for i := 0; i < 50; i++ {
		pw, err := GeneratePassword(DefaultLength, CharsetAll)
		require.NoError(t, err)
		_, exists := passwords[pw]
		assert.False(t, exists, "duplicate password generated")
		passwords[pw] = struct{}{}
	}
}

func TestGeneratePassword_CustomCharset(t *testing.T) {
	pw, err := GeneratePassword(16, "abc")
	require.NoError(t, err)
	assert.Len(t, pw, 16)
	for _, c := range pw {
		assert.True(t, c == 'a' || c == 'b' || c == 'c',
			"unexpected character: %c", c)
	}
}

func TestGeneratePassword_BoundaryMinLength(t *testing.T) {
	pw, err := GeneratePassword(8, CharsetAlphanumeric)
	require.NoError(t, err)
	assert.Len(t, pw, 8)
}

func TestGeneratePassword_BoundaryMaxLength(t *testing.T) {
	pw, err := GeneratePassword(128, CharsetAlphanumeric)
	require.NoError(t, err)
	assert.Len(t, pw, 128)
}

func TestGeneratePassword_AllCharsetString(t *testing.T) {
	// The literal "all" maps to CharsetAll via resolveCharset.
	pw, err := GeneratePassword(DefaultLength, "all")
	require.NoError(t, err)
	assert.Len(t, pw, DefaultLength)
}

func TestGeneratePassword_AlphanumericString(t *testing.T) {
	// The literal "alphanumeric" maps to CharsetAlphanumeric via resolveCharset.
	pw, err := GeneratePassword(DefaultLength, "alphanumeric")
	require.NoError(t, err)
	assert.Len(t, pw, DefaultLength)
	for _, c := range pw {
		assert.True(t, strings.ContainsRune(CharsetAlphanumeric, c),
			"unexpected character: %c", c)
	}
}

// --- Balanced generation (CharsetAll guarantees) ---

func TestGeneratePassword_AllCharset_GuaranteesAllClasses(t *testing.T) {
	// With "all" charset, every generated password must contain at least
	// one character from each class: upper, lower, digits, symbols.
	for i := 0; i < 20; i++ {
		pw, err := GeneratePassword(16, "all")
		require.NoError(t, err)
		assert.Len(t, pw, 16)

		hasUpper := strings.ContainsAny(pw, CharsetUpper)
		hasLower := strings.ContainsAny(pw, CharsetLower)
		hasDigit := strings.ContainsAny(pw, CharsetDigits)
		hasSymbol := strings.ContainsAny(pw, CharsetSymbols)

		assert.True(t, hasUpper, "password %q missing uppercase", pw)
		assert.True(t, hasLower, "password %q missing lowercase", pw)
		assert.True(t, hasDigit, "password %q missing digit", pw)
		assert.True(t, hasSymbol, "password %q missing symbol", pw)
	}
}

func TestGeneratePassword_AllCharset_MinSymbolCount(t *testing.T) {
	// A 32-char "all" password should have at least 4 symbols (32/8 per class).
	pw, err := GeneratePassword(32, "all")
	require.NoError(t, err)

	symbolCount := 0
	for _, c := range pw {
		if strings.ContainsRune(CharsetSymbols, c) {
			symbolCount++
		}
	}
	assert.GreaterOrEqual(t, symbolCount, 4,
		"password %q has only %d symbols, expected >= 4", pw, symbolCount)
}

func TestGeneratePassword_EmptyCharset_GuaranteesAllClasses(t *testing.T) {
	// Empty charset defaults to "all" and should also guarantee all classes.
	pw, err := GeneratePassword(32, "")
	require.NoError(t, err)

	assert.True(t, strings.ContainsAny(pw, CharsetUpper), "missing uppercase")
	assert.True(t, strings.ContainsAny(pw, CharsetLower), "missing lowercase")
	assert.True(t, strings.ContainsAny(pw, CharsetDigits), "missing digit")
	assert.True(t, strings.ContainsAny(pw, CharsetSymbols), "missing symbol")
}

func TestGeneratePassword_AllCharset_MinLength8_StillBalanced(t *testing.T) {
	// Even at minimum length (8), all 4 classes should be present.
	for i := 0; i < 20; i++ {
		pw, err := GeneratePassword(8, "all")
		require.NoError(t, err)
		assert.Len(t, pw, 8)

		assert.True(t, strings.ContainsAny(pw, CharsetUpper), "missing uppercase in %q", pw)
		assert.True(t, strings.ContainsAny(pw, CharsetLower), "missing lowercase in %q", pw)
		assert.True(t, strings.ContainsAny(pw, CharsetDigits), "missing digit in %q", pw)
		assert.True(t, strings.ContainsAny(pw, CharsetSymbols), "missing symbol in %q", pw)
	}
}

// --- resolveCharset ---

func TestResolveCharset_All(t *testing.T) {
	// Both empty string and "all" resolve to CharsetAll.
	assert.Equal(t, CharsetAll, resolveCharset(""))
	assert.Equal(t, CharsetAll, resolveCharset("all"))
}

func TestResolveCharset_Alphanumeric(t *testing.T) {
	assert.Equal(t, CharsetAlphanumeric, resolveCharset("alphanumeric"))
}

func TestResolveCharset_Custom(t *testing.T) {
	// Unrecognized strings are returned as-is for use as custom charsets.
	assert.Equal(t, "abc123!@#", resolveCharset("abc123!@#"))
	assert.Equal(t, "XYZ", resolveCharset("XYZ"))
}
