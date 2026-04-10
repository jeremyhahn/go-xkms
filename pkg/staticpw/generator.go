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
	"crypto/rand"
	"fmt"
	"math/big"
)

// Character class constants used by GeneratePassword.
const (
	// CharsetUpper contains uppercase ASCII letters.
	CharsetUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	// CharsetLower contains lowercase ASCII letters.
	CharsetLower = "abcdefghijklmnopqrstuvwxyz"

	// CharsetDigits contains ASCII decimal digits.
	CharsetDigits = "0123456789"

	// CharsetSymbols contains safe special characters that are universally
	// accepted by web forms, terminals, and clipboard without breaking
	// quoting, escaping, or copy-paste.
	CharsetSymbols = "!@#$%^&*()-_=+?."

	// CharsetAlphanumeric contains uppercase and lowercase ASCII letters
	// plus digits.
	CharsetAlphanumeric = CharsetLower + CharsetUpper + CharsetDigits

	// CharsetAll extends CharsetAlphanumeric with safe special characters.
	CharsetAll = CharsetAlphanumeric + CharsetSymbols
)

// Password length boundaries.
const (
	// DefaultLength is the password length used when zero is provided.
	DefaultLength = 32

	// MinLength is the minimum allowed password length.
	MinLength = 8

	// MaxLength is the maximum allowed password length.
	MaxLength = 128
)

// characterClasses defines the four standard character classes used for
// guaranteed minimum representation when generating with CharsetAll.
var characterClasses = []string{
	CharsetUpper,
	CharsetLower,
	CharsetDigits,
	CharsetSymbols,
}

// GeneratePassword produces a cryptographically random password of the
// requested length drawn from the specified charset.
//
// If length is 0, DefaultLength (32) is used. If charset is the empty string
// or "all", CharsetAll is used. The literal value "alphanumeric" selects
// CharsetAlphanumeric.
//
// When the "all" charset is selected, the generator guarantees at least
// length/8 (minimum 1) characters from each class (upper, lower, digits,
// symbols) to ensure visually strong passwords. Remaining slots are filled
// from the full charset. All positions are then shuffled with Fisher-Yates.
//
// The implementation uses crypto/rand.Int for uniform distribution, avoiding
// modulo bias.
func GeneratePassword(length int, charset string) (string, error) {
	if length == 0 {
		length = DefaultLength
	}
	if length < MinLength || length > MaxLength {
		return "", ErrInvalidLength
	}

	resolved := resolveCharset(charset)

	// Use guaranteed-mix generation for the "all" charset.
	if charset == "" || charset == "all" {
		return generateBalanced(length)
	}

	return generateUniform(length, resolved)
}

// generateBalanced produces a password with guaranteed minimum representation
// from each character class (upper, lower, digits, symbols), then fills
// remaining slots from the full charset and shuffles everything.
func generateBalanced(length int) (string, error) {
	// Guarantee at least length/8 chars per class (min 1).
	perClass := length / 8
	if perClass < 1 {
		perClass = 1
	}

	buf := make([]byte, 0, length)

	// Pick guaranteed characters from each class.
	for _, class := range characterClasses {
		chars, err := randChars(class, perClass)
		if err != nil {
			return "", err
		}
		buf = append(buf, chars...)
	}

	// Fill remaining slots from the full charset.
	remaining := length - len(buf)
	if remaining > 0 {
		chars, err := randChars(CharsetAll, remaining)
		if err != nil {
			return "", err
		}
		buf = append(buf, chars...)
	}

	// Fisher-Yates shuffle to randomize positions.
	if err := shuffle(buf); err != nil {
		return "", err
	}

	return string(buf), nil
}

// generateUniform produces a password by uniformly sampling from the charset.
func generateUniform(length int, charset string) (string, error) {
	buf := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := range buf {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrGenerateFailed, err)
		}
		buf[i] = charset[idx.Int64()]
	}

	return string(buf), nil
}

// randChars picks n cryptographically random characters from the charset.
func randChars(charset string, n int) ([]byte, error) {
	buf := make([]byte, n)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := range buf {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrGenerateFailed, err)
		}
		buf[i] = charset[idx.Int64()]
	}

	return buf, nil
}

// shuffle performs an in-place Fisher-Yates shuffle using crypto/rand.
func shuffle(buf []byte) error {
	for i := len(buf) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("%w: %v", ErrGenerateFailed, err)
		}
		buf[i], buf[j.Int64()] = buf[j.Int64()], buf[i]
	}
	return nil
}

// resolveCharset maps a charset name to the corresponding character string.
// Any non-empty, unrecognized string is treated as a custom charset.
func resolveCharset(charset string) string {
	switch charset {
	case "", "all":
		return CharsetAll
	case "alphanumeric":
		return CharsetAlphanumeric
	default:
		return charset
	}
}
