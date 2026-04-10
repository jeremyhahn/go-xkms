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

package keyboard

import (
	"testing"
)

func TestLookupScancode_LowercaseLetters(t *testing.T) {
	for r := 'a'; r <= 'z'; r++ {
		t.Run(string(r), func(t *testing.T) {
			mapping, ok := LookupScancode(r)
			if !ok {
				t.Errorf("LookupScancode(%q) not found", r)
				return
			}

			expectedScancode := byte(0x04 + (r - 'a'))
			if mapping.Scancode != expectedScancode {
				t.Errorf("LookupScancode(%q).Scancode = 0x%02X, want 0x%02X",
					r, mapping.Scancode, expectedScancode)
			}
			if mapping.Shift {
				t.Errorf("LookupScancode(%q).Shift = true, want false", r)
			}
		})
	}
}

func TestLookupScancode_UppercaseLetters(t *testing.T) {
	for r := 'A'; r <= 'Z'; r++ {
		t.Run(string(r), func(t *testing.T) {
			mapping, ok := LookupScancode(r)
			if !ok {
				t.Errorf("LookupScancode(%q) not found", r)
				return
			}

			expectedScancode := byte(0x04 + (r - 'A'))
			if mapping.Scancode != expectedScancode {
				t.Errorf("LookupScancode(%q).Scancode = 0x%02X, want 0x%02X",
					r, mapping.Scancode, expectedScancode)
			}
			if !mapping.Shift {
				t.Errorf("LookupScancode(%q).Shift = false, want true", r)
			}
		})
	}
}

func TestLookupScancode_Digits(t *testing.T) {
	tests := []struct {
		r        rune
		scancode byte
	}{
		{'1', 0x1E}, {'2', 0x1F}, {'3', 0x20}, {'4', 0x21}, {'5', 0x22},
		{'6', 0x23}, {'7', 0x24}, {'8', 0x25}, {'9', 0x26}, {'0', 0x27},
	}

	for _, tt := range tests {
		t.Run(string(tt.r), func(t *testing.T) {
			mapping, ok := LookupScancode(tt.r)
			if !ok {
				t.Errorf("LookupScancode(%q) not found", tt.r)
				return
			}
			if mapping.Scancode != tt.scancode {
				t.Errorf("LookupScancode(%q).Scancode = 0x%02X, want 0x%02X",
					tt.r, mapping.Scancode, tt.scancode)
			}
			if mapping.Shift {
				t.Errorf("LookupScancode(%q).Shift = true, want false", tt.r)
			}
		})
	}
}

func TestLookupScancode_ShiftedDigitSymbols(t *testing.T) {
	tests := []struct {
		r        rune
		scancode byte
	}{
		{'!', 0x1E}, {'@', 0x1F}, {'#', 0x20}, {'$', 0x21}, {'%', 0x22},
		{'^', 0x23}, {'&', 0x24}, {'*', 0x25}, {'(', 0x26}, {')', 0x27},
	}

	for _, tt := range tests {
		t.Run(string(tt.r), func(t *testing.T) {
			mapping, ok := LookupScancode(tt.r)
			if !ok {
				t.Errorf("LookupScancode(%q) not found", tt.r)
				return
			}
			if mapping.Scancode != tt.scancode {
				t.Errorf("LookupScancode(%q).Scancode = 0x%02X, want 0x%02X",
					tt.r, mapping.Scancode, tt.scancode)
			}
			if !mapping.Shift {
				t.Errorf("LookupScancode(%q).Shift = false, want true", tt.r)
			}
		})
	}
}

func TestLookupScancode_SpaceAndTab(t *testing.T) {
	tests := []struct {
		name     string
		r        rune
		scancode byte
	}{
		{"space", ' ', 0x2C},
		{"tab", '\t', 0x2B},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapping, ok := LookupScancode(tt.r)
			if !ok {
				t.Errorf("LookupScancode(%q) not found", tt.r)
				return
			}
			if mapping.Scancode != tt.scancode {
				t.Errorf("LookupScancode(%q).Scancode = 0x%02X, want 0x%02X",
					tt.r, mapping.Scancode, tt.scancode)
			}
			if mapping.Shift {
				t.Errorf("LookupScancode(%q).Shift = true, want false", tt.r)
			}
		})
	}
}

func TestLookupScancode_Enter(t *testing.T) {
	mapping, ok := LookupScancode('\n')
	if !ok {
		t.Fatal("LookupScancode('\\n') not found")
	}
	if mapping.Scancode != 0x28 {
		t.Errorf("LookupScancode('\\n').Scancode = 0x%02X, want 0x28", mapping.Scancode)
	}
	if mapping.Shift {
		t.Error("LookupScancode('\\n').Shift = true, want false")
	}
}

func TestLookupScancode_UnshiftedPunctuation(t *testing.T) {
	tests := []struct {
		r        rune
		scancode byte
	}{
		{'-', 0x2D}, {'=', 0x2E}, {'[', 0x2F}, {']', 0x30}, {'\\', 0x31},
		{';', 0x33}, {'\'', 0x34}, {'`', 0x35}, {',', 0x36}, {'.', 0x37},
		{'/', 0x38},
	}

	for _, tt := range tests {
		t.Run(string(tt.r), func(t *testing.T) {
			mapping, ok := LookupScancode(tt.r)
			if !ok {
				t.Errorf("LookupScancode(%q) not found", tt.r)
				return
			}
			if mapping.Scancode != tt.scancode {
				t.Errorf("LookupScancode(%q).Scancode = 0x%02X, want 0x%02X",
					tt.r, mapping.Scancode, tt.scancode)
			}
			if mapping.Shift {
				t.Errorf("LookupScancode(%q).Shift = true, want false", tt.r)
			}
		})
	}
}

func TestLookupScancode_ShiftedPunctuation(t *testing.T) {
	tests := []struct {
		r        rune
		scancode byte
	}{
		{'_', 0x2D}, {'+', 0x2E}, {'{', 0x2F}, {'}', 0x30}, {'|', 0x31},
		{':', 0x33}, {'"', 0x34}, {'~', 0x35}, {'<', 0x36}, {'>', 0x37},
		{'?', 0x38},
	}

	for _, tt := range tests {
		t.Run(string(tt.r), func(t *testing.T) {
			mapping, ok := LookupScancode(tt.r)
			if !ok {
				t.Errorf("LookupScancode(%q) not found", tt.r)
				return
			}
			if mapping.Scancode != tt.scancode {
				t.Errorf("LookupScancode(%q).Scancode = 0x%02X, want 0x%02X",
					tt.r, mapping.Scancode, tt.scancode)
			}
			if !mapping.Shift {
				t.Errorf("LookupScancode(%q).Shift = false, want true", tt.r)
			}
		})
	}
}

func TestLookupScancode_TildeAndBacktick(t *testing.T) {
	// Backtick (unshifted)
	mapping, ok := LookupScancode('`')
	if !ok {
		t.Fatal("LookupScancode('`') not found")
	}
	if mapping.Scancode != 0x35 {
		t.Errorf("backtick scancode = 0x%02X, want 0x35", mapping.Scancode)
	}
	if mapping.Shift {
		t.Error("backtick Shift = true, want false")
	}

	// Tilde (shifted)
	mapping, ok = LookupScancode('~')
	if !ok {
		t.Fatal("LookupScancode('~') not found")
	}
	if mapping.Scancode != 0x35 {
		t.Errorf("tilde scancode = 0x%02X, want 0x35", mapping.Scancode)
	}
	if !mapping.Shift {
		t.Error("tilde Shift = false, want true")
	}
}

func TestLookupScancode_UnmappedChars(t *testing.T) {
	unmapped := []rune{
		0x1F600,  // grinning face emoji
		0x00E9,   // e with acute accent
		0x00F1,   // n with tilde
		0x4E16,   // CJK character
		0x0000,   // null
		0x007F,   // DEL
		0x1B,     // escape (not mapped in our table)
		0x100000, // supplementary private use area
	}

	for _, r := range unmapped {
		t.Run("U+"+string([]rune{r}), func(t *testing.T) {
			_, ok := LookupScancode(r)
			if ok {
				t.Errorf("LookupScancode(U+%04X) found, want not found", r)
			}
		})
	}
}

func TestLookupScancode_ShiftConsistency(t *testing.T) {
	// Verify that lowercase letters never have shift, uppercase always have shift,
	// and that they share the same scancode.
	for lower := 'a'; lower <= 'z'; lower++ {
		upper := lower - 32 // ASCII uppercase offset

		lm, lok := LookupScancode(lower)
		um, uok := LookupScancode(upper)

		if !lok || !uok {
			t.Errorf("missing mapping for %q or %q", lower, upper)
			continue
		}

		if lm.Scancode != um.Scancode {
			t.Errorf("%q scancode 0x%02X != %q scancode 0x%02X",
				lower, lm.Scancode, upper, um.Scancode)
		}

		if lm.Shift {
			t.Errorf("%q should not have Shift", lower)
		}
		if !um.Shift {
			t.Errorf("%q should have Shift", upper)
		}
	}
}

func TestLookupScancode_AllPrintableASCII(t *testing.T) {
	// Verify that all printable ASCII characters (0x20-0x7E) are mapped,
	// except for characters we explicitly do not map.
	unmappedPrintable := map[rune]bool{
		// No printable ASCII characters should be unmapped in a US keyboard layout.
		// This test ensures complete coverage.
	}

	for r := rune(0x20); r <= 0x7E; r++ {
		if unmappedPrintable[r] {
			continue
		}
		t.Run(string(r), func(t *testing.T) {
			_, ok := LookupScancode(r)
			if !ok {
				t.Errorf("LookupScancode(%q / U+%04X) not found", r, r)
			}
		})
	}
}

func TestLookupScancode_ReturnsFalseForUnmapped(t *testing.T) {
	mapping, ok := LookupScancode(0xFFFF)
	if ok {
		t.Errorf("LookupScancode(0xFFFF) ok = true, want false")
	}
	if mapping.Scancode != 0 {
		t.Errorf("LookupScancode(0xFFFF).Scancode = 0x%02X, want 0x00", mapping.Scancode)
	}
	if mapping.Shift {
		t.Error("LookupScancode(0xFFFF).Shift = true, want false")
	}
}
