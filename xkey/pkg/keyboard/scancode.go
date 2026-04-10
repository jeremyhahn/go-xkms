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

// KeyMapping represents a USB HID key with its scancode and modifier state.
type KeyMapping struct {
	// Scancode is the USB HID Usage ID (e.g., 0x04 = 'a').
	Scancode byte

	// Shift indicates whether the Left Shift modifier is required.
	Shift bool
}

// scancodeMap maps runes to their USB HID scancode and shift state.
// This follows the US keyboard layout per the USB HID Usage Tables specification.
var scancodeMap = map[rune]KeyMapping{
	// Lowercase letters: a-z -> scancodes 0x04-0x1D
	'a': {Scancode: 0x04}, 'b': {Scancode: 0x05}, 'c': {Scancode: 0x06},
	'd': {Scancode: 0x07}, 'e': {Scancode: 0x08}, 'f': {Scancode: 0x09},
	'g': {Scancode: 0x0A}, 'h': {Scancode: 0x0B}, 'i': {Scancode: 0x0C},
	'j': {Scancode: 0x0D}, 'k': {Scancode: 0x0E}, 'l': {Scancode: 0x0F},
	'm': {Scancode: 0x10}, 'n': {Scancode: 0x11}, 'o': {Scancode: 0x12},
	'p': {Scancode: 0x13}, 'q': {Scancode: 0x14}, 'r': {Scancode: 0x15},
	's': {Scancode: 0x16}, 't': {Scancode: 0x17}, 'u': {Scancode: 0x18},
	'v': {Scancode: 0x19}, 'w': {Scancode: 0x1A}, 'x': {Scancode: 0x1B},
	'y': {Scancode: 0x1C}, 'z': {Scancode: 0x1D},

	// Uppercase letters: A-Z -> scancodes 0x04-0x1D with shift
	'A': {Scancode: 0x04, Shift: true}, 'B': {Scancode: 0x05, Shift: true},
	'C': {Scancode: 0x06, Shift: true}, 'D': {Scancode: 0x07, Shift: true},
	'E': {Scancode: 0x08, Shift: true}, 'F': {Scancode: 0x09, Shift: true},
	'G': {Scancode: 0x0A, Shift: true}, 'H': {Scancode: 0x0B, Shift: true},
	'I': {Scancode: 0x0C, Shift: true}, 'J': {Scancode: 0x0D, Shift: true},
	'K': {Scancode: 0x0E, Shift: true}, 'L': {Scancode: 0x0F, Shift: true},
	'M': {Scancode: 0x10, Shift: true}, 'N': {Scancode: 0x11, Shift: true},
	'O': {Scancode: 0x12, Shift: true}, 'P': {Scancode: 0x13, Shift: true},
	'Q': {Scancode: 0x14, Shift: true}, 'R': {Scancode: 0x15, Shift: true},
	'S': {Scancode: 0x16, Shift: true}, 'T': {Scancode: 0x17, Shift: true},
	'U': {Scancode: 0x18, Shift: true}, 'V': {Scancode: 0x19, Shift: true},
	'W': {Scancode: 0x1A, Shift: true}, 'X': {Scancode: 0x1B, Shift: true},
	'Y': {Scancode: 0x1C, Shift: true}, 'Z': {Scancode: 0x1D, Shift: true},

	// Digits: 1-9 -> scancodes 0x1E-0x26, 0 -> 0x27
	'1': {Scancode: 0x1E}, '2': {Scancode: 0x1F}, '3': {Scancode: 0x20},
	'4': {Scancode: 0x21}, '5': {Scancode: 0x22}, '6': {Scancode: 0x23},
	'7': {Scancode: 0x24}, '8': {Scancode: 0x25}, '9': {Scancode: 0x26},
	'0': {Scancode: 0x27},

	// Shifted digits (symbols on number row)
	'!': {Scancode: 0x1E, Shift: true}, // Shift+1
	'@': {Scancode: 0x1F, Shift: true}, // Shift+2
	'#': {Scancode: 0x20, Shift: true}, // Shift+3
	'$': {Scancode: 0x21, Shift: true}, // Shift+4
	'%': {Scancode: 0x22, Shift: true}, // Shift+5
	'^': {Scancode: 0x23, Shift: true}, // Shift+6
	'&': {Scancode: 0x24, Shift: true}, // Shift+7
	'*': {Scancode: 0x25, Shift: true}, // Shift+8
	'(': {Scancode: 0x26, Shift: true}, // Shift+9
	')': {Scancode: 0x27, Shift: true}, // Shift+0

	// Special keys
	'\n': {Scancode: 0x28}, // Enter
	'\t': {Scancode: 0x2B}, // Tab
	' ':  {Scancode: 0x2C}, // Space

	// Punctuation (unshifted)
	'-':  {Scancode: 0x2D},
	'=':  {Scancode: 0x2E},
	'[':  {Scancode: 0x2F},
	']':  {Scancode: 0x30},
	'\\': {Scancode: 0x31},
	';':  {Scancode: 0x33},
	'\'': {Scancode: 0x34},
	'`':  {Scancode: 0x35},
	',':  {Scancode: 0x36},
	'.':  {Scancode: 0x37},
	'/':  {Scancode: 0x38},

	// Punctuation (shifted)
	'_': {Scancode: 0x2D, Shift: true}, // Shift+-
	'+': {Scancode: 0x2E, Shift: true}, // Shift+=
	'{': {Scancode: 0x2F, Shift: true}, // Shift+[
	'}': {Scancode: 0x30, Shift: true}, // Shift+]
	'|': {Scancode: 0x31, Shift: true}, // Shift+backslash
	':': {Scancode: 0x33, Shift: true}, // Shift+;
	'"': {Scancode: 0x34, Shift: true}, // Shift+'
	'~': {Scancode: 0x35, Shift: true}, // Shift+`
	'<': {Scancode: 0x36, Shift: true}, // Shift+,
	'>': {Scancode: 0x37, Shift: true}, // Shift+.
	'?': {Scancode: 0x38, Shift: true}, // Shift+/
}

// LookupScancode returns the KeyMapping for the given rune and a boolean
// indicating whether the rune is supported. Returns an empty KeyMapping
// and false for unmapped characters.
func LookupScancode(r rune) (KeyMapping, bool) {
	mapping, ok := scancodeMap[r]
	return mapping, ok
}
