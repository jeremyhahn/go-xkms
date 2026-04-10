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
	"errors"
	"strings"
	"testing"
)

func TestErrors_NonNil(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrKeyboardClosed", ErrKeyboardClosed},
		{"ErrKeyboardOpenFailed", ErrKeyboardOpenFailed},
		{"ErrKeyboardCreateFailed", ErrKeyboardCreateFailed},
		{"ErrUnsupportedChar", ErrUnsupportedChar},
		{"ErrTypeFailed", ErrTypeFailed},
		{"ErrEmptyString", ErrEmptyString},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("%s is nil", tt.name)
			}
		})
	}
}

func TestErrors_KeyboardPrefix(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrKeyboardClosed", ErrKeyboardClosed},
		{"ErrKeyboardOpenFailed", ErrKeyboardOpenFailed},
		{"ErrKeyboardCreateFailed", ErrKeyboardCreateFailed},
		{"ErrUnsupportedChar", ErrUnsupportedChar},
		{"ErrTypeFailed", ErrTypeFailed},
		{"ErrEmptyString", ErrEmptyString},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.HasPrefix(tt.err.Error(), "keyboard:") {
				t.Errorf("%s message %q does not have 'keyboard:' prefix",
					tt.name, tt.err.Error())
			}
		})
	}
}

func TestErrors_Unique(t *testing.T) {
	allErrors := []error{
		ErrKeyboardClosed,
		ErrKeyboardOpenFailed,
		ErrKeyboardCreateFailed,
		ErrUnsupportedChar,
		ErrTypeFailed,
		ErrEmptyString,
	}

	for i, err1 := range allErrors {
		for j, err2 := range allErrors {
			if i != j && errors.Is(err1, err2) {
				t.Errorf("error %v should not match error %v", err1, err2)
			}
		}
	}
}

func TestErrors_NonEmptyMessage(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrKeyboardClosed", ErrKeyboardClosed},
		{"ErrKeyboardOpenFailed", ErrKeyboardOpenFailed},
		{"ErrKeyboardCreateFailed", ErrKeyboardCreateFailed},
		{"ErrUnsupportedChar", ErrUnsupportedChar},
		{"ErrTypeFailed", ErrTypeFailed},
		{"ErrEmptyString", ErrEmptyString},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() == "" {
				t.Errorf("%s has empty error message", tt.name)
			}
		})
	}
}

func TestErrors_SelfMatch(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrKeyboardClosed", ErrKeyboardClosed},
		{"ErrKeyboardOpenFailed", ErrKeyboardOpenFailed},
		{"ErrKeyboardCreateFailed", ErrKeyboardCreateFailed},
		{"ErrUnsupportedChar", ErrUnsupportedChar},
		{"ErrTypeFailed", ErrTypeFailed},
		{"ErrEmptyString", ErrEmptyString},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, tt.err) {
				t.Errorf("errors.Is(%s, %s) = false, want true", tt.name, tt.name)
			}
		})
	}
}
