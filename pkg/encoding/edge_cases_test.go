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

package encoding

import "testing"

// TestPasswordErrorDetection tests the isPasswordError function
func TestPasswordErrorDetection(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected bool
	}{
		{
			name:     "NilError",
			errMsg:   "",
			expected: false,
		},
		{
			name:     "IncorrectPasswordError",
			errMsg:   "pkcs8: incorrect password",
			expected: true,
		},
		{
			name:     "ShortIncorrectPassword",
			errMsg:   "incorrect password",
			expected: true,
		},
		{
			name:     "ASN1StructureError",
			errMsg:   "asn1: structure error",
			expected: true,
		},
		{
			name:     "TagsDontMatch",
			errMsg:   "tags don't match",
			expected: true,
		},
		{
			name:     "OtherError",
			errMsg:   "some other error",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.errMsg != "" {
				err = &testError{msg: tt.errMsg}
			}
			result := isPasswordError(err)
			if result != tt.expected {
				t.Fatalf("Expected %v, got %v for error: %s", tt.expected, result, tt.errMsg)
			}
		})
	}
}

// testError is a simple error type for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
