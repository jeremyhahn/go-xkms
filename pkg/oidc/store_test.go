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

package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeIssuer(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://auth.example.com", "https://auth.example.com"},
		{"https://auth.example.com/", "https://auth.example.com"},
		{"HTTPS://AUTH.EXAMPLE.COM", "https://auth.example.com"},
		{"HTTPS://AUTH.EXAMPLE.COM/", "https://auth.example.com"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := normalizeIssuer(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
