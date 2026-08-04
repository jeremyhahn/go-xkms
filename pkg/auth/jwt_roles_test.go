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

package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// TestExtractRolesClaim covers every shape the "roles"/"role" JWT claims can
// take: the canonical []string and []interface{} forms, a bare string, the
// single-role "role" fallback, and the absence of any role claim.
func TestExtractRolesClaim(t *testing.T) {
	tests := []struct {
		name   string
		claims jwt.MapClaims
		want   []string
	}{
		{
			name:   "roles as []string",
			claims: jwt.MapClaims{"roles": []string{"admin", "viewer"}},
			want:   []string{"admin", "viewer"},
		},
		{
			name:   "roles as []interface{} of strings",
			claims: jwt.MapClaims{"roles": []interface{}{"admin", "viewer"}},
			want:   []string{"admin", "viewer"},
		},
		{
			name:   "roles as []interface{} skips non-string and empty entries",
			claims: jwt.MapClaims{"roles": []interface{}{"admin", 42, "", "viewer"}},
			want:   []string{"admin", "viewer"},
		},
		{
			name:   "roles as single non-empty string",
			claims: jwt.MapClaims{"roles": "admin"},
			want:   []string{"admin"},
		},
		{
			name:   "roles as empty string falls through to role fallback",
			claims: jwt.MapClaims{"roles": "", "role": "viewer"},
			want:   []string{"viewer"},
		},
		{
			name:   "roles of unsupported type falls through to role fallback",
			claims: jwt.MapClaims{"roles": 12345, "role": "viewer"},
			want:   []string{"viewer"},
		},
		{
			name:   "role fallback claim",
			claims: jwt.MapClaims{"role": "editor"},
			want:   []string{"editor"},
		},
		{
			name:   "empty role fallback claim yields nil",
			claims: jwt.MapClaims{"role": ""},
			want:   nil,
		},
		{
			name:   "no role claims yields nil",
			claims: jwt.MapClaims{"sub": "alice"},
			want:   nil,
		},
		{
			name:   "empty roles []string yields empty non-nil slice",
			claims: jwt.MapClaims{"roles": []string{}},
			want:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRolesClaim(tt.claims)
			assert.Equal(t, tt.want, got)
		})
	}
}
